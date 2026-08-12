#!/bin/bash
#
# 15-handoff_validation.sh
#
# MedDefense Health Systems - Eyes on the Endpoint (2x02), Task 15.
#
# The final quality gate before crossing from the builder role into the
# analyst role: a meta-validator of telemetry_handoff/ itself - file
# existence, JSON validity, required-field presence, minimum event
# counts, ISO 8601 timestamp sanity (valid, no future dates), cross-
# platform time-range overlap, and ground truth completeness against the
# detection matrices (Tasks 10 and 12). Every check reports PASS/FAIL
# independently; the verdict is PASS only if every single one is.
#
# Read-only. Uses jq for all JSON processing. Makes no configuration changes.
#
# Usage: ./15-handoff_validation.sh

set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-telemetry_handoff}"
WINDOWS_EVENTS="$HANDOFF_DIR/windows_events.json"
LINUX_EVENTS="$HANDOFF_DIR/linux_events.json"
GROUND_TRUTH="$HANDOFF_DIR/attack_ground_truth.json"
WINDOWS_MATRIX="${WINDOWS_MATRIX:-windows_detection_matrix.json}"
LINUX_MATRIX="${LINUX_MATRIX:-linux_detection_matrix.json}"
OUT_JSON="${1:-handoff_validation.json}"

MIN_WINDOWS_EVENTS=1000
MIN_LINUX_EVENTS=500
MIN_GROUND_TRUTH_ACTIONS=10

CHECKS_JSONL=""
PASS_COUNT=0
FAIL_COUNT=0

# record <check_name> <passed:0/1> <detail>
record() {
    local name="$1" ok="$2" detail="$3"
    if [ "$ok" -eq 1 ]; then
        echo "[PASS] $detail"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "[FAIL] $detail"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    CHECKS_JSONL="${CHECKS_JSONL}$(jq -n --arg name "$name" --arg detail "$detail" --argjson ok "$([ "$ok" -eq 1 ] && echo true || echo false)" \
        '{check: $name, status: (if $ok then "PASS" else "FAIL" end), detail: $detail}')"$'\n'
}

human_size() {
    local bytes
    bytes=$(stat -c%s "$1" 2>/dev/null) || bytes=0
    numfmt --to=iec --suffix=B --format="%.1f" "$bytes" 2>/dev/null || echo "${bytes}B"
}

echo "[*] Validating $HANDOFF_DIR/ ..."

# --- File Existence ----------------------------------------------------------------------------
echo "=== File Existence ==="
for pair in "windows_events.json:$WINDOWS_EVENTS" "linux_events.json:$LINUX_EVENTS" "attack_ground_truth.json:$GROUND_TRUTH"; do
    name="${pair%%:*}"; path="${pair#*:}"
    if [ -f "$path" ]; then
        record "file_exists_$name" 1 "$name exists ($(human_size "$path"))"
    else
        record "file_exists_$name" 0 "$name NOT found at $path"
    fi
done

# --- JSON Validity -------------------------------------------------------------------------------
echo "=== JSON Validity ==="
WINDOWS_COUNT=0; LINUX_COUNT=0; GT_COUNT=0
for pair in "windows_events.json:$WINDOWS_EVENTS:events" "linux_events.json:$LINUX_EVENTS:events" "attack_ground_truth.json:$GROUND_TRUTH:actions"; do
    name="${pair%%:*}"; rest="${pair#*:}"; path="${rest%%:*}"; arraykey="${rest#*:}"
    if [ -f "$path" ] && jq empty "$path" >/dev/null 2>&1; then
        count=$(jq --arg k "$arraykey" '.[$k] | length' "$path" 2>/dev/null) || count=0
        count="${count:-0}"
        record "json_valid_$name" 1 "$name: valid JSON, $count objects"
        case "$name" in
            windows_events.json) WINDOWS_COUNT="$count" ;;
            linux_events.json) LINUX_COUNT="$count" ;;
            attack_ground_truth.json) GT_COUNT="$count" ;;
        esac
    else
        record "json_valid_$name" 0 "$name: invalid or missing JSON"
    fi
done

# --- Required Fields -----------------------------------------------------------------------------
echo "=== Required Fields ==="
REQUIRED_FIELDS='["timestamp","hostname","source_type","event_category"]'
MISSING_TOTAL=0
for path in "$WINDOWS_EVENTS" "$LINUX_EVENTS"; do
    if [ -f "$path" ]; then
        m=$(jq --argjson req "$REQUIRED_FIELDS" '[.events[]? | . as $e | ($req - ($e | keys)) | select(length > 0)] | length' "$path" 2>/dev/null) || m=0
        MISSING_TOTAL=$((MISSING_TOTAL + ${m:-0}))
    fi
done
if [ "$MISSING_TOTAL" -eq 0 ]; then
    record "required_fields" 1 "All events have timestamp, hostname, source_type, event_category"
else
    record "required_fields" 0 "$MISSING_TOTAL event(s) missing a required field"
fi

# --- Minimum Event Counts --------------------------------------------------------------------------
echo "=== Minimum Event Counts ==="
[ "$WINDOWS_COUNT" -ge "$MIN_WINDOWS_EVENTS" ] 2>/dev/null && wc_ok=1 || wc_ok=0
record "min_windows_events" "$wc_ok" "Windows: $WINDOWS_COUNT >= $MIN_WINDOWS_EVENTS"
[ "$LINUX_COUNT" -ge "$MIN_LINUX_EVENTS" ] 2>/dev/null && lc_ok=1 || lc_ok=0
record "min_linux_events" "$lc_ok" "Linux: $LINUX_COUNT >= $MIN_LINUX_EVENTS"
[ "$GT_COUNT" -ge "$MIN_GROUND_TRUTH_ACTIONS" ] 2>/dev/null && gt_ok=1 || gt_ok=0
record "min_ground_truth_actions" "$gt_ok" "Ground truth: $GT_COUNT >= $MIN_GROUND_TRUTH_ACTIONS"

# --- Timestamp Consistency ---------------------------------------------------------------------
echo "=== Timestamp Consistency ==="
NOW_EPOCH=$(date -u +%s)
ISO_RE='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'

ALL_TIMESTAMPS=""
for path in "$WINDOWS_EVENTS" "$LINUX_EVENTS"; do
    [ -f "$path" ] && ALL_TIMESTAMPS="${ALL_TIMESTAMPS}$(jq -r '.events[]?.timestamp' "$path" 2>/dev/null)"$'\n' || true
done
ALL_TIMESTAMPS=$(echo "$ALL_TIMESTAMPS" | sed '/^$/d')

INVALID_COUNT=$(echo "$ALL_TIMESTAMPS" | grep -vcE "$ISO_RE" || true)
if [ "${INVALID_COUNT:-0}" -eq 0 ]; then
    record "timestamps_valid_iso8601" 1 "All timestamps valid ISO 8601"
else
    record "timestamps_valid_iso8601" 0 "$INVALID_COUNT timestamp(s) not valid ISO 8601"
fi

# Batched in a single jq pass rather than a bash loop spawning `date` per
# line - this list can run to tens of thousands of timestamps.
FUTURE_COUNT=$(jq -R -s --argjson now "$NOW_EPOCH" '
    split("\n") | map(select(length > 0)) |
    map(select(test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))) |
    map(strptime("%Y-%m-%dT%H:%M:%SZ") | mktime) |
    map(select(. > $now)) | length
' <<<"$ALL_TIMESTAMPS") || FUTURE_COUNT=0
if [ "$FUTURE_COUNT" -eq 0 ]; then
    record "no_future_timestamps" 1 "No future timestamps"
else
    record "no_future_timestamps" 0 "$FUTURE_COUNT event(s) with a future timestamp"
fi

# || true on each: under pipefail, `sort | head -1` on a large stream
# has `head` close its read end after one line while `sort` still has
# more buffered to write, so `sort` gets SIGPIPE (exit 141) - real
# output already made it through the pipe by then, but without this
# guard `set -e` would treat that 141 as a hard failure and abort here.
RANGE_START=$(echo "$ALL_TIMESTAMPS" | sort | head -1) || true
RANGE_END=$(echo "$ALL_TIMESTAMPS" | sort | tail -1) || true
RANGE_START="${RANGE_START:-1970-01-01T00:00:00Z}"
RANGE_END="${RANGE_END:-1970-01-01T00:00:00Z}"
record "timestamp_range" 1 "Range: $RANGE_START to $RANGE_END"

# --- Cross-Platform Alignment ----------------------------------------------------------------------
echo "=== Cross-Platform Alignment ==="
WIN_TIMESTAMPS=$( { jq -r '.events[]?.timestamp' "$WINDOWS_EVENTS" 2>/dev/null || true; } | sort)
LIN_TIMESTAMPS=$( { jq -r '.events[]?.timestamp' "$LINUX_EVENTS" 2>/dev/null || true; } | sort)
WIN_MIN=$(echo "$WIN_TIMESTAMPS" | head -1) || true; WIN_MAX=$(echo "$WIN_TIMESTAMPS" | tail -1) || true
LIN_MIN=$(echo "$LIN_TIMESTAMPS" | head -1) || true; LIN_MAX=$(echo "$LIN_TIMESTAMPS" | tail -1) || true

if [ -n "$WIN_MIN" ] && [ -n "$LIN_MIN" ]; then
    win_min_e=$(date -u -d "$WIN_MIN" +%s 2>/dev/null) || win_min_e=0
    win_max_e=$(date -u -d "$WIN_MAX" +%s 2>/dev/null) || win_max_e=0
    lin_min_e=$(date -u -d "$LIN_MIN" +%s 2>/dev/null) || lin_min_e=0
    lin_max_e=$(date -u -d "$LIN_MAX" +%s 2>/dev/null) || lin_max_e=0

    overlap_start=$((win_min_e > lin_min_e ? win_min_e : lin_min_e))
    overlap_end=$((win_max_e < lin_max_e ? win_max_e : lin_max_e))
    overlap_seconds=$((overlap_end - overlap_start))

    if [ "$overlap_seconds" -gt 0 ]; then
        overlap_hours=$(awk -v s="$overlap_seconds" 'BEGIN{printf "%.1f", s/3600}')
        record "cross_platform_alignment" 1 "Windows and Linux time ranges overlap (${overlap_hours} hours shared)"
    else
        record "cross_platform_alignment" 0 "Windows and Linux time ranges do not overlap"
    fi
else
    record "cross_platform_alignment" 0 "Could not determine time ranges for one or both platforms"
fi

# --- Ground Truth Completeness ----------------------------------------------------------------------
echo "=== Ground Truth Completeness ==="
GT_TOTAL="$GT_COUNT"
MATRIX_ENTRIES=0
for path in "$WINDOWS_MATRIX" "$LINUX_MATRIX"; do
    if [ -f "$path" ]; then
        c=$(jq '[.detection_matrix[]?.action] | unique | length' "$path" 2>/dev/null) || c=0
        MATRIX_ENTRIES=$((MATRIX_ENTRIES + ${c:-0}))
    fi
done
if [ "$GT_TOTAL" -gt 0 ] && [ "$MATRIX_ENTRIES" -ge "$GT_TOTAL" ]; then
    record "ground_truth_completeness" 1 "$GT_TOTAL/$GT_TOTAL actions have detection matrix entries"
else
    record "ground_truth_completeness" 0 "Only $MATRIX_ENTRIES/$GT_TOTAL actions have a detection matrix entry"
fi

# --- Verdict --------------------------------------------------------------------------------------
TOTAL_CHECKS=$((PASS_COUNT + FAIL_COUNT))
if [ "$FAIL_COUNT" -eq 0 ]; then
    echo "VERDICT: PASS ($PASS_COUNT/$TOTAL_CHECKS checks)"
    echo "Handoff package is ready for Module 3."
    VERDICT="PASS"
else
    echo "VERDICT: FAIL ($PASS_COUNT/$TOTAL_CHECKS checks)"
    echo "Handoff package is NOT ready for Module 3 - review the FAIL lines above."
    VERDICT="FAIL"
fi

CHECKS_JSON=$(jq -s '.' <<<"$CHECKS_JSONL")
jq -n --argjson checks "$CHECKS_JSON" --arg generated "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson pass "$PASS_COUNT" --argjson fail "$FAIL_COUNT" --argjson total "$TOTAL_CHECKS" --arg verdict "$VERDICT" \
    '{generated: $generated, checks_passed: $pass, checks_failed: $fail, checks_total: $total, verdict: $verdict, checks: $checks}' \
    > "$OUT_JSON"

echo "Report saved to: $OUT_JSON"

[ "$FAIL_COUNT" -eq 0 ]
