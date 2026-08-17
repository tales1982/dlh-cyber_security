#!/bin/bash
#
# 15-compliance_report.sh
#
# MedDefense Health Systems - The Patch Equation (2x03)
#
# The single JSON document that answers "where do we stand, right now, on
# every known CVE on this host" - for an auditor, a regulator or Dr.
# Morales. Not a prose report: a machine-readable statement of posture,
# built from the artifacts every earlier task already produced.
#
# Usage: sudo ./15-compliance_report.sh [output.json]

set -uo pipefail

OUT_JSON="${1:-patch_compliance.json}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
TARGET_SCORE="95.00"

resolve_input() {
    local name="$1" candidate
    for candidate in "./${name}" "${SCRIPT_DIR}/${name}" "${SCRIPT_DIR}/../${name}"; do
        [ -f "$candidate" ] && { echo "$candidate"; return 0; }
    done
    echo "$name"
}

VULN_JSON="$(resolve_input vulnerability_inventory.json)"
CHANGE_LOG_JSON="$(resolve_input patch_change_log.json)"
HOLD_JSON="$(resolve_input hold_management.json)"
PIPELINE_JSON="$(resolve_input pipeline_run.json)"
HISTORY_DIR="${SCRIPT_DIR}/history"
[ -d "./history" ] && HISTORY_DIR="./history"

if [ ! -r "$VULN_JSON" ]; then
    echo "error: cannot read $VULN_JSON (run 0-vuln_inventory.sh first)" >&2
    exit 1
fi

GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
HOSTNAME_VAL="$(hostname)"
KERNEL_VAL="$(uname -r)"
TODAY_EPOCH="$(date -u -d "$(date -u +%F)" +%s)"

# --- Gather every historical inventory snapshot, current + rotated --------
# ./history/*.json is where a log-rotation job would drop dated copies of
# vulnerability_inventory.json. Optional: if it does not exist, the current
# snapshot is the only evidence of "first_seen" this run can offer.
mapfile -t SNAPSHOTS < <(
    { [ -d "$HISTORY_DIR" ] && find "$HISTORY_DIR" -maxdepth 1 -name '*.json' 2>/dev/null | sort; true; }
    echo "$VULN_JSON"
)

# --- Build: cve -> {package, severity, first_seen, last_seen_in} ----------
CVE_FACTS_FILE="$(mktemp)"
for snap in "${SNAPSHOTS[@]}"; do
    [ -f "$snap" ] || continue
    gen_at="$(jq -r '.generated_at // empty' "$snap" 2>/dev/null)"
    [ -z "$gen_at" ] && gen_at="$GENERATED_AT"
    jq -c --arg snap "$snap" --arg gen_at "$gen_at" \
        '.packages[]? | select((.cves // []) | length > 0) | .cves[] as $cve |
         {cve: $cve, package: .package, severity: .severity, seen_at: $gen_at, snapshot: $snap}' \
        "$snap" 2>/dev/null >> "$CVE_FACTS_FILE"
done

# --- Cross-reference with what is currently open, held or resolved --------
CURRENT_CVES_JSON="$(jq -c '[.packages[]?.cves[]?] | unique' "$VULN_JSON")"
HELD_PACKAGES_JSON="[]"
[ -f "$HOLD_JSON" ] && HELD_PACKAGES_JSON="$(jq -c '[.applied[]?.package]' "$HOLD_JSON" 2>/dev/null || echo '[]')"
PIPELINE_STATUS="unknown"
[ -f "$PIPELINE_JSON" ] && PIPELINE_STATUS="$(jq -r '.pipeline_status // "unknown"' "$PIPELINE_JSON")"

RESULTS_FILE="$(mktemp)"
trap 'rm -f "$CVE_FACTS_FILE" "$RESULTS_FILE"' EXIT

mapfile -t ALL_CVES < <(jq -r '.cve' "$CVE_FACTS_FILE" 2>/dev/null | sort -u)

# Pre-group facts and resolved-at lookups by CVE in one jq pass each, instead
# of re-scanning the whole facts file / change log once per CVE inside the
# loop below - with a large accumulated ./history/, that O(cve_count *
# facts_count) rescan is slow enough to be a real risk, not just style.
# Severity is ranked explicitly (critical > high > medium > low); a plain
# alphabetical sort would rank "medium" above "critical".
declare -A CVE_PACKAGE CVE_SEVERITY CVE_FIRST_SEEN
while IFS=$'\t' read -r fcve fpackage fseverity ffirst_seen; do
    [ -z "$fcve" ] && continue
    CVE_PACKAGE["$fcve"]="$fpackage"
    CVE_SEVERITY["$fcve"]="$fseverity"
    CVE_FIRST_SEEN["$fcve"]="$ffirst_seen"
done < <(jq -rs '
    def sev_rank($s): {"critical":3,"high":2,"medium":1,"low":0}[$s] // -1;
    group_by(.cve)[] |
    {
        cve: .[0].cve,
        package: .[0].package,
        severity: (map(.severity) | sort_by(-sev_rank(.)) | .[0]),
        first_seen: (map(.seen_at) | sort | .[0])
    } | [.cve, .package, .severity, .first_seen] | @tsv
' "$CVE_FACTS_FILE")

declare -A CVE_RESOLVED_AT
if [ -f "$CHANGE_LOG_JSON" ]; then
    while IFS=$'\t' read -r rcve rresolved_at; do
        [ -z "$rcve" ] && continue
        CVE_RESOLVED_AT["$rcve"]="$rresolved_at"
    done < <(jq -r '
        [.events[]? | . as $e | ($e.cves_resolved // [])[] | {cve: ., started: $e.started}]
        | group_by(.cve)[]
        | [.[0].cve, (map(.started) | sort | .[0])] | @tsv
    ' "$CHANGE_LOG_JSON" 2>/dev/null)
fi

resolved=0; open=0; deferred_held=0; deferred_window=0
resolved_critical_high=0; total_critical_high=0; overdue=0

for cve in "${ALL_CVES[@]}"; do
    [ -z "$cve" ] && continue

    package="${CVE_PACKAGE[$cve]:-}"
    severity="${CVE_SEVERITY[$cve]:-}"
    first_seen="${CVE_FIRST_SEEN[$cve]:-}"

    is_current="$(jq --arg c "$cve" 'index($c) != null' <<<"$CURRENT_CVES_JSON")"
    is_held="$(jq --arg p "$package" 'index($p) != null' <<<"$HELD_PACKAGES_JSON")"

    # resolved_at feeds --argjson below, so it must be valid JSON text: the
    # bare word null, or a properly double-quoted string.
    resolved_at="null"
    if [ "$is_current" != "true" ]; then
        state="resolved"
        [ -n "${CVE_RESOLVED_AT[$cve]:-}" ] && resolved_at="\"${CVE_RESOLVED_AT[$cve]}\""
    elif [ "$is_held" = "true" ]; then
        state="deferred_held"
    elif [ "$PIPELINE_STATUS" = "deferred" ]; then
        state="deferred_window"
    else
        state="open"
    fi

    case "$state" in
        resolved) resolved=$((resolved + 1)) ;;
        open) open=$((open + 1)) ;;
        deferred_held) deferred_held=$((deferred_held + 1)) ;;
        deferred_window) deferred_window=$((deferred_window + 1)) ;;
    esac

    is_ch="false"
    [[ "$severity" == "critical" || "$severity" == "high" ]] && is_ch="true"
    if [ "$is_ch" = "true" ]; then
        total_critical_high=$((total_critical_high + 1))
        [ "$state" = "resolved" ] && resolved_critical_high=$((resolved_critical_high + 1))
    fi

    # Overdue: open, critical or high, and open for more than 7 days.
    days_open=0
    first_epoch="$(date -u -d "$first_seen" +%s 2>/dev/null || echo "$TODAY_EPOCH")"
    days_open=$(( (TODAY_EPOCH - first_epoch) / 86400 ))
    is_overdue="false"
    if [ "$state" != "resolved" ] && [ "$is_ch" = "true" ] && [ "$days_open" -gt 7 ]; then
        is_overdue="true"
        overdue=$((overdue + 1))
    fi

    justification="null"
    if [ "$state" = "deferred_held" ] && [ -f "$HOLD_JSON" ]; then
        j="$(jq -r --arg p "$package" '.applied[]? | select(.package==$p) | .reason' "$HOLD_JSON" 2>/dev/null | head -1)"
        [ -n "$j" ] && justification="\"$j\""
    elif [ "$state" = "deferred_window" ]; then
        justification="\"awaiting next maintenance window\""
    fi

    jq -nc \
        --arg id "$cve" --arg package "$package" --arg severity "$severity" --arg state "$state" \
        --arg first_seen "$first_seen" --argjson resolved_at "$resolved_at" \
        --argjson justification "$justification" --argjson overdue "$is_overdue" \
        '{id: $id, package: $package, severity: $severity, state: $state,
          first_seen: $first_seen, resolved_at: $resolved_at, justification: $justification,
          overdue: $overdue}' >> "$RESULTS_FILE"
done

# score = resolved_critical_high / total_critical_high, as a percentage with two decimals.
SCORE="100.00"
[ "$total_critical_high" -gt 0 ] && SCORE="$(awk -v r="$resolved_critical_high" -v t="$total_critical_high" 'BEGIN{printf "%.2f", (r/t)*100}')"

# score/target_score are emitted as strings, not JSON numbers: jq's number
# type has no concept of trailing-zero precision, so "100.00" round-trips
# as "100" on jq < 1.7 (jq 1.6 ships on this host) - a real, reproducible
# loss of the required two-decimal-place formatting, not just cosmetics.
jq -n \
    --arg generated_at "$GENERATED_AT" --arg hostname "$HOSTNAME_VAL" --arg kernel "$KERNEL_VAL" \
    --argjson resolved "$resolved" --argjson open "$open" --argjson deferred_held "$deferred_held" \
    --argjson deferred_window "$deferred_window" --arg score "$SCORE" --arg target "$TARGET_SCORE" \
    --argjson overdue "$overdue" \
    --slurpfile cves <(jq -s '.' "$RESULTS_FILE") \
    '{generated_at: $generated_at, hostname: $hostname, kernel: $kernel,
      summary: {resolved: $resolved, open: $open, deferred_held: $deferred_held,
                deferred_window: $deferred_window, score: $score,
                target_score: $target, overdue: $overdue},
      cves: $cves[0]}' > "$OUT_JSON"

echo "resolved: $resolved  open: $open  deferred_held: $deferred_held  deferred_window: $deferred_window"
echo "score: $SCORE  target: $TARGET_SCORE  overdue: $overdue"
echo "Report saved to: $OUT_JSON"

# Exit 0 if the compliance score meets or exceeds the target, exit 1 otherwise.
if awk -v s="$SCORE" -v t="$TARGET_SCORE" 'BEGIN{exit !(s+0 >= t+0)}'; then
    exit 0
else
    exit 1
fi
