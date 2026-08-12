#!/bin/bash
#
# 12-linux_detection_proof.sh
#
# MedDefense Health Systems - Eyes on the Endpoint (2x02), Task 12.
#
# The Linux counterpart to 10-windows_detection_proof.ps1, applying the
# same methodology to auditd, auth.log and syslog: for every action in
# linux_attack_log.json (Task 11's ground truth), search each source
# within a 30-second window around its timestamp. This reveals whether
# the auditd rules from 2x00 Task 10 and 2x02 Task 5 actually provide the
# coverage they claim to - not just whether the key exists in
# meddefense.rules, but whether ausearch can actually produce a matching
# event.
#
# Read-only. Requires root to read auditd logs (ausearch) and auth.log.
#
# Usage: sudo ./12-linux_detection_proof.sh [ground_truth.json] [report.json]

set -euo pipefail

GROUND_TRUTH_PATH="${1:-linux_attack_log.json}"
REPORT_PATH="${2:-linux_detection_matrix.json}"
WINDOW_SECONDS=30
AUTH_LOG="${AUTH_LOG:-/var/log/auth.log}"
CURRENT_YEAR="$(date +%Y)"

if [ ! -r "$GROUND_TRUTH_PATH" ]; then
    echo "Error: $GROUND_TRUTH_PATH not found - run 11-linux_attack_sim.sh first." >&2
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: this script must run as root to query ausearch and read auth.log" >&2
    exit 1
fi

# to_epoch <syslog-style timestamp> -> epoch seconds. Handles both modern
# rsyslog ISO-8601-with-offset and classic "Mon DD HH:MM:SS" (assumed
# current year, no timezone of its own).
to_epoch() {
    local raw="$1"
    if [[ "$raw" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2} ]]; then
        date -d "${raw:0:19}${raw:19:6}" +%s 2>/dev/null || date -d "${raw:0:19}" +%s 2>/dev/null || echo 0
    else
        # Year must trail the rest of the string ("Mon DD HH:MM:SS YYYY") -
        # GNU date's parser rejects it prepended ("YYYY Mon DD HH:MM:SS"),
        # which made every classic syslog-format timestamp here silently
        # fail to parse and fall back to epoch 0.
        date -d "${raw:0:15} $CURRENT_YEAR" +%s 2>/dev/null || echo 0
    fi
}

# check_auditd <key> <start_epoch> <end_epoch>: ausearch -ts/-te each take a
# date and a time as two separate arguments.
check_auditd() {
    local key="$1" start="$2" end="$3"
    local sd st ed et hits
    # ausearch -ts/-te on this system's auditd build rejects a 4-digit
    # year ("Error parsing start date (08/12/2026)") and only accepts
    # 2-digit MM/DD/YY, matching what `date +%x` produces here - a build/
    # locale-specific parsing quirk, not documented behavior to rely on
    # generally, but this is what actually works on this target.
    sd="$(date -d "@$start" +%m/%d/%y)"; st="$(date -d "@$start" +%H:%M:%S)"
    ed="$(date -d "@$end" +%m/%d/%y)"; et="$(date -d "@$end" +%H:%M:%S)"
    # --input-logs forces a direct read of the on-disk audit log - on some
    # auditd/ausearch builds the default query path silently returns no
    # matches even though the event is present in the log. Matching is
    # restricted to type=SYSCALL records carrying this exact key:
    # ausearch -k groups by shared event ID, so a broader match could pull
    # in unrelated records sharing an event ID with a CONFIG_CHANGE
    # (op=add_rule) record, falsely counting as a "capture" if this
    # action's 30-second window happens to overlap a rule (re)load.
    hits=$(ausearch --input-logs -k "$key" -ts "$sd" "$st" -te "$ed" "$et" 2>/dev/null | grep -c "^type=SYSCALL.*key=\"$key\"") || true
    echo "${hits:-0}"
}

# key_fields_for <audit_key>: the raw audit record fields relevant to
# confirming a genuine match for this key, mirroring 7-linux_export.sh's
# own field1/field2 extraction - path+operation (name/nametype) for the
# -w watch rules (identity, sudoers_d, cron_config, cron_persist, etc.), comm+exe for
# the execve syscall rule (process_exec), saddr for the socket/connect
# syscall rule (network_connect).
key_fields_for() {
    case "$1" in
        process_exec) echo '["comm","exe"]' ;;
        network_connect) echo '["saddr"]' ;;
        useradd) echo '["username"]' ;;
        *) echo '["name","nametype"]' ;;
    esac
}

# check_auth_log <grep_pattern> <start_epoch> <end_epoch>: greps auth.log
# for the pattern, then keeps only matches whose own timestamp falls
# inside the window (auth.log entries are rare enough per pattern that a
# per-line date subprocess here is negligible, unlike Task 7's full-file
# scan).
check_auth_log() {
    local pattern="$1" start="$2" end="$3" count=0
    [ -r "$AUTH_LOG" ] || { echo 0; return; }
    while IFS= read -r line; do
        local epoch
        epoch="$(to_epoch "$line")"
        if [ "$epoch" -ge "$start" ] && [ "$epoch" -le "$end" ]; then
            count=$((count + 1))
        fi
    done < <(grep -F -- "$pattern" "$AUTH_LOG" 2>/dev/null || true)
    echo "$count"
}

ACTION_COUNT=$(jq -r '.actions_total' "$GROUND_TRUTH_PATH")
echo "[*] Loading ground truth ($ACTION_COUNT actions)..."
echo "[*] Searching telemetry..."

MATRIX_JSONL=""
ACTIONS_CAPTURED=0
MULTI_SOURCE_COUNT=0

printf '%-26s %-14s %-16s %-9s %s\n' "Action" "Source" "Key" "Detail" "Status"
printf '%-26s %-14s %-16s %-9s %s\n' "------" "------" "---" "------" "------"

ACTION_NUMBERS=$(jq -r '.actions[].action_number' "$GROUND_TRUTH_PATH")
for num in $ACTION_NUMBERS; do
    action=$(jq -c --argjson n "$num" '.actions[] | select(.action_number == $n)' "$GROUND_TRUTH_PATH")
    desc=$(jq -r '.description' <<<"$action")
    ts=$(jq -r '.timestamp' <<<"$action")
    expected_key=$(jq -r '.expected_detection_source.audit_key' <<<"$action")

    center_epoch=$(date -u -d "$ts" +%s 2>/dev/null) || center_epoch=$(date +%s)
    window_start=$((center_epoch - WINDOW_SECONDS))
    window_end=$((center_epoch + WINDOW_SECONDS))

    sources_captured=0
    row_label="$desc"

    # --- auditd: the primary expected source for every one of these actions ---
    auditd_hits="$(check_auditd "$expected_key" "$window_start" "$window_end")"
    if [ "$auditd_hits" -gt 0 ]; then
        status="[CAPTURED]"; detail="Full"
        sources_captured=$((sources_captured + 1))
    else
        status="[MISSED]"; detail="Missed"
    fi
    printf '%-26s %-14s %-16s %-9s %s\n' "$row_label" "auditd" "$expected_key" "$detail" "$status"
    key_fields="$(key_fields_for "$expected_key")"
    MATRIX_JSONL="${MATRIX_JSONL}$(jq -n --argjson n "$num" --arg action "$desc" --arg source "auditd" \
        --arg key "$expected_key" --argjson key_fields "$key_fields" --arg detail "$detail" --arg status "$status" \
        '{action_number: $n, action: $action, source: $source, audit_key: $key, key_fields: $key_fields, detail_level: $detail, status: $status}')"$'\n'
    row_label=""

    # --- auth.log secondary check: only meaningful for the user-creation action ---
    if [[ "$desc" == Creating\ user* ]]; then
        auth_hits="$(check_auth_log "new user" "$window_start" "$window_end")"
        if [ "$auth_hits" -gt 0 ]; then
            status2="[CAPTURED]"; detail2="Full"
            sources_captured=$((sources_captured + 1))
        else
            status2="[MISSED]"; detail2="Missed"
        fi
        printf '%-26s %-14s %-16s %-9s %s\n' "$row_label" "auth.log" "useradd" "$detail2" "$status2"
        key_fields2="$(key_fields_for "useradd")"
        MATRIX_JSONL="${MATRIX_JSONL}$(jq -n --argjson n "$num" --arg action "$desc" --arg source "auth.log" \
            --arg key "useradd" --argjson key_fields "$key_fields2" --arg detail "$detail2" --arg status "$status2" \
            '{action_number: $n, action: $action, source: $source, audit_key: $key, key_fields: $key_fields, detail_level: $detail, status: $status}')"$'\n'
    fi

    if [ "$sources_captured" -gt 0 ]; then ACTIONS_CAPTURED=$((ACTIONS_CAPTURED + 1)); fi
    if [ "$sources_captured" -gt 1 ]; then MULTI_SOURCE_COUNT=$((MULTI_SOURCE_COUNT + 1)); fi
done

CAPTURED_PCT=0
if [ "$ACTION_COUNT" -gt 0 ]; then
    CAPTURED_PCT=$(( (ACTIONS_CAPTURED * 100) / ACTION_COUNT ))
fi
echo "Actions: $ACTION_COUNT | Captured: $ACTIONS_CAPTURED/$ACTION_COUNT (${CAPTURED_PCT}%) | Multi-source: $MULTI_SOURCE_COUNT"

MATRIX_JSON=$(jq -s '.' <<<"$MATRIX_JSONL")
jq -n --argjson matrix "$MATRIX_JSON" --arg generated "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg source_ground_truth "$GROUND_TRUTH_PATH" --argjson window_seconds "$WINDOW_SECONDS" \
    --argjson actions_total "$ACTION_COUNT" --argjson actions_captured "$ACTIONS_CAPTURED" \
    --argjson captured_pct "$CAPTURED_PCT" --argjson multi_source "$MULTI_SOURCE_COUNT" \
    '{
      generated: $generated,
      source_ground_truth: $source_ground_truth,
      window_seconds: $window_seconds,
      actions_total: $actions_total,
      actions_captured: $actions_captured,
      captured_percentage: $captured_pct,
      multi_source_actions: $multi_source,
      detection_matrix: $matrix
    }' > "$REPORT_PATH"

echo "Report saved to: $REPORT_PATH"
