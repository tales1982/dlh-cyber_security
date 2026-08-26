#!/bin/bash
#
# Orchestrates the Linux hardening pass against hawthorne-app-01 in
# deterministic order: SSH hardening, sysctl hardening, permission sweep,
# service minimization, PAM configuration, AppArmor enforcement, auditd deployment.
# Captures the stdout and exit code of each sub-step into the execution log below.
# After the run, re-runs lynis audit system and captures the new Hardening Index.
# Exits 0 only if every sub-step exited 0 and lynis_after >= target_state.linux.hardening_index.
#
# Artifacts (relative to this script's directory):
#   capstone/exec/linux_harden.log
#   capstone/exec/linux_harden.json

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAPSTONE_DIR="${SCRIPT_DIR}/capstone"
EXEC_DIR="${CAPSTONE_DIR}/exec"
BASELINE_FILE="${CAPSTONE_DIR}/baseline/baseline_linux.json"
TARGET_STATE_FILE="${CAPSTONE_DIR}/target_state.json"
GATES_DIR="${SCRIPT_DIR}/../2x00_locking_the_gates"
OVERRIDES_DIR="${SCRIPT_DIR}/overrides"
LOG_FILE="${EXEC_DIR}/linux_harden.log"
OUTPUT_JSON_FILE="${EXEC_DIR}/linux_harden.json"

for cmd in jq lynis sudo; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Error: required command '$cmd' not found." >&2
        exit 2
    fi
done

if [[ ! -f "$TARGET_STATE_FILE" ]]; then
    echo "Error: '$TARGET_STATE_FILE' is missing. Run 2-target_state.sh first." >&2
    exit 2
fi

if ! jq -e . "$TARGET_STATE_FILE" > /dev/null 2>&1; then
    echo "Error: '$TARGET_STATE_FILE' is corrupted." >&2
    exit 2
fi

if [[ ! -f "$BASELINE_FILE" ]]; then
    echo "Error: '$BASELINE_FILE' is missing. Run 1-baseline_snapshot.sh first." >&2
    exit 2
fi

if ! jq -e . "$BASELINE_FILE" > /dev/null 2>&1; then
    echo "Error: '$BASELINE_FILE' is corrupted." >&2
    exit 2
fi

if [[ ! -d "$GATES_DIR" ]]; then
    echo "Error: hardening script directory '$GATES_DIR' not found." >&2
    exit 2
fi

mkdir -p "$EXEC_DIR" || {
    echo "Error: unable to create '$EXEC_DIR'." >&2
    exit 2
}

LYNIS_BEFORE=$(jq -r '.hardening_index // 0' "$BASELINE_FILE")
TARGET_LYNIS=$(jq -r '.controls[] | select(.id=="LNX-LYNIS-01") | .expected_value' "$TARGET_STATE_FILE")
TARGET_LYNIS="${TARGET_LYNIS:-80}"

: > "$LOG_FILE"

STEP_NAMES=(ssh_hardening sysctl_hardening permission_sweep service_minimization pam_configuration apparmor_enforcement auditd_deployment)
STEP_SCRIPTS=(4-ssh_hardening.sh 5-sysctl_hardening.sh 6-filesystem_hardening.sh 7-service_minimization.sh 8-pam_hardening.sh 9-apparmor_config.sh 10-auditd_config.sh)
STEP_CONTROLS=("LNX-SSH-01 LNX-SSH-02" "LNX-SYSCTL-01 LNX-SYSCTL-02" "" "" "" "LNX-APPARMOR-01" "LNX-AUDITD-01")

STEPS_JSON="[]"
CONTROLS_TOUCHED="[]"
ALL_OK=1

for i in "${!STEP_NAMES[@]}"; do
    NAME="${STEP_NAMES[$i]}"
    SCRIPT="${STEP_SCRIPTS[$i]}"
    if [[ -f "${OVERRIDES_DIR}/${SCRIPT}" ]]; then
        SCRIPT_PATH="${OVERRIDES_DIR}/${SCRIPT}"
    else
        SCRIPT_PATH="${GATES_DIR}/${SCRIPT}"
    fi

    {
        echo "===== STEP: ${NAME} (${SCRIPT}) ====="
        date -u +"%Y-%m-%dT%H:%M:%SZ"
    } >> "$LOG_FILE"

    START_TS=$(date +%s)

    if [[ ! -f "$SCRIPT_PATH" ]]; then
        echo "ERROR: script not found: $SCRIPT_PATH" >> "$LOG_FILE"
        EXIT_CODE=1
    else
        chmod +x "$SCRIPT_PATH" 2> /dev/null
        STEP_OUTPUT=$(cd "$EXEC_DIR" && sudo "$SCRIPT_PATH" 2>&1)
        EXIT_CODE=$?
        echo "$STEP_OUTPUT" >> "$LOG_FILE"
    fi

    END_TS=$(date +%s)
    DURATION=$((END_TS - START_TS))

    echo "exit_code=${EXIT_CODE} duration=${DURATION}s" >> "$LOG_FILE"

    if [[ "$EXIT_CODE" -ne 0 ]]; then
        ALL_OK=0
        CHANGED=false
    else
        CHANGED=true
    fi

    STEP_ENTRY=$(jq -n \
        --arg name "$NAME" \
        --arg script_path "$SCRIPT_PATH" \
        --argjson exit_code "$EXIT_CODE" \
        --argjson duration_seconds "$DURATION" \
        --argjson changed "$CHANGED" \
        '{name: $name, script_path: $script_path, exit_code: $exit_code, duration_seconds: $duration_seconds, changed: $changed}')

    STEPS_JSON=$(jq --argjson step "$STEP_ENTRY" '. + [$step]' <<< "$STEPS_JSON")

    for id in ${STEP_CONTROLS[$i]}; do
        CONTROLS_TOUCHED=$(jq --arg id "$id" '. + [$id]' <<< "$CONTROLS_TOUCHED")
    done
done

{
    echo "===== POST-HARDENING LYNIS AUDIT ====="
    date -u +"%Y-%m-%dT%H:%M:%SZ"
} >> "$LOG_FILE"

LYNIS_OUTPUT=$(sudo lynis audit system --quick --no-colors 2>&1)
echo "$LYNIS_OUTPUT" >> "$LOG_FILE"

LYNIS_AFTER=$(sudo grep -m1 '^hardening_index=' /var/log/lynis-report.dat 2> /dev/null | cut -d= -f2)
LYNIS_AFTER="${LYNIS_AFTER:-0}"

if [[ "$LYNIS_AFTER" -ge "$TARGET_LYNIS" ]]; then
    CONTROLS_TOUCHED=$(jq '. + ["LNX-LYNIS-01"]' <<< "$CONTROLS_TOUCHED")
fi

INDEX_DELTA=$((LYNIS_AFTER - LYNIS_BEFORE))
HOSTNAME_VAL=$(hostname)
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

if ! jq -n \
    --arg timestamp "$TIMESTAMP" \
    --arg hostname "$HOSTNAME_VAL" \
    --argjson steps "$STEPS_JSON" \
    --argjson lynis_before "$LYNIS_BEFORE" \
    --argjson lynis_after "$LYNIS_AFTER" \
    --argjson index_delta "$INDEX_DELTA" \
    --argjson controls_touched "$CONTROLS_TOUCHED" \
    '{
        timestamp: $timestamp,
        hostname: $hostname,
        steps: $steps,
        lynis_before: $lynis_before,
        lynis_after: $lynis_after,
        index_delta: $index_delta,
        controls_touched: $controls_touched
    }' > "$OUTPUT_JSON_FILE"; then
    echo "Error: failed to write '$OUTPUT_JSON_FILE'." >&2
    exit 2
fi

echo "Linux hardening evidence written to $OUTPUT_JSON_FILE"
echo "Lynis: ${LYNIS_BEFORE} -> ${LYNIS_AFTER} (delta ${INDEX_DELTA}, target ${TARGET_LYNIS})"

if [[ "$ALL_OK" -eq 1 && "$LYNIS_AFTER" -ge "$TARGET_LYNIS" ]]; then
    exit 0
else
    exit 1
fi
