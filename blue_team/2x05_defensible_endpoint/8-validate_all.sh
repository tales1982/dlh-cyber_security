#!/bin/bash
#
# Loads capstone/target_state.json and evaluates every control in
# target_state.controls. Dispatches on check_type: file_exists,
# json_field_equals, json_field_gte, command_exit_zero, grep_match.
# Records a verdict (pass, fail, error) and the evidence that produced it
# for each control, aggregates totals by family, prints a table to stdout,
# and exits 0 only if fail_count == 0 and error_count == 0.
#
# This is a dispatcher, not a rewrite of every control: it reuses the
# artifacts T3 through T7 already produced by reading target_state.json's
# own check_target values, and never re-implements a control's logic here.
#
# A corrupted or missing target_state.json is fatal.
#
# Windows controls (platform: windows) are dispatched over WinRM to the
# host in WINRM_HOST (default: DC01's IP) using WINRM_USER / WINRM_PASS
# from the environment - never hardcoded here. A Windows control whose
# credentials are not set, or whose WinRM call cannot even connect, gets
# verdict "error" (distinct from "fail": the check itself could not run).
#
# Usage: WINRM_USER=analyst WINRM_PASS='...' ./8-validate_all.sh
#
# Artifact (relative to this script's directory):
#   capstone/validation_report.json

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAPSTONE_DIR="${SCRIPT_DIR}/capstone"
TARGET_STATE_FILE="${CAPSTONE_DIR}/target_state.json"
REPORT_FILE="${CAPSTONE_DIR}/validation_report.json"
WINRM_HELPER="${SCRIPT_DIR}/overrides/winrm_exec.py"

export WINRM_HOST="${WINRM_HOST:-192.168.56.119}"

for cmd in jq grep; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Error: required command '$cmd' not found." >&2
        exit 2
    fi
done

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Error: this script must run as root - several controls (aa-status, auditctl, nft list ruleset) read root-only state and would otherwise report false failures instead of a truthful verdict." >&2
    exit 2
fi

if [[ ! -f "$TARGET_STATE_FILE" ]]; then
    echo "Error: '$TARGET_STATE_FILE' is missing. A missing target_state.json is fatal. Run 2-target_state.sh first." >&2
    exit 2
fi

if ! jq -e . "$TARGET_STATE_FILE" > /dev/null 2>&1; then
    echo "Error: '$TARGET_STATE_FILE' is corrupted. A corrupted target_state.json is fatal." >&2
    exit 2
fi

resolve_local_path() {
    local p="$1"
    [[ "$p" = /* ]] && { echo "$p"; return; }
    echo "${SCRIPT_DIR}/${p}"
}

# Normalizes a json_field_* check_target's field expression: a bare field
# name/path (no leading "." or "[") is treated as shorthand for ".<expr>";
# an expression that already starts with "." or "[" is used verbatim, so
# both "hardening_index" and ".sysmon_events | length" work.
normalize_jq_expr() {
    local expr="$1"
    case "$expr" in
        .*|\[*) echo "$expr" ;;
        *) echo ".${expr}" ;;
    esac
}

winrm_dispatch() {
    local ps_command="$1"
    if [[ -z "${WINRM_USER:-}" || -z "${WINRM_PASS:-}" ]]; then
        echo "__WINRM_ERROR__:WINRM_USER/WINRM_PASS not set in the environment"
        return 2
    fi
    if [[ ! -f "$WINRM_HELPER" ]]; then
        echo "__WINRM_ERROR__:winrm_exec.py helper not found at $WINRM_HELPER"
        return 2
    fi
    local out
    out=$(python3 "$WINRM_HELPER" "$ps_command" 2>&1)
    local rc=$?
    echo "$out"
    return "$rc"
}

RESULTS="[]"
TOTAL=0
PASS_COUNT=0
FAIL_COUNT=0
ERROR_COUNT=0

CONTROL_COUNT=$(jq '.controls | length' "$TARGET_STATE_FILE")

for ((i = 0; i < CONTROL_COUNT; i++)); do
    CONTROL=$(jq -c ".controls[$i]" "$TARGET_STATE_FILE")
    ID=$(jq -r '.id' <<< "$CONTROL")
    PLATFORM=$(jq -r '.platform' <<< "$CONTROL")
    FAMILY=$(jq -r '.family' <<< "$CONTROL")
    CHECK_TYPE=$(jq -r '.check_type' <<< "$CONTROL")
    CHECK_TARGET=$(jq -r '.check_target' <<< "$CONTROL")
    EXPECTED=$(jq -c '.expected_value' <<< "$CONTROL")
    EXPECTED_RAW=$(jq -r '.expected_value' <<< "$CONTROL")
    SEVERITY=$(jq -r '.severity' <<< "$CONTROL")

    VERDICT=""
    EVIDENCE=""
    TOTAL=$((TOTAL + 1))

    case "$CHECK_TYPE" in
        file_exists)
            if [[ "$PLATFORM" == "windows" ]]; then
                winrm_dispatch "if (Test-Path '${CHECK_TARGET}') { exit 0 } else { exit 1 }" >/dev/null
                RC=$?
                if [[ "$RC" -eq 0 ]]; then VERDICT="pass"; elif [[ "$RC" -eq 2 ]]; then VERDICT="error"; else VERDICT="fail"; fi
                EVIDENCE="winrm:Test-Path '${CHECK_TARGET}' (exit ${RC})"
            else
                LOCAL_PATH="$(resolve_local_path "$CHECK_TARGET")"
                if [[ -e "$LOCAL_PATH" ]]; then VERDICT="pass"; else VERDICT="fail"; fi
                EVIDENCE="$LOCAL_PATH"
            fi
            ;;

        json_field_equals | json_field_gte)
            FILE_PART="${CHECK_TARGET%%#*}"
            FIELD_PART="${CHECK_TARGET#*#}"
            JQ_EXPR="$(normalize_jq_expr "$FIELD_PART")"

            if [[ "$PLATFORM" == "windows" ]]; then
                JSON_TEXT=$(winrm_dispatch "Get-Content '${FILE_PART}' -Raw")
                RC=$?
                if [[ "$RC" -ne 0 ]]; then
                    VERDICT="error"
                    EVIDENCE="winrm:Get-Content '${FILE_PART}' failed (exit ${RC})"
                fi
            else
                LOCAL_PATH="$(resolve_local_path "$FILE_PART")"
                if [[ ! -f "$LOCAL_PATH" ]]; then
                    VERDICT="error"
                    EVIDENCE="file not found: $LOCAL_PATH"
                else
                    JSON_TEXT=$(cat "$LOCAL_PATH")
                fi
            fi

            if [[ -z "$VERDICT" ]]; then
                ACTUAL=$(jq -c "$JQ_EXPR" <<< "$JSON_TEXT" 2>/dev/null)
                if [[ -z "$ACTUAL" ]]; then
                    VERDICT="error"
                    EVIDENCE="${FILE_PART}#${JQ_EXPR}: field could not be evaluated"
                else
                    if [[ "$CHECK_TYPE" == "json_field_equals" ]]; then
                        if [[ "$ACTUAL" == "$EXPECTED" ]]; then VERDICT="pass"; else VERDICT="fail"; fi
                    else
                        if jq -ne --argjson a "$ACTUAL" --argjson e "$EXPECTED" '$a >= $e' >/dev/null 2>&1 && [[ "$(jq -ne --argjson a "$ACTUAL" --argjson e "$EXPECTED" '$a >= $e' 2>/dev/null)" == "true" ]]; then
                            VERDICT="pass"
                        else
                            VERDICT="fail"
                        fi
                    fi
                    EVIDENCE="${FILE_PART}#${JQ_EXPR} = ${ACTUAL} (expected ${CHECK_TYPE##json_field_}: ${EXPECTED})"
                fi
            fi
            ;;

        command_exit_zero)
            if [[ "$PLATFORM" == "windows" ]]; then
                winrm_dispatch "$CHECK_TARGET" >/dev/null
                RC=$?
                if [[ "$RC" -eq 0 ]]; then VERDICT="pass"; elif [[ "$RC" -eq 2 ]]; then VERDICT="error"; else VERDICT="fail"; fi
                EVIDENCE="winrm:${CHECK_TARGET} (exit ${RC})"
            else
                bash -c "$CHECK_TARGET" >/dev/null 2>&1
                RC=$?
                if [[ "$RC" -eq 0 ]]; then VERDICT="pass"; else VERDICT="fail"; fi
                EVIDENCE="${CHECK_TARGET} (exit ${RC})"
            fi
            ;;

        grep_match)
            if [[ "$PLATFORM" == "windows" ]]; then
                FILE_TEXT=$(winrm_dispatch "Get-Content '${CHECK_TARGET}' -Raw")
                RC=$?
                if [[ "$RC" -ne 0 ]]; then
                    VERDICT="error"
                    EVIDENCE="winrm:Get-Content '${CHECK_TARGET}' failed (exit ${RC})"
                else
                    if grep -E -q -- "$EXPECTED_RAW" <<< "$FILE_TEXT"; then VERDICT="pass"; else VERDICT="fail"; fi
                    EVIDENCE="${CHECK_TARGET} ~= /${EXPECTED_RAW}/"
                fi
            else
                LOCAL_PATH="$(resolve_local_path "$CHECK_TARGET")"
                if [[ ! -f "$LOCAL_PATH" ]]; then
                    VERDICT="error"
                    EVIDENCE="file not found: $LOCAL_PATH"
                else
                    if grep -E -q -- "$EXPECTED_RAW" "$LOCAL_PATH"; then VERDICT="pass"; else VERDICT="fail"; fi
                    EVIDENCE="${LOCAL_PATH} ~= /${EXPECTED_RAW}/"
                fi
            fi
            ;;

        *)
            VERDICT="error"
            EVIDENCE="unknown check_type: $CHECK_TYPE"
            ;;
    esac

    if [[ -z "$VERDICT" ]]; then
        VERDICT="error"
        EVIDENCE="internal dispatcher error: no verdict was set for check_type '$CHECK_TYPE'"
    fi

    case "$VERDICT" in
        pass) PASS_COUNT=$((PASS_COUNT + 1)) ;;
        fail) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
        error) ERROR_COUNT=$((ERROR_COUNT + 1)) ;;
    esac

    printf '%-16s %-8s %-8s\n' "$ID" "$FAMILY" "$VERDICT"

    ENTRY=$(jq -n \
        --arg id "$ID" --arg platform "$PLATFORM" --arg family "$FAMILY" \
        --arg check_type "$CHECK_TYPE" --arg severity "$SEVERITY" \
        --arg verdict "$VERDICT" --arg evidence "$EVIDENCE" \
        '{id: $id, platform: $platform, family: $family, check_type: $check_type,
          severity: $severity, verdict: $verdict, evidence: $evidence}')
    RESULTS=$(jq --argjson e "$ENTRY" '. + [$e]' <<< "$RESULTS")
done

PASS_PCT=0
[[ "$TOTAL" -gt 0 ]] && PASS_PCT=$(jq -n --argjson p "$PASS_COUNT" --argjson t "$TOTAL" '(($p / $t) * 100 * 10 | round) / 10')

echo ""
echo "=== Family summary ==="
printf '%-14s %-8s %-8s %-8s %-8s\n' "FAMILY" "TOTAL" "PASS" "FAIL" "ERROR"
for family in $(jq -r '[.controls[].family] | unique[]' "$TARGET_STATE_FILE"); do
    F_TOTAL=$(jq --arg f "$family" '[.[] | select(.family == $f)] | length' <<< "$RESULTS")
    F_PASS=$(jq --arg f "$family" '[.[] | select(.family == $f and .verdict == "pass")] | length' <<< "$RESULTS")
    F_FAIL=$(jq --arg f "$family" '[.[] | select(.family == $f and .verdict == "fail")] | length' <<< "$RESULTS")
    F_ERROR=$(jq --arg f "$family" '[.[] | select(.family == $f and .verdict == "error")] | length' <<< "$RESULTS")
    printf '%-14s %-8s %-8s %-8s %-8s\n' "$family" "$F_TOTAL" "$F_PASS" "$F_FAIL" "$F_ERROR"
done

echo ""
echo "Total: $TOTAL   Pass: $PASS_COUNT   Fail: $FAIL_COUNT   Error: $ERROR_COUNT   Pass%: ${PASS_PCT}"

HOSTNAME_VAL=$(hostname)
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

if ! jq -n \
    --arg timestamp "$TIMESTAMP" \
    --arg hostname "$HOSTNAME_VAL" \
    --argjson total "$TOTAL" \
    --argjson pass_count "$PASS_COUNT" \
    --argjson fail_count "$FAIL_COUNT" \
    --argjson error_count "$ERROR_COUNT" \
    --argjson pass_percentage "$PASS_PCT" \
    --argjson controls "$RESULTS" \
    '{
        timestamp: $timestamp,
        hostname: $hostname,
        total: $total,
        pass_count: $pass_count,
        fail_count: $fail_count,
        error_count: $error_count,
        pass_percentage: $pass_percentage,
        controls: $controls
    }' > "$REPORT_FILE"; then
    echo "Error: failed to write '$REPORT_FILE'." >&2
    exit 2
fi

echo "Validation report written to $REPORT_FILE"

if [[ "$FAIL_COUNT" -eq 0 && "$ERROR_COUNT" -eq 0 ]]; then
    exit 0
else
    exit 1
fi
