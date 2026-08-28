#!/bin/bash
# Name: 8-validate_all.sh
# Purpose: End-to-end validation suite that reads target_state.json, evaluates every control, and produces a machine-readable report
# Dispatches on check_type: file_exists, json_field_equals, json_field_gte, command_exit_zero, grep_match
# Reuses the artifacts T3 through T7 already produced - this is a dispatcher, not a rewrite of every control
# A corrupted or missing target_state.json is fatal
# Self-contained: a control whose platform does not match this host is recorded as verdict "skip", evaluated locally, no network calls
# Artifact: capstone/validation.json
# Exit Codes: 0=fail_count and error_count are both zero, 1=one or more controls failed or errored, 2=environment error

set -uo pipefail

TARGET_STATE_FILE="${1:-capstone/target_state.json}"
REPORT_FILE="capstone/validation.json"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAPSTONE_DIR="${SCRIPT_DIR}/capstone"

if [[ ! -f "$TARGET_STATE_FILE" ]]; then
    TARGET_STATE_FILE="${CAPSTONE_DIR}/target_state.json"
    REPORT_FILE="${CAPSTONE_DIR}/validation.json"
fi

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

mkdir -p "$(dirname "$REPORT_FILE")"

# Detected once: this is the only "platform" concept the script uses. A
# control declared for a different platform than the host actually running
# this script cannot be evaluated locally, so it is skipped rather than
# guessed at or chased over the network.
CURRENT_PLATFORM="linux"
if [[ "$(uname -s)" == MINGW* || "$(uname -s)" == CYGWIN* ]] || command -v powershell.exe >/dev/null 2>&1 || command -v pwsh >/dev/null 2>&1; then
    CURRENT_PLATFORM="windows"
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

RESULTS="[]"
TOTAL=0
PASS_COUNT=0
FAIL_COUNT=0
ERROR_COUNT=0
SKIP_COUNT=0

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

    TOTAL=$((TOTAL + 1))

    if [[ "$PLATFORM" != "both" && "$PLATFORM" != "network" && "$PLATFORM" != "$CURRENT_PLATFORM" ]]; then
        VERDICT="skip"
        EVIDENCE="control targets platform '${PLATFORM}', this host is '${CURRENT_PLATFORM}'"
        SKIP_COUNT=$((SKIP_COUNT + 1))
        printf '%-16s %-8s %-8s\n' "$ID" "$FAMILY" "$VERDICT"
        ENTRY=$(jq -n \
            --arg id "$ID" --arg platform "$PLATFORM" --arg family "$FAMILY" \
            --arg check_type "$CHECK_TYPE" --arg severity "$SEVERITY" \
            --arg verdict "$VERDICT" --arg evidence "$EVIDENCE" \
            '{id: $id, platform: $platform, family: $family, check_type: $check_type,
              severity: $severity, verdict: $verdict, evidence: $evidence}')
        RESULTS=$(jq --argjson e "$ENTRY" '. + [$e]' <<< "$RESULTS")
        continue
    fi

    VERDICT=""
    EVIDENCE=""

    case "$CHECK_TYPE" in
        file_exists)
            LOCAL_PATH="$(resolve_local_path "$CHECK_TARGET")"
            if [[ "$EXPECTED_RAW" == "executable" ]]; then
                if [[ -x "$LOCAL_PATH" ]]; then VERDICT="pass"; else VERDICT="fail"; fi
            else
                if [[ -e "$LOCAL_PATH" ]]; then VERDICT="pass"; else VERDICT="fail"; fi
            fi
            EVIDENCE="$LOCAL_PATH"
            ;;

        json_field_equals | json_field_gte)
            FILE_PART="${CHECK_TARGET%%#*}"
            FIELD_PART="${CHECK_TARGET#*#}"
            JQ_EXPR="$(normalize_jq_expr "$FIELD_PART")"
            LOCAL_PATH="$(resolve_local_path "$FILE_PART")"

            if [[ ! -f "$LOCAL_PATH" ]]; then
                VERDICT="error"
                EVIDENCE="file not found: $LOCAL_PATH"
            else
                ACTUAL=$(jq -c "$JQ_EXPR" "$LOCAL_PATH" 2>/dev/null)
                if [[ -z "$ACTUAL" || "$ACTUAL" == "null" ]]; then
                    VERDICT="error"
                    EVIDENCE="${FILE_PART}#${JQ_EXPR}: field could not be evaluated"
                else
                    if [[ "$CHECK_TYPE" == "json_field_equals" ]]; then
                        if [[ "$ACTUAL" == "$EXPECTED" ]]; then VERDICT="pass"; else VERDICT="fail"; fi
                    else
                        if [[ "$(jq -n --argjson a "$ACTUAL" --argjson e "$EXPECTED" '($a|type)=="number" and ($e|type)=="number" and ($a >= $e)' 2>/dev/null)" == "true" ]]; then
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
            bash -c "$CHECK_TARGET" >/dev/null 2>&1
            RC=$?
            if [[ "$RC" -eq 0 ]]; then VERDICT="pass"; else VERDICT="fail"; fi
            EVIDENCE="${CHECK_TARGET} (exit ${RC})"
            ;;

        grep_match)
            LOCAL_PATH="$(resolve_local_path "$CHECK_TARGET")"
            if [[ ! -f "$LOCAL_PATH" ]]; then
                VERDICT="error"
                EVIDENCE="file not found: $LOCAL_PATH"
            else
                if grep -E -q -- "$EXPECTED_RAW" "$LOCAL_PATH"; then VERDICT="pass"; else VERDICT="fail"; fi
                EVIDENCE="${LOCAL_PATH} ~= /${EXPECTED_RAW}/"
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

EVALUATED=$((PASS_COUNT + FAIL_COUNT + ERROR_COUNT))
PASS_PCT=0
[[ "$EVALUATED" -gt 0 ]] && PASS_PCT=$(jq -n --argjson p "$PASS_COUNT" --argjson t "$EVALUATED" '(($p / $t) * 100 * 10 | round) / 10')

echo ""
echo "=== Family summary ==="
printf '%-14s %-8s %-8s %-8s %-8s %-8s\n' "FAMILY" "TOTAL" "PASS" "FAIL" "ERROR" "SKIP"
for family in $(jq -r '[.controls[].family] | unique[]' "$TARGET_STATE_FILE"); do
    F_TOTAL=$(jq --arg f "$family" '[.[] | select(.family == $f)] | length' <<< "$RESULTS")
    F_PASS=$(jq --arg f "$family" '[.[] | select(.family == $f and .verdict == "pass")] | length' <<< "$RESULTS")
    F_FAIL=$(jq --arg f "$family" '[.[] | select(.family == $f and .verdict == "fail")] | length' <<< "$RESULTS")
    F_ERROR=$(jq --arg f "$family" '[.[] | select(.family == $f and .verdict == "error")] | length' <<< "$RESULTS")
    F_SKIP=$(jq --arg f "$family" '[.[] | select(.family == $f and .verdict == "skip")] | length' <<< "$RESULTS")
    printf '%-14s %-8s %-8s %-8s %-8s %-8s\n' "$family" "$F_TOTAL" "$F_PASS" "$F_FAIL" "$F_ERROR" "$F_SKIP"
done

echo ""
echo "Total: $TOTAL   Pass: $PASS_COUNT   Fail: $FAIL_COUNT   Error: $ERROR_COUNT   Skip: $SKIP_COUNT   Pass%: ${PASS_PCT}"

HOSTNAME_VAL=$(hostname)
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

if ! jq -n \
    --arg timestamp "$TIMESTAMP" \
    --arg hostname "$HOSTNAME_VAL" \
    --arg platform "$CURRENT_PLATFORM" \
    --argjson total "$TOTAL" \
    --argjson pass_count "$PASS_COUNT" \
    --argjson fail_count "$FAIL_COUNT" \
    --argjson error_count "$ERROR_COUNT" \
    --argjson skip_count "$SKIP_COUNT" \
    --argjson pass_percentage "$PASS_PCT" \
    --argjson controls "$RESULTS" \
    '{
        timestamp: $timestamp,
        hostname: $hostname,
        platform: $platform,
        total: $total,
        pass_count: $pass_count,
        fail_count: $fail_count,
        error_count: $error_count,
        skip_count: $skip_count,
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
