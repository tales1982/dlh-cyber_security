#!/bin/bash
# Name: 8-validate_all.sh
# Purpose: End-to-end validation suite that reads target_state.json, evaluates every control, and produces a machine-readable report
# Total controls: loaded from target_state.json controls array, aggregated by family
# Aggregates total controls, pass count, fail count, error count and pass percentage
# Exit Codes: 0=All controls passed, 1=One or more controls failed or errored, 2=Environment error

set -euo pipefail

# --- Configuration ---
TARGET_STATE="${1:-capstone/target_state.json}"
REPORT_FILE="capstone/validation.json"

# --- Helper Functions ---

log() {
    echo "[$(date '+%H:%M:%S')] $1"
}

# --- Detect Platform ---

CURRENT_PLATFORM="linux"
if [[ "$(uname -s)" == "MINGW"* ]] || [[ "$(uname -s)" == "CYGWIN"* ]] || \
   command -v powershell.exe &>/dev/null || command -v pwsh &>/dev/null; then
    CURRENT_PLATFORM="windows"
fi
log "Detected platform: $CURRENT_PLATFORM"

# --- Pre-flight Checks ---

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root."
    exit 2
fi

if [[ ! -f "$TARGET_STATE" ]]; then
    echo "ERROR: target_state.json not found at $TARGET_STATE"
    exit 2
fi

if ! command -v jq &>/dev/null; then
    echo "ERROR: jq is required but not installed"
    exit 2
fi

mkdir -p "$(dirname "$REPORT_FILE")"

# --- Load Controls ---

CONTROL_COUNT=$(jq '.controls | length' "$TARGET_STATE")
log "Loaded $CONTROL_COUNT controls from $TARGET_STATE"

# --- Initialize Tracking ---

declare -A FAMILY_TOTAL FAMILY_PASS FAMILY_FAIL FAMILY_ERROR
CONTROL_RESULTS="[]"
TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_ERROR=0
TOTAL_SKIP=0

# --- Evaluate Each Control ---

for i in $(seq 0 $((CONTROL_COUNT - 1))); do
    ctrl_id=$(jq -r ".controls[$i].id" "$TARGET_STATE")
    ctrl_platform=$(jq -r ".controls[$i].platform" "$TARGET_STATE")
    ctrl_family=$(jq -r ".controls[$i].family" "$TARGET_STATE")
    ctrl_desc=$(jq -r ".controls[$i].description" "$TARGET_STATE")
    ctrl_check_type=$(jq -r ".controls[$i].check_type" "$TARGET_STATE")
    ctrl_check_target=$(jq -r ".controls[$i].check_target" "$TARGET_STATE")
    ctrl_expected=$(jq -r ".controls[$i].expected_value" "$TARGET_STATE")
    ctrl_severity=$(jq -r ".controls[$i].severity" "$TARGET_STATE")
    ctrl_source=$(jq -r ".controls[$i].source_project" "$TARGET_STATE")

    verdict="error"
    evidence=""

    # Track family totals
    FAMILY_TOTAL[$ctrl_family]=$(( ${FAMILY_TOTAL[$ctrl_family]:-0} + 1 ))

    # --- Platform Gate ---

    if [[ "$ctrl_platform" != "both" && "$ctrl_platform" != "network" && "$ctrl_platform" != "$CURRENT_PLATFORM" ]]; then
        verdict="skip"
        evidence="Skipped: control targets ${ctrl_platform}, this host is ${CURRENT_PLATFORM}"
        TOTAL_SKIP=$((TOTAL_SKIP + 1))

        CONTROL_RESULTS=$(echo "$CONTROL_RESULTS" | jq \
            --arg id "$ctrl_id" \
            --arg platform "$ctrl_platform" \
            --arg family "$ctrl_family" \
            --arg desc "$ctrl_desc" \
            --arg check_type "$ctrl_check_type" \
            --arg check_target "$ctrl_check_target" \
            --arg expected "$ctrl_expected" \
            --arg severity "$ctrl_severity" \
            --arg source "$ctrl_source" \
            --arg verdict "$verdict" \
            --arg evidence "$evidence" \
            '. + [{
                id: $id,
                platform: $platform,
                family: $family,
                description: $desc,
                check_type: $check_type,
                check_target: $check_target,
                expected_value: $expected,
                severity: $severity,
                source_project: $source,
                verdict: $verdict,
                evidence: $evidence
            }]')

        log "  [$verdict] $ctrl_id ($ctrl_family) - $ctrl_desc"
        continue
    fi

    # --- Dispatch on check_type ---

    case "$ctrl_check_type" in

        file_exists)
            if [[ "$ctrl_expected" == "executable" ]]; then
                if [[ -x "$ctrl_check_target" ]]; then
                    verdict="pass"
                    evidence="File $ctrl_check_target exists and is executable"
                else
                    verdict="fail"
                    evidence="File $ctrl_check_target not found or not executable"
                fi
            else
                if [[ -e "$ctrl_check_target" ]]; then
                    verdict="pass"
                    evidence="File $ctrl_check_target exists"
                else
                    verdict="fail"
                    evidence="File $ctrl_check_target not found"
                fi
            fi
            ;;

        json_field_equals)
            # check_target format: <json_file>#<jq field expression>
            json_file="${ctrl_check_target%%#*}"
            json_field="${ctrl_check_target#*#}"
            case "$json_field" in
                .*|\[*) : ;;
                *) json_field=".${json_field}" ;;
            esac

            if [[ ! -f "$json_file" ]]; then
                verdict="error"
                evidence="JSON file $json_file not found"
            else
                actual_raw=$(jq -c "$json_field" "$json_file" 2>/dev/null || echo "JQ_ERROR")
                if [[ "$actual_raw" == "JQ_ERROR" || "$actual_raw" == "null" || -z "$actual_raw" ]]; then
                    verdict="error"
                    evidence="Field '$json_field' not found or null in $json_file"
                else
                    expected_raw=$(jq -c ".controls[$i].expected_value" "$TARGET_STATE")
                    match=$(jq -n --argjson actual "$actual_raw" --argjson expected "$expected_raw" \
                        '$actual == $expected' 2>/dev/null || echo "false")

                    if [[ "$match" == "true" ]]; then
                        verdict="pass"
                        evidence="$json_file:$json_field = $actual_raw (expected $ctrl_expected)"
                    else
                        verdict="fail"
                        evidence="$json_file:$json_field = $actual_raw (expected $ctrl_expected)"
                    fi
                fi
            fi
            ;;

        json_field_gte)
            json_file="${ctrl_check_target%%#*}"
            json_field="${ctrl_check_target#*#}"
            case "$json_field" in
                .*|\[*) : ;;
                *) json_field=".${json_field}" ;;
            esac

            if [[ ! -f "$json_file" ]]; then
                verdict="error"
                evidence="JSON file $json_file not found"
            else
                actual_raw=$(jq -c "$json_field" "$json_file" 2>/dev/null || echo "JQ_ERROR")
                if [[ "$actual_raw" == "JQ_ERROR" || "$actual_raw" == "null" || -z "$actual_raw" ]]; then
                    verdict="error"
                    evidence="Field '$json_field' not found or null in $json_file"
                else
                    expected_raw=$(jq -c ".controls[$i].expected_value" "$TARGET_STATE")

                    type_ok=$(jq -n --argjson actual "$actual_raw" --argjson expected "$expected_raw" \
                        '(($actual | type) == "number") and (($expected | type) == "number")' 2>/dev/null || echo "false")

                    if [[ "$type_ok" != "true" ]]; then
                        verdict="error"
                        actual_type=$(jq -n --argjson a "$actual_raw" '$a | type' 2>/dev/null || echo "unknown")
                        evidence="Type error: $json_file:$json_field is $actual_type, expected number"
                    else
                        match=$(jq -n --argjson actual "$actual_raw" --argjson expected "$expected_raw" \
                            '$actual >= $expected' 2>/dev/null || echo "false")

                        if [[ "$match" == "true" ]]; then
                            verdict="pass"
                            evidence="$json_file:$json_field = $actual_raw (>= $ctrl_expected)"
                        else
                            verdict="fail"
                            evidence="$json_file:$json_field = $actual_raw (expected >= $ctrl_expected)"
                        fi
                    fi
                fi
            fi
            ;;

        command_exit_zero)
            # Per spec: run the command in check_target and check its exit code.
            if eval "$ctrl_check_target" >/dev/null 2>&1; then
                verdict="pass"
                evidence="Command succeeded: $ctrl_check_target"
            else
                verdict="fail"
                evidence="Command failed: $ctrl_check_target"
            fi
            ;;

        grep_match)
            if [[ ! -f "$ctrl_check_target" ]]; then
                verdict="error"
                evidence="File not found: $ctrl_check_target"
            elif grep -Eq -- "$ctrl_expected" "$ctrl_check_target" 2>/dev/null; then
                verdict="pass"
                evidence="Pattern '$ctrl_expected' matched in $ctrl_check_target"
            else
                verdict="fail"
                evidence="Pattern '$ctrl_expected' not found in $ctrl_check_target"
            fi
            ;;

        *)
            verdict="error"
            evidence="Unknown check_type: $ctrl_check_type"
            ;;
    esac

    # Update counters
    case "$verdict" in
        pass)
            TOTAL_PASS=$((TOTAL_PASS + 1))
            FAMILY_PASS[$ctrl_family]=$(( ${FAMILY_PASS[$ctrl_family]:-0} + 1 ))
            ;;
        fail)
            TOTAL_FAIL=$((TOTAL_FAIL + 1))
            FAMILY_FAIL[$ctrl_family]=$(( ${FAMILY_FAIL[$ctrl_family]:-0} + 1 ))
            ;;
        error)
            TOTAL_ERROR=$((TOTAL_ERROR + 1))
            FAMILY_ERROR[$ctrl_family]=$(( ${FAMILY_ERROR[$ctrl_family]:-0} + 1 ))
            ;;
    esac

    # Build result entry
    CONTROL_RESULTS=$(echo "$CONTROL_RESULTS" | jq \
        --arg id "$ctrl_id" \
        --arg platform "$ctrl_platform" \
        --arg family "$ctrl_family" \
        --arg desc "$ctrl_desc" \
        --arg check_type "$ctrl_check_type" \
        --arg check_target "$ctrl_check_target" \
        --arg expected "$ctrl_expected" \
        --arg severity "$ctrl_severity" \
        --arg source "$ctrl_source" \
        --arg verdict "$verdict" \
        --arg evidence "$evidence" \
        '. + [{
            id: $id,
            platform: $platform,
            family: $family,
            description: $desc,
            check_type: $check_type,
            check_target: $check_target,
            expected_value: $expected,
            severity: $severity,
            source_project: $source,
            verdict: $verdict,
            evidence: $evidence
        }]')

    log "  [$verdict] $ctrl_id ($ctrl_family) - $ctrl_desc"

done

# --- Calculate Totals ---

EVALUATED_COUNT=$((TOTAL_PASS + TOTAL_FAIL + TOTAL_ERROR))
if [[ $EVALUATED_COUNT -gt 0 ]]; then
    PASS_PCT=$(awk -v p="$TOTAL_PASS" -v t="$EVALUATED_COUNT" 'BEGIN { printf "%.1f", (p / t) * 100 }')
else
    PASS_PCT="0.0"
fi

OVERALL="READY"
if [[ $TOTAL_FAIL -gt 0 || $TOTAL_ERROR -gt 0 ]]; then
    OVERALL="NOT_READY"
fi

# --- Print Summary Table ---

echo ""
echo "============================================================"
echo "  End-to-End Validation Report"
echo "  Target State: $TARGET_STATE"
echo "  Host: $(hostname)"
echo "  Timestamp: $(date -Iseconds)"
echo "============================================================"
echo ""
printf "%-14s %-8s %-8s %-8s %-8s %-8s\n" "FAMILY" "TOTAL" "PASS" "FAIL" "ERR" "SKIP"
printf "%-14s %-8s %-8s %-8s %-8s %-8s\n" "------" "-----" "----" "----" "---" "----"

# Collect unique families in order they appeared
FAMILIES_SEEN=""
for i in $(seq 0 $((CONTROL_COUNT - 1))); do
    f=$(jq -r ".controls[$i].family" "$TARGET_STATE")
    if ! echo "$FAMILIES_SEEN" | grep -qw "$f"; then
        FAMILIES_SEEN="$FAMILIES_SEEN $f"
    fi
done

for family in $FAMILIES_SEEN; do
    ft=${FAMILY_TOTAL[$family]:-0}
    fp=${FAMILY_PASS[$family]:-0}
    ff=${FAMILY_FAIL[$family]:-0}
    fe=${FAMILY_ERROR[$family]:-0}
    if [[ $ft -gt 0 ]]; then
        printf "%-14s %-8s %-8s %-8s %-8s %-8s\n" "$family" "$ft" "$fp" "$ff" "$fe" "0"
    fi
done

echo ""
printf "%-14s %-8s %-8s %-8s %-8s %-8s\n" "TOTAL" "$EVALUATED_COUNT" "$TOTAL_PASS" "$TOTAL_FAIL" "$TOTAL_ERROR" "$TOTAL_SKIP"
printf "Pass percentage: %s%%\n" "$PASS_PCT"
echo "Total controls: $EVALUATED_COUNT | Pass: $TOTAL_PASS | Fail: $TOTAL_FAIL | Error: $TOTAL_ERROR | Skip: $TOTAL_SKIP"
echo ""

if [[ "$OVERALL" == "READY" ]]; then
    echo "VERDICT: READY FOR HANDOFF"
else
    echo "VERDICT: NOT READY - failing controls listed below"
    echo ""
    echo "$CONTROL_RESULTS" | jq -r \
        '.[] | select(.verdict == "fail" or .verdict == "error") | "  [\(.verdict | ascii_upcase)] \(.id) (\(.family)) - \(.evidence)"'
fi

echo ""

# --- Generate Machine-Readable Report ---

FAMILY_SUMMARY="[]"
for family in $FAMILIES_SEEN; do
    ft=${FAMILY_TOTAL[$family]:-0}
    fp=${FAMILY_PASS[$family]:-0}
    ff=${FAMILY_FAIL[$family]:-0}
    fe=${FAMILY_ERROR[$family]:-0}
    if [[ $ft -gt 0 ]]; then
        FAMILY_SUMMARY=$(echo "$FAMILY_SUMMARY" | jq \
            --arg family "$family" \
            --argjson total "$ft" \
            --argjson pass "$fp" \
            --argjson fail "$ff" \
            --argjson err "$fe" \
            '. + [{family: $family, total: $total, pass: $pass, fail: $fail, error: $err}]')
    fi
done

jq -n \
    --arg timestamp "$(date -Iseconds)" \
    --arg host "$(hostname)" \
    --arg platform "$CURRENT_PLATFORM" \
    --arg target_state "$TARGET_STATE" \
    --argjson total_controls "$EVALUATED_COUNT" \
    --argjson pass_count "$TOTAL_PASS" \
    --argjson fail_count "$TOTAL_FAIL" \
    --argjson error_count "$TOTAL_ERROR" \
    --argjson skip_count "$TOTAL_SKIP" \
    --arg pass_pct "$PASS_PCT" \
    --arg overall "$OVERALL" \
    --arg summary_line "Total controls: $EVALUATED_COUNT | Pass: $TOTAL_PASS | Fail: $TOTAL_FAIL | Error: $TOTAL_ERROR | Skip: $TOTAL_SKIP" \
    --argjson family_summary "$FAMILY_SUMMARY" \
    --argjson controls "$CONTROL_RESULTS" \
    '{
        timestamp: $timestamp,
        host: $host,
        platform: $platform,
        target_state: $target_state,
        total_controls: $total_controls,
        pass_count: $pass_count,
        fail_count: $fail_count,
        error_count: $error_count,
        skip_count: $skip_count,
        pass_percentage: ($pass_pct | tonumber),
        overall_verdict: $overall,
        summary: $summary_line,
        family_summary: $family_summary,
        controls: $controls
    }' > "$REPORT_FILE"

log "Validation report saved to $REPORT_FILE"

# --- Exit: fail_count == 0 AND error_count == 0 means ready for handoff ---

if [[ $TOTAL_FAIL -eq 0 && $TOTAL_ERROR -eq 0 ]]; then
    log "SUCCESS: All $TOTAL_PASS controls passed ($TOTAL_SKIP skipped). Environment is ready for handoff."
    exit 0
else
    log "FAILURE: $TOTAL_FAIL failed, $TOTAL_ERROR errored out of $EVALUATED_COUNT controls ($TOTAL_SKIP skipped)."
    exit 1
fi
