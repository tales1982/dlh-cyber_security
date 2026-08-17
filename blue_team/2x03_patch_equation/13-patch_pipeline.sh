#!/bin/bash
#
# 13-patch_pipeline.sh
#
# MedDefense Health Systems - The Patch Equation (2x03)
#
# The assembly line: inventory, dependency map, snapshot, plan, window
# check, execute, validate, drift, change log. One script, one exit code,
# one composite artifact that tells the operator what happened - runnable
# by hand today, by cron tomorrow, by another analyst next week, with
# identical results on identical input state.
#
# Usage: sudo ./13-patch_pipeline.sh [output.json]
# Env:   PIPELINE_TEST=1        passed through to 4-patch_execute.sh (--dry-run)
#        MEDDEFENSE_EMERGENCY=1 accept the emergency maintenance window as a green light

set -uo pipefail

OUT_JSON="${1:-pipeline_run.json}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
PIPELINE_TEST="${PIPELINE_TEST:-0}"

find_script() {
    local name="$1" candidate
    for candidate in "./${name}" "${SCRIPT_DIR}/${name}" "${SCRIPT_DIR}/../${name}" "${SCRIPT_DIR}/../"*"/${name}"; do
        [ -f "$candidate" ] && { echo "$candidate"; return 0; }
    done
    echo ""
}

STAGES_FILE="$(mktemp)"
ARTIFACTS_FILE="$(mktemp)"
trap 'rm -f "$STAGES_FILE" "$ARTIFACTS_FILE"' EXIT

STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
HOSTNAME_VAL="$(hostname)"
PIPELINE_STATUS="ok"
DEFERRED="false"
TOTAL=9
n=0

run_stage() {
    n=$((n + 1))
    local label="$1" script_name="$2"; shift 2
    local path exit_code=0 start end duration out err

    path="$(find_script "$script_name")"
    if [ -z "$path" ]; then
        echo "[$n/$TOTAL] $label $(printf '%*s' $((30 - ${#label})) '') NOT FOUND"
        jq -nc --arg name "$label" --argjson exit_code 127 --argjson duration 0 \
            '{name: $name, status: "not_found", exit_code: $exit_code, duration_seconds: $duration}' >> "$STAGES_FILE"
        PIPELINE_STATUS="failed"
        return 1
    fi

    out="$(mktemp)"; err="$(mktemp)"
    start=$(date +%s.%N)
    if bash "$path" "$@" >"$out" 2>"$err"; then
        exit_code=0
    else
        exit_code=$?
    fi
    end=$(date +%s.%N)
    duration="$(awk -v a="$start" -v b="$end" 'BEGIN{printf "%.1f", b-a}')"

    printf '[%d/%d] %-32s %s  (%ss)\n' "$n" "$TOTAL" "$script_name" \
        "$([ "$exit_code" -eq 0 ] && echo OK || echo "FAILED(${exit_code})")" "$duration"

    jq -nc --arg name "$label" --arg status "$([ "$exit_code" -eq 0 ] && echo ok || echo failed)" \
        --argjson exit_code "$exit_code" --argjson duration "$duration" \
        --arg stdout_tail "$(tail -c 1000 "$out")" --arg stderr_tail "$(tail -c 1000 "$err")" \
        '{name: $name, status: $status, exit_code: $exit_code, duration_seconds: $duration,
          stdout_tail: $stdout_tail, stderr_tail: $stderr_tail}' >> "$STAGES_FILE"
    rm -f "$out" "$err"
    return "$exit_code"
}

record_artifact() {
    jq -nc --arg k "$1" --arg v "$2" '{($k): $v}' >> "$ARTIFACTS_FILE"
}

abort() {
    PIPELINE_STATUS="failed"
    echo "[!] Pipeline stopped: $1"
}

# --- Stages 1-4: measurement and planning ------------------------------
run_stage "vulnerability_inventory" "0-vuln_inventory.sh" || { abort "0-vuln_inventory.sh failed"; }
record_artifact "vulnerability_inventory" "vulnerability_inventory.json"

[ "$PIPELINE_STATUS" = "ok" ] && { run_stage "service_dependency_map" "1-service_deps.sh" || abort "1-service_deps.sh failed"; }
record_artifact "service_dependency_map" "service_dependency_map.json"

[ "$PIPELINE_STATUS" = "ok" ] && { run_stage "pre_patch_snapshot" "2-pre_patch_snapshot.sh" || abort "2-pre_patch_snapshot.sh failed"; }
record_artifact "pre_patch_snapshot" "pre_patch_state.json"

[ "$PIPELINE_STATUS" = "ok" ] && { run_stage "patch_plan" "3-patch_plan.sh" || abort "3-patch_plan.sh failed"; }
record_artifact "patch_plan" "patch_plan.json"

# --- Stage 5: maintenance window gate ---------------------------------
WINDOW_EXIT=0
if [ "$PIPELINE_STATUS" = "ok" ]; then
    run_stage "maintenance_window" "11-maintenance_window.sh" --check
    WINDOW_EXIT=$?
    record_artifact "maintenance_window" "maintenance_window.json"
    # Exit 20 (outside every window) and exit 10 (only the emergency window
    # applies) are BOTH "do not proceed" from 11-maintenance_window.sh
    # unless MEDDEFENSE_EMERGENCY=1 - the spec's example only walks through
    # the 20 case, but 10 means the same thing minus an explicit override,
    # so it is deferred here too rather than silently patching anyway.
    if { [ "$WINDOW_EXIT" -eq 20 ] || [ "$WINDOW_EXIT" -eq 10 ]; } && [ "${MEDDEFENSE_EMERGENCY:-0}" != "1" ]; then
        DEFERRED="true"
    elif [ "$WINDOW_EXIT" -eq 127 ]; then
        PIPELINE_STATUS="failed"
    fi
fi

# --- Stages 6-8: execute, validate, drift - skipped if deferred --------
if [ "$PIPELINE_STATUS" = "ok" ] && [ "$DEFERRED" = "true" ]; then
    n=$((n + 3))
    echo "[*] Out of maintenance window and no emergency override - skipping execute/validate/drift"
elif [ "$PIPELINE_STATUS" = "ok" ]; then
    PIPELINE_TEST="$PIPELINE_TEST" run_stage "patch_execute" "4-patch_execute.sh" || abort "4-patch_execute.sh failed"
    record_artifact "patch_execute" "patch_execution_log.json"

    [ "$PIPELINE_STATUS" = "ok" ] && { run_stage "post_patch_validate" "5-post_patch_validate.sh" || abort "5-post_patch_validate.sh failed"; }
    record_artifact "post_patch_validate" "post_patch_validation.json"

    [ "$PIPELINE_STATUS" = "ok" ] && { run_stage "config_drift" "6-config_drift.sh" || abort "6-config_drift.sh failed"; }
    record_artifact "config_drift" "config_drift.json"
fi

# --- Stage 9: change log - always runs if we got this far --------------
if [ "$PIPELINE_STATUS" = "ok" ]; then
    run_stage "change_log" "12-change_log.sh" || abort "12-change_log.sh failed"
    record_artifact "change_log" "patch_change_log.json"
fi

FINISHED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
[ "$PIPELINE_STATUS" = "ok" ] && [ "$DEFERRED" = "true" ] && PIPELINE_STATUS="deferred"

jq -n \
    --arg started_at "$STARTED_AT" --arg finished_at "$FINISHED_AT" --arg hostname "$HOSTNAME_VAL" \
    --arg status "$PIPELINE_STATUS" \
    --slurpfile stages <(jq -s '.' "$STAGES_FILE") \
    --slurpfile artifacts_raw <(jq -s 'add // {}' "$ARTIFACTS_FILE") \
    '{started_at: $started_at, finished_at: $finished_at, hostname: $hostname,
      pipeline_status: $status, stages: $stages[0], artifacts: $artifacts_raw[0]}' > "$OUT_JSON"

DURATION_TOTAL="$(jq '([.stages[].duration_seconds] | add // 0) * 10 | round / 10' "$OUT_JSON")"
echo "PIPELINE: $PIPELINE_STATUS"
echo "Duration: ${DURATION_TOTAL}s"
echo "Report saved to: $OUT_JSON"

# Exit 0 on ok or deferred, exit 1 on any stage failure.
if [ "$PIPELINE_STATUS" = "ok" ] || [ "$PIPELINE_STATUS" = "deferred" ]; then
    exit 0
else
    exit 1
fi
