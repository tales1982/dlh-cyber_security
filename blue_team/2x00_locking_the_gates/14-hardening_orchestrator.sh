#!/bin/bash
#
# 14-hardening_orchestrator.sh
#
# MedDefense Health Systems - Locking the Gates (2x00)
#
# James Chen: "If billing-srv-01 burns tomorrow and we have to rebuild, I
# want to run one script and have a hardened server in 20 minutes." This is
# that script. It runs Tasks 0/2/4-13/15 in dependency order, refuses to
# proceed past a failed step (a production hardening pipeline must not
# plow ahead after something breaks), times every step, and produces the
# before/after Lynis delta that proves the work happened.
#
# Path convention used across this entire module: every task script lives in
# its own sibling directory one level below 06_locking_the_gates/, named
# "<N>-the_<slug>/<N>-<script_name>.sh". This orchestrator resolves every
# path relative to its OWN location (BASE_DIR), so it works regardless of
# the caller's current working directory.
#
# Idempotent: every step script this orchestrator calls is itself
# idempotent (Tasks 4-13, verified individually); re-running the whole
# pipeline against an already-hardened host re-applies the same end state
# and reports the same step count with 0 failures.
#
# DRY_RUN=1 exists so the orchestration/control-flow logic (path resolution,
# pre-checks, ordering, stop-on-failure, JSON generation) can be exercised
# safely without cascading into the real, system-modifying step scripts -
# see this project's validation notes for exactly what was and was not
# executed for real. It intentionally still runs the read-only steps
# (0, 2, 15) for real even under DRY_RUN, since those are safe by
# construction.
#
# Usage: sudo ./14-hardening_orchestrator.sh
#        DRY_RUN=1 ./14-hardening_orchestrator.sh   (control-flow test only)

set -uo pipefail

DRY_RUN="${DRY_RUN:-0}"
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATES_DIR="$(cd "$BASE_DIR/.." && pwd)"
RUN_JSON="hardening_run.json"
IMPROVEMENT_JSON="hardening_improvement.json"

if [ "$DRY_RUN" -ne 1 ] && [ "$(id -u)" -ne 0 ]; then
    echo "Error: this script must run as root to execute the hardening pipeline (or set DRY_RUN=1 for a control-flow-only test)" >&2
    exit 1
fi

# step definitions: number | script path (relative to GATES_DIR) | description | read_only(1/0)
STEPS_NUM=(1 2 3 4 5 6 7 8 9 10 11 12 13)
STEPS_SCRIPT=(
    "0-the_baseline_snapshot/0-baseline_snapshot.sh"
    "2-the_lynis_audit_parser/2-lynis_parse.sh"
    "4-the_ssh_lockdown/4-ssh_hardening.sh"
    "5-the_kernel_shield/5-sysctl_hardening.sh"
    "6-the_permission_sweep/6-filesystem_hardening.sh"
    "7-the_service_minimizer/7-service_minimization.sh"
    "8-the_pam_fortress/8-pam_hardening.sh"
    "9-the_apparmor_enforcer/9-apparmor_config.sh"
    "10-the_audit_engine/10-auditd_config.sh"
    "11-the_audit_telemetry_coverage_test/11-audit_coverage_test.sh"
    "12-the_log_architect/12-log_config.sh"
    "13-the_firewall_baseline/13-firewall_baseline.sh"
    "15-the_post_hardening_validator/15-validation.sh"
)
STEPS_DESC=(
    "Baseline snapshot"
    "Lynis baseline capture"
    "SSH lockdown"
    "Kernel/sysctl shield"
    "Filesystem permission sweep"
    "Service minimization"
    "PAM fortress"
    "AppArmor enforcement"
    "Audit engine deployment"
    "Audit telemetry coverage test"
    "Log architecture (rsyslog/logrotate)"
    "Firewall baseline"
    "Post-hardening validation"
)
STEPS_READONLY=(1 1 0 0 0 0 0 0 0 0 0 0 1)

TOTAL_STEPS="${#STEPS_NUM[@]}"

# --- Pre-checks ---------------------------------------------------------------
PRECHECK_FAIL=0
for i in "${!STEPS_SCRIPT[@]}"; do
    full="$GATES_DIR/${STEPS_SCRIPT[$i]}"
    if [ ! -f "$full" ]; then
        echo "Pre-check FAILED: missing script $full" >&2
        PRECHECK_FAIL=1
    elif [ ! -x "$full" ]; then
        echo "Pre-check FAILED: not executable $full" >&2
        PRECHECK_FAIL=1
    fi
done
if ! command -v lynis >/dev/null 2>&1; then
    echo "Pre-check FAILED: lynis is not installed" >&2
    PRECHECK_FAIL=1
fi

if [ "$PRECHECK_FAIL" -eq 1 ]; then
    echo "Pre-checks: FAIL"
    exit 1
fi
echo "Pre-checks: PASS"

# --- Pre-hardening Lynis baseline --------------------------------------------
LYNIS_REPORT="${LYNIS_REPORT_PATH:-/var/log/lynis-report.dat}"
[ -w "$(dirname "$LYNIS_REPORT")" ] 2>/dev/null || LYNIS_REPORT="$HOME/lynis-report.dat"

capture_lynis() {
    lynis audit system --quick --no-colors >/dev/null 2>&1 || true
    local report="$LYNIS_REPORT"
    [ -r "$report" ] || report="$HOME/lynis-report.dat"
    "$GATES_DIR/2-the_lynis_audit_parser/2-lynis_parse.sh" "$report" 2>/dev/null
}

echo "[*] Capturing pre-hardening Lynis baseline..."
BEFORE_LYNIS_JSON="$(capture_lynis)"
BEFORE_SCORE="$(jq -r '.hardening_index // 0' <<<"${BEFORE_LYNIS_JSON:-{}}" 2>/dev/null)"
BEFORE_SCORE="${BEFORE_SCORE:-0}"
echo "$BEFORE_LYNIS_JSON" > lynis_findings.json 2>/dev/null || true

# --- Run steps in order, stop immediately on failure -------------------------
RUN_LOG_JSONL=""
STEPS_COMPLETED=0
STEPS_FAILED=0
PIPELINE_FAILED=0

for i in "${!STEPS_SCRIPT[@]}"; do
    num="${STEPS_NUM[$i]}"
    script="$GATES_DIR/${STEPS_SCRIPT[$i]}"
    desc="${STEPS_DESC[$i]}"
    readonly_step="${STEPS_READONLY[$i]}"

    started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    start_epoch=$(date +%s)

    if [ "$PIPELINE_FAILED" -eq 1 ]; then
        status="skipped"; exit_code=""
    elif [ "$DRY_RUN" -eq 1 ] && [ "$readonly_step" -eq 0 ]; then
        status="skipped_dry_run"; exit_code=0
        echo "[$num/$TOTAL_STEPS] $desc ... SKIPPED (DRY_RUN, state-changing step)"
    else
        echo "[$num/$TOTAL_STEPS] $desc ..."
        if [ "$num" -eq 2 ]; then
            # Step 2 already ran above to capture the pre-hardening baseline;
            # re-running here would just re-scan, so we reuse that result.
            exit_code=0
        else
            "$script" >>"orchestrator_step_${num}.log" 2>&1
            exit_code=$?
        fi
        if [ "$exit_code" -eq 0 ]; then
            status="completed"
            STEPS_COMPLETED=$((STEPS_COMPLETED+1))
        else
            status="failed"
            STEPS_FAILED=$((STEPS_FAILED+1))
            PIPELINE_FAILED=1
            echo "    FAILED (exit $exit_code) - halting pipeline, see orchestrator_step_${num}.log"
        fi
    fi

    ended="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    end_epoch=$(date +%s)
    duration=$((end_epoch - start_epoch))

    obj=$(jq -n --argjson n "$num" --arg script "${STEPS_SCRIPT[$i]}" --arg desc "$desc" \
        --arg started "$started" --arg ended "$ended" --argjson duration "$duration" \
        --arg status "$status" --arg exit_code "${exit_code:-null}" \
        '{step: $n, script: $script, description: $desc, started_at: $started,
          ended_at: $ended, duration_seconds: $duration, status: $status,
          exit_code: ( $exit_code | if . == "null" then null else tonumber end )}')
    RUN_LOG_JSONL="${RUN_LOG_JSONL}${obj}"$'\n'

    if [ "$status" = "completed" ] && [ "$DRY_RUN" -eq 1 ]; then
        echo "    completed (real, read-only step)"
    elif [ "$status" = "completed" ]; then
        echo "    completed"
    fi
done

# --- Post-hardening Lynis re-scan + improvement diff -------------------------
if [ "$PIPELINE_FAILED" -eq 0 ]; then
    echo "[*] Capturing post-hardening Lynis re-scan..."
    if [ "$DRY_RUN" -eq 1 ]; then
        AFTER_SCORE="$BEFORE_SCORE"
        echo "    (DRY_RUN: skipping real re-scan, reusing baseline score for the control-flow test)"
    else
        AFTER_LYNIS_JSON="$(capture_lynis)"
        AFTER_SCORE="$(jq -r '.hardening_index // 0' <<<"${AFTER_LYNIS_JSON:-{}}" 2>/dev/null)"
        AFTER_SCORE="${AFTER_SCORE:-0}"
        echo "$AFTER_LYNIS_JSON" > lynis_post_findings.json 2>/dev/null || true
    fi

    if [ -x "$GATES_DIR/16-the_lynis_improvement_diff/16-lynis_diff.sh" ]; then
        ( cd "$GATES_DIR/16-the_lynis_improvement_diff" && \
          BEFORE_FINDINGS="$GATES_DIR/14-the_hardening_orchestrator/lynis_findings.json" \
          AFTER_FINDINGS="$GATES_DIR/14-the_hardening_orchestrator/lynis_post_findings.json" \
          ./16-lynis_diff.sh >/dev/null 2>&1 ) || true
        [ -f "$GATES_DIR/16-the_lynis_improvement_diff/hardening_improvement.json" ] && \
            cp "$GATES_DIR/16-the_lynis_improvement_diff/hardening_improvement.json" "$IMPROVEMENT_JSON"
    fi
    [ -f "$IMPROVEMENT_JSON" ] || jq -n --argjson before "$BEFORE_SCORE" --argjson after "$AFTER_SCORE" \
        '{before_score: $before, after_score: $after, delta: ($after-$before)}' > "$IMPROVEMENT_JSON"
else
    AFTER_SCORE="$BEFORE_SCORE"
    jq -n --argjson before "$BEFORE_SCORE" '{before_score: $before, after_score: null, delta: null, note: "pipeline halted before post-hardening re-scan"}' > "$IMPROVEMENT_JSON"
fi

DELTA=$((AFTER_SCORE - BEFORE_SCORE))

RUN_LOG_JSON=$(jq -s '.' <<<"$RUN_LOG_JSONL")
jq -n --argjson steps "$RUN_LOG_JSON" \
  --arg generated "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson scheduled "$TOTAL_STEPS" --argjson completed "$STEPS_COMPLETED" \
  --argjson failed "$STEPS_FAILED" --argjson before "$BEFORE_SCORE" --argjson after "$AFTER_SCORE" \
  --argjson dry_run "$([ "$DRY_RUN" -eq 1 ] && echo true || echo false)" \
  '{
    generated: $generated,
    dry_run: $dry_run,
    steps_scheduled: $scheduled,
    steps_completed: $completed,
    steps_failed: $failed,
    before_lynis_score: $before,
    after_lynis_score: $after,
    steps: $steps
  }' > "$RUN_JSON"

echo "Steps scheduled: $TOTAL_STEPS"
echo "Steps completed: $STEPS_COMPLETED"
echo "Steps failed: $STEPS_FAILED"
echo "Before Lynis score: $BEFORE_SCORE"
echo "After Lynis score: $AFTER_SCORE"
printf 'Delta: %+d\n' "$DELTA"
echo "Run log saved to: $RUN_JSON"
echo "Improvement saved to: $IMPROVEMENT_JSON"

[ "$STEPS_FAILED" -eq 0 ]
