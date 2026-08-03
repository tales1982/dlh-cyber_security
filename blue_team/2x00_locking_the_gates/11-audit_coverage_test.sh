#!/bin/bash
#
# 11-audit_coverage_test.sh
#
# MedDefense Health Systems - Locking the Gates (2x00)
#
# Task 10 deployed audit rules. This script proves they actually fire. A
# rule that is deployed but never proven to capture an event is a false
# sense of security - exactly the gap that let the 1x00 attacker move
# undetected for 5 days with no telemetry at all. Six controlled, safe,
# reversible actions are triggered here and each is checked against
# `ausearch` for the matching audit key.
#
# This script requires root for two independent reasons: (1) several
# trigger actions are only meaningful/available to root (e.g. a live sudo
# invocation), and (2) `ausearch`/`auditctl -l` themselves require root to
# read the audit log and rule set. Where root is not available, each test
# is still executed as far as it safely can be (the trigger command itself
# is real and harmless), and its capture verification is honestly reported
# as not_assessed rather than fabricated.
#
# Idempotent / safe to re-run: every artifact this script creates (the test
# file, any temp cron listing) is cleaned up at the end of every run,
# success or failure. No test accounts are created. No destructive command
# is ever run.
#
# Maps to CIS control MD-CIS-014 (audit telemetry coverage validated) from
# cis_profile.json.
#
# Usage: sudo ./11-audit_coverage_test.sh

set -uo pipefail

OUT_JSON="audit_validation.json"
TEST_FILE="/tmp/meddefense_audit_test_$$"
IS_ROOT=0
[ "$(id -u)" -eq 0 ] && IS_ROOT=1
HAVE_SUDO_CACHED=0
if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    HAVE_SUDO_CACHED=1
fi

cleanup() {
    rm -f "$TEST_FILE" 2>/dev/null
}
trap cleanup EXIT

echo "[*] Running audit telemetry coverage tests..."

TESTS_JSONL=""
CAPTURED_COUNT=0
NOT_ASSESSED_COUNT=0
MISSED_COUNT=0
TEST_NUM=0
TOTAL_TESTS=6

# run_test <label> <audit_key> <trigger_description> <trigger_fn>
run_test() {
    TEST_NUM=$((TEST_NUM+1))
    local label="$1" key="$2" description="$3"
    local ts
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    # Run the trigger (function name passed as $4, invoked below by caller)
    local status="not_assessed" match_count=0 excerpt=""

    if [ "$IS_ROOT" -eq 1 ]; then
        sleep 1
        match_count=$(ausearch -ts recent -k "$key" 2>/dev/null | grep -c '^type=')
        excerpt=$(ausearch -ts recent -k "$key" 2>/dev/null | grep '^type=' | tail -1)
        if [ "${match_count:-0}" -gt 0 ]; then
            status="captured"
            printf '[%d/%d] %-38s [CAPTURED]\n' "$TEST_NUM" "$TOTAL_TESTS" "$label"
            CAPTURED_COUNT=$((CAPTURED_COUNT+1))
        else
            status="missed"
            printf '[%d/%d] %-38s [MISSED]\n' "$TEST_NUM" "$TOTAL_TESTS" "$label"
            MISSED_COUNT=$((MISSED_COUNT+1))
        fi
    else
        printf '[%d/%d] %-38s [NOT ASSESSED - ausearch requires root]\n' "$TEST_NUM" "$TOTAL_TESTS" "$label"
        NOT_ASSESSED_COUNT=$((NOT_ASSESSED_COUNT+1))
    fi

    obj=$(jq -n --arg name "$label" --arg key "$key" --arg cmd "$description" \
        --arg ts "$ts" --arg status "$status" --argjson count "${match_count:-0}" \
        --arg excerpt "$excerpt" \
        '{test_name: $name, expected_audit_key: $key, command_executed: $cmd,
          timestamp: $ts, capture_status: $status, matching_event_count: $count,
          excerpt: $excerpt}')
    TESTS_JSONL="${TESTS_JSONL}${obj}"$'\n'
}

# --- Test 1: privileged command execution through sudo -----------------------
if [ "$IS_ROOT" -eq 1 ] || [ "$HAVE_SUDO_CACHED" -eq 1 ]; then
    sudo -n true >/dev/null 2>&1
    CMD1="sudo -n true"
else
    CMD1="sudo -n true (skipped - no root/cached sudo credentials available in this environment)"
fi
run_test "sudo execution" "priv_esc" "$CMD1"

# --- Test 2: attempted access to /etc/shadow ----------------------------------
cat /etc/shadow >/dev/null 2>&1
run_test "shadow access" "identity" "cat /etc/shadow"

# --- Test 3: execution of a suspicious download tool --------------------------
if command -v curl >/dev/null 2>&1; then
    curl --version >/dev/null 2>&1
    CMD3="curl --version"
elif command -v wget >/dev/null 2>&1; then
    wget --version >/dev/null 2>&1
    CMD3="wget --version"
else
    CMD3="(neither curl nor wget present)"
fi
run_test "suspicious download tool" "suspicious_download" "$CMD3"

# --- Test 4: sshd config read/metadata check ----------------------------------
stat /etc/ssh/sshd_config >/dev/null 2>&1
run_test "sshd config read" "sshd_config" "stat /etc/ssh/sshd_config"

# --- Test 5: controlled write to a monitored test path ------------------------
echo "meddefense audit coverage test $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$TEST_FILE"
run_test "monitored test file write" "startup_scripts" "echo test > $TEST_FILE"

# --- Test 6: cron configuration inspection ------------------------------------
crontab -l >/dev/null 2>&1
run_test "cron configuration check" "cron_config" "crontab -l"

echo "[*] Cleaning test artifacts..."
cleanup
trap - EXIT

TESTS_JSON=$(jq -s '.' <<<"$TESTS_JSONL")
EXECUTED=$(jq 'length' <<<"$TESTS_JSON")

jq -n --argjson tests "$TESTS_JSON" \
  --arg generated "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson executed "$EXECUTED" \
  --argjson captured "$CAPTURED_COUNT" \
  --argjson missed "$MISSED_COUNT" \
  --argjson not_assessed "$NOT_ASSESSED_COUNT" \
  --argjson is_root "$([ "$IS_ROOT" -eq 1 ] && echo true || echo false)" \
  '{
    generated: $generated,
    executed_as_root: $is_root,
    tests: $tests,
    summary: {
      tests_executed: $executed,
      captured: $captured,
      missed: $missed,
      not_assessed: $not_assessed
    }
  }' > "$OUT_JSON"

echo "Tests executed: $EXECUTED"
echo "Captured: $CAPTURED_COUNT"
echo "Missed: $MISSED_COUNT"
echo "Not assessed: $NOT_ASSESSED_COUNT"
echo "Report saved to: $OUT_JSON"
