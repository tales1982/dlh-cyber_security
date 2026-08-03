#!/bin/bash
#
# 2-lynis_parse.sh
#
# MedDefense Health Systems - Locking the Gates (2x00)
#
# Parses a Lynis .dat report (the key=value report file Lynis writes to
# /var/log/lynis-report.dat, NOT the verbose log or terminal output) into a
# structured JSON summary: the hardening index plus every warning[],
# suggestion[] and manual_check[] finding. This becomes the machine-readable
# evidence Task 3 cross-references against the CIS profile, and the baseline
# Task 16 diffs against the post-hardening re-scan.
#
# Read-only. Makes no system changes.
#
# Usage: ./2-lynis_parse.sh /var/log/lynis-report.dat

set -uo pipefail

REPORT_FILE="${1:-}"

if [ -z "$REPORT_FILE" ]; then
    echo "Usage: $0 <path-to-lynis-report.dat>" >&2
    exit 1
fi

if [ ! -r "$REPORT_FILE" ]; then
    echo "Error: cannot read report file: $REPORT_FILE" >&2
    exit 1
fi

HARDENING_INDEX=$(grep -m1 '^hardening_index=' "$REPORT_FILE" | cut -d= -f2)
HARDENING_INDEX="${HARDENING_INDEX:-0}"

# Parse one Lynis array type (warning[], suggestion[], manual_check[]) into
# JSON objects of {severity, test_id, message}. Lynis's report format is
# key[]=TEST_ID|message|field3|field4|  (pipe-delimited, fields 3/4 optional).
parse_findings() {
    local key="$1"
    local severity="$2"

    grep "^${key}\[\]=" "$REPORT_FILE" | while IFS= read -r line; do
        local payload="${line#*=}"
        local test_id message
        test_id="$(cut -d'|' -f1 <<<"$payload")"
        message="$(cut -d'|' -f2 <<<"$payload")"
        [ -z "$test_id" ] && continue
        jq -n --arg sev "$severity" --arg tid "$test_id" --arg msg "$message" \
            '{severity: $sev, test_id: $tid, message: $msg}'
    done
}

{
    parse_findings "warning" "warning"
    parse_findings "suggestion" "suggestion"
    parse_findings "manual_check" "manual_check"
} | jq -s --argjson idx "$HARDENING_INDEX" '{hardening_index: $idx, findings: .}'
