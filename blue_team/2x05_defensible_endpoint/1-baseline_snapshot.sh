#!/bin/bash
#
# Artifacts (relative to this script's directory):
#   capstone/baseline/lynis_baseline.log
#   capstone/baseline/baseline_linux.json

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAPSTONE_DIR="${SCRIPT_DIR}/capstone"
BASELINE_DIR="${CAPSTONE_DIR}/baseline"
LOG_FILE="${BASELINE_DIR}/lynis_baseline.log"
OUTPUT_JSON_FILE="${BASELINE_DIR}/baseline_linux.json"

for cmd in jq lynis sudo; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Error: required command '$cmd' not found." >&2
        exit 2
    fi
done

mkdir -p "$BASELINE_DIR" || {
    echo "Error: unable to create '$BASELINE_DIR'." >&2
    exit 2
}

LYNIS_OUTPUT=$(sudo lynis audit system --quick --no-colors 2>&1)
LYNIS_EXIT=$?

echo "$LYNIS_OUTPUT" > "$LOG_FILE"

if [[ "$LYNIS_EXIT" -ne 0 ]]; then
    echo "Error: lynis exited with code ${LYNIS_EXIT}. See ${LOG_FILE}." >&2
    exit 2
fi

if [[ ! -f /var/log/lynis-report.dat ]]; then
    echo "Error: /var/log/lynis-report.dat not found after lynis run." >&2
    exit 2
fi

HARDENING_INDEX=$(sudo grep -m1 '^hardening_index=' /var/log/lynis-report.dat | cut -d= -f2)
HARDENING_INDEX="${HARDENING_INDEX:-0}"

WARNINGS_COUNT=$(sudo grep -c '^warning\[\]=' /var/log/lynis-report.dat)
SUGGESTIONS_COUNT=$(sudo grep -c '^suggestion\[\]=' /var/log/lynis-report.dat)

LYNIS_VERSION=$(lynis --version 2>/dev/null)
HOSTNAME_VAL=$(hostname)
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

if ! jq -n \
    --arg timestamp "$TIMESTAMP" \
    --arg hostname "$HOSTNAME_VAL" \
    --arg lynis_version "$LYNIS_VERSION" \
    --argjson hardening_index "$HARDENING_INDEX" \
    --argjson warnings_count "$WARNINGS_COUNT" \
    --argjson suggestions_count "$SUGGESTIONS_COUNT" \
    --arg log_path "$LOG_FILE" \
    '{
        timestamp: $timestamp,
        hostname: $hostname,
        lynis_version: $lynis_version,
        hardening_index: $hardening_index,
        warnings_count: $warnings_count,
        suggestions_count: $suggestions_count,
        log_path: $log_path
    }' > "$OUTPUT_JSON_FILE"; then
    echo "Error: failed to write '$OUTPUT_JSON_FILE'." >&2
    exit 2
fi

echo "Baseline written to $OUTPUT_JSON_FILE (hardening_index=${HARDENING_INDEX})"

if [[ "$HARDENING_INDEX" -eq 0 ]]; then
    echo "Error: hardening_index parsed as 0 - lynis ran but the report did not contain a usable score." >&2
    exit 1
fi

exit 0
