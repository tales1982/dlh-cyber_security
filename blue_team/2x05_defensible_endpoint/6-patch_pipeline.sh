#!/bin/bash
#
# Orchestrates the patch pipeline from the previous project (2x03) end-to-end
# against hawthorne-app-01. Does not reinvent the pipeline: wraps 2x03's
# 13-patch_pipeline.sh with client specific directory redirection (via
# CAPSTONE_ARTIFACTS_DIR=capstone/patch/ set in the environment, so every
# sub-step artifact lands inside the capstone package) and a summary emitter.
#
# Consumes the provided capstone CVE feed at
# /home/analyst/MedDefense_Lab/capstone/cve_feed.json and configures
# unattended-upgrades with the mandated blacklist from
# /home/analyst/MedDefense_Lab/capstone/blacklist.json.
#
# Exits 0 only if the pipeline exit code was 0 and failed_entries == 0.
#
# Artifacts (relative to this script's directory):
#   capstone/patch/pipeline_run.json
#   capstone/patch/unattended_config.json
#   capstone/patch/patch_pipeline_summary.json

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAPSTONE_DIR="${SCRIPT_DIR}/capstone"
PATCH_DIR="${CAPSTONE_DIR}/patch"
OVERRIDES_DIR="${SCRIPT_DIR}/overrides"
PATCH_EQUATION_DIR="${SCRIPT_DIR}/../2x03_patch_equation"
PIPELINE_SCRIPT="${PATCH_EQUATION_DIR}/13-patch_pipeline.sh"
SUMMARY_FILE="${PATCH_DIR}/patch_pipeline_summary.json"

CVE_FEED="/home/analyst/MedDefense_Lab/capstone/cve_feed.json"
BLACKLIST_FILE="/home/analyst/MedDefense_Lab/capstone/blacklist.json"

for cmd in jq sudo bash; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Error: required command '$cmd' not found." >&2
        exit 2
    fi
done

if [[ ! -f "$PIPELINE_SCRIPT" ]]; then
    echo "Error: pipeline script not found: $PIPELINE_SCRIPT" >&2
    exit 2
fi

if [[ ! -f "$CVE_FEED" ]]; then
    echo "Error: capstone CVE feed not found: $CVE_FEED" >&2
    exit 2
fi

if [[ ! -f "$BLACKLIST_FILE" ]]; then
    echo "Error: mandated blacklist not found: $BLACKLIST_FILE" >&2
    exit 2
fi

mkdir -p "$PATCH_DIR" || {
    echo "Error: unable to create '$PATCH_DIR'." >&2
    exit 2
}

cp "${OVERRIDES_DIR}/0-vuln_inventory.sh" "${PATCH_DIR}/0-vuln_inventory.sh"
cp "${OVERRIDES_DIR}/8-unattended_config.sh" "${PATCH_DIR}/8-unattended_config.sh"
chmod +x "${PATCH_DIR}/0-vuln_inventory.sh" "${PATCH_DIR}/8-unattended_config.sh"

cd "$PATCH_DIR" || {
    echo "Error: unable to cd into '$PATCH_DIR'." >&2
    exit 2
}

export CAPSTONE_ARTIFACTS_DIR="$PATCH_DIR"
export CAPSTONE_CVE_FEED="$CVE_FEED"
export CAPSTONE_BLACKLIST_FILE="$BLACKLIST_FILE"

echo "[*] Running patch pipeline (13-patch_pipeline.sh) with CAPSTONE_ARTIFACTS_DIR=${CAPSTONE_ARTIFACTS_DIR}..."
sudo -E bash "$PIPELINE_SCRIPT" "${PATCH_DIR}/pipeline_run.json"
PIPELINE_EXIT=$?

echo "[*] Configuring unattended-upgrades with the mandated blacklist..."
sudo -E bash "${PATCH_DIR}/8-unattended_config.sh" "${PATCH_DIR}/unattended_config.json"
UU_EXIT=$?

if [[ "$UU_EXIT" -ne 0 ]]; then
    echo "Warning: 8-unattended_config.sh exited with code ${UU_EXIT}." >&2
fi

PATCH_EXEC_LOG="${PATCH_DIR}/patch_execution_log.json"
FAILED_ENTRIES=0
if [[ -f "$PATCH_EXEC_LOG" ]]; then
    FAILED_ENTRIES=$(jq '[.entries[]? | select(.status=="failed")] | length' "$PATCH_EXEC_LOG" 2>/dev/null)
    FAILED_ENTRIES="${FAILED_ENTRIES:-0}"
fi

ARTIFACTS_JSON="{}"
if [[ -f "${PATCH_DIR}/pipeline_run.json" ]]; then
    ARTIFACTS_JSON=$(jq -c '.artifacts // {}' "${PATCH_DIR}/pipeline_run.json" 2>/dev/null)
    ARTIFACTS_JSON="${ARTIFACTS_JSON:-\{\}}"
fi
ARTIFACTS_JSON=$(jq -c --arg k "unattended_config" --arg v "unattended_config.json" '. + {($k): $v}' <<< "$ARTIFACTS_JSON")

HOSTNAME_VAL=$(hostname)
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

if ! jq -n \
    --arg timestamp "$TIMESTAMP" \
    --arg hostname "$HOSTNAME_VAL" \
    --argjson pipeline_exit_code "$PIPELINE_EXIT" \
    --argjson unattended_upgrades_exit_code "$UU_EXIT" \
    --argjson failed_entries "$FAILED_ENTRIES" \
    --arg cve_feed "$CVE_FEED" \
    --arg blacklist_file "$BLACKLIST_FILE" \
    --argjson artifacts "$ARTIFACTS_JSON" \
    '{
        timestamp: $timestamp,
        hostname: $hostname,
        pipeline_exit_code: $pipeline_exit_code,
        unattended_upgrades_exit_code: $unattended_upgrades_exit_code,
        failed_entries: $failed_entries,
        cve_feed: $cve_feed,
        blacklist_file: $blacklist_file,
        artifacts: $artifacts
    }' > "$SUMMARY_FILE"; then
    echo "Error: failed to write '$SUMMARY_FILE'." >&2
    exit 2
fi

echo "Patch pipeline summary written to $SUMMARY_FILE"
echo "Pipeline exit code: ${PIPELINE_EXIT}, failed_entries: ${FAILED_ENTRIES}"

if [[ "$PIPELINE_EXIT" -eq 0 && "$FAILED_ENTRIES" -eq 0 ]]; then
    exit 0
else
    exit 1
fi
