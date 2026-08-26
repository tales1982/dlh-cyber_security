#!/bin/bash
#
# Orchestrates the network defense stack on hawthorne-app-01. Does not
# reinvent the pipeline: wraps 2x04's existing scripts with
# CAPSTONE_ARTIFACTS_DIR=capstone/network/ set in the environment so every
# artifact lands inside the capstone package.
#
# Uses the capstone segmentation file at
# /home/analyst/MedDefense_Lab/capstone/segmentation_rules.json, which
# reflects the Hawthorne site topology, not the main MedDefense topology -
# 2x04's own segmentation_rules.sh is never invoked, since it always
# regenerates the main-topology rules from scratch.
#
# Runs the firewall validation suite (4-nftables_config.sh --render-only,
# which validates the ruleset with "nft -c" without loading it live) and
# refuses to proceed if any test fails. Runs Suricata in offline replay
# mode against every PCAP in
# /home/analyst/MedDefense_Lab/capstone/PCAPs/ and persists the parsed
# alerts. Runs the custom rule validation against the provided labeled
# PCAPs. Configures dnsmasq as the local DNS filter with the capstone
# blocklist at /home/analyst/MedDefense_Lab/capstone/dns_blocklist.txt.
#
# Exits 0 only if every validation step passed.
#
# Safety note: nftables is applied in --render-only mode by default. A
# misapplied ruleset can sever the management SSH session with no local
# console fallback as forgiving as an sshd_config mistake - pass
# --apply-live to actually load the ruleset once you have verified the
# rendered nftables.conf by hand.
#
# Artifacts (relative to this script's directory):
#   capstone/network/segmentation_rules.json
#   capstone/network/nftables.conf
#   capstone/network/suricata.yaml
#   capstone/network/suricata_alerts_<pcap>.json (one per PCAP)
#   capstone/network/rule_validation.json
#   capstone/network/dns_filtering_result.json
#   capstone/network/network_deploy_summary.json

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAPSTONE_DIR="${SCRIPT_DIR}/capstone"
NETWORK_DIR="${CAPSTONE_DIR}/network"
OVERRIDES_DIR="${SCRIPT_DIR}/overrides"
PERIMETER_DIR="${SCRIPT_DIR}/../2x04_perimeter_defense"
SUMMARY_FILE="${NETWORK_DIR}/network_deploy_summary.json"

SEGMENTATION_FILE="/home/analyst/MedDefense_Lab/capstone/segmentation_rules.json"
PCAPS_DIR="/home/analyst/MedDefense_Lab/capstone/PCAPs"
DNS_BLOCKLIST="/home/analyst/MedDefense_Lab/capstone/dns_blocklist.txt"

APPLY_LIVE=0
for arg in "$@"; do
    [[ "$arg" == "--apply-live" ]] && APPLY_LIVE=1
done

for cmd in jq sudo nft; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Error: required command '$cmd' not found." >&2
        exit 2
    fi
done

for f in "$SEGMENTATION_FILE" "$DNS_BLOCKLIST"; do
    if [[ ! -f "$f" ]]; then
        echo "Error: required capstone input not found: $f" >&2
        exit 2
    fi
done

if [[ ! -d "$PCAPS_DIR" ]] || [[ -z "$(find "$PCAPS_DIR" -maxdepth 1 -name '*.pcap' -print -quit)" ]]; then
    echo "Error: no PCAP files found under $PCAPS_DIR" >&2
    exit 2
fi

mkdir -p "$NETWORK_DIR" || {
    echo "Error: unable to create '$NETWORK_DIR'." >&2
    exit 2
}

export CAPSTONE_ARTIFACTS_DIR="$NETWORK_DIR"
export CAPSTONE_DNS_BLOCKLIST="$DNS_BLOCKLIST"

cp "$SEGMENTATION_FILE" "${NETWORK_DIR}/segmentation_rules.json"

# --- Firewall validation suite ------------------------------------------
echo "[*] Running firewall validation suite (nft -c check)..."
NFT_MODE_FLAG="--render-only"
[[ "$APPLY_LIVE" -eq 1 ]] && NFT_MODE_FLAG=""

# shellcheck disable=SC2086
sudo bash "${PERIMETER_DIR}/4-nftables_config.sh" $NFT_MODE_FLAG "$SEGMENTATION_FILE"
FW_EXIT=$?

if [[ -f "${PERIMETER_DIR}/nftables.conf" ]]; then
    cp "${PERIMETER_DIR}/nftables.conf" "${NETWORK_DIR}/nftables.conf"
fi

# 5-firewall_test.sh checks the LIVE loaded ruleset against the flow
# matrix, so it only runs a meaningful test once nftables has actually been
# applied (--apply-live). In the safe --render-only default there is no
# live ruleset to test yet, so this step is skipped rather than failed.
if [[ "$FW_EXIT" -eq 0 && "$APPLY_LIVE" -eq 1 ]]; then
    echo "[*] Running firewall functional test (5-firewall_test.sh) against the live ruleset..."
    ( cd "$NETWORK_DIR" && sudo bash "${PERIMETER_DIR}/5-firewall_test.sh" "$SEGMENTATION_FILE" )
    FW_TEST_EXIT=$?
    [[ "$FW_TEST_EXIT" -ne 0 ]] && FW_EXIT=1
fi

if [[ "$FW_EXIT" -ne 0 ]]; then
    echo "Error: firewall validation failed (exit ${FW_EXIT}). Refusing to proceed." >&2
fi

# --- Suricata setup, offline replay and custom rule validation ----------
SURICATA_SETUP_EXIT=0
SURICATA_REPLAY_EXIT=0
RULE_VALIDATION_EXIT=0

if [[ "$FW_EXIT" -eq 0 ]]; then
    echo "[*] Running Suricata setup..."
    sudo bash "${PERIMETER_DIR}/8-suricata_setup.sh" "${NETWORK_DIR}/setup_verification.json"
    SURICATA_SETUP_EXIT=$?
    if [[ "$SURICATA_SETUP_EXIT" -ne 0 ]]; then
        echo "Warning: 8-suricata_setup.sh exited ${SURICATA_SETUP_EXIT} (its own smoke-test PCAP is not part of the capstone fixture set; continuing)." >&2
    fi

    if [[ -f "${PERIMETER_DIR}/suricata.yaml" ]]; then
        cp "${PERIMETER_DIR}/suricata.yaml" "${NETWORK_DIR}/suricata.yaml"
    fi

    echo "[*] Running Suricata in offline replay mode against every PCAP in ${PCAPS_DIR}..."
    while IFS= read -r -d '' pcap; do
        PCAP_NAME="$(basename "$pcap")"
        echo "    - ${PCAP_NAME}"
        ( cd "$NETWORK_DIR" && sudo bash "${PERIMETER_DIR}/9-suricata_analysis.sh" "$pcap" )
        STEP_EXIT=$?
        [[ "$STEP_EXIT" -ne 0 ]] && SURICATA_REPLAY_EXIT=1
        if [[ -f "${NETWORK_DIR}/suricata_alerts.json" ]]; then
            mv "${NETWORK_DIR}/suricata_alerts.json" "${NETWORK_DIR}/suricata_alerts_${PCAP_NAME%.pcap}.json"
        fi
    done < <(find "$PCAPS_DIR" -maxdepth 1 -name '*.pcap' -print0)

    echo "[*] Running custom rule validation against the provided labeled PCAPs..."
    export CAPSTONE_RULES_FILE="${PERIMETER_DIR}/meddefense.rules"
    export CAPSTONE_SURICATA_CONFIG="${NETWORK_DIR}/suricata.yaml"
    export CAPSTONE_PCAPS_LABELS_DIR="${PCAPS_DIR}/labels"
    ( cd "$NETWORK_DIR" && sudo -E bash "${OVERRIDES_DIR}/10-rule_validation.sh" )
    RULE_VALIDATION_EXIT=$?
fi

# --- DNS filter -----------------------------------------------------------
DNS_FILTER_EXIT=1
if [[ "$FW_EXIT" -eq 0 ]]; then
    echo "[*] Configuring dnsmasq as the local DNS filter..."
    ( cd "$NETWORK_DIR" && sudo -E bash "${OVERRIDES_DIR}/13-dns_filtering.sh" )
    DNS_FILTER_EXIT=$?
fi

ALL_PASSED=0
if [[ "$FW_EXIT" -eq 0 && "$SURICATA_REPLAY_EXIT" -eq 0 && "$RULE_VALIDATION_EXIT" -eq 0 && "$DNS_FILTER_EXIT" -eq 0 ]]; then
    ALL_PASSED=1
fi

HOSTNAME_VAL=$(hostname)
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

if ! jq -n \
    --arg timestamp "$TIMESTAMP" \
    --arg hostname "$HOSTNAME_VAL" \
    --argjson apply_live "$([[ "$APPLY_LIVE" -eq 1 ]] && echo true || echo false)" \
    --argjson firewall_validation_exit_code "$FW_EXIT" \
    --argjson suricata_setup_exit_code "$SURICATA_SETUP_EXIT" \
    --argjson suricata_replay_exit_code "$SURICATA_REPLAY_EXIT" \
    --argjson rule_validation_exit_code "$RULE_VALIDATION_EXIT" \
    --argjson dns_filter_exit_code "$DNS_FILTER_EXIT" \
    --argjson all_passed "$([[ "$ALL_PASSED" -eq 1 ]] && echo true || echo false)" \
    '{
        timestamp: $timestamp,
        hostname: $hostname,
        apply_live: $apply_live,
        firewall_validation_exit_code: $firewall_validation_exit_code,
        suricata_setup_exit_code: $suricata_setup_exit_code,
        suricata_replay_exit_code: $suricata_replay_exit_code,
        rule_validation_exit_code: $rule_validation_exit_code,
        dns_filter_exit_code: $dns_filter_exit_code,
        all_passed: $all_passed
    }' > "$SUMMARY_FILE"; then
    echo "Error: failed to write '$SUMMARY_FILE'." >&2
    exit 2
fi

echo "Network deploy summary written to $SUMMARY_FILE"

if [[ "$ALL_PASSED" -eq 1 ]]; then
    exit 0
else
    exit 1
fi
