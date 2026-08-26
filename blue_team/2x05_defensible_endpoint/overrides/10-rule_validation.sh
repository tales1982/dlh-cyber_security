#!/bin/bash
#
# Name:        10-rule_validation.sh
# Purpose:     Validate meddefense.rules against labeled PCAPs
#
# MedDefense Health Systems - Perimeter and Network Defense (2x04)
#
# A custom rule that never fires is worse than no rule at all - it is a
# false sense of coverage. This script proves each meddefense.rules
# signature actually fires against the labeled PCAP built for it.
#
# Usage: sudo ./10-rule_validation.sh

set -euo pipefail

# Configuration
LAB_DIR="/home/analyst/MedDefense_Lab"
# Capstone (2x05) fix: the original script hardcodes RULES_FILE/CONFIG_FILE
# to CWD (no resolve_input fallback) and PCAPS_DIR to the 2x04 lab path with
# no override at all. CAPSTONE_RULES_FILE / CAPSTONE_SURICATA_CONFIG /
# CAPSTONE_PCAPS_LABELS_DIR let the Task 7 orchestrator point these at the
# capstone-provided files instead.
RULES_FILE="${CAPSTONE_RULES_FILE:-./meddefense.rules}"
# Labeled PCAPs directory: /home/analyst/MedDefense_Lab/PCAPs/labels
PCAPS_DIR="${CAPSTONE_PCAPS_LABELS_DIR:-${LAB_DIR}/PCAPs/labels}"
CONFIG_FILE="${CAPSTONE_SURICATA_CONFIG:-./suricata.yaml}"
OUTPUT_DIR="/tmp/meddefense-validation-$$"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Mapping of PCAP to expected SID and description
declare -A PCAP_SID_MAP
PCAP_SID_MAP["meddev_egress.pcap"]="9000001|MEDDEV to Internet"
PCAP_SID_MAP["guest_smb.pcap"]="9000002|Guest to SMB"
PCAP_SID_MAP["large_outbound.pcap"]="9000003|Large Outbound From Server"
PCAP_SID_MAP["dns_tunnel.pcap"]="9000004|DNS Tunneling Long Label"
PCAP_SID_MAP["clinical_wrong_db.pcap"]="9000005|Clinical to Unauthorized DB"
PCAP_SID_MAP["telnet_meddev.pcap"]="9000006|Telnet to MEDDEV"

# Count rules
RULE_COUNT=$(grep -cE '^alert' "$RULES_FILE" 2>/dev/null || true)
RULE_COUNT=${RULE_COUNT:-0}
echo "[*] Loading meddefense.rules...          $RULE_COUNT rules"

# Verify inputs
if [[ ! -f "$RULES_FILE" ]]; then
    echo "Error: meddefense.rules not found at $RULES_FILE" >&2
    exit 1
fi

if [[ ! -d "$PCAPS_DIR" ]]; then
    echo "Error: PCAP directory $PCAPS_DIR not found." >&2
    exit 1
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Error: suricata.yaml not found. Run 8-suricata_setup.sh first." >&2
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo "[*] Running validation against labeled PCAPs..."
echo ""

PASSED=0
FAILED=0

for pcaps_file in "$PCAPS_DIR"/*.pcap; do
    [[ -f "$pcaps_file" ]] || continue

    PCAP_NAME=$(basename "$pcaps_file")

    # Skip if no SID mapping for this PCAP
    if [[ -z "${PCAP_SID_MAP[$PCAP_NAME]:-}" ]]; then
        continue
    fi

    EXPECTED_INFO="${PCAP_SID_MAP[$PCAP_NAME]}"
    EXPECTED_SID=$(echo "$EXPECTED_INFO" | cut -d'|' -f1)
    EXPECTED_DESC=$(echo "$EXPECTED_INFO" | cut -d'|' -f2)

    echo "sid $EXPECTED_SID $EXPECTED_DESC"
    echo "  target: $PCAP_NAME"
    echo "  expected: fire"

    # Run suricata with custom rules loaded
    LOG_DIR="${OUTPUT_DIR}/${PCAP_NAME%.pcap}"
    mkdir -p "$LOG_DIR"

    # Temporarily modify suricata.yaml to load meddefense.rules
    RULES_FILE_ABS="$(readlink -f "$RULES_FILE")"
    TMP_CONFIG="${LOG_DIR}/test.yaml"
    sed "s|rule-files:|rule-files:\n  - ${RULES_FILE_ABS}|g" "$CONFIG_FILE" > "$TMP_CONFIG"

    # Run suricata replay (suppress noisy stderr)
    suricata -c "$TMP_CONFIG" -r "$pcaps_file" -l "$LOG_DIR" 2>/dev/null

    EVE_FILE="${LOG_DIR}/eve.json"

    if [[ -f "$EVE_FILE" ]]; then
        # Count alerts with expected SID
        ALERT_COUNT=$(jq -s "[.[] | select(.alert.signature_id == $EXPECTED_SID)] | length" "$EVE_FILE" 2>/dev/null || true)
        ALERT_COUNT=${ALERT_COUNT:-0}

        if [[ "$ALERT_COUNT" -gt 0 ]]; then
            echo "  observed: fire ($ALERT_COUNT hits)                PASS"
            PASSED=$((PASSED + 1))
        else
            echo "  observed: FAILED (no matches)                      FAIL"
            FAILED=$((FAILED + 1))
        fi
    else
        echo "  observed: FAILED (no eve.json)                         FAIL"
        FAILED=$((FAILED + 1))
    fi
    echo ""
done

# Summary
echo "Rules:  $RULE_COUNT"
echo "Passed: $PASSED"
echo "Failed: $FAILED"
echo "Output: rule_validation.json"

# ---------------------------------------------------------------
# Emit rule_validation.json with structured results
# ---------------------------------------------------------------
VALIDATION_JSON=$(jq -n \
    --arg ts "$TIMESTAMP" \
    --argjson rule_count "$RULE_COUNT" \
    --argjson passed "$PASSED" \
    --argjson failed "$FAILED" \
    '{
        timestamp: $ts,
        rules_file: "meddefense.rules",
        rule_count: $rule_count,
        passed: $passed,
        failed: $failed,
        status: (if $failed == 0 then "all_passed" else "failures_detected" end)
    }')

echo "$VALIDATION_JSON" > "rule_validation.json"

# Cleanup
rm -rf "$OUTPUT_DIR"

# Exit non-zero if any failures
if [[ "$FAILED" -gt 0 ]]; then
    exit 1
fi

exit 0
