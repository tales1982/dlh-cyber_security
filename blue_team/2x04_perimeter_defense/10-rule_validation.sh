#!/bin/bash
#
# 10-rule_validation.sh
#
# MedDefense Health Systems - Perimeter and Network Defense (2x04)
#
# A custom rule that never fires is worse than no rule at all - it is a
# false sense of coverage. This script proves each meddefense.rules
# signature actually fires against the labeled PCAP built for it, using
# the same suricata.yaml (and therefore the same ruleset) as T8/T9.
#
# Usage: sudo ./10-rule_validation.sh

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
LABELS_DIR="/home/analyst/MedDefense_Lab/PCAPs/labels"

resolve_input() {
    local name="$1" candidate
    for candidate in "./${name}" "${SCRIPT_DIR}/${name}" "${SCRIPT_DIR}/../${name}"; do
        [ -f "$candidate" ] && { echo "$candidate"; return 0; }
    done
    echo "$name"
}
YAML="$(resolve_input suricata.yaml)"
RULES_FILE="$(resolve_input meddefense.rules)"

if [ ! -f "$YAML" ]; then
    echo "error: cannot find suricata.yaml (run 8-suricata_setup.sh first)" >&2
    exit 1
fi
if [ ! -d "$LABELS_DIR" ]; then
    echo "error: labeled PCAP directory not found: $LABELS_DIR" >&2
    exit 1
fi

RULE_COUNT="$(grep -c '^alert' "$RULES_FILE" 2>/dev/null || echo 0)"
echo "[*] Loading meddefense.rules...          $RULE_COUNT rules"
echo "[*] Running validation against labeled PCAPs..."
echo ""

# --- Declarative target: pcap -> "sid:description" pairs -------------------
declare -A TARGETS=(
    ["meddev_egress.pcap"]="9000001:MEDDEV to Internet"
    ["guest_smb.pcap"]="9000002:Guest to SMB"
    ["large_outbound.pcap"]="9000003:Large Outbound From Server"
    ["dns_tunnel.pcap"]="9000004:DNS Tunneling Long Label"
    ["clinical_wrong_db.pcap"]="9000005:Clinical to Unauthorized DB"
    ["telnet_meddev.pcap"]="9000006:Telnet to MEDDEV"
)

RESULTS_FILE="$(mktemp)"
trap 'rm -rf "$RESULTS_FILE" "${RUN_DIR:-}"' EXIT

total=0
passed=0

for pcap_name in meddev_egress.pcap guest_smb.pcap large_outbound.pcap dns_tunnel.pcap clinical_wrong_db.pcap telnet_meddev.pcap; do
    pcap_path="${LABELS_DIR}/${pcap_name}"
    if [ ! -f "$pcap_path" ]; then
        echo "[!] missing labeled PCAP: $pcap_path - skipping" >&2
        continue
    fi

    RUN_DIR="$(mktemp -d)"
    suricata -c "$YAML" -r "$pcap_path" -l "$RUN_DIR" >/dev/null 2>&1
    HITS_JSON="[]"
    [ -f "$RUN_DIR/eve.json" ] && HITS_JSON="$(jq -nc '[inputs | select(.event_type=="alert") | .alert.signature_id]' "$RUN_DIR/eve.json" 2>/dev/null)"
    rm -rf "$RUN_DIR"

    IFS=';' read -ra pairs <<< "${TARGETS[$pcap_name]}"
    for pair in "${pairs[@]}"; do
        sid="${pair%%:*}"
        desc="${pair#*:}"
        total=$((total + 1))
        count="$(jq --argjson s "$sid" '[.[] | select(. == $s)] | length' <<<"$HITS_JSON")"

        echo "sid $sid $desc"
        echo "  target: $pcap_name"
        echo "  expected: fire"
        if [ "$count" -gt 0 ]; then
            echo "  observed: fire ($count hits)                PASS"
            passed=$((passed + 1))
            jq -nc --argjson sid "$sid" --arg desc "$desc" --arg pcap "$pcap_name" --argjson count "$count" \
                '{sid: $sid, description: $desc, pcap: $pcap, hits: $count, result: "pass"}' >> "$RESULTS_FILE"
        else
            echo "  observed: did not fire                       FAIL"
            jq -nc --argjson sid "$sid" --arg desc "$desc" --arg pcap "$pcap_name" --argjson count "$count" \
                '{sid: $sid, description: $desc, pcap: $pcap, hits: $count, result: "fail"}' >> "$RESULTS_FILE"
        fi
        echo ""
    done
done

failed=$((total - passed))
echo "Rules:  $total"
echo "Passed: $passed"
echo "Failed: $failed"

jq -s '.' "$RESULTS_FILE" > rule_validation.json

[ "$failed" -eq 0 ]
