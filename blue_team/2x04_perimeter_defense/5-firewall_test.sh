#!/bin/bash
#
# 5-firewall_test.sh
#
# MedDefense Health Systems - Perimeter and Network Defense (2x04)
#
# 4-nftables_config.sh's own "nft -c" check only proves the ruleset is
# syntactically valid - it says nothing about whether the *live, loaded*
# ruleset actually matches the flow matrix in segmentation_rules.json. This
# script is the functional test: it reads the live ruleset with
# "nft list ruleset" and checks, for every zone and every declared flow,
# that the rule an operator would expect to find is actually there.
#
# Read-only: makes no configuration changes.
#
# Usage: sudo ./5-firewall_test.sh [segmentation_rules.json]

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
OUT_JSON="rule_test_results.json"

resolve_input() {
    local name="$1" candidate
    for candidate in "./${name}" "${SCRIPT_DIR}/${name}" "${SCRIPT_DIR}/../${name}"; do
        [ -f "$candidate" ] && { echo "$candidate"; return 0; }
    done
    echo "$name"
}

RULES_FILE="${1:-$(resolve_input segmentation_rules.json)}"

if ! command -v nft >/dev/null 2>&1; then
    echo "Error: nft not found." >&2
    exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "Error: jq not found." >&2
    exit 2
fi

if [[ ! -f "$RULES_FILE" ]]; then
    echo "Error: segmentation_rules.json not found at $RULES_FILE" >&2
    exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Error: this script must run as root to read the live nftables ruleset." >&2
    exit 1
fi

LIVE_RULESET="$(nft list ruleset 2>/dev/null)"

if [[ -z "$LIVE_RULESET" ]]; then
    echo "Error: no live nftables ruleset loaded. Run 4-nftables_config.sh first." >&2
    exit 1
fi

echo "[*] Checking table inet meddefense is loaded..."
TABLE_LOADED=0
grep -q "table inet meddefense" <<< "$LIVE_RULESET" && TABLE_LOADED=1
if [[ "$TABLE_LOADED" -eq 1 ]]; then
    echo "    table inet meddefense                          PASS"
else
    echo "    table inet meddefense                          FAIL"
fi

echo "[*] Checking input/forward chain default policy is drop..."
POLICY_PASS=1
for chain in input forward; do
    if grep -A2 "chain ${chain} {" <<< "$LIVE_RULESET" | grep -q "policy drop"; then
        echo "    chain ${chain} policy drop                        PASS"
    else
        echo "    chain ${chain} policy drop                        FAIL"
        POLICY_PASS=0
    fi
done

echo "[*] Checking each declared flow has a matching live accept rule..."
FLOW_RESULTS="[]"
FLOWS_PASSED=0
FLOWS_FAILED=0

FLOW_COUNT=$(jq '.flows | length' "$RULES_FILE")
for ((i = 0; i < FLOW_COUNT; i++)); do
    FLOW=$(jq -c ".flows[$i]" "$RULES_FILE")
    SRC_ZONE=$(jq -r '.src_zone' <<< "$FLOW")
    DST_ZONE=$(jq -r '.dst_zone' <<< "$FLOW")
    PROTO=$(jq -r '.proto' <<< "$FLOW")
    DPORT=$(jq -r '.dport' <<< "$FLOW")

    if grep -q "${PROTO} dport ${DPORT} accept" <<< "$LIVE_RULESET"; then
        FOUND=true
        FLOWS_PASSED=$((FLOWS_PASSED + 1))
        STATUS="PASS"
    else
        FOUND=false
        FLOWS_FAILED=$((FLOWS_FAILED + 1))
        STATUS="FAIL"
    fi

    printf '    %-8s -> %-8s %s/%-5s %s\n' "$SRC_ZONE" "$DST_ZONE" "$PROTO" "$DPORT" "$STATUS"

    ENTRY=$(jq -n --arg src "$SRC_ZONE" --arg dst "$DST_ZONE" --arg proto "$PROTO" \
        --argjson dport "$DPORT" --argjson found "$FOUND" \
        '{src_zone: $src, dst_zone: $dst, proto: $proto, dport: $dport, found: $found}')
    FLOW_RESULTS=$(jq --argjson e "$ENTRY" '. + [$e]' <<< "$FLOW_RESULTS")
done

echo ""
echo "Table loaded: $([ "$TABLE_LOADED" -eq 1 ] && echo yes || echo no)"
echo "Default policy: $([ "$POLICY_PASS" -eq 1 ] && echo pass || echo fail)"
echo "Flows passed: $FLOWS_PASSED"
echo "Flows failed: $FLOWS_FAILED"
echo "Output: $OUT_JSON"

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
ALL_PASS=1
[[ "$TABLE_LOADED" -eq 1 && "$POLICY_PASS" -eq 1 && "$FLOWS_FAILED" -eq 0 ]] || ALL_PASS=0

jq -n \
    --arg ts "$TIMESTAMP" \
    --argjson table_loaded "$([ "$TABLE_LOADED" -eq 1 ] && echo true || echo false)" \
    --argjson default_policy_pass "$([ "$POLICY_PASS" -eq 1 ] && echo true || echo false)" \
    --argjson flows_passed "$FLOWS_PASSED" \
    --argjson flows_failed "$FLOWS_FAILED" \
    --argjson flows "$FLOW_RESULTS" \
    --argjson all_pass "$([ "$ALL_PASS" -eq 1 ] && echo true || echo false)" \
    '{
        timestamp: $ts,
        table_loaded: $table_loaded,
        default_policy_pass: $default_policy_pass,
        flows_passed: $flows_passed,
        flows_failed: $flows_failed,
        flows: $flows,
        all_pass: $all_pass
    }' > "$OUT_JSON"

if [[ "$ALL_PASS" -eq 1 ]]; then
    exit 0
else
    exit 1
fi
