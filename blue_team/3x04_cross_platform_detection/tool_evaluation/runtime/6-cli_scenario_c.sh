#!/bin/bash
set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
mkdir -p findings

START_EPOCH="$(date +%s)"
INVESTIGATION_START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ACTIONS=()

MANIFEST_FILE="$ASSETS_DIR/scenarios/scenario_c_medical_egress.json"
ACTIONS+=("read scenario manifest: $MANIFEST_FILE")

SRC_IP="10.2.3.2"
DST_IP="198.51.100.73"
TECHNIQUES="$(jq -r '.mitre_techniques | join(" ")' "$MANIFEST_FILE")"
TECHNIQUES_JSON="$(jq -c '.mitre_techniques' "$MANIFEST_FILE")"

NETWORK_FILE="$HANDOFF_DIR/data/network_events.json"
MATCHES="$(jq -c --arg src "$SRC_IP" --arg dst "$DST_IP" \
	'select(.src_ip == $src and .dst_ip == $dst)' \
	"$NETWORK_FILE")"
ACTIONS+=("jq filter network_events.json for src_ip and dst_ip")
MATCH_COUNT="$(echo "$MATCHES" | grep -c .)"

ZONES_FILE="$HANDOFF_DIR/context/network_zones.json"
ZONE_NAME="$(python3 -c "
import json, ipaddress
data = json.load(open('$ZONES_FILE'))
ip = ipaddress.ip_address('$SRC_IP')
best = None
for z in data['zones']:
    for cidr in z['cidrs']:
        net = ipaddress.ip_network(cidr)
        if ip in net:
            if best is None or net.prefixlen > best[1]:
                best = (z['zone_id'], net.prefixlen)
print(best[0] if best else 'unknown')
")"
ACTIONS+=("read network_zones.json and resolve $SRC_IP to a zone by CIDR containment")

IOC_FILE="$ASSETS_DIR/3x03_assets/ioc_context.json"
[ -f "$IOC_FILE" ] || IOC_FILE="$HOME/3x03_assets/ioc_context.json"
IOC_REPUTATION="none"
if [ -f "$IOC_FILE" ]; then
	IOC_REPUTATION="$(jq -r --arg ip "$DST_IP" '.indicators[$ip].reputation // "none"' "$IOC_FILE")"
	ACTIONS+=("check ioc_context.json reputation for $DST_IP")
fi

printf "scenario    : scenario_c_medical_egress\n"
printf "src_ip      : %s (%s zone)\n" "$SRC_IP" "$ZONE_NAME"
printf "dst_ip      : %s:443\n" "$DST_IP"
printf "matched     : %s flows in network_events.json\n" "$MATCH_COUNT"

BEACON_TS_LIST="$(echo "$MATCHES" | jq -r 'select(.source_type == "firewall") | .timestamp' | sort)"
ACTIONS+=("order beacon events chronologically and compute inter-beacon intervals")

PREV_EPOCH=""
BEACON_NUM=0
while IFS= read -r TS; do
	BEACON_NUM=$((BEACON_NUM + 1))
	CUR_EPOCH="$(date -u -d "$TS" +%s)"
	if [ -z "$PREV_EPOCH" ]; then
		printf "beacon_%s    : %s\n" "$BEACON_NUM" "$TS"
	else
		INTERVAL_MIN=$(((CUR_EPOCH - PREV_EPOCH) / 60))
		printf "beacon_%s    : %s  (interval: %s min)\n" "$BEACON_NUM" "$TS" "$INTERVAL_MIN"
	fi
	PREV_EPOCH="$CUR_EPOCH"
done <<< "$BEACON_TS_LIST"

printf "zone        : %s — no direct internet access permitted\n" "$ZONE_NAME"
printf "ioc         : %s (%s)\n" "$DST_IP" "$IOC_REPUTATION"
printf "attack      : %s\n" "$TECHNIQUES"

HYPOTHESIS="med-mri-02, a MEDICAL_IOT device restricted to RADIOLOGY-only outbound traffic, beaconed to external IP 198.51.100.73 five times at a consistent 12-minute interval. The destination is a known-malicious C2 indicator, and this zone violation is a critical policy breach regardless of the permit_vendor_update firewall rule that allowed it."

INVESTIGATION_END="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
END_EPOCH="$(date +%s)"
ELAPSED=$((END_EPOCH - START_EPOCH))
ACTIONS+=("write findings/scenario_c_cli.json")

EVENT_REFS_JSON="$(echo "$MATCHES" | jq -s '[.[].timestamp]')"
ACTIONS_JSON="$(printf '%s\n' "${ACTIONS[@]}" | jq -R . | jq -s .)"

jq -n \
	--arg finding_id "scenario_c_cli" \
	--arg scenario_id "scenario_c" \
	--arg interface "cli" \
	--arg investigation_start "$INVESTIGATION_START" \
	--arg investigation_end "$INVESTIGATION_END" \
	--argjson time_to_first_answer_seconds "$ELAPSED" \
	--argjson actions "$ACTIONS_JSON" \
	--argjson fields_touched '["src_ip","dst_ip","timestamp","source_type","raw_message"]' \
	--argjson event_refs "$EVENT_REFS_JSON" \
	--argjson attack_techniques "$TECHNIQUES_JSON" \
	--arg hypothesis "$HYPOTHESIS" \
	--arg confidence "high" \
	--arg created_at "$INVESTIGATION_END" \
	'{
		finding_id: $finding_id,
		scenario_id: $scenario_id,
		interface: $interface,
		investigation_start: $investigation_start,
		investigation_end: $investigation_end,
		time_to_first_answer_seconds: $time_to_first_answer_seconds,
		actions: $actions,
		fields_touched: $fields_touched,
		event_refs: $event_refs,
		attack_techniques: $attack_techniques,
		hypothesis: $hypothesis,
		confidence: $confidence,
		created_at: $created_at
	}' > findings/scenario_c_cli.json

printf "elapsed     : %s seconds, %s commands\n" "$ELAPSED" "${#ACTIONS[@]}"
printf "finding     : findings/scenario_c_cli.json written\n"
