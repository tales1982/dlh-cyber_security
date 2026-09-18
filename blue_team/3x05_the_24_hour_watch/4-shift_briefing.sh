#!/bin/bash
set -euo pipefail

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x05_assets/capstone_pack/meta}"
SHIFT_WORKSPACE="${SHIFT_WORKSPACE:-$HOME/bt/3x05/shift_pack}"

fail() {
	echo "[brief] FAIL: $1" >&2
	exit 1
}

ADVISORY_FILE="$ASSETS_DIR/hc_red7_advisory.md"
IOC_FILE="$ASSETS_DIR/ioc_feed.json"
TICKETS_FILE="$ASSETS_DIR/change_tickets.json"
NOTES_FILE="$ASSETS_DIR/prior_shift_notes.md"
BASELINE_RUN_FILE="$SHIFT_WORKSPACE/runtime/baseline_run.json"

for F in "$ADVISORY_FILE" "$IOC_FILE" "$TICKETS_FILE" "$NOTES_FILE" "$BASELINE_RUN_FILE"; do
	[ -s "$F" ] || fail "missing or empty required file: $F"
done
printf "[brief] checking input files... OK\n"

CLUSTER_ID="$(grep -m1 -oE 'HC-RED[0-9]+' "$ADVISORY_FILE")"
[ -n "$CLUSTER_ID" ] || fail "cluster ID not found in $ADVISORY_FILE"
printf "[brief] cluster %s loaded\n" "$CLUSTER_ID"

TACTICS_JSON="$(grep -oE 'T[0-9]{4}(\.[0-9]{3})?' "$ADVISORY_FILE" | sort -u | jq -R . | jq -s .)"
TACTICS_LIST="$(echo "$TACTICS_JSON" | jq -r 'join(" ")')"
printf "[brief] tactics: %s\n" "$TACTICS_LIST"

IOC_COUNT="$(jq '.iocs | length' "$IOC_FILE")"
IOC_BY_TYPE_JSON="$(jq '
	{ip: 0, domain: 0, hash: 0, account: 0, service_name: 0, port: 0}
	+ (.iocs | group_by(.type) | map({(.[0].type): length}) | add // {})
' "$IOC_FILE")"
IOC_VALUES_JSON="$(jq '[.iocs[].value]' "$IOC_FILE")"

echo "$IOC_BY_TYPE_JSON" | jq -r \
	--argjson total "$IOC_COUNT" \
	'"[brief] IOCs: ip=\(.ip) domain=\(.domain) hash=\(.hash) account=\(.account) service_name=\(.service_name) port=\(.port) total=\($total)"'

TICKETS_JSON="$(jq '
	[.tickets[] | {
		ticket_id: .ticket_id,
		window_start: (.window | split("/")[0]),
		window_end: (.window | split("/")[1]),
		hosts: .hosts,
		owner: .owner,
		approved_activity: .approved_activity
	}]
' "$TICKETS_FILE")"
TICKETS_COUNT="$(echo "$TICKETS_JSON" | jq 'length')"
printf "[brief] active change tickets in window: %s\n" "$TICKETS_COUNT"

OPEN_ITEMS_JSON="$(python3 -c '
import json, re, sys

with open(sys.argv[1]) as f:
    text = f.read()

m = re.search(r"^## Open Items.*?\n(.*?)(?=\n## |\Z)", text, re.S | re.M)
body = m.group(1) if m else ""

items = re.split(r"\n(?=\d+\.\s)", body.strip())
items = [re.sub(r"^\d+\.\s*", "", i).strip() for i in items if i.strip()]
items = [re.sub(r"\s+", " ", i) for i in items]
print(json.dumps(items))
' "$NOTES_FILE")"
OPEN_ITEMS_COUNT="$(echo "$OPEN_ITEMS_JSON" | jq 'length')"
printf "[brief] prior shift open items: %s\n" "$OPEN_ITEMS_COUNT"

HOT_HOSTS_JSON="$(jq '.hot_hosts' "$BASELINE_RUN_FILE")"
HOSTS_WITH_DEVIATIONS="$(jq '.hosts_with_deviations' "$BASELINE_RUN_FILE")"
printf "[brief] baseline hot hosts: %s\n" "$(echo "$HOT_HOSTS_JSON" | jq 'length')"

SHIFT_START_FILE="$SHIFT_WORKSPACE/runtime/shift_start.json"
if [ -s "$SHIFT_START_FILE" ]; then
	RECORDED_CLUSTER="$(jq -r '.advisory_cluster_id' "$SHIFT_START_FILE")"
	[ "$RECORDED_CLUSTER" = "$CLUSTER_ID" ] || fail "cluster ID mismatch: shift_start.json has $RECORDED_CLUSTER, advisory has $CLUSTER_ID"
fi
printf "[brief] cluster ID cross-check: OK\n"

jq -n \
	--arg cluster_id "$CLUSTER_ID" \
	--argjson cluster_tactics "$TACTICS_JSON" \
	--argjson ioc_count "$IOC_COUNT" \
	--argjson ioc_by_type "$IOC_BY_TYPE_JSON" \
	--argjson ioc_values "$IOC_VALUES_JSON" \
	--argjson active_change_tickets "$TICKETS_JSON" \
	--argjson prior_shift_open_items "$OPEN_ITEMS_JSON" \
	--argjson baseline_hot_hosts "$HOT_HOSTS_JSON" \
	--argjson hosts_with_deviations "$HOSTS_WITH_DEVIATIONS" \
	'{
		cluster_id: $cluster_id,
		cluster_tactics: $cluster_tactics,
		ioc_count: $ioc_count,
		ioc_by_type: $ioc_by_type,
		ioc_values: $ioc_values,
		active_change_tickets: $active_change_tickets,
		prior_shift_open_items: $prior_shift_open_items,
		baseline_hot_hosts: $baseline_hot_hosts,
		hosts_with_deviations: $hosts_with_deviations
	}' > "$SHIFT_WORKSPACE/alerts/shift_briefing.json"

printf "[brief] shift_briefing.json written\n"
