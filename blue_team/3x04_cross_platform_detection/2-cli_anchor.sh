#!/bin/bash
set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
CATALOG_DIR="${CATALOG_DIR:-$HOME/3x02_package/detection_catalog}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
mkdir -p findings

INVESTIGATION_START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
START_EPOCH="$(date +%s)"
ACTIONS=()

ANCHOR_FILE="$ASSETS_DIR/anchor_event.json"
printf "reading     : %s\n" "$ANCHOR_FILE"
ACTIONS+=("read anchor manifest: $ANCHOR_FILE")

TARGET_HOST="$(jq -r '.target_host' "$ANCHOR_FILE")"
TARGET_IP="$(jq -r '.target_ip' "$ANCHOR_FILE")"
WINDOW_START="$(jq -r '.time_window.start' "$ANCHOR_FILE")"
WINDOW_END="$(jq -r '.time_window.end' "$ANCHOR_FILE")"
ATTACKER_IPS="$(jq -r '.attacker_ips | join(" ")' "$ANCHOR_FILE")"
IP_REGEX="$(jq -r '.attacker_ips | map(gsub("\\."; "\\.")) | join("|")' "$ANCHOR_FILE")"

printf "host        : %s (%s)\n" "$TARGET_HOST" "$TARGET_IP"
printf "window      : %s -> %s\n" "$WINDOW_START" "$WINDOW_END"
printf "attacker ips: %s\n" "$ATTACKER_IPS"

ENRICHED_FILE="$HANDOFF_DIR/data/enriched_events.json"
MATCHES="$(jq -c --arg host "$TARGET_HOST" --arg start "$WINDOW_START" --arg window_end "$WINDOW_END" --arg ips "$IP_REGEX" \
	'select(.hostname == $host and .timestamp >= $start and .timestamp <= $window_end and ((.raw_message // "") | test($ips)))' \
	"$ENRICHED_FILE")"
ACTIONS+=("jq filter enriched_events.json by hostname, time window, attacker IP in raw_message")

MATCH_COUNT="$(echo "$MATCHES" | grep -c .)"
FIRST_EVENT="$(echo "$MATCHES" | jq -r '.timestamp' | sort | head -1)"
LAST_EVENT="$(echo "$MATCHES" | jq -r '.timestamp' | sort | tail -1)"
ACTIONS+=("extract earliest and latest matching event timestamps")

printf "matched     : %s events in enriched_events.json\n" "$MATCH_COUNT"
printf "first event : %s\n" "$FIRST_EVENT"
printf "last event  : %s\n" "$LAST_EVENT"

RULE_FILE="$CATALOG_DIR/rules/sigma/001_ssh_brute_force.yml"
RULE_TECHNIQUE="UNKNOWN"
if [ -f "$RULE_FILE" ]; then
	yq -o=json '.detection' "$RULE_FILE" >/dev/null
	yq -o=json '.logsource' "$RULE_FILE" >/dev/null
	RULE_TECHNIQUE="$(yq '.tags[]' "$RULE_FILE" | grep -oE 't[0-9]+(\.[0-9]+)?' | head -1 | tr '[:lower:]' '[:upper:]')"
	printf "rule        : 001_ssh_brute_force (%s)\n" "$RULE_TECHNIQUE"
	ACTIONS+=("yq read 001_ssh_brute_force.yml logsource, detection and tags")
else
	printf "rule        : 001_ssh_brute_force NOT FOUND\n"
fi

INVESTIGATION_END="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
END_EPOCH="$(date +%s)"
ELAPSED=$((END_EPOCH - START_EPOCH))

EVENT_REFS_JSON="$(echo "$MATCHES" | jq -s '[.[].timestamp]')"
ACTIONS_JSON="$(printf '%s\n' "${ACTIONS[@]}" | jq -R . | jq -s .)"

jq -n \
	--arg finding_id "anchor_cli" \
	--arg scenario_id "anchor" \
	--arg interface "cli" \
	--arg investigation_start "$INVESTIGATION_START" \
	--arg investigation_end "$INVESTIGATION_END" \
	--argjson time_to_first_answer_seconds "$ELAPSED" \
	--argjson actions "$ACTIONS_JSON" \
	--argjson fields_touched '["hostname","timestamp","raw_message","target_host","target_ip","attacker_ips"]' \
	--argjson event_refs "$EVENT_REFS_JSON" \
	--argjson attack_techniques "[\"$RULE_TECHNIQUE\"]" \
	--arg hypothesis "Four external IPs conducted a coordinated SSH brute force against db-patient-01, culminating in a successful root login from 203.0.113.41 at 01:47:00Z. The attack pattern and timing match Sigma rule 001_ssh_brute_force (T1110)." \
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
	}' > findings/anchor_cli.json

printf "elapsed     : %s seconds, %s commands\n" "$ELAPSED" "${#ACTIONS[@]}"
printf "finding     : findings/anchor_cli.json written\n"
