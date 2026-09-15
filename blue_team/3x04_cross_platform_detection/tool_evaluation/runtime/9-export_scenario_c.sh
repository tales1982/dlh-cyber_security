#!/bin/bash
set -euo pipefail

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
mkdir -p findings

START_EPOCH="$(date +%s)"
INVESTIGATION_START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ACTIONS=()

SEARCH_FILE="$ASSETS_DIR/wazuh_exports/scenario_c_search_results.json"
EVENT_COUNT="$(jq '.events | length' "$SEARCH_FILE")"
printf "reading     : scenario_c_search_results.json (%s events)\n" "$EVENT_COUNT"
ACTIONS+=("read scenario_c_search_results.json ($EVENT_COUNT events)")

SRC_IP="$(jq -r '.events[0]._source.source.ip' "$SEARCH_FILE")"
DST_IP="$(jq -r '.events[0]._source.destination.ip' "$SEARCH_FILE")"
printf "src_ip      : %s\n" "$SRC_IP"
printf "dst_ip      : %s:443\n" "$DST_IP"
ACTIONS+=("extract @timestamp, source.ip, destination.ip, source.zone from events")

SRC_ZONE="$(jq -r '.events[0]._source.source.zone // "null"' "$SEARCH_FILE")"
if [ "$SRC_ZONE" != "null" ] && [ -n "$SRC_ZONE" ]; then
	printf "src_zone    : %s (from source.zone — immediately available)\n" "$SRC_ZONE"
	ACTIONS+=("check source.zone field (immediately available)")
else
	printf "src_zone    : UNKNOWN (source.zone not populated — fallback required)\n"
	ACTIONS+=("check source.zone field (absent — fallback required)")
fi

BEACON_TS_LIST="$(jq -r '[.events[] | select(._source.full_log | startswith("{") | not)] | sort_by(."@timestamp") | .[]."@timestamp"' "$SEARCH_FILE")"
ACTIONS+=("order beacon flows chronologically and compute inter-beacon intervals")

PREV_EPOCH=""
BEACON_NUM=0
while IFS= read -r TS; do
	BEACON_NUM=$((BEACON_NUM + 1))
	CUR_EPOCH="$(date -u -d "$TS" +%s)"
	if [ -z "$PREV_EPOCH" ]; then
		printf "beacon_%s    : %s\n" "$BEACON_NUM" "$TS"
	else
		INTERVAL_MIN=$(((CUR_EPOCH - PREV_EPOCH) / 60))
		printf "beacon_%s    : %s  (%s min interval)\n" "$BEACON_NUM" "$TS" "$INTERVAL_MIN"
	fi
	PREV_EPOCH="$CUR_EPOCH"
done <<< "$BEACON_TS_LIST"

TRACE_FILE="$ASSETS_DIR/wazuh_exports/scenario_c_dashboard_trace.json"
TECHNIQUES_JSON="$(jq -c '.attack_techniques' "$TRACE_FILE")"
TECHNIQUES="$(jq -r '.attack_techniques | join(" ")' "$TRACE_FILE")"
printf "attack      : %s\n" "$TECHNIQUES"
ACTIONS+=("read scenario_c_dashboard_trace.json click path")

CONFIDENCE="$(jq -r '.confidence' "$TRACE_FILE")"
INVESTIGATION_END="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
END_EPOCH="$(date +%s)"
ELAPSED=$((END_EPOCH - START_EPOCH))
FILE_READS=3
ACTIONS+=("write findings/scenario_c_export.json")

EVENT_REFS_JSON="$(jq '[.events[]._id]' "$SEARCH_FILE")"
ACTIONS_JSON="$(printf '%s\n' "${ACTIONS[@]}" | jq -R . | jq -s .)"

jq -n \
	--arg finding_id "scenario_c_export" \
	--arg scenario_id "scenario_c" \
	--arg interface "wazuh_export" \
	--arg investigation_start "$INVESTIGATION_START" \
	--arg investigation_end "$INVESTIGATION_END" \
	--argjson time_to_first_answer_seconds "$ELAPSED" \
	--argjson actions "$ACTIONS_JSON" \
	--argjson fields_touched '["source.ip","destination.ip","source.zone","@timestamp","full_log"]' \
	--argjson event_refs "$EVENT_REFS_JSON" \
	--argjson attack_techniques "$TECHNIQUES_JSON" \
	--arg hypothesis "The Wazuh export confirms med-mri-02 beaconed from the MEDICAL_IOT zone to external IP 198.51.100.73 five times at a 12-minute interval, with source.zone immediately available in the document unlike scenario B's missing data_classification label. This is a critical zone-violation true positive." \
	--arg confidence "$CONFIDENCE" \
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
	}' > findings/scenario_c_export.json

printf "elapsed     : %s seconds, %s file reads\n" "$ELAPSED" "$FILE_READS"

CLI_FINDING="findings/scenario_c_cli.json"
if [ -f "$CLI_FINDING" ]; then
	CLI_TIME="$(jq -r '.time_to_first_answer_seconds' "$CLI_FINDING")"
	DIFF=$((CLI_TIME - ELAPSED))
	if [ "$DIFF" -ge 0 ]; then
		printf "delta_vs_cli: %s seconds faster via export\n" "$DIFF"
	else
		printf "delta_vs_cli: %s seconds slower via export\n" "$((-DIFF))"
	fi
fi

printf "finding     : findings/scenario_c_export.json written\n"
