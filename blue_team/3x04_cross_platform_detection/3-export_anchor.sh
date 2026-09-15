#!/bin/bash
set -euo pipefail

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
mkdir -p findings

START_EPOCH="$(date +%s)"
INVESTIGATION_START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

SEARCH_FILE="$ASSETS_DIR/wazuh_exports/anchor_search_results.json"
printf "reading     : %s\n" "$SEARCH_FILE"

HITS_TOTAL="$(jq -r '.hits_total' "$SEARCH_FILE")"
KQL_QUERY="$(jq -r '.query.kql' "$SEARCH_FILE")"

FIRST_EVENT="$(jq -r '[.events[]."@timestamp"] | sort | first' "$SEARCH_FILE")"
LAST_EVENT="$(jq -r '[.events[]."@timestamp"] | sort | last' "$SEARCH_FILE")"

printf "hits_total  : %s\n" "$HITS_TOTAL"
printf "kql_query   : %s\n" "$KQL_QUERY"
printf "first event : %s\n" "$FIRST_EVENT"
printf "last event  : %s\n" "$LAST_EVENT"

MAP_FILE="$ASSETS_DIR/wazuh_exports/field_mapping.json"
FIELD_NAMES=(src_ip hostname user event_ref raw_message)
printf "field map   : "
FIRST_LINE=1
for FIELD in "${FIELD_NAMES[@]}"; do
	WAZUH_FIELD="$(jq -r --arg n "$FIELD" '.mappings[] | select(.normalized == $n) | .wazuh' "$MAP_FILE")"
	if [ "$FIRST_LINE" -eq 1 ]; then
		printf "%-14s-> %s\n" "$FIELD" "$WAZUH_FIELD"
		FIRST_LINE=0
	else
		printf "              %-14s-> %s\n" "$FIELD" "$WAZUH_FIELD"
	fi
done

TRACE_FILE="$ASSETS_DIR/wazuh_exports/anchor_dashboard_trace.json"
CLICK_PATH_COUNT="$(jq '.click_path | length' "$TRACE_FILE")"
ESTIMATED_TIME="$(jq -r '.estimated_time_seconds' "$TRACE_FILE")"
printf "click_path  : %s steps loaded from dashboard_trace\n" "$CLICK_PATH_COUNT"

INVESTIGATION_END="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
END_EPOCH="$(date +%s)"
ELAPSED=$((END_EPOCH - START_EPOCH))
FILE_READS=4

ACTIONS_JSON="$(jq '.click_path' "$TRACE_FILE")"
EVENT_REFS_JSON="$(jq '[.events[]._id]' "$SEARCH_FILE")"
ATTACK_TECHNIQUES_JSON="$(jq '.attack_techniques' "$TRACE_FILE")"
CONFIDENCE="$(jq -r '.confidence' "$TRACE_FILE")"

jq -n \
	--arg finding_id "anchor_export" \
	--arg scenario_id "anchor" \
	--arg interface "wazuh_export" \
	--arg investigation_start "$INVESTIGATION_START" \
	--arg investigation_end "$INVESTIGATION_END" \
	--argjson time_to_first_answer_seconds "$ELAPSED" \
	--argjson actions "$ACTIONS_JSON" \
	--argjson fields_touched '["@timestamp","_id","source.ip","destination.ip","agent.name","user.name","full_log"]' \
	--argjson event_refs "$EVENT_REFS_JSON" \
	--argjson attack_techniques "$ATTACK_TECHNIQUES_JSON" \
	--arg hypothesis "The Wazuh export's firewall-side documents corroborate the same SSH brute force cluster against db-patient-01 seen in the CLI investigation. The dashboard trace records this as a true positive with high confidence." \
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
	}' > findings/anchor_export.json

printf "elapsed     : %s seconds, %s file reads\n" "$ELAPSED" "$FILE_READS"
printf "finding     : findings/anchor_export.json written\n"
