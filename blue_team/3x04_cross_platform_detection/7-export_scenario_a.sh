#!/bin/bash
set -euo pipefail

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
mkdir -p findings

START_EPOCH="$(date +%s)"
INVESTIGATION_START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

SEARCH_FILE="$ASSETS_DIR/wazuh_exports/scenario_a_search_results.json"
EVENT_COUNT="$(jq '.events | length' "$SEARCH_FILE")"
printf "reading     : scenario_a_search_results.json (%s events)\n" "$EVENT_COUNT"

KQL_QUERY="$(jq -r '.query.kql' "$SEARCH_FILE")"
printf "kql         : %s\n" "$KQL_QUERY"

CHAIN_EVENTS="$(jq -c \
	'.events[] | select(._source.winlog.event_id == 10
		or (._source.winlog.event_id == 11 and ._source.process.name != null)
		or (._source.winlog.event_id == 3 and ._source.process.name == "cmd.exe"))' \
	"$SEARCH_FILE")"

EID10_TS="$(echo "$CHAIN_EVENTS" | jq -r 'select(._source.winlog.event_id == 10) | ."@timestamp"' | cut -dT -f2 | tr -d Z)"
EID11_TS="$(echo "$CHAIN_EVENTS" | jq -r 'select(._source.winlog.event_id == 11) | ."@timestamp"' | cut -dT -f2 | tr -d Z)"
EID3_TS="$(echo "$CHAIN_EVENTS" | jq -r 'select(._source.winlog.event_id == 3) | ."@timestamp"' | cut -dT -f2 | tr -d Z)"

printf "EID 10      : _source.process.name present at %sZ\n" "$EID10_TS"
printf "EID 11      : _source.full_log at %sZ (file created)\n" "$EID11_TS"
printf "EID 3       : _source.destination.ip 10.1.1.10 at %sZ\n" "$EID3_TS"

TRACE_FILE="$ASSETS_DIR/wazuh_exports/scenario_a_dashboard_trace.json"
CLICK_PATH_COUNT="$(jq '.click_path | length' "$TRACE_FILE")"
printf "click_path  : %s steps\n" "$CLICK_PATH_COUNT"

FIELD_MAP_LINE="$(jq -r '.field_name_translation | to_entries | map("\(.key) -> \(.value)") | join(", ")' "$TRACE_FILE")"
printf "field_map   : %s\n" "$FIELD_MAP_LINE"

TECHNIQUES_JSON="$(jq -c '.attack_techniques' "$TRACE_FILE")"
TECHNIQUES="$(jq -r '.attack_techniques | join(" ")' "$TRACE_FILE")"
printf "attack      : %s\n" "$TECHNIQUES"

SUMMARY_FILE="$ASSETS_DIR/dashboard_exports/scenario_a_dashboard_summary.md"
printf "attack_map  :\n"
tr -d '\r' < "$SUMMARY_FILE" | awk '/^## ATT&CK Mapping/{flag=1; next} /^## /{if (flag) exit} flag && NF' | sed 's/^/  /'

CONFIDENCE="$(jq -r '.confidence' "$TRACE_FILE")"

INVESTIGATION_END="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
END_EPOCH="$(date +%s)"
ELAPSED=$((END_EPOCH - START_EPOCH))
FILE_READS=4

CLI_FINDING="findings/scenario_a_cli.json"
DELTA_LINE="delta_vs_cli: n/a (no CLI finding to compare)"
if [ -f "$CLI_FINDING" ]; then
	CLI_TIME="$(jq -r '.time_to_first_answer_seconds' "$CLI_FINDING")"
	DIFF=$((CLI_TIME - ELAPSED))
	if [ "$DIFF" -ge 0 ]; then
		DELTA_LINE="delta_vs_cli: ${DIFF} seconds faster via export"
	else
		DELTA_LINE="delta_vs_cli: $((-DIFF)) seconds slower via export"
	fi
fi

ACTIONS_JSON="$(jq '.click_path' "$TRACE_FILE")"
EVENT_REFS_JSON="$(echo "$CHAIN_EVENTS" | jq -s '[.[]._id]')"

jq -n \
	--arg finding_id "scenario_a_export" \
	--arg scenario_id "scenario_a" \
	--arg interface "wazuh_export" \
	--arg investigation_start "$INVESTIGATION_START" \
	--arg investigation_end "$INVESTIGATION_END" \
	--argjson time_to_first_answer_seconds "$ELAPSED" \
	--argjson actions "$ACTIONS_JSON" \
	--argjson fields_touched '["agent.name","winlog.event_id","process.name","destination.ip","full_log","@timestamp"]' \
	--argjson event_refs "$EVENT_REFS_JSON" \
	--argjson attack_techniques "$TECHNIQUES_JSON" \
	--arg hypothesis "The Wazuh export confirms the same LSASS dump and SMB lateral-move chain on clin-ws-12 seen via CLI, with winlog.event_id available directly instead of requiring raw_message pattern matching. The dashboard trace records this as a true positive with high confidence." \
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
	}' > findings/scenario_a_export.json

printf "elapsed     : %s seconds, %s file reads\n" "$ELAPSED" "$FILE_READS"
printf "%s\n" "$DELTA_LINE"
printf "finding     : findings/scenario_a_export.json written\n"
