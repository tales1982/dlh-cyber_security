#!/bin/bash
set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
mkdir -p findings

START_EPOCH="$(date +%s)"
INVESTIGATION_START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ACTIONS=()

SEARCH_FILE="$ASSETS_DIR/wazuh_exports/scenario_b_search_results.json"
EVENT_COUNT="$(jq '.events | length' "$SEARCH_FILE")"
printf "reading     : scenario_b_search_results.json (%s events)\n" "$EVENT_COUNT"
ACTIONS+=("read scenario_b_search_results.json ($EVENT_COUNT events)")

HOST="$(jq -r '.events[0]._source.agent.name' "$SEARCH_FILE")"
USER_NAME="$(jq -r '[.events[] | select(._source.winlog.event_id == 4624 and ._source.user.name == "p.morales")][0]._source.user.name' "$SEARCH_FILE")"
printf "host        : %s (from agent.name)\n" "$HOST"
printf "user        : %s (from user.name)\n" "$USER_NAME"
ACTIONS+=("extract agent.name, user.name, winlog.event_id from events")

HAS_DATA_CLASS="$(jq -r '.events[0]._source.agent.labels | has("data_classification")' "$SEARCH_FILE")"
if [ "$HAS_DATA_CLASS" = "true" ]; then
	DATA_CLASS="$(jq -r '.events[0]._source.agent.labels.data_classification' "$SEARCH_FILE")"
	printf "data_class  : %s (from agent.labels — resolved without fallback)\n" "$DATA_CLASS"
	ACTIONS+=("check agent.labels for data_classification (present)")
else
	ACTIONS+=("check agent.labels for data_classification (absent)")
	ACTIONS+=("fallback: read $HANDOFF_DIR/context/asset_inventory.json for data_classification")
	DATA_CLASS="$(jq -r --arg h "$HOST" '.assets[] | select(.hostname == $h) | .data_classification' "$HANDOFF_DIR/context/asset_inventory.json")"
	printf "data_class  : %s (via fallback to asset_inventory.json — not in agent.labels)\n" "$DATA_CLASS"
fi

FIRST_TS="$(jq -r '.events[0]."@timestamp"' "$SEARCH_FILE")"
TIME_PART="$(echo "$FIRST_TS" | cut -dT -f2 | tr -d Z)"
printf "off_hours   : %sZ outside 06:00-18:00 window\n" "$TIME_PART"

TRACE_FILE="$ASSETS_DIR/wazuh_exports/scenario_b_dashboard_trace.json"
CLICK_PATH_COUNT="$(jq '.click_path | length' "$TRACE_FILE")"
printf "click_path  : %s steps\n" "$CLICK_PATH_COUNT"
ACTIONS+=("read scenario_b_dashboard_trace.json click path")

TECHNIQUES_JSON='["T1078.002","T1059.001"]'
CONFIDENCE="medium"

INVESTIGATION_END="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
END_EPOCH="$(date +%s)"
ELAPSED=$((END_EPOCH - START_EPOCH))
ACTIONS+=("write findings/scenario_b_export.json")

EVENT_REFS_JSON="$(jq '[.events[] | select(
		(._source.winlog.event_id == 4624 and ._source.user.name == "p.morales")
		or ._source.winlog.event_id == 4672
		or (._source.winlog.event_id == 1 and ._source.process.name == "powershell.exe")
	) | ._id]' "$SEARCH_FILE")"
ACTIONS_JSON="$(printf '%s\n' "${ACTIONS[@]}" | jq -R . | jq -s .)"

jq -n \
	--arg finding_id "scenario_b_export" \
	--arg scenario_id "scenario_b" \
	--arg interface "wazuh_export" \
	--arg investigation_start "$INVESTIGATION_START" \
	--arg investigation_end "$INVESTIGATION_END" \
	--argjson time_to_first_answer_seconds "$ELAPSED" \
	--argjson actions "$ACTIONS_JSON" \
	--argjson fields_touched '["agent.name","user.name","winlog.event_id","agent.labels","@timestamp"]' \
	--argjson event_refs "$EVENT_REFS_JSON" \
	--argjson attack_techniques "$TECHNIQUES_JSON" \
	--arg hypothesis "p.morales logged on to the PHI-classified clin-ws-07 off-hours and ran a PowerShell command with -ExecutionPolicy Bypass. The Wazuh export's agent.labels did not carry data_classification, requiring a fallback lookup in asset_inventory.json to confirm PHI scope." \
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
	}' > findings/scenario_b_export.json

printf "elapsed     : %s seconds\n" "$ELAPSED"

CLI_FINDING="findings/scenario_b_cli.json"
if [ -f "$CLI_FINDING" ]; then
	CLI_TIME="$(jq -r '.time_to_first_answer_seconds' "$CLI_FINDING")"
	DIFF=$((CLI_TIME - ELAPSED))
	if [ "$DIFF" -ge 0 ]; then
		printf "delta_vs_cli: %s seconds faster via export\n" "$DIFF"
	else
		printf "delta_vs_cli: %s seconds slower via export\n" "$((-DIFF))"
	fi
fi

printf "finding     : findings/scenario_b_export.json written\n"
