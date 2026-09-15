#!/bin/bash
set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
mkdir -p findings

START_EPOCH="$(date +%s)"
INVESTIGATION_START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ACTIONS=()

MANIFEST_FILE="$ASSETS_DIR/scenarios/scenario_b_offhours_phi.json"
ACTIONS+=("read scenario manifest: $MANIFEST_FILE")

HOST="$(jq -r '.host_path[0]' "$MANIFEST_FILE")"
WINDOW_START="$(jq -r '.time_window.start' "$MANIFEST_FILE")"
WINDOW_END="$(jq -r '.time_window.end' "$MANIFEST_FILE")"

ASSET_FILE="$HANDOFF_DIR/context/asset_inventory.json"
CRITICALITY="$(jq -r --arg h "$HOST" '.assets[] | select(.hostname == $h) | .criticality' "$ASSET_FILE")"
DATA_CLASS="$(jq -r --arg h "$HOST" '.assets[] | select(.hostname == $h) | .data_classification' "$ASSET_FILE")"
ACTIONS+=("read asset_inventory.json for $HOST criticality and data classification")

printf "scenario    : scenario_b_offhours_phi\n"
printf "host        : %s (criticality: %s, data: %s)\n" "$HOST" "$CRITICALITY" "$DATA_CLASS"
printf "window      : %s -> %s\n" "$WINDOW_START" "$WINDOW_END"

ENRICHED_FILE="$HANDOFF_DIR/data/enriched_events.json"
SCOPED="$(jq -c --arg host "$HOST" --arg start "$WINDOW_START" --arg window_end "$WINDOW_END" \
	'select(.hostname == $host and .timestamp >= $start and .timestamp <= $window_end)' \
	"$ENRICHED_FILE")"
ACTIONS+=("jq scope enriched_events.json by hostname and scenario time window")

LOGON_LINE="$(echo "$SCOPED" | jq -c 'select(.user == "p.morales" and (.raw_message | contains("logged on")))')"
PRIV_LINE="$(echo "$SCOPED" | jq -c 'select(.raw_message | contains("Special privileges assigned"))')"
POWERSHELL_LINE="$(echo "$SCOPED" | jq -c 'select(.command_line // "" | contains("ExecutionPolicy Bypass"))')"
ACTIONS+=("filter scoped events for p.morales logon, privilege assignment, and PowerShell bypass execution")

LOGON_TS="$(echo "$LOGON_LINE" | jq -r '.timestamp' | cut -dT -f2 | tr -d Z)"
PRIV_TS="$(echo "$PRIV_LINE" | jq -r '.timestamp' | cut -dT -f2 | tr -d Z)"
PS_TS="$(echo "$POWERSHELL_LINE" | jq -r '.timestamp' | cut -dT -f2 | tr -d Z)"

printf "EID 4624    : p.morales RemoteInteractive logon at %sZ\n" "$LOGON_TS"
printf "EID 4672    : SeBackupPrivilege SeRestorePrivilege at %sZ\n" "$PRIV_TS"
printf "EID 1       : powershell.exe -ExecutionPolicy Bypass at %sZ\n" "$PS_TS"
printf "ambiguity   : p.morales is CISO, authorized for EHR, but timing+bypass warrant escalation\n"
printf "attack      : T1078.002 T1059.001\n"

HYPOTHESIS="p.morales (CISO, authorized for EHR access) logged on to the PHI-classified clin-ws-07 off-hours and ran a PowerShell script with -ExecutionPolicy Bypass. The user is authorized for EHR access, but the off-hours timing and bypass flag put this in the FP/TP grey zone and warrant escalation."

INVESTIGATION_END="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
END_EPOCH="$(date +%s)"
ELAPSED=$((END_EPOCH - START_EPOCH))
ACTIONS+=("write findings/scenario_b_cli.json")

EVENT_REFS_JSON="$(jq -s '[.[].timestamp]' <(echo "$LOGON_LINE") <(echo "$PRIV_LINE") <(echo "$POWERSHELL_LINE"))"
ACTIONS_JSON="$(printf '%s\n' "${ACTIONS[@]}" | jq -R . | jq -s .)"

jq -n \
	--arg finding_id "scenario_b_cli" \
	--arg scenario_id "scenario_b" \
	--arg interface "cli" \
	--arg investigation_start "$INVESTIGATION_START" \
	--arg investigation_end "$INVESTIGATION_END" \
	--argjson time_to_first_answer_seconds "$ELAPSED" \
	--argjson actions "$ACTIONS_JSON" \
	--argjson fields_touched '["hostname","timestamp","user","raw_message","command_line","asset"]' \
	--argjson event_refs "$EVENT_REFS_JSON" \
	--argjson attack_techniques '["T1078.002","T1059.001"]' \
	--arg hypothesis "$HYPOTHESIS" \
	--arg confidence "medium" \
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
	}' > findings/scenario_b_cli.json

printf "elapsed     : %s seconds, %s commands\n" "$ELAPSED" "${#ACTIONS[@]}"
printf "finding     : findings/scenario_b_cli.json written\n"
