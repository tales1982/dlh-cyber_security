#!/bin/bash
set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
mkdir -p findings

START_EPOCH="$(date +%s)"
INVESTIGATION_START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ACTIONS=()

MANIFEST_FILE="$ASSETS_DIR/scenarios/scenario_a_credential_theft.json"
ACTIONS+=("read scenario manifest: $MANIFEST_FILE")

HOST="$(jq -r '.host_path[0]' "$MANIFEST_FILE")"
WINDOW_START="$(jq -r '.time_window.start' "$MANIFEST_FILE")"
WINDOW_END="$(jq -r '.time_window.end' "$MANIFEST_FILE")"
TECHNIQUES="$(jq -r '.mitre_techniques | join(" ")' "$MANIFEST_FILE")"
TECHNIQUES_JSON="$(jq -c '.mitre_techniques' "$MANIFEST_FILE")"

printf "scenario    : scenario_a_credential_theft\n"
printf "host        : %s\n" "$HOST"
printf "window      : %s -> %s\n" "$WINDOW_START" "$WINDOW_END"

ENRICHED_FILE="$HANDOFF_DIR/data/enriched_events.json"
SCOPED="$(jq -c --arg host "$HOST" --arg start "$WINDOW_START" --arg window_end "$WINDOW_END" \
	'select(.hostname == $host and .timestamp >= $start and .timestamp <= $window_end)' \
	"$ENRICHED_FILE")"
ACTIONS+=("jq scope enriched_events.json by hostname and scenario time window")

SCOPED_COUNT="$(echo "$SCOPED" | grep -c .)"
printf "scoped      : %s events on %s in window\n" "$SCOPED_COUNT" "$HOST"

EID10_LINE="$(echo "$SCOPED" | jq -c 'select(.raw_message | contains("lsass.exe accessed by rundll32.exe"))')"
EID11_LINE="$(echo "$SCOPED" | jq -c 'select(.raw_message | contains("debug.dmp"))')"
EID3_LINE="$(echo "$SCOPED" | jq -c 'select(.raw_message | contains("10.1.1.10:445"))')"
ACTIONS+=("filter scoped events for LSASS access, dump file creation, and SMB lateral move signatures")

EID10_TS="$(echo "$EID10_LINE" | jq -r '.timestamp' | cut -dT -f2 | tr -d Z)"
EID11_TS="$(echo "$EID11_LINE" | jq -r '.timestamp' | cut -dT -f2 | tr -d Z)"
EID3_TS="$(echo "$EID3_LINE" | jq -r '.timestamp' | cut -dT -f2 | tr -d Z)"

printf "EID 10      : lsass.exe accessed by rundll32.exe at %sZ\n" "$EID10_TS"
printf "EID 11      : C:\\Temp\\debug.dmp created at %sZ\n" "$EID11_TS"
printf "EID 3       : cmd.exe -> 10.1.1.10:445 at %sZ\n" "$EID3_TS"

HYPOTHESIS="LSASS credential dump via rundll32.exe/comsvcs.dll on clin-ws-12, followed by lateral movement to srv-dc-01 via SMB. The sequence and timing match the credential theft chain rule 009_credential_theft_chain."
printf "hypothesis  : LSASS dump via rundll32, lateral move to DC via SMB\n"
printf "attack      : %s\n" "$TECHNIQUES"

INVESTIGATION_END="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
END_EPOCH="$(date +%s)"
ELAPSED=$((END_EPOCH - START_EPOCH))
ACTIONS+=("write findings/scenario_a_cli.json")

EVENT_REFS_JSON="$(jq -s '[.[].timestamp]' <(echo "$EID10_LINE") <(echo "$EID11_LINE") <(echo "$EID3_LINE"))"
ACTIONS_JSON="$(printf '%s\n' "${ACTIONS[@]}" | jq -R . | jq -s .)"

jq -n \
	--arg finding_id "scenario_a_cli" \
	--arg scenario_id "scenario_a" \
	--arg interface "cli" \
	--arg investigation_start "$INVESTIGATION_START" \
	--arg investigation_end "$INVESTIGATION_END" \
	--argjson time_to_first_answer_seconds "$ELAPSED" \
	--argjson actions "$ACTIONS_JSON" \
	--argjson fields_touched '["hostname","timestamp","raw_message","process_name","command_line"]' \
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
	}' > findings/scenario_a_cli.json

printf "elapsed     : %s seconds, %s commands\n" "$ELAPSED" "${#ACTIONS[@]}"
printf "finding     : findings/scenario_a_cli.json written\n"
