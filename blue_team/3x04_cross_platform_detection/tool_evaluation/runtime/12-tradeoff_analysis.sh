#!/bin/bash
set -euo pipefail

mkdir -p comparison

SCENARIOS=(anchor scenario_a scenario_b scenario_c)

# Cause attribution is an analyst judgment call grounded in what each
# investigation actually hit (see findings/*.json hypotheses), not something
# derivable from the timing numbers alone.
declare -A CAUSES=(
	[anchor]="native_field_surface"
	[scenario_a]="native_field_surface"
	[scenario_b]="context_join_ergonomics"
	[scenario_c]="native_field_surface"
)

ROWS_JSON="[]"
EXPORT_WINS=0
CLI_WINS=0

for SCENARIO in "${SCENARIOS[@]}"; do
	CLI_FILE="findings/${SCENARIO}_cli.json"
	EXPORT_FILE="findings/${SCENARIO}_export.json"

	CLI_TIME="$(jq -r '.time_to_first_answer_seconds' "$CLI_FILE")"
	EXPORT_TIME="$(jq -r '.time_to_first_answer_seconds' "$EXPORT_FILE")"
	CLI_ACTIONS="$(jq '.actions | length' "$CLI_FILE")"
	EXPORT_ACTIONS="$(jq '.actions | length' "$EXPORT_FILE")"

	TIME_DELTA=$((CLI_TIME - EXPORT_TIME))
	if [ "$TIME_DELTA" -gt 0 ]; then
		FASTER="wazuh_export"
		EXPORT_WINS=$((EXPORT_WINS + 1))
	elif [ "$TIME_DELTA" -lt 0 ]; then
		FASTER="cli"
		CLI_WINS=$((CLI_WINS + 1))
	else
		FASTER="tie"
	fi

	CAUSE="${CAUSES[$SCENARIO]}"

	ROW_JSON="$(jq -n \
		--arg scenario_id "$SCENARIO" \
		--argjson cli_seconds "$CLI_TIME" \
		--argjson export_seconds "$EXPORT_TIME" \
		--argjson time_delta_seconds "$TIME_DELTA" \
		--argjson cli_actions "$CLI_ACTIONS" \
		--argjson export_actions "$EXPORT_ACTIONS" \
		--arg faster_interface "$FASTER" \
		--arg cause "$CAUSE" \
		'{scenario_id: $scenario_id, cli_seconds: $cli_seconds, export_seconds: $export_seconds, time_delta_seconds: $time_delta_seconds, cli_actions: $cli_actions, export_actions: $export_actions, faster_interface: $faster_interface, cause: $cause}')"

	ROWS_JSON="$(echo "$ROWS_JSON" | jq --argjson row "$ROW_JSON" '. + [$row]')"
done

echo "$ROWS_JSON" > comparison/tradeoff_table.json

{
	echo "# Cross-Platform Trade-off Table"
	echo
	echo "| Scenario | CLI (s) | Export (s) | Delta (s) | Faster | Cause |"
	echo "|---|---|---|---|---|---|"
	echo "$ROWS_JSON" | jq -r '.[] | "| \(.scenario_id) | \(.cli_seconds) | \(.export_seconds) | \(.time_delta_seconds) | \(.faster_interface) | \(.cause) |"'
} > comparison/tradeoff_table.md

printf "scenarios analyzed   : %s (anchor + 3)\n" "${#SCENARIOS[@]}"
printf "export advantages    : %s\n" "$EXPORT_WINS"
printf "cli advantages       : %s\n" "$CLI_WINS"
printf "comparison/tradeoff_table.json written\n"
printf "comparison/tradeoff_table.md written\n"
