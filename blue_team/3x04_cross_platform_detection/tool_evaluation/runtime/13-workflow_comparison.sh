#!/bin/bash
set -euo pipefail

mkdir -p comparison

FINDINGS_COUNT="$(ls findings/*.json | wc -l)"
CLI_COUNT="$(ls findings/*_cli.json | wc -l)"
EXPORT_COUNT="$(ls findings/*_export.json | wc -l)"
printf "findings loaded       : %s (%s cli + %s wazuh_export)\n" "$FINDINGS_COUNT" "$CLI_COUNT" "$EXPORT_COUNT"

RESULT_JSON="$(jq -s '
	def median(arr):
		(arr | sort) as $s
		| ($s | length) as $n
		| if $n == 0 then null
		  elif ($n % 2 == 1) then $s[($n - 1) / 2]
		  else ($s[$n/2 - 1] + $s[$n/2]) / 2
		  end;

	def interface_stats:
		{
			interface: .[0].interface,
			total_seconds: (map(.time_to_first_answer_seconds) | add),
			avg_seconds: ((map(.time_to_first_answer_seconds) | add) / length),
			median_seconds: median(map(.time_to_first_answer_seconds)),
			total_actions: (map(.actions | length) | add),
			avg_actions: ((map(.actions | length) | add) / length),
			total_fields_touched: (map(.fields_touched | length) | add),
			avg_fields_touched: ((map(.fields_touched | length) | add) / length),
			total_event_refs: (map(.event_refs | length) | add),
			avg_event_refs: ((map(.event_refs | length) | add) / length)
		};

	def confidence_counts:
		{
			interface: .[0].interface,
			high: (map(select(.confidence == "high")) | length),
			medium: (map(select(.confidence == "medium")) | length),
			low: (map(select(.confidence == "low")) | length)
		};

	(group_by(.interface) | map(interface_stats) | map({(.interface): .}) | add) as $per_iface
	| (group_by(.interface) | map(confidence_counts) | map({(.interface): .}) | add) as $conf
	| (group_by(.scenario_id) | map({
		scenario_id: .[0].scenario_id,
		cli_seconds: (map(select(.interface == "cli")) | .[0].time_to_first_answer_seconds),
		export_seconds: (map(select(.interface == "wazuh_export")) | .[0].time_to_first_answer_seconds)
	  } | . + {
		delta_seconds: (.export_seconds - .cli_seconds),
		faster: (if (.export_seconds - .cli_seconds) < 0 then "wazuh_export" elif (.export_seconds - .cli_seconds) > 0 then "cli" else "tie" end)
	  })) as $per_scenario
	| {
		per_interface: $per_iface,
		per_scenario: $per_scenario,
		confidence_distribution: $conf,
		generated_at: (now | strftime("%Y-%m-%dT%H:%M:%SZ"))
	}
' findings/*.json)"

echo "$RESULT_JSON" > comparison/workflow_comparison.json

echo "per interface totals:"
echo "$RESULT_JSON" | jq -r 'def pad(s): s + (" " * ([13 - (s | length), 1] | max)); .per_interface | to_entries[] | "  \(pad(.key)): \(.value.total_seconds)s total, avg \(.value.avg_seconds | floor)s, median \(.value.median_seconds)s, \(.value.total_actions) actions"'

echo "per interface confidence:"
echo "$RESULT_JSON" | jq -r 'def pad(s): s + (" " * ([13 - (s | length), 1] | max)); .confidence_distribution | to_entries[] | "  \(pad(.key)): high=\(.value.high) medium=\(.value.medium) low=\(.value.low)"'

echo "per scenario deltas (wazuh_export - cli):"
echo "$RESULT_JSON" | jq -r 'def pad(s): s + (" " * ([13 - (s | length), 1] | max)); .per_scenario[] | "  \(pad(.scenario_id)): \(if .delta_seconds >= 0 then "+" else "" end)\(.delta_seconds)s (\(.faster) faster)"'

printf "comparison/workflow_comparison.json written\n"
