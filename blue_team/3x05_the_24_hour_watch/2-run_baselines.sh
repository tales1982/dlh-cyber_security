#!/bin/bash
set -euo pipefail

SHIFT_WORKSPACE="${SHIFT_WORKSPACE:-$HOME/bt/3x05/shift_pack}"
HANDOFF_DIR_DEFAULT="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_BIN="${BASELINE_BIN:-$HOME/bt/3x01/baseline/build_baseline.sh}"

fail() {
	echo "[baseline] FAIL: $1" >&2
	exit 1
}

PIPELINE_RUN_FILE="$SHIFT_WORKSPACE/runtime/pipeline_run.json"
[ -s "$PIPELINE_RUN_FILE" ] || fail "pipeline_run.json missing or empty"
PIPELINE_EXIT_STATUS="$(jq -r '.exit_status' "$PIPELINE_RUN_FILE")"
[ "$PIPELINE_EXIT_STATUS" = "0" ] || fail "pipeline exit_status was $PIPELINE_EXIT_STATUS"
printf "[baseline] pipeline check: OK\n"

ENRICHED_FILE=""
for CANDIDATE in "$SHIFT_WORKSPACE/enriched/enriched_events.jsonl" "$SHIFT_WORKSPACE/enriched/enriched_events.json"; do
	[ -s "$CANDIDATE" ] && ENRICHED_FILE="$CANDIDATE" && break
done
[ -n "$ENRICHED_FILE" ] || fail "no enriched events file found in $SHIFT_WORKSPACE/enriched/"

printf "[baseline] invoking %s\n" "$BASELINE_BIN"
printf "[baseline] input: %s\n" "$ENRICHED_FILE"
printf "[baseline] output: %s\n" "$SHIFT_WORKSPACE/enriched/baseline.json"

BASELINE_HANDOFF="$SHIFT_WORKSPACE/.baseline_handoff"
mkdir -p "$BASELINE_HANDOFF/data"
ln -sf "$ENRICHED_FILE" "$BASELINE_HANDOFF/data/enriched_events.json"

STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

set +e
HANDOFF_DIR="$BASELINE_HANDOFF" "$BASELINE_BIN" > "$SHIFT_WORKSPACE/runtime/baseline_run.log" 2>&1
BASELINE_EXIT=$?
set -e
[ "$BASELINE_EXIT" -eq 0 ] || fail "baseline script exited with status $BASELINE_EXIT — see $SHIFT_WORKSPACE/runtime/baseline_run.log"

ENDED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

BASELINE_DIR="$(dirname "$BASELINE_BIN")"
SUMMARY_FILE="$BASELINE_DIR/baseline_summary.json"
[ -s "$SUMMARY_FILE" ] || fail "baseline_summary.json missing or empty"

cp "$SUMMARY_FILE" "$SHIFT_WORKSPACE/enriched/baseline.json.summary"

HOSTS_TOTAL="$(jq '.host_inventory | length' "$SUMMARY_FILE")"
[ "$HOSTS_TOTAL" -gt 0 ] || fail "hosts_total is zero"
printf "[baseline] hosts processed: %s\n" "$HOSTS_TOTAL"

# --- collect the three anomaly files and normalize into deviation_markers ---
MARKERS_JSON="$(jq -s '
	[.[] | .[] |
		{
			host: .host,
			marker: (
				{
					"offhours_login": "off_hours_login",
					"unknown_parent_child": "unusual_parent_process",
					"unknown_destination_for_host": "unknown_destination",
					"unknown_port_for_host": "unknown_destination"
				}[.anomaly_type] // .anomaly_type
			),
			field: (
				if .anomaly_type == "unknown_account" then "user"
				elif .anomaly_type | test("process") then "process_name"
				elif .anomaly_type | test("destination|port") then "dst_ip"
				else "src_ip"
				end
			),
			observed_value: (.observed_value | tostring),
			baseline_reference: (.baseline_value | tostring),
			deviation_score: ({critical: 3.0, high: 2.0, medium: 1.0, low: 0.5}[.severity] // 1.0)
		}
	]
' "$BASELINE_DIR/anomalies_auth.json" "$BASELINE_DIR/anomalies_process.json" "$BASELINE_DIR/anomalies_network.json")"

HOSTS_WITH_DEVIATIONS="$(echo "$MARKERS_JSON" | jq '[.[].host] | unique | length')"
printf "[baseline] hosts with deviations: %s\n" "$HOSTS_WITH_DEVIATIONS"

HOT_HOSTS_JSON="$(echo "$MARKERS_JSON" | jq '
	group_by(.host) | map({host: .[0].host, total: (map(.deviation_score) | add)})
	| sort_by(-.total) | .[0:5] | map(.host)
')"
HOT_HOSTS_LIST="$(echo "$HOT_HOSTS_JSON" | jq -r 'join(" ")')"
printf "[baseline] hot hosts: %s\n" "${HOT_HOSTS_LIST:-none}"

UNSEEN_COUNT="$(echo "$MARKERS_JSON" | jq '[.[] | select(.marker=="unseen_src_ip")] | length')"
OFFHOURS_COUNT="$(echo "$MARKERS_JSON" | jq '[.[] | select(.marker=="off_hours_login")] | length')"
NEWSVC_COUNT="$(echo "$MARKERS_JSON" | jq '[.[] | select(.marker=="new_service")] | length')"
TOTAL_MARKERS="$(echo "$MARKERS_JSON" | jq 'length')"
printf "[baseline] markers: %s total (unseen_src_ip: %s  off_hours: %s  new_service: %s)\n" \
	"$TOTAL_MARKERS" "$UNSEEN_COUNT" "$OFFHOURS_COUNT" "$NEWSVC_COUNT"

jq -n \
	--arg baseline_version "1.0" \
	--argjson hosts_total "$HOSTS_TOTAL" \
	--argjson hosts_with_deviations "$HOSTS_WITH_DEVIATIONS" \
	--argjson deviation_markers "$MARKERS_JSON" \
	--argjson hot_hosts "$HOT_HOSTS_JSON" \
	--arg started_at "$STARTED_AT" \
	--arg ended_at "$ENDED_AT" \
	--argjson exit_status "$BASELINE_EXIT" \
	'{
		baseline_version: $baseline_version,
		hosts_total: $hosts_total,
		hosts_with_deviations: $hosts_with_deviations,
		deviation_markers: $deviation_markers,
		hot_hosts: $hot_hosts,
		started_at: $started_at,
		ended_at: $ended_at,
		exit_status: $exit_status
	}' > "$SHIFT_WORKSPACE/runtime/baseline_run.json"

jq '{hosts_total, hosts_with_deviations, deviation_markers, hot_hosts, generated_at: (now | strftime("%Y-%m-%dT%H:%M:%SZ"))}' \
	"$SHIFT_WORKSPACE/runtime/baseline_run.json" > "$SHIFT_WORKSPACE/enriched/baseline.json"

printf "[baseline] baseline_run.json written\n"
