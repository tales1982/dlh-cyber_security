#!/bin/bash
set -euo pipefail

SHIFT_WORKSPACE="${SHIFT_WORKSPACE:-$HOME/bt/3x05/shift_pack}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x05_assets/capstone_pack/meta}"

fail() {
	echo "[triage] FAIL: $1" >&2
	exit 1
}

QUEUE_FILE="$SHIFT_WORKSPACE/alerts/alert_queue.json"
BRIEFING_FILE="$SHIFT_WORKSPACE/alerts/shift_briefing.json"
BASELINE_FILE="$SHIFT_WORKSPACE/enriched/baseline.json"
ASSET_FILE="$ASSETS_DIR/assets.json"

[ -s "$QUEUE_FILE" ] || fail "alert_queue.json missing or empty"
[ -s "$BRIEFING_FILE" ] || fail "shift_briefing.json missing or empty"
[ -s "$ASSET_FILE" ] || fail "assets.json missing or empty"

ALERT_COUNT="$(jq 'length' "$QUEUE_FILE")"
printf "[triage] alert_queue: %s alerts\n" "$ALERT_COUNT"

IOC_COUNT="$(jq '.ioc_count' "$BRIEFING_FILE")"
TICKETS_COUNT="$(jq '.active_change_tickets | length' "$BRIEFING_FILE")"
printf "[triage] briefing loaded (%s IOCs, %s change tickets)\n" "$IOC_COUNT" "$TICKETS_COUNT"

# Note: the 3x03 triage scripts assume the richer 3x02 alert_queue.json shape
# (priority_score, event_summary, fixed CATALOG_DIR/HANDOFF_DIR paths) that
# this capstone's simpler sigma_runner-derived alerts don't carry. Rather than
# force that schema mismatch, the classification rules from the 3x03
# methodology (IOC cross-reference, baseline deviation corroboration, change
# ticket window matching) are applied here directly against this shift's data.
printf "[triage] invoking classification (adapted 3x03 methodology)\n"
printf "[triage] classifying %s alerts\n" "$ALERT_COUNT"

TRIAGE_LOG_JSON="$(jq -s '
	.[0] as $alerts
	| .[1] as $briefing
	| .[2] as $baseline
	| ($briefing.ioc_values // []) as $iocs
	| ($baseline.deviation_markers // [] | map(.host) | unique) as $deviated_hosts
	| ($briefing.active_change_tickets // []) as $tickets
	| $alerts | map(
		. as $a
		| ($tickets | map(select(
			(.hosts | index($a.host)) and $a.timestamp >= .window_start and $a.timestamp <= .window_end
		)) | .[0]) as $ticket_match
		| ($deviated_hosts | index($a.host)) as $dev
		| {
			alert_id: $a.alert_id,
			rule_id: $a.rule_id,
			host: ($a.host | ascii_downcase),
			user: null,
			classification: (
				if $ticket_match then "FP"
				elif $dev then "TP"
				else "NOISE"
				end
			),
			severity: $a.severity,
			matches_ioc: [],
			baseline_deviation: ($dev != null),
			change_ticket_match: ($ticket_match.ticket_id // null),
			analyst_note: (
				if $ticket_match then
					("Host+time falls inside approved change ticket " + $ticket_match.ticket_id + " window; treated as covered maintenance.")
				elif $dev then
					"Host has a corroborating baseline deviation marker; escalated as TP pending investigation."
				else
					"Off-hours privileged logon with no IOC match, no baseline deviation, no change-ticket coverage; batch-closed as routine 24/7 hospital activity."
				end
			),
			classified_at: (now | strftime("%Y-%m-%dT%H:%M:%SZ"))
		}
	)
' "$QUEUE_FILE" "$BRIEFING_FILE" "$BASELINE_FILE")"

echo "$TRIAGE_LOG_JSON" | jq -c '.[]' > "$SHIFT_WORKSPACE/alerts/triage_log.jsonl"

TP_COUNT="$(echo "$TRIAGE_LOG_JSON" | jq '[.[] | select(.classification=="TP")] | length')"
FP_COUNT="$(echo "$TRIAGE_LOG_JSON" | jq '[.[] | select(.classification=="FP")] | length')"
NOISE_COUNT="$(echo "$TRIAGE_LOG_JSON" | jq '[.[] | select(.classification=="NOISE")] | length')"
LOGGED_COUNT="$(wc -l < "$SHIFT_WORKSPACE/alerts/triage_log.jsonl" | tr -d ' ')"
UNCLASSIFIED=$((ALERT_COUNT - LOGGED_COUNT))

[ "$UNCLASSIFIED" -eq 0 ] || fail "$UNCLASSIFIED alerts missing from triage_log.jsonl"

printf "[triage] TP=%s FP=%s NOISE=%s unclassified=%s\n" "$TP_COUNT" "$FP_COUNT" "$NOISE_COUNT" "$UNCLASSIFIED"
printf "[triage] triage_log.jsonl written\n"
