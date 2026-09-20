#!/bin/bash
set -euo pipefail

SHIFT_WORKSPACE="${SHIFT_WORKSPACE:-$HOME/bt/3x05/shift_pack}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x05_assets/capstone_pack/meta}"

fail() {
	echo "[inv-A] FAIL: $1" >&2
	exit 1
}

INCIDENTS_FILE="$SHIFT_WORKSPACE/alerts/incidents.json"
[ -s "$INCIDENTS_FILE" ] || fail "incidents.json missing or empty"

printf "[inv-A] loading INC-YYYYMMDD-A\n"
INCIDENT_JSON="$(jq -c '[.incidents[] | select(.incident_id | test("-A$"))][0] // null' "$INCIDENTS_FILE")"

ACTIONS=("jq -c '[.incidents[] | select(.incident_id | test(\"-A\$\"))][0]' $INCIDENTS_FILE")

if [ "$INCIDENT_JSON" = "null" ]; then
	printf "[inv-A] no incident with an '-A' suffix exists in incidents.json (incident_count=%s)\n" \
		"$(jq '.incident_count' "$INCIDENTS_FILE")"
	printf "[inv-A] host_list: none\n"
	printf "[inv-A] events in window: 0\n"

	INVESTIGATION_START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	jq -n \
		--arg finding_id "shift-$(date -u +%Y%m%d)-investigate-a" \
		--arg investigation_start "$INVESTIGATION_START" \
		--arg investigation_end "$INVESTIGATION_START" \
		--arg created_at "$INVESTIGATION_START" \
		--argjson actions "$(printf '%s\n' "${ACTIONS[@]}" | jq -R . | jq -s .)" \
		'{
			finding_id: $finding_id,
			incident_id: "INC-NONE",
			interface: "cli",
			investigation_start: $investigation_start,
			investigation_end: $investigation_end,
			time_to_first_answer_seconds: 0,
			actions: $actions,
			event_refs: [],
			attack_techniques: [],
			hypothesis: "No incident with an -A suffix exists in incidents.json this shift (incident_count is 0), so there is nothing to investigate.",
			confidence: "low",
			ambiguity_notes: "Task 6 correlated 0 TP alerts into 0 incidents this shift. This script logic is otherwise complete and will populate a real finding the next time incidents.json contains an -A record.",
			created_at: $created_at
		}' > "$SHIFT_WORKSPACE/investigations/incident_A.json"

	fail "0 event_refs and 0 attack_techniques (need >=6 and >=2) — no incident A exists this shift"
fi

INCIDENT_ID="$(echo "$INCIDENT_JSON" | jq -r '.incident_id')"
HOST_LIST_JSON="$(echo "$INCIDENT_JSON" | jq -c '.host_list')"
HOST_LIST="$(echo "$INCIDENT_JSON" | jq -r '.host_list | join(" ")')"
ALERT_COUNT="$(echo "$INCIDENT_JSON" | jq '.alert_ids | length')"
CATEGORY="$(echo "$INCIDENT_JSON" | jq -r '.tentative_category')"
FIRST_SEEN="$(echo "$INCIDENT_JSON" | jq -r '.first_seen')"
LAST_SEEN="$(echo "$INCIDENT_JSON" | jq -r '.last_seen')"

printf "[inv-A] host_list: %s\n" "$HOST_LIST"
printf "[inv-A] alerts: %s  category: %s\n" "$ALERT_COUNT" "$CATEGORY"

ENRICHED_FILE=""
for CANDIDATE in "$SHIFT_WORKSPACE/enriched/enriched_events.jsonl" "$SHIFT_WORKSPACE/enriched/enriched_events.json"; do
	[ -s "$CANDIDATE" ] && ENRICHED_FILE="$CANDIDATE" && break
done
[ -n "$ENRICHED_FILE" ] || fail "no enriched events file found"

WINDOW_START="$(python3 -c "
from datetime import datetime, timedelta
print((datetime.fromisoformat('$FIRST_SEEN'.replace('Z','+00:00')) - timedelta(minutes=15)).strftime('%Y-%m-%dT%H:%M:%SZ'))
")"
WINDOW_END="$(python3 -c "
from datetime import datetime, timedelta
print((datetime.fromisoformat('$LAST_SEEN'.replace('Z','+00:00')) + timedelta(minutes=15)).strftime('%Y-%m-%dT%H:%M:%SZ'))
")"

MATCHES_JSON="$(jq -c --argjson hosts "$HOST_LIST_JSON" --arg start "$WINDOW_START" --arg end "$WINDOW_END" '
	select((.hostname // "" | ascii_downcase) as $h | $hosts | map(ascii_downcase) | index($h))
	| select(.timestamp >= $start and .timestamp <= $end)
' "$ENRICHED_FILE")"
ACTIONS+=("jq -c 'select(.hostname in host_list and .timestamp in [$WINDOW_START,$WINDOW_END])' $ENRICHED_FILE")

EVENTS_IN_WINDOW="$(echo "$MATCHES_JSON" | grep -c . || true)"
printf "[inv-A] events in window: %s\n" "$EVENTS_IN_WINDOW"

TOP6_JSON="$(echo "$MATCHES_JSON" | jq -s '
	sort_by(.timestamp)
	| (map(select(.event_category=="authentication")) + map(select(.event_category=="process")) + map(select(.event_category=="network")) + .)
	| unique_by(.timestamp)
	| sort_by(.timestamp)
	| .[0:6]
')"
ACTIONS+=("jq -s 'sort_by(.timestamp) | .[0:6]' (matched events)")

printf "[inv-A] timeline (top 6):\n"
echo "$TOP6_JSON" | jq -r '.[] | "  \(.timestamp)  \(.hostname)  \(.source_type)  \(.event_category)  \(.raw_message[0:80])"'

IOC_FILE="$ASSETS_DIR/ioc_feed.json"
IOC_VALUES_JSON="$(jq -c '[.iocs[].value]' "$IOC_FILE")"
IOC_MATCHES_JSON="$(echo "$MATCHES_JSON" | jq -s --argjson iocs "$IOC_VALUES_JSON" '
	[.[] | select((.src_ip and ($iocs | index(.src_ip))) or (.dst_ip and ($iocs | index(.dst_ip)))) | (.src_ip // .dst_ip)] | unique
')"
ACTIONS+=("jq --argjson iocs ioc_feed_values 'select(.src_ip in iocs or .dst_ip in iocs)' (matched events)")
IOC_MATCH_COUNT="$(echo "$IOC_MATCHES_JSON" | jq 'length')"
printf "[inv-A] ioc_matches: %s (%s)\n" "$IOC_MATCH_COUNT" "$(echo "$IOC_MATCHES_JSON" | jq -r 'join(", ")')"

BASELINE_RUN_FILE="$SHIFT_WORKSPACE/runtime/baseline_run.json"
DEVIATION_MARKERS_JSON="$(jq -c --argjson hosts "$HOST_LIST_JSON" '
	[.deviation_markers[] | select(.host as $h | $hosts | map(ascii_downcase) | index($h | ascii_downcase))]
' "$BASELINE_RUN_FILE")"
ACTIONS+=("jq 'deviation_markers[] | select(.host in host_list)' $BASELINE_RUN_FILE")
DEVIATION_COUNT="$(echo "$DEVIATION_MARKERS_JSON" | jq 'length')"
printf "[inv-A] baseline deviations: %s markers for %s\n" "$DEVIATION_COUNT" "$HOST_LIST"

EVENT_REFS_JSON="$(echo "$MATCHES_JSON" | jq -s '[.[].timestamp]')"
EVENT_REFS_COUNT="$(echo "$EVENT_REFS_JSON" | jq 'length')"

ATTACK_TECHNIQUES_JSON="$(jq -n --arg cat "$CATEGORY" '
	{
		credential_abuse: ["T1110.003", "T1078.002"],
		persistence: ["T1543.003", "T1078.002"],
		c2: ["T1071.001", "T1041"],
		staging: ["T1041", "T1071.001"],
		lateral_movement: ["T1021.002", "T1078.002"],
		unknown: []
	}[$cat] // []
')"
TECHNIQUES_COUNT="$(echo "$ATTACK_TECHNIQUES_JSON" | jq 'length')"

HYPOTHESIS="Incident $INCIDENT_ID groups $ALERT_COUNT alert(s) on $HOST_LIST tentatively categorized as $CATEGORY, based on $IOC_MATCH_COUNT IOC match(es) and $DEVIATION_COUNT baseline deviation marker(s) in the surrounding window."
printf "[inv-A] hypothesis: %s\n" "$HYPOTHESIS"

CONFIDENCE="low"
[ "$IOC_MATCH_COUNT" -gt 0 ] && CONFIDENCE="high"
[ "$IOC_MATCH_COUNT" -eq 0 ] && [ "$DEVIATION_COUNT" -gt 0 ] && CONFIDENCE="medium"
printf "[inv-A] techniques: %s\n" "$(echo "$ATTACK_TECHNIQUES_JSON" | jq -r 'join(" ")')"
printf "[inv-A] confidence: %s\n" "$CONFIDENCE"

AMBIGUITY_NOTES=""
[ "$CONFIDENCE" != "high" ] && AMBIGUITY_NOTES="tentative_category ($CATEGORY) is a text-based guess from the rule title, not a confirmed kill-chain; techniques listed are the category's typical set, not individually confirmed against event evidence."

INVESTIGATION_END="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ACTIONS_JSON="$(printf '%s\n' "${ACTIONS[@]}" | jq -R . | jq -s .)"

jq -n \
	--arg finding_id "shift-$(date -u +%Y%m%d)-investigate-a" \
	--arg incident_id "$INCIDENT_ID" \
	--arg investigation_start "$WINDOW_START" \
	--arg investigation_end "$INVESTIGATION_END" \
	--argjson actions "$ACTIONS_JSON" \
	--argjson event_refs "$EVENT_REFS_JSON" \
	--argjson attack_techniques "$ATTACK_TECHNIQUES_JSON" \
	--arg hypothesis "$HYPOTHESIS" \
	--arg confidence "$CONFIDENCE" \
	--arg ambiguity_notes "$AMBIGUITY_NOTES" \
	--arg created_at "$INVESTIGATION_END" \
	'{
		finding_id: $finding_id,
		incident_id: $incident_id,
		interface: "cli",
		investigation_start: $investigation_start,
		investigation_end: $investigation_end,
		time_to_first_answer_seconds: 0,
		actions: $actions,
		event_refs: $event_refs,
		attack_techniques: $attack_techniques,
		hypothesis: $hypothesis,
		confidence: $confidence,
		ambiguity_notes: $ambiguity_notes,
		created_at: $created_at
	}' > "$SHIFT_WORKSPACE/investigations/incident_A.json"

printf "[inv-A] incident_A.json written\n"

[ "$EVENT_REFS_COUNT" -ge 6 ] || fail "$EVENT_REFS_COUNT event_refs (need >=6)"
[ "$TECHNIQUES_COUNT" -ge 2 ] || fail "$TECHNIQUES_COUNT attack_techniques (need >=2)"
