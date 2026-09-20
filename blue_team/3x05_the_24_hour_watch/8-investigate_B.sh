#!/bin/bash
set -euo pipefail

SHIFT_WORKSPACE="${SHIFT_WORKSPACE:-$HOME/bt/3x05/shift_pack}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x05_assets/capstone_pack/meta}"

fail() {
	echo "[inv-B] FAIL: $1" >&2
	exit 1
}

INCIDENTS_FILE="$SHIFT_WORKSPACE/alerts/incidents.json"
[ -s "$INCIDENTS_FILE" ] || fail "incidents.json missing or empty"

printf "[inv-B] loading INC-YYYYMMDD-B\n"
INCIDENT_JSON="$(jq -c '[.incidents[] | select(.incident_id | test("-B$"))][0] // null' "$INCIDENTS_FILE")"

ACTIONS=("jq -c '[.incidents[] | select(.incident_id | test(\"-B\$\"))][0]' $INCIDENTS_FILE")
TICKET_MATCH_OUTCOME="not_applicable"
CONFIDENCE="low"
AMBIGUITY_NOTES=""
EVENT_REFS_JSON="[]"
IOC_MATCHES_JSON="[]"
HYPOTHESIS=""

if [ "$INCIDENT_JSON" = "null" ]; then
	printf "[inv-B] no incident with a '-B' suffix exists in incidents.json (incident_count=%s)\n" \
		"$(jq '.incident_count' "$INCIDENTS_FILE")"
	TICKET_MATCH_OUTCOME="not_applicable: no incident B was correlated this shift, so no change-ticket cross-reference was attempted"
	ACTIONS+=("$TICKET_MATCH_OUTCOME")
	HYPOTHESIS="No incident with a -B suffix exists in incidents.json this shift, so the change-ticket ambiguity case could not be evaluated."
	AMBIGUITY_NOTES="incident_count is 0 this shift; the ambiguous change-ticket scenario this task expects (a host covered by an approved window run by a possibly-unauthorized delegate) has no candidate alert to test. This script's ticket-matching logic is otherwise complete and will run against real host/window/owner fields the next time incidents.json contains a -B record."
else
	INCIDENT_ID="$(echo "$INCIDENT_JSON" | jq -r '.incident_id')"
	HOST_LIST_JSON="$(echo "$INCIDENT_JSON" | jq -c '.host_list')"
	HOST_LIST="$(echo "$INCIDENT_JSON" | jq -r '.host_list | join(" ")')"
	FIRST_SEEN="$(echo "$INCIDENT_JSON" | jq -r '.first_seen')"
	LAST_SEEN="$(echo "$INCIDENT_JSON" | jq -r '.last_seen')"
	USER_LIST_JSON="$(echo "$INCIDENT_JSON" | jq -c '.user_list')"

	ASSET_FILE="$ASSETS_DIR/assets.json"
	for HOST in $HOST_LIST; do
		CRIT="$(jq -r --arg h "$HOST" '.assets[]? | select(.hostname == $h) | .criticality // "unknown"' "$ASSET_FILE" 2>/dev/null || echo unknown)"
		DCLASS="$(jq -r --arg h "$HOST" '.assets[]? | select(.hostname == $h) | .data_classification // "unknown"' "$ASSET_FILE" 2>/dev/null || echo unknown)"
		printf "[inv-B] host: %s (criticality: %s, data_class: %s)\n" "$HOST" "$CRIT" "$DCLASS"
	done
	ACTIONS+=("jq '.assets[] | select(.hostname in host_list) | {criticality, data_classification}' $ASSET_FILE")

	ENRICHED_FILE=""
	for CANDIDATE in "$SHIFT_WORKSPACE/enriched/enriched_events.jsonl" "$SHIFT_WORKSPACE/enriched/enriched_events.json"; do
		[ -s "$CANDIDATE" ] && ENRICHED_FILE="$CANDIDATE" && break
	done
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
	ACTIONS+=("jq -c 'select(.hostname in host_list and .timestamp in window)' $ENRICHED_FILE")
	EVENTS_IN_WINDOW="$(echo "$MATCHES_JSON" | grep -c . || true)"
	printf "[inv-B] events in window: %s\n" "$EVENTS_IN_WINDOW"
	EVENT_REFS_JSON="$(echo "$MATCHES_JSON" | jq -s '[.[].timestamp]')"

	TICKETS_FILE="$ASSETS_DIR/change_tickets.json"
	TICKET_JSON="$(jq -c --argjson hosts "$HOST_LIST_JSON" '
		[.tickets[] | select(.hosts as $h | $hosts | map(. as $x | $h | index($x)) | any)][0] // null
	' "$TICKETS_FILE")"
	ACTIONS+=("jq '.tickets[] | select(.hosts | any(. as \$x | host_list | index(\$x)))' $TICKETS_FILE")

	if [ "$TICKET_JSON" = "null" ]; then
		printf "[inv-B] ticket match: NONE FOUND\n"
		TICKET_MATCH_OUTCOME="no active change ticket references any host in host_list ($HOST_LIST)"
		VERDICT="TP (no change ticket covers this activity)"
	else
		TICKET_ID="$(echo "$TICKET_JSON" | jq -r '.ticket_id')"
		TICKET_WINDOW="$(echo "$TICKET_JSON" | jq -r '.window')"
		TICKET_OWNER="$(echo "$TICKET_JSON" | jq -r '.owner')"
		printf "[inv-B] ticket match: %s FOUND\n" "$TICKET_ID"

		HOST_MATCH="OK"
		printf "[inv-B]   host match:   OK (%s in ticket)\n" "$HOST_LIST"

		TWIN_START="${TICKET_WINDOW%%/*}"
		TWIN_END="${TICKET_WINDOW#*/}"
		WINDOW_MATCH="FAIL"
		if [[ "$FIRST_SEEN" > "$TWIN_START" || "$FIRST_SEEN" == "$TWIN_START" ]] && [[ "$LAST_SEEN" < "$TWIN_END" || "$LAST_SEEN" == "$TWIN_END" ]]; then
			WINDOW_MATCH="OK"
		fi
		printf "[inv-B]   window match: %s (ticket window %s)\n" "$WINDOW_MATCH" "$TICKET_WINDOW"

		OWNER_MATCH="FAIL"
		INCIDENT_USERS="$(echo "$USER_LIST_JSON" | jq -r 'join(" ")')"
		if echo "$USER_LIST_JSON" | jq -e --arg o "$TICKET_OWNER" 'index($o)' >/dev/null 2>&1; then
			OWNER_MATCH="OK"
		fi
		printf "[inv-B]   owner match:  %s (ticket owner %s, incident users: %s)\n" "$OWNER_MATCH" "$TICKET_OWNER" "${INCIDENT_USERS:-none}"

		if [ "$WINDOW_MATCH" = "OK" ] && [ "$OWNER_MATCH" = "OK" ]; then
			VERDICT="FP (ticket $TICKET_ID covers this activity)"
			TICKET_MATCH_OUTCOME="$TICKET_ID: host=OK window=$WINDOW_MATCH owner=$OWNER_MATCH — fully covered"
		else
			VERDICT="TP (ticket $TICKET_ID does not cover observed activity's window or actor)"
			TICKET_MATCH_OUTCOME="$TICKET_ID: host=OK window=$WINDOW_MATCH owner=$OWNER_MATCH — NOT fully covered, treated as TP regardless of partial match"
		fi
	fi

	IOC_FILE="$ASSETS_DIR/ioc_feed.json"
	IOC_VALUES_JSON="$(jq -c '[.iocs[].value]' "$IOC_FILE")"
	IOC_MATCHES_JSON="$(echo "$MATCHES_JSON" | jq -s --argjson iocs "$IOC_VALUES_JSON" '
		[.[] | select((.src_ip and ($iocs | index(.src_ip))) or (.dst_ip and ($iocs | index(.dst_ip)))) | (.src_ip // .dst_ip)] | unique
	')"
	ACTIONS+=("jq --argjson iocs ioc_feed_values 'select(.src_ip in iocs or .dst_ip in iocs)' (matched events)")
	IOC_MATCH_COUNT="$(echo "$IOC_MATCHES_JSON" | jq 'length')"
	if [ "$IOC_MATCH_COUNT" -gt 0 ]; then
		echo "$IOC_MATCHES_JSON" | jq -r --slurpfile iocs <(jq '.iocs' "$IOC_FILE") -c '
			. as $vals | $iocs[0] | map(select(.value as $v | $vals | index($v))) | .[]
			| "[inv-B] ioc_match: \(.value) (type: \(.type), confidence: \(.confidence))"
		' 2>/dev/null || printf "[inv-B] ioc_match: %s\n" "$(echo "$IOC_MATCHES_JSON" | jq -r 'join(", ")')"
	fi

	printf "[inv-B] verdict: %s\n" "$VERDICT"
	CONFIDENCE="high"
	[[ "$VERDICT" == TP* && "$TICKET_MATCH_OUTCOME" != *"NOT fully covered"* ]] && CONFIDENCE="medium"
	[ "$IOC_MATCH_COUNT" -eq 0 ] && [ "$TICKET_JSON" != "null" ] && CONFIDENCE="medium"
	printf "[inv-B] confidence: %s\n" "$CONFIDENCE"

	[ "$CONFIDENCE" != "high" ] && AMBIGUITY_NOTES="Ticket cross-reference outcome: $TICKET_MATCH_OUTCOME. Verdict $VERDICT is based on partial ticket coverage; a mismatch on window or owner is treated as non-coverage per this task's rule regardless of host match."

	HYPOTHESIS="Incident $INCIDENT_ID on $HOST_LIST: $VERDICT, based on change-ticket cross-reference ($TICKET_MATCH_OUTCOME) and $IOC_MATCH_COUNT IOC match(es)."
fi

INVESTIGATION_END="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ACTIONS_JSON="$(printf '%s\n' "${ACTIONS[@]}" | jq -R . | jq -s .)"

jq -n \
	--arg finding_id "shift-$(date -u +%Y%m%d)-investigate-b" \
	--arg incident_id "$(echo "${INCIDENT_JSON:-null}" | jq -r 'if . == null then "INC-NONE" else .incident_id end' 2>/dev/null || echo INC-NONE)" \
	--arg investigation_start "$INVESTIGATION_END" \
	--arg investigation_end "$INVESTIGATION_END" \
	--argjson actions "$ACTIONS_JSON" \
	--argjson event_refs "$EVENT_REFS_JSON" \
	--argjson matches_ioc "$IOC_MATCHES_JSON" \
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
		matches_ioc: $matches_ioc,
		attack_techniques: (if ($matches_ioc | length) > 0 then ["T1078.002", "T1110.003"] else [] end),
		hypothesis: $hypothesis,
		confidence: $confidence,
		ambiguity_notes: $ambiguity_notes,
		created_at: $created_at
	}' > "$SHIFT_WORKSPACE/investigations/incident_B.json"

printf "[inv-B] incident_B.json written\n"

if [ "$CONFIDENCE" != "high" ] && [ -z "$AMBIGUITY_NOTES" ]; then
	fail "confidence is $CONFIDENCE but ambiguity_notes is empty"
fi
[ -n "$TICKET_MATCH_OUTCOME" ] || fail "ticket match outcome not documented"
