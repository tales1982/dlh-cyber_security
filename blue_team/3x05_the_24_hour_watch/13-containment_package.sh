#!/bin/bash
set -euo pipefail

SHIFT_WORKSPACE="${SHIFT_WORKSPACE:-$HOME/bt/3x05/shift_pack}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x05_assets/capstone_pack/meta}"

fail() {
	echo "[resp] FAIL: $1" >&2
	exit 1
}

CAMPAIGN_FILE="$SHIFT_WORKSPACE/campaign/campaign_assessment.json"
INCIDENTS_FILE="$SHIFT_WORKSPACE/alerts/incidents.json"
[ -s "$CAMPAIGN_FILE" ] || fail "campaign_assessment.json missing or empty"
[ -s "$INCIDENTS_FILE" ] || fail "incidents.json missing or empty"
printf "[resp] loading campaign_assessment and incidents\n"

SHIFT_ID="$(jq -r '.shift_id' "$INCIDENTS_FILE")"
GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
INCIDENT_IDS_JSON="$(jq -c '[.incidents[].incident_id]' "$INCIDENTS_FILE")"
INCIDENT_COUNT="$(echo "$INCIDENT_IDS_JSON" | jq 'length')"

# --- containment actions: one immediate + one short_term + one medium_term
# per real incident, derived from its finding's matches_ioc/host_list/user_list.
ACTIONS_JSON="$(jq -n --argjson incidents "$(jq -c '.incidents' "$INCIDENTS_FILE")" --arg gen "$GENERATED_AT" '
	[
		$incidents[] as $inc
		| ($inc.incident_id) as $id
		| ($inc.host_list[0] // null) as $host
		| ($inc.ioc_list[0] // null) as $ioc
		| (
			(if $ioc then [{
				action: ("Block IOC " + $ioc + " at the perimeter firewall"),
				target_type: "ip",
				target_value: $ioc,
				priority: "immediate"
			}] else [] end)
			+
			(if $host then [{
				action: ("Isolate " + $host + " from the network pending investigation"),
				target_type: "host",
				target_value: $host,
				priority: "immediate"
			}] else [] end)
			+
			(if ($inc.user_list | length) > 0 then [{
				action: ("Reset credentials for " + ($inc.user_list | join(", "))),
				target_type: "user",
				target_value: ($inc.user_list | join(",")),
				priority: "short_term"
			}] else [] end)
			+
			[{
				action: ("Review and tighten firewall rules for the zone(s) hosting " + ($host // "the affected asset")),
				target_type: "rule",
				target_value: ($host // "n/a"),
				priority: "medium_term"
			}]
		)[] as $a
		| $a + {incident_id: $id}
	]
' <<< "{}" 2>/dev/null || echo '[]')"

# jq -n with --argjson on an empty incidents array naturally yields [] here.
ACTIONS_COUNT="$(echo "$ACTIONS_JSON" | jq 'length')"
[ "$ACTIONS_COUNT" -le 12 ] || fail "$ACTIONS_COUNT actions exceeds the 12-action cap"

# every action must cite an incident_id that exists in incidents.json
INVALID="$(echo "$ACTIONS_JSON" | jq --argjson ids "$INCIDENT_IDS_JSON" '[.[] | select(.incident_id as $i | $ids | index($i) | not)] | length')"
[ "$INVALID" -eq 0 ] || fail "$INVALID action(s) cite an incident_id not present in incidents.json"

ACTIONS_NUMBERED_JSON="$(echo "$ACTIONS_JSON" | jq '
	to_entries | map(.value + {action_id: ("ACT-" + (((.key + 1) | tostring) | if length < 3 then ("0" * (3 - length)) + . else . end))})
')"

IMMEDIATE_COUNT="$(echo "$ACTIONS_NUMBERED_JSON" | jq '[.[] | select(.priority=="immediate")] | length')"
SHORT_COUNT="$(echo "$ACTIONS_NUMBERED_JSON" | jq '[.[] | select(.priority=="short_term")] | length')"
MEDIUM_COUNT="$(echo "$ACTIONS_NUMBERED_JSON" | jq '[.[] | select(.priority=="medium_term")] | length')"
printf "[resp] actions: immediate=%s short_term=%s medium_term=%s total=%s\n" \
	"$IMMEDIATE_COUNT" "$SHORT_COUNT" "$MEDIUM_COUNT" "$ACTIONS_COUNT"

jq -n \
	--arg shift_id "$SHIFT_ID" \
	--arg generated_at "$GENERATED_AT" \
	--argjson actions "$(echo "$ACTIONS_NUMBERED_JSON" | jq 'map({action_id, priority, action: .action[0:160], target_type, target_value, incident_id, operational_impact: "Blocks or resets access for the affected target; verify no legitimate business process depends on it first."[0:160], requires_approval_from: (if .priority == "immediate" then "on-call SOC lead" elif .priority == "short_term" then "change management" else "security architecture review" end)})')" \
	'{
		shift_id: $shift_id,
		generated_at: $generated_at,
		actions: $actions
	}' > "$SHIFT_WORKSPACE/response/containment.json"

printf "[resp] containment.json written\n"

# --- IOC package: every IOC observed in a finding's matches_ioc, traced
# back to at least one event_ref in that same finding.
IOC_FEED_FILE="$ASSETS_DIR/ioc_feed.json"
IOC_FEED_VALUES_JSON="$(jq -c '[.iocs[].value]' "$IOC_FEED_FILE")"

PACKAGE_IOCS_JSON="[]"
for LETTER_FILE in "$SHIFT_WORKSPACE/investigations/incident_A.json:A" "$SHIFT_WORKSPACE/investigations/incident_B.json:B" "$SHIFT_WORKSPACE/investigations/incident_C_cli.json:C"; do
	FPATH="${LETTER_FILE%%:*}"
	[ -s "$FPATH" ] || continue
	FIRST_REF="$(jq -r '.event_refs[0] // ""' "$FPATH")"
	LAST_REF="$(jq -r '.event_refs[-1] // ""' "$FPATH")"
	INC_ID="$(jq -r '.incident_id' "$FPATH")"
	ENTRY="$(jq -c --argjson feed "$IOC_FEED_VALUES_JSON" --arg first "$FIRST_REF" --arg last "$LAST_REF" --arg inc "$INC_ID" '
		[.matches_ioc[]? | {
			type: "ip",
			value: .,
			first_seen: $first,
			last_seen: $last,
			incident_id: $inc,
			source: (if ([.] | inside($feed)) then "ioc_feed" else "shift_discovered" end),
			confidence: "medium"
		}]
	' "$FPATH")"
	PACKAGE_IOCS_JSON="$(echo "$PACKAGE_IOCS_JSON" | jq --argjson e "$ENTRY" '. + $e')"
done

# every IOC in the package must have non-empty first_seen/last_seen (i.e. be
# traceable to at least one event_ref); drop (and warn on) any that are not.
UNTRACEABLE="$(echo "$PACKAGE_IOCS_JSON" | jq '[.[] | select(.first_seen == "" or .last_seen == "")] | length')"
[ "$UNTRACEABLE" -eq 0 ] || fail "$UNTRACEABLE IOC(s) in the package have no event_ref backing"

# defang network indicators
PACKAGE_IOCS_DEFANGED="$(echo "$PACKAGE_IOCS_JSON" | jq '
	map(if .type == "ip" or .type == "domain" then . + {value: (.value | gsub("\\."; "[.]"))} else . end)
')"

IOC_TOTAL="$(echo "$PACKAGE_IOCS_DEFANGED" | jq 'length')"
IOC_BY_TYPE="$(echo "$PACKAGE_IOCS_DEFANGED" | jq '
	{ip: 0, domain: 0, hash: 0, account: 0, service_name: 0, port: 0}
	+ (group_by(.type) | map({(.[0].type): length}) | add // {})
')"
NEW_COUNT="$(echo "$PACKAGE_IOCS_DEFANGED" | jq '[.[] | select(.source=="shift_discovered")] | length')"

echo "$IOC_BY_TYPE" | jq -r --argjson total "$IOC_TOTAL" \
	'"[resp] IOCs: ip=\(.ip) domain=\(.domain) hash=\(.hash) account=\(.account) service=\(.service_name) total=\($total)"'
printf "[resp] newly discovered (not in feed): %s\n" "$NEW_COUNT"
printf "[resp] all IOCs traced to events: OK\n"

CLUSTER_ID="$(jq -r '.cluster_id' "$CAMPAIGN_FILE")"

jq -n \
	--arg shift_id "$SHIFT_ID" \
	--arg cluster_id "$CLUSTER_ID" \
	--arg generated_at "$GENERATED_AT" \
	--argjson iocs "$PACKAGE_IOCS_DEFANGED" \
	'{
		shift_id: $shift_id,
		tlp: "AMBER",
		cluster_id: $cluster_id,
		generated_at: $generated_at,
		iocs: $iocs
	}' > "$SHIFT_WORKSPACE/response/ioc_package.json"

printf "[resp] ioc_package.json written\n"
