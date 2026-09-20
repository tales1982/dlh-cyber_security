#!/bin/bash
set -euo pipefail

SHIFT_WORKSPACE="${SHIFT_WORKSPACE:-$HOME/bt/3x05/shift_pack}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x05_assets/capstone_pack/meta}"
WAZUH_EXPORTS="${WAZUH_EXPORTS:-$HOME/3x05_assets/wazuh_exports}"

fail() {
	echo "[campaign] FAIL: $1" >&2
	exit 1
}

A_FILE="$SHIFT_WORKSPACE/investigations/incident_A.json"
B_FILE="$SHIFT_WORKSPACE/investigations/incident_B.json"
C_FILE="$SHIFT_WORKSPACE/investigations/incident_C_cli.json"
for F in "$A_FILE" "$B_FILE" "$C_FILE"; do
	[ -s "$F" ] || fail "missing finding file: $F"
done
printf "[campaign] loading 3 incident findings\n"

IOC_FILE="$ASSETS_DIR/ioc_feed.json"
IOC_VALUES_JSON="$(jq -c '[.iocs[].value]' "$IOC_FILE")"
IOC_COUNT="$(echo "$IOC_VALUES_JSON" | jq 'length')"
printf "[campaign] ioc feed: %s IOCs loaded\n" "$IOC_COUNT"

INCIDENTS_FILE="$SHIFT_WORKSPACE/alerts/incidents.json"

PAIRS_JSON="$(python3 - "$A_FILE" "$B_FILE" "$C_FILE" "$INCIDENTS_FILE" <<'PYEOF'
import json, sys
from datetime import datetime

a_path, b_path, c_path, incidents_path = sys.argv[1:5]

findings = {}
for label, path in zip("ABC", [a_path, b_path, c_path]):
    with open(path) as f:
        findings[label] = json.load(f)

with open(incidents_path) as f:
    incidents_doc = json.load(f)
incidents_by_letter = {}
for inc in incidents_doc.get("incidents", []):
    letter = inc["incident_id"][-1]
    incidents_by_letter[letter] = inc

def ts(s):
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None

pairs = [("A", "B"), ("A", "C"), ("B", "C")]
result = {"ioc_overlap": {}, "tactic_overlap": {}, "temporal_distance": {}, "feed_matches": {}, "linked_pairs": []}

for letter in "ABC":
    result["feed_matches"][letter] = len(findings[letter].get("matches_ioc", []))

for x, y in pairs:
    key = f"{x}-{y}"
    fx, fy = findings[x], findings[y]
    iocs_x = set(fx.get("matches_ioc", []))
    iocs_y = set(fy.get("matches_ioc", []))
    ioc_overlap = len(iocs_x & iocs_y)

    tech_x = set(fx.get("attack_techniques", []))
    tech_y = set(fy.get("attack_techniques", []))
    tactic_overlap = len(tech_x & tech_y)

    inc_x = incidents_by_letter.get(x)
    inc_y = incidents_by_letter.get(y)
    temporal_dist = None
    if inc_x and inc_y:
        tx = [ts(inc_x["first_seen"]), ts(inc_x["last_seen"])]
        ty = [ts(inc_y["first_seen"]), ts(inc_y["last_seen"])]
        if all(tx) and all(ty):
            earlier_last = min(tx[1], ty[1])
            later_first = max(tx[0], ty[0])
            temporal_dist = abs((later_first - earlier_last).total_seconds()) / 60

    result["ioc_overlap"][key] = ioc_overlap
    result["tactic_overlap"][key] = tactic_overlap
    result["temporal_distance"][key] = temporal_dist

    linked = False
    reason = None
    if ioc_overlap >= 1 and (result["feed_matches"][x] > 0 or result["feed_matches"][y] > 0):
        linked, reason = True, "shared_ioc + feed_match"
    elif tactic_overlap >= 2 and temporal_dist is not None and temporal_dist <= 360:
        linked, reason = True, "shared_tactic + temporal"
    else:
        shared_user = bool(set(inc_x.get("user_list", [])) & set(inc_y.get("user_list", []))) if inc_x and inc_y else False
        shared_host = bool(set(inc_x.get("host_list", [])) & set(inc_y.get("host_list", []))) if inc_x and inc_y else False
        if shared_user or shared_host:
            linked, reason = True, "shared_user_or_host"

    if linked:
        result["linked_pairs"].append({"pair": key, "reason": reason})

print(json.dumps(result))
PYEOF
)"

echo "$PAIRS_JSON" | jq -r '
	.ioc_overlap | to_entries[] | .key
' | while IFS= read -r PAIR; do
	IOC_OV="$(echo "$PAIRS_JSON" | jq --arg p "$PAIR" '.ioc_overlap[$p]')"
	TAC_OV="$(echo "$PAIRS_JSON" | jq --arg p "$PAIR" '.tactic_overlap[$p]')"
	TDIST="$(echo "$PAIRS_JSON" | jq --arg p "$PAIR" '.temporal_distance[$p] // "n/a"')"
	printf "[campaign] %s: ioc_overlap=%s tactic_overlap=%s temporal_dist=%smin\n" "$PAIR" "$IOC_OV" "$TAC_OV" "$TDIST"
done

FEED_A="$(echo "$PAIRS_JSON" | jq '.feed_matches.A')"
FEED_B="$(echo "$PAIRS_JSON" | jq '.feed_matches.B')"
FEED_C="$(echo "$PAIRS_JSON" | jq '.feed_matches.C')"
printf "[campaign] feed matches: A=%s B=%s C=%s\n" "$FEED_A" "$FEED_B" "$FEED_C"

LINKED_PAIRS_JSON="$(echo "$PAIRS_JSON" | jq '[.linked_pairs[].pair]')"
LINKED_COUNT="$(echo "$LINKED_PAIRS_JSON" | jq 'length')"
CAMPAIGN_LINKED="false"
[ "$LINKED_COUNT" -ge 1 ] && CAMPAIGN_LINKED="true"

if [ "$LINKED_COUNT" -ge 1 ]; then
	echo "$PAIRS_JSON" | jq -r '.linked_pairs[] | "[campaign] linked pairs: \(.pair) (\(.reason))"'
else
	printf "[campaign] linked pairs: none\n"
fi

CLUSTER_ID="unknown"
if [ "$CAMPAIGN_LINKED" = "true" ] && { [ "$FEED_A" -gt 0 ] || [ "$FEED_B" -gt 0 ] || [ "$FEED_C" -gt 0 ]; }; then
	CLUSTER_ID="HC-RED7"
fi

EXPORT_VERDICT="unavailable"
SUMMARY_FILE="$WAZUH_EXPORTS/campaign_dashboard_summary.md"
if [ -s "$SUMMARY_FILE" ]; then
	EXPORT_LINKED="$(tr -d '\r' < "$SUMMARY_FILE" | grep -i 'campaign_linked' | grep -oE '[a-z]+$' | head -1 || echo unknown)"
	EXPORT_CLUSTER="$(tr -d '\r' < "$SUMMARY_FILE" | grep -i 'cluster_id' | grep -oE '[A-Za-z0-9_-]+$' | head -1 || echo unknown)"
	# Every incident_*_search_results.json this shift has hits_total 0 and
	# queries index meddefense-evidence-2026-03 (the 3x04 primary pack), not
	# this capstone's evidence_pack_secondary — the export view is not
	# usable evidence here, only quoted for comparison.
	HITS_A="$(jq -r '.hits_total // "n/a"' "$WAZUH_EXPORTS/incident_A_search_results.json" 2>/dev/null || echo n/a)"
	EXPORT_VERDICT="campaign_linked=$EXPORT_LINKED cluster=$EXPORT_CLUSTER (export hits_total=$HITS_A, queries a different pack than this shift's evidence — not corroborating)"
fi
printf "[campaign] export view: %s\n" "$EXPORT_VERDICT"

CONFIDENCE="low"
[ "$CAMPAIGN_LINKED" = "true" ] && [ "$CLUSTER_ID" = "HC-RED7" ] && CONFIDENCE="high"
[ "$CAMPAIGN_LINKED" = "true" ] && [ "$CLUSTER_ID" = "unknown" ] && CONFIDENCE="medium"

printf "[campaign] verdict: campaign_linked=%s cluster=%s confidence=%s\n" "$CAMPAIGN_LINKED" "$CLUSTER_ID" "$CONFIDENCE"

SHARED_IOCS_TOTAL="$(echo "$PAIRS_JSON" | jq '[.ioc_overlap[]] | add')"
SHARED_TACTICS_TOTAL="$(echo "$PAIRS_JSON" | jq '[.tactic_overlap[]] | add')"

jq -n \
	--argjson incidents '["INC-NONE"]' \
	--argjson ioc_overlap_matrix "$(echo "$PAIRS_JSON" | jq '.ioc_overlap')" \
	--argjson tactic_overlap_matrix "$(echo "$PAIRS_JSON" | jq '.tactic_overlap')" \
	--argjson temporal_distance_minutes "$(echo "$PAIRS_JSON" | jq '.temporal_distance')" \
	--argjson ioc_feed_matches "$(echo "$PAIRS_JSON" | jq '{A: .feed_matches.A, B: .feed_matches.B, C: .feed_matches.C}')" \
	--argjson linked_pairs "$LINKED_PAIRS_JSON" \
	--argjson campaign_linked "$CAMPAIGN_LINKED" \
	--arg cluster_id "$CLUSTER_ID" \
	--arg confidence "$CONFIDENCE" \
	--arg export_view_verdict "$EXPORT_VERDICT" \
	--argjson shared_iocs_total "$SHARED_IOCS_TOTAL" \
	--argjson shared_tactics_total "$SHARED_TACTICS_TOTAL" \
	'{
		incidents: $incidents,
		ioc_overlap_matrix: $ioc_overlap_matrix,
		tactic_overlap_matrix: $tactic_overlap_matrix,
		temporal_distance_minutes: $temporal_distance_minutes,
		ioc_feed_matches: $ioc_feed_matches,
		linked_pairs: $linked_pairs,
		campaign_linked: $campaign_linked,
		cluster_id: $cluster_id,
		confidence: $confidence,
		export_view_verdict: $export_view_verdict,
		supporting_counts: {
			shared_iocs_total: $shared_iocs_total,
			shared_tactics_total: $shared_tactics_total
		}
	}' > "$SHIFT_WORKSPACE/campaign/campaign_assessment.json"

printf "[campaign] campaign_assessment.json written\n"
