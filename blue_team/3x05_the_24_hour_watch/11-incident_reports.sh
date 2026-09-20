#!/bin/bash
set -euo pipefail

SHIFT_WORKSPACE="${SHIFT_WORKSPACE:-$HOME/bt/3x05/shift_pack}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x05_assets/capstone_pack/meta}"

fail() {
	echo "[report] FAIL: $1" >&2
	exit 1
}

defang() {
	sed -E 's/([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/\1[.]\2[.]\3[.]\4/g'
}

ENRICHED_FILE=""
for CANDIDATE in "$SHIFT_WORKSPACE/enriched/enriched_events.jsonl" "$SHIFT_WORKSPACE/enriched/enriched_events.json"; do
	[ -s "$CANDIDATE" ] && ENRICHED_FILE="$CANDIDATE" && break
done
[ -n "$ENRICHED_FILE" ] || fail "no enriched events file found"

INCIDENTS_FILE="$SHIFT_WORKSPACE/alerts/incidents.json"
ASSET_FILE="$ASSETS_DIR/assets.json"

TOTAL_REFS_VERIFIED=0

generate_report() {
	LETTER="$1"
	FINDING_FILE="$2"
	OUT_FILE="$SHIFT_WORKSPACE/reports/incident_${LETTER}.md"

	printf "[report] generating incident_%s.md\n" "$LETTER"

	INCIDENT_ID="$(jq -r '.incident_id' "$FINDING_FILE")"
	HYPOTHESIS="$(jq -r '.hypothesis' "$FINDING_FILE")"
	CONFIDENCE="$(jq -r '.confidence' "$FINDING_FILE")"
	AMBIGUITY="$(jq -r '.ambiguity_notes // ""' "$FINDING_FILE")"
	EVENT_REFS_JSON="$(jq -c '.event_refs' "$FINDING_FILE")"
	TECHNIQUES_JSON="$(jq -c '.attack_techniques' "$FINDING_FILE")"
	IOC_JSON="$(jq -c '.matches_ioc // []' "$FINDING_FILE")"

	INCIDENT_RECORD="$(jq -c --arg id "$INCIDENT_ID" '[.incidents[] | select(.incident_id == $id)][0] // null' "$INCIDENTS_FILE")"
	HOST_LIST_JSON="$(echo "$INCIDENT_RECORD" | jq -c '.host_list // []')"

	TIMELINE_COUNT=0
	TIMELINE_BODY="_No events are attributable to a confirmed incident._"
	if [ "$(echo "$EVENT_REFS_JSON" | jq 'length')" -gt 0 ]; then
		TIMELINE_BODY="$(echo "$EVENT_REFS_JSON" | jq -r '.[0:15][]' | while IFS= read -r TS; do
			jq -r --arg ts "$TS" 'select(.timestamp == $ts) | "\(.timestamp) | \(.hostname) | \(.raw_message[0:80])"' "$ENRICHED_FILE" | head -1
		done)"
		TIMELINE_COUNT="$(echo "$TIMELINE_BODY" | grep -c . || true)"
	fi
	[ "$TIMELINE_COUNT" -le 15 ] || fail "$LETTER timeline has $TIMELINE_COUNT events (cap 15)"

	ASSETS_COUNT=0
	ASSETS_BODY="| — | — | — | — |"
	if [ "$(echo "$HOST_LIST_JSON" | jq 'length')" -gt 0 ]; then
		ASSETS_BODY="$(echo "$HOST_LIST_JSON" | jq -r '.[]' | while IFS= read -r HOST; do
			jq -r --arg h "$HOST" '.assets[]? | select(.hostname == $h) | "| \(.hostname) | \(.criticality) | \(.data_classification) | \(.zone) |"' "$ASSET_FILE" 2>/dev/null
		done)"
		ASSETS_COUNT="$(echo "$ASSETS_BODY" | grep -c . || true)"
	fi
	[ "$ASSETS_COUNT" -le 10 ] || fail "$LETTER affected-assets table has $ASSETS_COUNT rows (cap 10)"

	IOC_COUNT="$(echo "$IOC_JSON" | jq 'length')"
	IOC_BODY="| — | — | — | — |"
	if [ "$IOC_COUNT" -gt 0 ]; then
		IOC_BODY="$(echo "$IOC_JSON" | jq -r '.[]' | while IFS= read -r VAL; do
			printf "| ip | %s | see ioc_feed.json | shift_briefing |\n" "$VAL"
		done | defang)"
	fi
	[ "$IOC_COUNT" -le 15 ] || fail "$LETTER IOC table has $IOC_COUNT rows (cap 15)"

	TECH_COUNT="$(echo "$TECHNIQUES_JSON" | jq 'length')"
	TECH_BODY="| — | — | — |"
	if [ "$TECH_COUNT" -gt 0 ]; then
		TECH_BODY="$(echo "$TECHNIQUES_JSON" | jq -r '.[]' | while IFS= read -r T; do
			printf "| %s | (see hc_red7_advisory.md) | tentative_category-derived, not individually confirmed |\n" "$T"
		done)"
	fi
	[ "$TECH_COUNT" -le 8 ] || fail "$LETTER ATT&CK table has $TECH_COUNT rows (cap 8)"

	REFS_COUNT="$(echo "$EVENT_REFS_JSON" | jq 'length')"
	[ "$REFS_COUNT" -le 12 ] || fail "$LETTER evidence references has $REFS_COUNT entries (cap 12)"
	REFS_BODY="_None — no event_refs are attributable to a confirmed incident._"
	if [ "$REFS_COUNT" -gt 0 ]; then
		REFS_BODY="$(echo "$EVENT_REFS_JSON" | jq -r '.[]' | sed 's/^/- /')"
		# verify every cited ref actually exists as an event timestamp in the enriched file
		while IFS= read -r TS; do
			jq -e --arg ts "$TS" 'select(.timestamp == $ts)' "$ENRICHED_FILE" >/dev/null 2>&1 | head -1 || true
			MATCH="$(jq -r --arg ts "$TS" 'select(.timestamp == $ts) | .timestamp' "$ENRICHED_FILE" | head -1)"
			[ -n "$MATCH" ] || fail "$LETTER evidence reference $TS not found in enriched events"
			TOTAL_REFS_VERIFIED=$((TOTAL_REFS_VERIFIED + 1))
		done < <(echo "$EVENT_REFS_JSON" | jq -r '.[]')
	fi

	ACTIONS_COUNT=3
	ACTIONS_BODY="1. Review the catalog-coverage gap documented in response/tuning_recommendations.json.
2. Confirm whether hc_red7_advisory.md / change_tickets.json / prior_shift_notes.md were generated against this evidence pack.
3. Re-run this investigation once the catalog and/or context files are corrected."

	cat > "$OUT_FILE" <<EOF
## Incident Identifier

$INCIDENT_ID

## Executive Summary

$HYPOTHESIS Confidence in this finding is $CONFIDENCE. ${AMBIGUITY:+$AMBIGUITY}

## Timeline

$TIMELINE_BODY

## Affected Assets

| HOST | CRITICALITY | DATA_CLASS | ZONE |
|------|-------------|------------|------|
$ASSETS_BODY

## Indicators of Compromise

| TYPE | VALUE | CONFIDENCE | SOURCE |
|------|-------|------------|--------|
$IOC_BODY

## ATT&CK Mapping

| TECHNIQUE | NAME | EVIDENCE |
|-----------|------|----------|
$TECH_BODY

## Detection Performance

- See runtime/catalog_run.json and alerts/triage_log.jsonl for this shift's full detection performance (1 rule fired, 1014 alerts, 0 TP).

## Recommended Actions

$ACTIONS_BODY

## Evidence References

$REFS_BODY
EOF

	printf "[report] %s: timeline=%s assets=%s IOCs=%s techniques=%s actions=%s refs=%s\n" \
		"$LETTER" "$TIMELINE_COUNT" "$ASSETS_COUNT" "$IOC_COUNT" "$TECH_COUNT" "$ACTIONS_COUNT" "$REFS_COUNT"
	printf "[report] %s: section caps respected\n" "$LETTER"
}

generate_report "A" "$SHIFT_WORKSPACE/investigations/incident_A.json"
generate_report "B" "$SHIFT_WORKSPACE/investigations/incident_B.json"
generate_report "C" "$SHIFT_WORKSPACE/investigations/incident_C_cli.json"

printf "[report] %s event references verified against enriched_events.jsonl\n" "$TOTAL_REFS_VERIFIED"
printf "[report] reports written\n"
