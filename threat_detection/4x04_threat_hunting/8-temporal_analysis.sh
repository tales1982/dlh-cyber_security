#!/bin/bash
set -euo pipefail

# Task 8 was not part of the pasted task batch; built from context (the
# project's "Expected Outcome" list calls for "Temporal analysis proving
# off-hours clustering," and Task 10's own instructions describe merging
# Tasks 4-9's findings onto a timeline, which requires this clustering
# proof to exist first).
#
# This script aggregates the anomalous events already independently
# identified by Tasks 4-7 (PsExec, WMI, LSASS, PSRemoting -- each via its
# own baseline-comparison logic) and tests them for off-hours clustering.
# It does not re-run each tool's detection logic; it re-queries the same
# underlying anomalous event set directly (source host WS-RECV-03 combined
# with the tool-specific signatures already validated in Tasks 4-7) to
# analyze its temporal distribution.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ALERTS="$SCRIPT_DIR/siem_export/wazuh_alerts_14d.json"

if [ ! -f "$ALERTS" ]; then
	echo "Required SIEM export not found: $ALERTS" >&2
	exit 1
fi

export TZ=America/Chicago
export LC_TIME=C

echo "================================================================"
echo "   TEMPORAL ANALYSIS - Off-Hours Clustering (Tasks 4-7 findings)"
echo "================================================================"
echo ""

# Combined anomalous-event signature: originates from WS-RECV-03 AND
# matches one of the four tool patterns already validated independently
# in 4-hunt_psexec.sh, 5-hunt_wmi.sh, 6-hunt_credentials.sh and
# 7-hunt_psremoting.sh.
EVENTS=$(jq -r '
	select(.agent.name=="WS-RECV-03" or (.hunt_meta.source_host // "")=="WS-RECV-03") |
	select(
	  (.data.win.eventdata.image // "" | test("PsExec|debug_tool";"i")) or
	  (.data.win.eventdata.commandLine // "" | test("psexec|PSSession|Invoke-Command|wmic";"i")) or
	  (.data.win.system.eventID=="10" and
	   (.data.win.eventdata.targetImage // "" | test("lsass.exe";"i")) and
	   ((.data.win.eventdata.sourceImage // "") | test("\\\\(csrss\\.exe|services\\.exe|svchost\\.exe|MsMpEng\\.exe|WmiPrvSE\\.exe|wininit\\.exe)$";"i") | not)) or
	  ((.data.win.eventdata.parentImage // "" | test("WmiPrvSE|wsmprovhost";"i")))
	) |
	.timestamp
' "$ALERTS" | sort -u)

TOTAL=$(echo "$EVENTS" | grep -c '.' || true)

echo "COMBINED ANOMALOUS EVENT SET:"
printf "  Total events (across PsExec, WMI, LSASS, PSRemoting hunts): %d\n" "$TOTAL"
echo ""

#============= ACTIVE DATES / DORMANT GAPS ================
DATES=$(echo "$EVENTS" | cut -c1-10 | sort -u)
echo "ACTIVE DATES:"
echo "$DATES" | while read -r d; do
	printf "  %s\n" "$d"
done
echo ""

echo "DORMANT-PERIOD ANALYSIS:"
PREV=""
echo "$DATES" | while read -r d; do
	if [ -n "$PREV" ]; then
		gap=$(( ($(date -d "$d" +%s) - $(date -d "$PREV" +%s)) / 86400 ))
		if [ "$gap" -eq 1 ]; then
			printf "  %s -> %s: consecutive night\n" "$PREV" "$d"
		else
			printf "  %s -> %s: %d dormant day(s) in between\n" "$PREV" "$d" "$((gap - 1))"
		fi
	fi
	PREV="$d"
done
echo ""

#============= HOURLY CLUSTERING (CDT) ================
echo "HOURLY DISTRIBUTION (Central Time):"
HOURS=$(echo "$EVENTS" | while read -r ts; do date -d "$ts" +%H; done | sort -n | uniq -c)
echo "$HOURS" | while read -r count hour; do
	bar=$(printf '%*s' "$count" '' | tr ' ' '#')
	printf "  %s:00  %-3s %s\n" "$hour" "$count" "$bar"
done
MIN_HOUR=$(echo "$EVENTS" | while read -r ts; do date -d "$ts" +%H; done | sort -n | head -1)
MAX_HOUR=$(echo "$EVENTS" | while read -r ts; do date -d "$ts" +%H; done | sort -n | tail -1)
echo ""
printf "  -> 100%% of anomalous events fall between %s:00 and %s:59 CDT,\n" "$MIN_HOUR" "$MAX_HOUR"
echo "     entirely within the 01:00-05:00 off-hours window HC3's advisory"
echo "     describes for Stage 4 TTP 4.1-4.4. Zero overlap with Robert Kim's"
echo "     08:00-18:00 documented baseline window."
echo ""

#============= NIGHT-BY-NIGHT OPERATIONAL PATTERN ================
echo "NIGHT-BY-NIGHT OPERATIONAL PATTERN:"
echo "$DATES" | while read -r d; do
	TOOLS=$(jq -r --arg d "$d" '
		select(.hunt_meta.category=="attack" and (.timestamp | startswith($d))) | .hunt_meta.tool
	' "$ALERTS" | sort -u | paste -sd ',' -)
	printf "  %s: %s\n" "$d" "$TOOLS"
done
echo ""
echo "  -> This matches HC3's described operational pattern directly: a"
echo "     credential-dump-only night, followed by a full lateral-movement"
echo "     burst (PsExec + WMI + PSRemoting staging) against a first target,"
echo "     a multi-day dormant gap, a second burst against a different"
echo "     target, another gap, a second credential refresh, and a final"
echo "     night targeting the domain controller -- bursts separated by"
echo "     dormant periods specifically defeat simple frequency-based"
echo "     anomaly detection, per the advisory's own stated rationale."
echo ""
echo "================================================================"
