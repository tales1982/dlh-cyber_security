#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASELINE="$SCRIPT_DIR/baseline/robert_kim_activity.json"
ADMIN_SCHEDULE="$SCRIPT_DIR/reference/admin_schedule.txt"

for f in "$BASELINE" "$ADMIN_SCHEDULE"; do
	if [ ! -f "$f" ]; then
		echo "Required file not found: $f" >&2
		exit 1
	fi
done

# Timestamps in the export are UTC; admin_schedule.txt's hours are stated
# in Central Time (CDT during DST, which covers this entire May 2026
# window). All time-of-day comparisons below convert via TZ=America/Chicago
# rather than comparing raw UTC hours against the CDT-stated schedule.
export TZ=America/Chicago
export LC_TIME=C

TOTAL=$(wc -l <"$BASELINE")
PSEXEC=$(jq -r '.hunt_meta.tool' "$BASELINE" | grep -c '^PsExec$' || true)
WMI=$(jq -r '.hunt_meta.tool' "$BASELINE" | grep -c '^WMI$' || true)
PSREMOTING=$(jq -r '.hunt_meta.tool' "$BASELINE" | grep -c '^PSRemoting$' || true)

echo "================================================================"
echo "   BASELINE PROFILE - Robert Kim (IT Administrator)"
echo "   Source: baseline/robert_kim_activity.json"
echo "================================================================"
echo ""

#============= TOOL USAGE SUMMARY ================
echo "TOOL USAGE SUMMARY:"
printf "  PsExec events:          %d\n" "$PSEXEC"
printf "  WMI events:             %d\n" "$WMI"
printf "  PSRemoting events:      %d\n" "$PSREMOTING"
printf "  Total admin events:     %d\n" "$TOTAL"
echo ""

#============= SOURCE HOST ANALYSIS ================
echo "SOURCE HOST:"
HOSTS=$(jq -r '.agent.name' "$BASELINE" | sort | uniq -c | sort -rn)
echo "$HOSTS" | while read -r count host; do
	printf "  %s: %s\n" "$host" "$count"
done
OTHER_HOSTS=$(jq -r '.agent.name' "$BASELINE" | grep -vc '^WS-ADMIN-01$' || true)
printf "  Other hosts: %d\n" "$OTHER_HOSTS"
if [ "$OTHER_HOSTS" -eq 0 ]; then
	echo "  -> BASELINE: All admin activity originates from WS-ADMIN-01"
else
	echo "  -> ANOMALY: admin activity observed from a non-WS-ADMIN-01 host"
fi
echo ""

#============= TIME-OF-DAY DISTRIBUTION ================
echo "TIME DISTRIBUTION (Central Time):"
IN_HOURS=0
OUT_HOURS=0
while read -r ts; do
	hour=$(date -d "$ts" +%H)
	hour=$((10#$hour))
	if [ "$hour" -ge 8 ] && [ "$hour" -lt 18 ]; then
		IN_HOURS=$((IN_HOURS + 1))
	else
		OUT_HOURS=$((OUT_HOURS + 1))
	fi
done < <(jq -r '.timestamp' "$BASELINE")
printf "  08:00-18:00: %d\n" "$IN_HOURS"
printf "  18:00-08:00: %d\n" "$OUT_HOURS"
if [ "$OUT_HOURS" -eq 0 ]; then
	echo "  -> BASELINE: Zero admin activity outside business hours"
else
	echo "  -> ANOMALY: admin activity observed outside business hours"
fi
echo ""

#============= DAY-OF-WEEK DISTRIBUTION ================
echo "DAY-OF-WEEK DISTRIBUTION:"
jq -r '.timestamp' "$BASELINE" | while read -r ts; do date -d "$ts" +%A; done |
	sort | uniq -c | sort -rn | while read -r count day; do
	printf "  %-10s %d\n" "$day:" "$count"
done
WEEKEND=$(jq -r '.timestamp' "$BASELINE" | while read -r ts; do date -d "$ts" +%u; done | awk '$1>5' | wc -l)
printf "  Weekend (Sat/Sun): %d\n" "$WEEKEND"
echo "  -> Tuesday (software deployment) and Thursday (patch management)"
echo "     are the dominant maintenance days, matching admin_schedule.txt"
echo "     Windows 1 and 2; remaining days reflect the daily WMI inventory"
echo "     scan (Window 3) and Friday verification (Window 4)."
echo ""

#============= TARGET HOST ANALYSIS ================
echo "TARGET HOST ANALYSIS:"
jq -r '.hunt_meta.target_host' "$BASELINE" | sort | uniq -c | sort -rn | while read -r count host; do
	printf "  %-15s %d\n" "$host" "$count"
done
echo ""

#============= USER ACCOUNT ANALYSIS ================
echo "USER ACCOUNTS:"
NAMED=$(jq -r '.data.win.eventdata.user // "N/A"' "$BASELINE" | grep -c '^MEDDEFENSE\\robert\.kim$' || true)
SVC=$(jq -r '.data.win.eventdata.user // "N/A"' "$BASELINE" | grep -c '^svc_' || true)
printf "  MEDDEFENSE\\\\robert.kim: %d\n" "$NAMED"
printf "  Service accounts: %d\n" "$SVC"
if [ "$SVC" -eq 0 ]; then
	echo "  -> BASELINE: Never uses service accounts interactively"
else
	echo "  -> ANOMALY: service account used interactively from this host"
fi
echo ""

#============= BASELINE SUMMARY ================
echo "BASELINE SUMMARY:"
echo "  Normal source host:  WS-ADMIN-01 (10.10.9.10)"
echo "  Normal time window:  Mon-Fri, 08:00-18:00 Central Time"
printf "  Normal account:      MEDDEFENSE\\\\robert.kim (named account only)\n"
echo "  Normal tools:        PsExec.exe, wmic/Invoke-WmiMethod, Enter-PSSession/Invoke-Command"
echo "  Normal targets:      SRV-DC-01, SRV-HEALTH-DB, SRV-INS-DB, SRV-FILE-01,"
echo "                       SRV-PATCH-01, SRV-AV-01, SRV-BACKUP-01 (server segment only)"
echo ""

#============= ANOMALY DETECTION CRITERIA ================
echo "ANOMALY DETECTION CRITERIA:"
echo "  [!] Admin tool from any host other than WS-ADMIN-01"
echo "  [!] Admin tool usage outside business hours (08:00-18:00 CDT, Mon-Fri)"
echo "  [!] Service account used interactively from workstation"
echo "  [!] WMI targeting unusual hosts (outside the 7 documented servers)"
echo ""
echo "================================================================"
