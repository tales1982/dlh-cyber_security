#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ALERTS="$SCRIPT_DIR/siem_export/wazuh_alerts_14d.json"
SYSMON="$SCRIPT_DIR/siem_export/wazuh_raw_sysmon_14d.json"

for f in "$ALERTS" "$SYSMON"; do
	if [ ! -f "$f" ]; then
		echo "Required SIEM export not found: $f" >&2
		exit 1
	fi
done

# Both exports are JSON Lines (one JSON object per line, not a wrapping
# array) -- confirmed by direct inspection, not assumed. All jq queries
# below stream both files as a single combined event set via `cat`.

echo "================================================================"
echo "   DATA RECONNAISSANCE - MedDefense SIEM Export"
echo "================================================================"
echo ""

#============= DATASET METADATA ================
ALERTS_N=$(wc -l <"$ALERTS")
SYSMON_N=$(wc -l <"$SYSMON")
TOTAL=$((ALERTS_N + SYSMON_N))

TIMESTAMPS_SORTED=$(cat "$ALERTS" "$SYSMON" | jq -r '.timestamp' | sort)
FIRST="${TIMESTAMPS_SORTED%%$'\n'*}"
LAST="${TIMESTAMPS_SORTED##*$'\n'}"
DAYS=$(( ($(date -d "$LAST" +%s) - $(date -d "$FIRST" +%s)) / 86400 ))

echo "DATASET METADATA:"
printf "  Total events:   %d  (alerts: %d, raw sysmon: %d)\n" "$TOTAL" "$ALERTS_N" "$SYSMON_N"
printf "  Time range:     %s to %s\n" "$FIRST" "$LAST"
printf "  Duration:       %d days\n" "$DAYS"
echo "  Format:         JSON Lines (one JSON object per line)"
echo ""

#============= TOP 10 EVENT TYPES ================
echo "TOP 10 EVENT TYPES:"
EVENT_TYPES=$(cat "$ALERTS" "$SYSMON" | jq -r '.rule.id + "\t" + .rule.description' | sort | uniq -c | sort -rn)
echo "$EVENT_TYPES" | head -10 | while read -r count rest; do
	id="${rest%%$'\t'*}"
	desc="${rest#*$'\t'}"
	printf "  %-6s %-6s %s\n" "$count" "$id" "$desc"
done
echo ""

#============= SOURCE HOST DISTRIBUTION ================
HOST_COUNTS=$(cat "$ALERTS" "$SYSMON" | jq -r '.agent.name' | sort | uniq -c | sort -rn)
HOST_UNIQ=$(echo "$HOST_COUNTS" | wc -l)
echo "SOURCE HOST DISTRIBUTION (top 10 of $HOST_UNIQ hosts):"
echo "$HOST_COUNTS" | head -10 | while read -r count host; do
	printf "  %-15s %d\n" "$host:" "$count"
done
echo ""

#============= SEVERITY DISTRIBUTION ================
echo "SEVERITY DISTRIBUTION (rule.level):"
cat "$ALERTS" "$SYSMON" | jq -r '.rule.level' | sort -n | uniq -c |
	while read -r count level; do
		printf "  Level %-3s %d\n" "$level" "$count"
	done
echo ""

#============= HOURLY DISTRIBUTION ================
echo "HOURLY DISTRIBUTION (24-hour histogram, Central Time / CDT):"
cat "$ALERTS" "$SYSMON" |
	jq -r '.timestamp | sub("\\.[0-9]+\\+00:00$"; "Z") | strptime("%Y-%m-%dT%H:%M:%SZ") | mktime - 18000 | strftime("%H")' |
	sort | uniq -c | while read -r count hour; do
	bar=$(printf '%*s' "$((count / 20))" '' | tr ' ' '#')
	printf "  %s:00  %-4s %s\n" "$hour" "$count" "$bar"
done
echo ""

#============= HYPOTHESIS COVERAGE MATRIX ================
echo "HYPOTHESIS COVERAGE MATRIX:"

H1=$(cat "$ALERTS" "$SYSMON" | jq -sr '[.[] | select((.data.win.eventdata.image // "" | test("PsExec";"i")) or (.data.win.eventdata.commandLine // "" | test("psexec";"i")))] | length')
H2=$(cat "$ALERTS" "$SYSMON" | jq -sr '[.[] | select(.data.win.system.eventID=="10" and (.data.win.eventdata.targetImage // "" | test("lsass.exe";"i")))] | length')
H3=$(cat "$ALERTS" "$SYSMON" | jq -sr '[.[] | select((.data.win.eventdata.image // "" | test("wmic|WmiPrvSE";"i")) or (.data.win.eventdata.commandLine // "" | test("wmic";"i")))] | length')
H4=$(cat "$ALERTS" "$SYSMON" | jq -sr '[.[] | select((.data.win.eventdata.commandLine // "" | test("PSSession|Invoke-Command|wsmprovhost";"i")) or (.data.win.eventdata.image // "" | test("wsmprovhost";"i")))] | length')
H5=$(cat "$ALERTS" "$SYSMON" | jq -sr '[.[] | select(.data.win.system.eventID=="4624" and (.data.win.eventdata.targetUserName // "" | test("^svc_")))] | length')

print_hyp() {
	local label="$1" count="$2"
	if [ "$count" -gt 0 ]; then
		printf "  %-20s [OK]   %d candidate events available\n" "$label" "$count"
	else
		printf "  %-20s [GAP]  no candidate events found -- hypothesis not testable\n" "$label"
	fi
}
print_hyp "H1 (PsExec):" "$H1"
print_hyp "H2 (LSASS):" "$H2"
print_hyp "H3 (WMI):" "$H3"
print_hyp "H4 (PSRemoting):" "$H4"
print_hyp "H5 (Svc Accounts):" "$H5"
echo ""
echo "================================================================"
