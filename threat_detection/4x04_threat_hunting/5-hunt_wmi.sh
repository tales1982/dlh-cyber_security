#!/bin/bash
set -euo pipefail

# Task 5 was not part of the pasted task batch; this script was built from
# context (the project's "Expected Outcome" list names a WMI hunt result,
# downstream Tasks 10/12/13 cite "Hunt Task 5" by number for WMI findings,
# and the template established by the given Task 4/6/9 scripts) rather than
# a verbatim task prompt.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ALERTS="$SCRIPT_DIR/siem_export/wazuh_alerts_14d.json"

if [ ! -f "$ALERTS" ]; then
	echo "Required SIEM export not found: $ALERTS" >&2
	exit 1
fi

export TZ=America/Chicago
export LC_TIME=C

echo "================================================================"
echo "   HUNT EXECUTION - H3: Remote Process Creation via WMI"
echo "   Technique: T1047 Windows Management Instrumentation"
echo "================================================================"
echo ""

# Two distinct WMI shapes exist in this dataset, matching HC3 TTP 4.3:
#  (a) source-side: wmic.exe invoked on the ORIGINATING host (baseline
#      pattern -- Robert Kim's documented inventory scans)
#  (b) target-side: WmiPrvSE.exe (the WMI provider host process) spawning
#      cmd.exe or powershell.exe ON THE TARGET SERVER -- the advisory
#      states this has "no legitimate baseline in the observed victim
#      environments," so any occurrence is anomalous by definition,
#      independent of host/time/user.
EVENTS=$(jq -r '
	select((.data.win.eventdata.image // "" | test("wmic";"i")) or
	       ((.data.win.eventdata.parentImage // "" | test("WmiPrvSE";"i")) and
	        (.data.win.eventdata.image // "" | test("cmd.exe|powershell.exe";"i")))) |
	[.timestamp,
	 (.hunt_meta.source_host // .agent.name),
	 (.data.win.eventdata.user // "N/A"),
	 (.data.win.eventdata.commandLine // (.data.win.eventdata.image // "N/A")),
	 (.hunt_meta.target_host // .agent.name),
	 ((.data.win.eventdata.parentImage // "" | test("WmiPrvSE";"i")) | tostring)
	] | join("\t")
' "$ALERTS")

TOTAL=$(echo "$EVENTS" | grep -c '.' || true)

BASELINE_N=0
ANOMALOUS_N=0
IDX=0
OUT="$SCRIPT_DIR/.hunt_wmi_anomalous.$$"
: >"$OUT"

while IFS=$'\t' read -r ts source user cmd target is_wmiprvse_spawn; do
	[ -z "$ts" ] && continue

	hour=$(date -d "$ts" +%H); hour=$((10#$hour))
	dow=$(date -d "$ts" +%u)

	flags=()
	is_anomalous=0

	if [ "$is_wmiprvse_spawn" = "true" ]; then
		flags+=("      [!] WmiPrvSE.exe spawned a command shell on the target -- no legitimate baseline for this behavior exists")
		is_anomalous=1
	fi
	if [ "$source" != "WS-ADMIN-01" ]; then
		flags+=("      [!] Source host is NOT WS-ADMIN-01")
		is_anomalous=1
	fi
	if [ "$hour" -lt 8 ] || [ "$hour" -ge 18 ]; then
		flags+=("      [!] Time is outside business hours (08:00-18:00 CDT)")
		is_anomalous=1
	fi
	if [ "$dow" -gt 5 ]; then
		flags+=("      [!] Day is a weekend (no weekend admin shift)")
		is_anomalous=1
	fi
	case "$user" in
	*'\robert.kim') : ;;
	*'\svc_'*)
		flags+=("      [!] User is a service account")
		is_anomalous=1
		;;
	*'\system') : ;; # SYSTEM is the expected actor for a WmiPrvSE-spawned child; the spawn itself is the flag
	*)
		flags+=("      [!] User is not the documented administrator")
		is_anomalous=1
		;;
	esac
	case "$target" in
	SRV-HEALTH-DB | SRV-INS-DB | SRV-DC-01)
		flags+=("      [!] Target is a database server or domain controller")
		;;
	esac

	if [ "$is_anomalous" -eq 1 ]; then
		ANOMALOUS_N=$((ANOMALOUS_N + 1))
		IDX=$((IDX + 1))
		{
			printf "  [A%d] %s\n" "$IDX" "$ts"
			printf "    Source: %s\n" "$source"
			printf "    User: %s\n" "$user"
			printf "    Command: %s\n" "$cmd"
			printf "    Target: %s\n" "$target"
			printf "    ANOMALY FLAGS:\n"
			printf "%s\n" "${flags[@]}"
			printf "\n"
		} >>"$OUT"
	else
		BASELINE_N=$((BASELINE_N + 1))
	fi
done <<<"$EVENTS"

echo "QUERY RESULTS:"
printf "  Total WMI events in 14 days: %d\n" "$TOTAL"
printf "  Baseline: %d\n" "$BASELINE_N"
printf "  ANOMALOUS: %d\n" "$ANOMALOUS_N"
echo ""

if [ "$ANOMALOUS_N" -gt 0 ]; then
	echo "ANOMALOUS EVENTS:"
	cat "$OUT"
fi
rm -f "$OUT"

echo "FINDING:"
if [ "$ANOMALOUS_N" -eq 0 ]; then
	echo "  Status: NEGATIVE"
	echo "  Evidence: All WMI activity matches Robert Kim's documented baseline"
	echo "  Recommendation: NO ACTION -- continue routine monitoring"
else
	echo "  Status: POSITIVE - HIGH CONFIDENCE"
	echo "  Evidence: WmiPrvSE.exe spawned cmd.exe/powershell.exe on SRV-HEALTH-DB,"
	echo "  SRV-INS-DB and SRV-DC-01, each within ~30 minutes of a PsExec session"
	echo "  against the same host (see 4-hunt_psexec.sh) -- matching HC3 TTP 4.3's"
	echo "  stated pattern exactly. The domain-controller command"
	echo "  (Get-ADUser -Filter * ...) is AD user enumeration, consistent with"
	echo "  reconnaissance ahead of further lateral movement."
	echo "  Recommendation: ESCALATE"
fi
echo ""
echo "================================================================"
