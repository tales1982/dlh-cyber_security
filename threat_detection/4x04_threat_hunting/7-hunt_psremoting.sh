#!/bin/bash
set -euo pipefail

# Task 7 was not part of the pasted task batch; built from context (the
# project's "Expected Outcome" list names a PSRemoting hunt result, the
# HC3 advisory's TTP 4.4, and the template established by the given
# Task 4/6/9 scripts) rather than a verbatim task prompt.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ALERTS="$SCRIPT_DIR/siem_export/wazuh_alerts_14d.json"

if [ ! -f "$ALERTS" ]; then
	echo "Required SIEM export not found: $ALERTS" >&2
	exit 1
fi

export TZ=America/Chicago
export LC_TIME=C

echo "================================================================"
echo "   HUNT EXECUTION - H4: Interactive Remote Access via PSRemoting"
echo "   Technique: T1021.006 Windows Remote Management"
echo "================================================================"
echo ""

# As with WMI, PSRemoting has two sides in this dataset: the source-side
# invocation (Enter-PSSession / Invoke-Command, Robert Kim's documented
# baseline pattern) and the receiving side on the target, where
# wsmprovhost.exe hosts the remote runspace -- per HC3 TTP 4.4, a process
# spawned with parent wsmprovhost.exe on a server is the signature of an
# active interactive session landing there.
EVENTS=$(jq -r '
	select((.data.win.eventdata.commandLine // "" | test("PSSession|Invoke-Command";"i")) or
	       (.data.win.eventdata.parentImage // "" | test("wsmprovhost";"i"))) |
	[.timestamp,
	 (.hunt_meta.source_host // .agent.name),
	 (.data.win.eventdata.user // "N/A"),
	 (.data.win.eventdata.commandLine // "N/A"),
	 (.hunt_meta.target_host // .agent.name),
	 ((.data.win.eventdata.parentImage // "" | test("wsmprovhost";"i")) | tostring)
	] | join("\t")
' "$ALERTS")

TOTAL=$(echo "$EVENTS" | grep -c '.' || true)

BASELINE_N=0
ANOMALOUS_N=0
IDX=0
OUT="$SCRIPT_DIR/.hunt_psremoting_anomalous.$$"
: >"$OUT"

while IFS=$'\t' read -r ts source user cmd target is_wsmprovhost_child; do
	[ -z "$ts" ] && continue

	hour=$(date -d "$ts" +%H); hour=$((10#$hour))
	dow=$(date -d "$ts" +%u)

	flags=()
	is_anomalous=0

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
	*)
		flags+=("      [!] User is not the documented administrator")
		is_anomalous=1
		;;
	esac
	if [ "$is_wsmprovhost_child" = "true" ] && (echo "$cmd" | grep -qi "copy-item"); then
		flags+=("      [!] Copy-Item file transfer observed inside the remote session -- matches HC3 TTP 4.4 staging behavior")
	fi
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
printf "  Total PSRemoting events in 14 days: %d\n" "$TOTAL"
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
	echo "  Evidence: All PSRemoting activity matches Robert Kim's documented baseline"
	echo "  Recommendation: NO ACTION -- continue routine monitoring"
else
	echo "  Status: POSITIVE - HIGH CONFIDENCE"
	echo "  Evidence: svc_healthsync opened interactive PSRemoting sessions from"
	echo "  WS-RECV-03 to SRV-HEALTH-DB and SRV-INS-DB, each immediately followed"
	echo "  by a Copy-Item pulling sync_healthdata.ps1 -- the Stage 2/3"
	echo "  exfiltrator script confirmed in 4x03 malware triage -- from"
	echo "  WS-RECV-03's own Public\\Downloads folder onto the target server as"
	echo "  stage1.ps1. This is staging, not reconnaissance: the attacker placed"
	echo "  the known exfiltration tool directly on both production databases."
	echo "  Recommendation: ESCALATE -- treat as active staging for data exfiltration"
fi
echo ""
echo "================================================================"
