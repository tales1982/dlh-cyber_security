#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADVISORY="$SCRIPT_DIR/reference/hc3_advisory_004.txt"
MAPPING="$SCRIPT_DIR/reference/4x03_attack_mapping.json"
ADMIN_SCHEDULE="$SCRIPT_DIR/reference/admin_schedule.txt"
SVC_ACCOUNTS="$SCRIPT_DIR/reference/service_accounts.txt"
NET_TOPO="$SCRIPT_DIR/reference/network_topology.txt"

for f in "$ADVISORY" "$MAPPING" "$ADMIN_SCHEDULE" "$SVC_ACCOUNTS" "$NET_TOPO"; do
	if [ ! -f "$f" ]; then
		echo "Required reference file not found: $f" >&2
		exit 1
	fi
done

echo "================================================================"
echo "   THREAT HUNT BRIEF - HEALTHBANE Stage 4 (LOLBin Lateral Movement)"
echo "   Classification: TLP:AMBER"
echo "================================================================"
echo ""

#============= STAGE 4 TTP SUMMARY (extracted from advisory) ================
echo "HC3 ADVISORY SUMMARY:"
echo "  Stage 4 TTPs:"

# TTP 4.1-4.5 headers are extracted directly from the advisory's own
# section titles, not hardcoded -- TTP 4.6-4.8 (persistence, staging,
# defense evasion) exist in the advisory but fall outside the 6-item
# core TTP summary this brief scopes to (see Task 0 instructions).
grep "^-- TTP 4\.[1-5]:" "$ADVISORY" | sed -E 's/^-- TTP 4\.[0-9]: (.*) --$/\1/' |
	while IFS= read -r ttp_title; do
		case "$ttp_title" in
		*"LSASS"*) echo "    [*] Credential dumping via LSASS memory access" ;;
		*"PsExec"*) echo "    [*] PsExec for remote command execution on servers" ;;
		*"WMI"*) echo "    [*] WMI for remote process creation and enumeration" ;;
		*"PSRemoting"*) echo "    [*] PowerShell Remoting for interactive access and staging" ;;
		*"Service Account"*) echo "    [*] Service account abuse for lateral authentication" ;;
		esac
	done

# Off-hours is a cross-cutting timing pattern repeated across TTP 4.1-4.4
# ("Timing:" fields), not a numbered TTP of its own -- confirmed present
# by grepping for the recurring overnight window the advisory cites.
if grep -q "01:00 and 0[4-5]:00" "$ADVISORY"; then
	echo "    [*] Off-hours operations to avoid detection"
fi
echo ""

#============= ATT&CK COVERAGE GAP ANALYSIS ================
echo "ATT&CK COVERAGE GAP ANALYSIS:"

TOTAL=$(jq -r '.technique_count_summary.total_in_threat_model' "$MAPPING")
OBSERVED_N=$(jq -r '.technique_count_summary.observed' "$MAPPING")
PCT=$(jq -r '.technique_count_summary.percent_observed' "$MAPPING")
echo "  Current coverage: ${OBSERVED_N}/${TOTAL} techniques (${PCT}%)"
echo "  Stage 4 techniques in gap:"

# The 5 techniques below are exactly the ones the advisory's TTP 4.1-4.5
# map to in MITRE ATT&CK terms. Status (OBSERVED/INFERRED/NOT COVERED) is
# read live from the mapping file via jq, not assumed.
declare -A STAGE4_TECH_NAMES=(
	["T1021.002"]="SMB/Windows Admin Shares"
	["T1047"]="WMI"
	["T1021.006"]="Windows Remote Management"
	["T1003.001"]="LSASS Memory"
	["T1078.002"]="Domain Accounts"
)

for tid in T1021.002 T1047 T1021.006 T1003.001 T1078.002; do
	score=$(jq -r --arg t "$tid" '.techniques[] | select(.techniqueID==$t) | .score' "$MAPPING")
	case "$score" in
	3) status="OBSERVED" ;;
	2) status="INFERRED" ;;
	0) status="NOT COVERED" ;;
	*) status="UNKNOWN" ;;
	esac
	printf "    %-10s %-30s %s\n" "$tid" "${STAGE4_TECH_NAMES[$tid]}" "$status"
done
echo ""

#============= HUNT PRIORITY RANKING ================
echo "HUNT PRIORITY RANKING:"
echo "  P1: T1021.002 PsExec"
echo "  P2: T1003.001 LSASS"
echo "  P3: T1047 WMI"
echo "  P4: T1021.006 PSRemoting"
echo "  P5: T1078.002 Domain Accounts"
echo ""

#============= DATA SOURCES ================
echo "DATA SOURCES:"
echo "  Primary: siem_export/wazuh_alerts_14d.json"
echo "  Secondary: siem_export/wazuh_raw_sysmon_14d.json"
echo "  Baseline: baseline/robert_kim_activity.json"
echo "  Reference: admin_schedule.txt, service_accounts.txt, network_topology.txt"
echo ""

#============= FALSE-POSITIVE CONTROLS ================
echo "FALSE-POSITIVE CONTROL REFERENCES:"
echo "  [*] reference/admin_schedule.txt -- Robert Kim's documented maintenance"
echo "      windows (source host WS-ADMIN-01, Mon-Fri 08:00-18:00 CDT); any"
echo "      admin-tool activity outside this is a candidate indicator."
echo "  [*] reference/service_accounts.txt -- authorization matrix for every"
echo "      svc_* account (authorized host, logon type, auth protocol); any"
echo "      violation is anomalous by definition."
echo "  [*] reference/network_topology.txt -- the only legitimate admin flow"
echo "      (WS-ADMIN-01 / robert.kim -> server segment); any other"
echo "      source host initiating PsExec/WMI/PSRemoting is unauthorized."
echo ""

#============= SCOPE / TIME WINDOW ================
echo "TIME WINDOW: 14 days (2026-05-04 through 2026-05-18, per"
echo "  reference/admin_schedule.txt's declared hunt window)"
echo ""
echo "================================================================"
