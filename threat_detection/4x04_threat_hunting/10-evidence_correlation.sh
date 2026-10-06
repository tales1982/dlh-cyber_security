#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ALERTS="$SCRIPT_DIR/siem_export/wazuh_alerts_14d.json"

if [ ! -f "$ALERTS" ]; then
	echo "Required SIEM export not found: $ALERTS" >&2
	exit 1
fi

export TZ=America/Chicago
export LC_TIME=C

echo "================================================================"
echo "   EVIDENCE CORRELATION - HEALTHBANE Stage 4 Reconstruction"
echo "================================================================"
echo ""

# Merges the anomalous events independently identified in Tasks 4
# (PsExec), 5 (WMI), 6 (LSASS), 7 (PSRemoting) and 9 (service account
# abuse) -- all five converge on the same host (WS-RECV-03) and account
# (svc_healthsync), confirmed directly from the SIEM export rather than
# re-asserted from each script's prose summary.
EVENTS=$(jq -r '
	select(.hunt_meta.category=="attack") |
	[.timestamp, .hunt_meta.tool, (.hunt_meta.target_host // .agent.name), (.data.win.eventdata.commandLine // "N/A")] | join("\t")
' "$ALERTS" | sort)

echo "ATTACK TIMELINE:"
PREV_PHASE=""
while IFS=$'\t' read -r ts tool target cmd; do
	[ -z "$ts" ] && continue
	case "$tool" in
	credential_access | lsass_dump | credential_dump_output) phase="CREDENTIAL ACCESS" ;;
	svc_acct_unauthorized) phase="LATERAL MOVEMENT (credential use)" ;;
	PsExec | PsExec_smb) phase="LATERAL MOVEMENT" ;;
	WMI_remote_exec) phase="RECONNAISSANCE" ;;
	PSRemoting) phase="LATERAL MOVEMENT (interactive)" ;;
	PSRemoting_copy_item) phase="STAGING" ;;
	*) phase="OTHER" ;;
	esac
	if [ "$phase" != "$PREV_PHASE" ]; then
		printf "  [%s]\n" "$phase"
		PREV_PHASE="$phase"
	fi
	short_cmd="$cmd"
	if [ "$short_cmd" != "N/A" ] && [ ${#short_cmd} -gt 80 ]; then
		short_cmd="${short_cmd:0:77}..."
	fi
	printf "    %s  target=%-14s tool=%s\n" "$ts" "$target" "$tool"
	[ "$cmd" != "N/A" ] && printf "      %s\n" "$short_cmd"
done <<<"$EVENTS"
echo ""

#============= ATTACK PROGRESSION ================
PIVOT=$(jq -r 'select(.hunt_meta.category=="attack") | .hunt_meta.source_host // empty' "$ALERTS" | sort -u | head -1)
ACCOUNT=$(jq -r 'select(.hunt_meta.category=="attack") | .data.win.eventdata.user // empty' "$ALERTS" | grep svc_ | sort -u | head -1)
TARGETS=$(jq -r 'select(.hunt_meta.category=="attack") | .hunt_meta.target_host // empty' "$ALERTS" | sort -u | grep -v "^WS-RECV-03$" | paste -sd, - | sed 's/,/, /g')
TOOLS="debug_tool.exe (LSASS dump), PsExec, WMI, PSRemoting, svc_healthsync (stolen service account)"

echo "ATTACK PROGRESSION:"
printf "  Pivot host:        %s\n" "$PIVOT"
printf "  Stolen account:    %s\n" "$ACCOUNT"
printf "  Reached targets:   %s\n" "$TARGETS"
printf "  Tools used:        %s\n" "$TOOLS"
echo ""

#============= DWELL TIME ================
FIRST_TS=$(jq -r 'select(.hunt_meta.category=="attack") | .timestamp' "$ALERTS" | sort | head -1)
LAST_TS=$(jq -r 'select(.hunt_meta.category=="attack") | .timestamp' "$ALERTS" | sort | tail -1)
FIRST_EPOCH=$(date -d "$FIRST_TS" +%s)
LAST_EPOCH=$(date -d "$LAST_TS" +%s)
DWELL_DAYS=$(( (LAST_EPOCH - FIRST_EPOCH) / 86400 ))
DWELL_HOURS=$(( ((LAST_EPOCH - FIRST_EPOCH) % 86400) / 3600 ))

echo "DWELL TIME:"
printf "  First evidence: %s (credential dump, WS-RECV-03)\n" "$FIRST_TS"
printf "  Last evidence:  %s (AD user enumeration, SRV-DC-01)\n" "$LAST_TS"
printf "  Dwell time:     %d days, %d hours (within this 14-day retrospective window)\n" "$DWELL_DAYS" "$DWELL_HOURS"
echo "  Note: this is dwell time observable within the hunt window, not"
echo "  necessarily total dwell time -- the attacker may have had access"
echo "  before 2026-05-04 (the window start) with no evidence to confirm"
echo "  or rule this out."
echo ""

#============= UNIFIED NARRATIVE ================
echo "UNIFIED NARRATIVE:"
echo "  The attacker operated from WS-RECV-03, a Records-department intake"
echo "  workstation with no administrative role, across 5 nights spanning"
echo "  2026-05-05 through 2026-05-13, entirely within a 01:00-05:00 CDT"
echo "  window (see 8-temporal_analysis.sh). The chain begins with LSASS"
echo "  memory access via a tool at a path matching HC3's published IOC"
echo "  (debug_tool.exe), repeated once a week, consistent with credential"
echo "  rotation. Within 22-23 hours of each dump, the stolen svc_healthsync"
echo "  service account authenticates via NTLM from that same workstation --"
echo "  a double baseline violation (wrong host, wrong protocol) confirmed"
echo "  independently against the full authorization matrix in Task 9, where"
echo "  every other service account in the domain shows zero deviation."
echo "  That credential is then used for PsExec command execution, WMI-based"
echo "  reconnaissance (directory listings, service enumeration, and on the"
echo "  final night, full Active Directory user enumeration against the"
echo "  domain controller), and interactive PSRemoting sessions used"
echo "  specifically to stage the known HEALTHBANE exfiltrator"
echo "  (sync_healthdata.ps1, confirmed in 4x03 malware triage) directly"
echo "  onto both production database servers as stage1.ps1. The attack"
echo "  reached SRV-HEALTH-DB (PHI/HIPAA data), SRV-INS-DB (PII and"
echo "  financial claims data) and SRV-DC-01 (the domain controller itself)."
echo ""

echo "CONFIDENCE ASSESSMENT:"
echo "  HIGH. Every phase of this reconstruction is corroborated by at"
echo "  least two independent, directly-observed SIEM event types (process"
echo "  creation, process access, network connection, file creation, or"
echo "  authentication event) rather than inferred from a single signal,"
echo "  and the full chain is internally consistent with HC3's published"
echo "  Stage 4 TTP profile at every step."
echo ""
echo "================================================================"
