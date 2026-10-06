#!/bin/bash
set -euo pipefail

# Task 11 was not part of the pasted task batch; built from context (the
# project's "Expected Outcome" list calls for an "Updated ATT&CK Navigator
# layer," and Task 14's own instructions cite "ATT&CK Update (from T11)").
#
# This script upgrades ONLY the 5 techniques this hunt directly confirmed
# with real SIEM evidence in Tasks 4-9 (PsExec, WMI, PSRemoting, LSASS,
# service account abuse). T1550.002 (Pass-the-Hash) and T1053.005
# (Scheduled Task) remain at their pre-hunt status deliberately: the NTLM
# authentication observed is consistent with, but does not on its own
# prove, pass-the-hash (vs. a recovered plaintext credential used over
# NTLM), and a direct search of this dataset for scheduled-task-creation
# evidence (Event 4698, Sysmon 12/13 on the Schedule\TaskCache registry
# key) found none -- upgrading either would overclaim beyond the evidence,
# exactly the mistake this whole project's OBSERVED/INFERRED discipline
# exists to prevent.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_LAYER="$SCRIPT_DIR/reference/4x03_attack_mapping.json"
OUTPUT_LAYER="$SCRIPT_DIR/attack_layer_post_hunt.json"

if [ ! -f "$SOURCE_LAYER" ]; then
	echo "Required file not found: $SOURCE_LAYER" >&2
	exit 1
fi

echo "================================================================"
echo "   ATT&CK NAVIGATOR LAYER UPDATE - Post-Hunt (4x04)"
echo "================================================================"
echo ""

echo "TECHNIQUES UPGRADED (NOT COVERED -> OBSERVED):"
echo "  T1021.002  SMB/Windows Admin Shares (PsExec)      -- 4-hunt_psexec.sh"
echo "  T1047      Windows Management Instrumentation     -- 5-hunt_wmi.sh"
echo "  T1021.006  Windows Remote Management (PSRemoting) -- 7-hunt_psremoting.sh"
echo "  T1003.001  OS Credential Dumping: LSASS Memory     -- 6-hunt_credentials.sh"
echo "  T1078.002  Valid Accounts: Domain Accounts         -- 9-hunt_svcaccount.sh"
echo ""
echo "TECHNIQUES DELIBERATELY NOT UPGRADED:"
echo "  T1550.002  Pass-the-Hash -- NTLM auth observed is consistent with"
echo "             but does not prove hash-based (vs. recovered plaintext)"
echo "             authentication; remains INFERRED."
echo "  T1053.005  Scheduled Task -- no Event 4698 or Schedule\\TaskCache"
echo "             registry evidence found in this dataset; remains NOT COVERED."
echo ""

UPGRADE_IDS="T1021.002 T1047 T1021.006 T1003.001 T1078.002"
UPGRADE_COMMENTS='{
  "T1021.002": "OBSERVED (post-hunt, 4x04 Task 4) - 6 PsExec events from WS-RECV-03 (non-admin workstation) using svc_healthsync, off-hours, against SRV-HEALTH-DB/SRV-INS-DB/SRV-DC-01. See 4-hunt_psexec.sh.",
  "T1047": "OBSERVED (post-hunt, 4x04 Task 5) - WmiPrvSE.exe spawned cmd.exe/powershell.exe on all 3 target servers within ~30 min of each PsExec session, matching HC3 TTP 4.3 exactly. See 5-hunt_wmi.sh.",
  "T1021.006": "OBSERVED (post-hunt, 4x04 Task 7) - Interactive PSRemoting sessions from WS-RECV-03 to SRV-HEALTH-DB/SRV-INS-DB, each followed by Copy-Item staging the 4x03-confirmed exfiltrator sync_healthdata.ps1 onto the target. See 7-hunt_psremoting.sh.",
  "T1003.001": "OBSERVED (post-hunt, 4x04 Task 6) - debug_tool.exe (path matches HC3 IOC) accessed lsass.exe (grantedAccess 0x1010) twice, ~1 week apart, each followed by a .dat output file and svc_healthsync auth within 24h. See 6-hunt_credentials.sh.",
  "T1078.002": "OBSERVED (post-hunt, 4x04 Task 9) - svc_healthsync authenticated via NTLM from WS-RECV-03 (a workstation) 6 times -- a double violation (wrong host + wrong auth protocol) of the service account authorization matrix. Every other service account in the domain shows zero deviation. See 9-hunt_svcaccount.sh."
}'

jq --argjson ids "$(echo "$UPGRADE_IDS" | tr ' ' '\n' | jq -R . | jq -s .)" \
   --argjson comments "$UPGRADE_COMMENTS" \
   --arg desc "HEALTHBANE - MedDefense Coverage (post-4x04 hunt). Upgrades T1021.002, T1047, T1021.006, T1003.001 and T1078.002 from NOT COVERED to OBSERVED based on direct SIEM evidence found in Tasks 4-9 of the 4x04 threat hunt. T1550.002 and T1053.005 deliberately left unchanged -- see 11-attack_update.sh header comment." '
	.description = $desc |
	.name = "HEALTHBANE - MedDefense Coverage (post-4x04)" |
	.techniques = [.techniques[] |
		if (.techniqueID as $t | $ids | index($t)) then
			.score = 3 |
			.color = "#c40000" |
			.comment = $comments[.techniqueID]
		else . end
	] |
	.technique_count_summary.observed = ([.techniques[] | select(.score==3)] | length) |
	.technique_count_summary.not_covered = ([.techniques[] | select(.score==0)] | length) |
	.technique_count_summary.inferred = ([.techniques[] | select(.score==2)] | length) |
	.technique_count_summary.percent_observed = (([.techniques[] | select(.score==3)] | length) * 100 / (.technique_count_summary.total_in_threat_model) | floor) |
	.technique_count_summary.percent_mapped = ((([.techniques[] | select(.score==3)] | length) + ([.techniques[] | select(.score==2)] | length)) * 100 / (.technique_count_summary.total_in_threat_model) | floor) |
	.metadata = (.metadata | map(if .name=="coverage_summary" then .value = "\(.value) -> POST-HUNT: \([$ids[]] | length) techniques upgraded via 4x04" else . end))
' "$SOURCE_LAYER" >"$OUTPUT_LAYER"

echo "Output file: attack_layer_post_hunt.json"
echo ""

echo "COVERAGE COMPARISON:"
# Recomputed directly from each file's technique[].score array, not from
# the stored technique_count_summary metadata: the SOURCE file's own
# summary (16 observed / 3 inferred) does not match its own technique
# array (14 score=3, 5 score=2) -- a genuine inconsistency in the provided
# reference file, not introduced here. Both before/after figures below are
# computed the same way for a valid comparison.
BEFORE_TOTAL=$(jq -r '.techniques | length' "$SOURCE_LAYER")
BEFORE_OBS=$(jq -r '[.techniques[] | select(.score==3)] | length' "$SOURCE_LAYER")
BEFORE_INF=$(jq -r '[.techniques[] | select(.score==2)] | length' "$SOURCE_LAYER")
BEFORE_PCT=$(awk -v o="$BEFORE_OBS" -v t="$BEFORE_TOTAL" 'BEGIN{printf "%d", 100*o/t}')
BEFORE_MAPPED_PCT=$(awk -v o="$BEFORE_OBS" -v i="$BEFORE_INF" -v t="$BEFORE_TOTAL" 'BEGIN{printf "%d", 100*(o+i)/t}')
AFTER_OBS=$(jq -r '.technique_count_summary.observed' "$OUTPUT_LAYER")
AFTER_PCT=$(jq -r '.technique_count_summary.percent_observed' "$OUTPUT_LAYER")
AFTER_MAPPED_PCT=$(jq -r '.technique_count_summary.percent_mapped' "$OUTPUT_LAYER")
printf "  Before hunt: %d/%d OBSERVED (%d%%)   [%d%% when INFERRED is included]\n" "$BEFORE_OBS" "$BEFORE_TOTAL" "$BEFORE_PCT" "$BEFORE_MAPPED_PCT"
printf "  After hunt:  %d/%d OBSERVED (%d%%)   [%d%% when INFERRED is included]\n" "$AFTER_OBS" "$BEFORE_TOTAL" "$AFTER_PCT" "$AFTER_MAPPED_PCT"
echo ""
echo "  Note: the source reference file's own technique_count_summary"
echo "  (16 observed / 3 inferred) does not match its own technique array"
echo "  (14 score=3 / 5 score=2) -- both before/after figures above are"
echo "  recomputed directly from each file's technique list, not from"
echo "  stored summary metadata, so this comparison is apples-to-apples."
echo ""
echo "================================================================"
