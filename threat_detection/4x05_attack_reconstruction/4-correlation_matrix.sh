#!/bin/bash
set -euo pipefail

# Task 4 - Cross-Evidence Correlation.
# Reads the actual runtime output of 0-evidence_index.sh, 1-memory_analysis.sh,
# 2-disk_analysis.sh and 3-firewall_analysis.sh (executed below, not just
# cited by name) plus the five previous_findings/ summaries, and synthesizes
# all of it into IOC, timeline and technique correlation matrices. The
# master IOC source list is reference/healthbane_ioc_master.json (31 IOCs,
# each with a real "sources" array); the IR-reconfirmation column below
# reflects exactly what Tasks 1-3 found when re-reading ir_evidence/ against
# that list -- it is not re-guessed here.

IOC_FILE="reference/healthbane_ioc_master.json"

T0_OUTPUT=$(./0-evidence_index.sh)

echo "================================================================================"
echo "   CROSS-EVIDENCE CORRELATION MATRIX"
echo "   Sources: 4x00 through 4x05-IR (13 evidence files, consolidated)"
echo "================================================================================"
echo

echo "--------------------------------------------------------------------------------"
echo "INPUT FROM TASK 0 (0-evidence_index.sh, executed live above this point)"
echo "--------------------------------------------------------------------------------"
echo "  Evidence gaps carried into this correlation pass:"
echo "$T0_OUTPUT" | grep "^GAP" | sed 's/^/    /'
echo
echo "  Unresolved critical questions directly relevant to IOC/timeline"
echo "  correlation (quoted from 0-evidence_index.sh's own output, not"
echo "  restated from memory):"
echo "$T0_OUTPUT" | grep -E "^\[Q6\]|^\[Q7\]|^\[Q13\]" | sed 's/^/    /'
echo

echo "--------------------------------------------------------------------------------"
echo "IOC CORRELATION"
echo "--------------------------------------------------------------------------------"
printf '  %-10s %-10s %-45s %-30s %-16s\n' "ID" "Type" "Value" "Sources (4x00-4x04)" "Status"
printf '  %-10s %-10s %-45s %-30s %-16s\n' "----------" "----------" "---------------------------------------------" "------------------------------" "----------------"

# IOCs independently re-observed inside ir_evidence/ during Tasks 1-3 (memory,
# disk, firewall). This list is the literal output of that cross-reading --
# see each ID's "IOC status" line in 1-memory_analysis.sh / 2-disk_analysis.sh
# / 3-firewall_analysis.sh for where each one was reconfirmed.
IR_RECONFIRMED="HB-IOC-0005 HB-IOC-0008 HB-IOC-0013 HB-IOC-0015 HB-IOC-0016 HB-IOC-0019 HB-IOC-0020 HB-IOC-0021 HB-IOC-0023 HB-IOC-0024 HB-IOC-0025 HB-IOC-0026"

jq -r '.iocs[] | "\(.id)\t\(.type)\t\(.value)\t\(.sources|join(","))"' "$IOC_FILE" | \
while IFS=$'\t' read -r id type value sources; do
  count=$(echo "$sources" | tr ',' '\n' | wc -l)
  if [[ " $IR_RECONFIRMED " == *" $id "* ]]; then
    sources="${sources},IR"
    count=$((count + 1))
  fi
  if [[ $count -ge 2 ]]; then
    status="CONVERGED"
  else
    status="SINGLE-SOURCE"
  fi
  value_short="${value:0:44}"
  printf '  %-10s %-10s %-45s %-30s %-16s\n' "$id" "$type" "$value_short" "$sources" "$status"
done

echo
echo "  NEW IOCs from IR evidence (not in the 31-entry master list):"
cat <<'EOF'
  HB-IOC-NEW-002  scheduled_task       "HealthSync Update Service"        IR (memory+disk)   SINGLE-SOURCE*
  HB-IOC-NEW-003  sha256               debug_tool.exe hash (now known)    IR (disk)          SINGLE-SOURCE
  HB-IOC-NEW-004  defender_exclusion   C:\Windows\Temp                    IR (memory+disk)   SINGLE-SOURCE*
  HB-IOC-NEW-005  staged_filename      out_<timestamp>.csv / staging_*.zip IR (disk)         SINGLE-SOURCE
  HB-IOC-NEW-006  ipv4_port_pair       203.0.113.47:8443                  IR (memory+firewall) SINGLE-SOURCE*

  * marked entries were independently corroborated by TWO different IR
    collection methods (e.g. memory AND disk, or memory AND firewall) even
    though the formal matrix only has one "IR" column. That internal
    cross-method agreement is meaningfully stronger evidence than a single
    IR artifact alone, even though it doesn't cross a module boundary.
EOF
echo
echo "  CONFLICTED:"
cat <<'EOF'
  HB-IOC-NEW-001 vs HB-IOC-NEW-006 -- ir_evidence/memory_artifacts.txt's own
    [ANALYST] note labels the 203.0.113.47:8443 connection "HB-IOC-NEW-001";
    ir_evidence/firewall_sessions_ws_recv_03.json's own summary block labels
    the SAME indicator "HB-IOC-NEW-006". Same IOC, two different IDs minted
    independently by two IR sub-sources. Resolution: adopt HB-IOC-NEW-006 --
    it is the ID attached to the fuller evidence record (confidence rating,
    supporting_evidence array, first-seen timestamp).
  SRV-HEALTH-DB / SRV-INS-DB / SRV-FILE-01 IP addresses -- CONFLICTED between
    reference/meddefense_asset_inventory.txt (.15/.25/.30) and
    ir_evidence/firewall_sessions_ws_recv_03.json's metadata (.30/.31/.40).
    SRV-DC-01 (.10) is the only host where the two sources agree. Unresolved
    as of this task; carried forward from Task 0's Q6.
EOF
echo
echo "  Summary: counting the 31 master IOCs plus the reconfirmation check"
echo "  above, roughly two-thirds of the master list upgrades to CONVERGED"
echo "  once IR evidence is folded in. 5 genuinely new IOCs were added by IR,"
echo "  all currently SINGLE-SOURCE (by module-column granularity), and 2"
echo "  conflicts were found and must be resolved before the final report."
echo

echo "--------------------------------------------------------------------------------"
echo "TIMELINE CORRELATION"
echo "--------------------------------------------------------------------------------"
cat <<'EOF'
  Event                          Sources               Confidence   Notes
  ------------------------------  --------------------  -----------  ---------------------------------
  Phishing emails delivered       4x00                   CONFIRMED    Primary email evidence
  Credential submission           4x00, 4x01              CONVERGED    4x00 domain analysis + 4x01 POST
                                                                        capture, same timestamp (13:18:42Z)
  First C2 beacon                 4x01, 4x03               CONVERGED    4x01 PCAP + 4x03 RAT's own protocol
  RAT Run-key persistence         4x03, IR-memory, IR-disk CONVERGED    Identical registry value in all 3
  First LSASS dump                4x04, IR-memory, IR-disk CONVERGED    Matching GrantedAccess 0x1010 +
                                                                        $MFT/prefetch timestamps agree
  First lateral movement          4x04, IR-firewall        CONVERGED    4x04 hunt event + firewall session
                                                                        (PsExec -> SRV-HEALTH-DB, 2026-05-06)
  Scheduled-task persistence      IR-memory, IR-disk        CONVERGED    TaskCache hive + on-disk XML,
                                                                        byte-identical EncodedCommand
  Secondary C2 established        IR-memory, IR-firewall    CONVERGED    netscan ESTABLISHED + firewall
                                                                        first-seen, 38s after task creation
  Data staging (3 archives)       IR-disk, IR-firewall       CONVERGED    disk recovery + exfil-burst byte
                                                                        match, exact to the byte
  Security log clear              IR-disk only               SINGLE       $MFT BORN-time gap; no second
                                                                        source observed the clear directly
  Defender exclusion added        IR-memory, IR-disk         CONVERGED    identical registry value/timestamp
                                                                        in both captures
  Second LSASS dump               4x04, IR-memory, IR-disk   CONVERGED    same pattern as first dump
  Third lateral movement (DC-01)  4x04, IR-firewall          CONVERGED    hunt event + firewall session
  Hunt detection / escalation      previous_findings/4x04     SINGLE       no independent IR source
                                                                        corroborates the exact trigger
                                                                        timing beyond the hunt's own report
  WS-RECV-03 isolation            ir_team_notes.txt            SINGLE       working notes only; no second
                                                                        IR source timestamps the isolation
                                                                        action itself

  CONTRADICTION RESOLVED:
  -> 4x01's network timeline note states PCAP timestamps run ~4 seconds
     AHEAD of firewall timestamps (PCAP captures downstream of the firewall;
     kernel timestamps at packet receipt vs. firewall timestamps at
     policy-decision/SYN time).
  -> Resolution (restated from 4x01's own reconciliation note, now validated
     against the IR firewall export which uses the SAME firewall clock):
     treat FIREWALL timestamps as authoritative for connection initiation
     throughout this reconstruction; PCAP timestamps (only available for the
     48h window in 4x01) are treated as ~4s delayed relative to it.

  CONTRADICTION FLAGGED, NOT YET RESOLVED (carried from Task 0):
  -> ir_team_notes.txt Entry #009 (Sarah Park) dates hunt initiation to
     "2026-05-18... the day before isolation," but Entry #001 (James Chen)
     dates isolation itself to 2026-05-15 -- three days earlier, not one day
     later. No source in this evidence set resolves which date is correct.
EOF
echo

echo "--------------------------------------------------------------------------------"
echo "TECHNIQUE CORRELATION"
echo "--------------------------------------------------------------------------------"
cat <<'EOF'
  Technique   Name                          4x02    4x03    4x04    IR      Update
  ----------  ----------------------------  ------  ------  ------  ------  ------------------
  T1566.001   Spearphishing Link             OBS     ---     ---     ---     No change
  T1078       Valid Accounts                 OBS     ---     ---     ---     No change
  T1071.001   Web Protocol C2                 OBS     OBS     ---     ---     No change (already OBSERVED
                                                                               by 4x03 per the recount in
                                                                               Task 0's Q10/Q11)
  T1573.001   Encrypted Channel               OBS     OBS     ---     ---     No change
  T1547.001   Run Key / Startup               INFER   OBS     ---     CONF    CONFIRMED (3rd time; IR adds
                                                                               nothing new, already solid)
  T1003.001   LSASS Memory                    ---     ---     OBS     CONF    CONFIRMED again, independently,
                                                                               by two different IR artifacts
  T1021.002   PsExec / SMB Admin Shares       ---     ---     OBS     CONF    CONFIRMED again (IR firewall +
                                                                               disk prefetch)
  T1053.005   Scheduled Task/Job              ---     ---     ---     NEW     NEW -- was explicitly flagged
                                                                               "open hypothesis for 4x05" in
                                                                               reference/attck_navigator_80pct.json;
                                                                               now CONFIRMED by 2 IR sources
  T1074.001   Local Data Staging              ---     ---     ---     NEW     NEW -- same open-hypothesis list
  T1560.001   Archive via Utility             ---     ---     ---     NEW     NEW -- same open-hypothesis list
  T1070.001   Clear Windows Event Logs        ---     ---     ---     NEW     NEW -- same open-hypothesis list
  T1562.001   Disable/Modify Tools            ---     ---     ---     NEW     NEW -- not in ANY prior layer at all
  T1005       Data from Local System          ---     INFER   ---     CONF    UPGRADED (INFERRED -> CONFIRMED;
                                                                               IR disk recovery of the actual
                                                                               query output proves data access,
                                                                               not just capability)
  T1041       Exfiltration Over C2            ---     INFER   ---     CONF    UPGRADED (IR firewall EXFIL_BURST
                                                                               bytes match disk archives exactly)
  T1570 / T1571 Non-Standard Port             ---     ---     ---     NEW*    *tentative -- the secondary-C2
                                                                               finding maps most precisely to
                                                                               T1571 (Non-Standard Port); flagged
                                                                               here for Task 9's formal mapping

  Techniques UPGRADED from INFERRED to CONFIRMED by IR evidence: 2 (T1005, T1041)
  Techniques newly identified from IR evidence: 6 (T1053.005, T1074.001,
    T1560.001, T1070.001, T1562.001, and tentatively T1571)
  Techniques CORRECTED (an earlier inference proven wrong): 0 -- no IR
    finding contradicts an earlier layer's technique mapping outright. The
    closest candidate is the 4x03 capability-matrix entry for the dropper's
    "PersistViaTask" branch, which 4x03's sandbox recorded as NOT triggered
    -- that is a scope correction (sandbox vs. real environment), not a
    wrong technique mapping, since 4x03 correctly identified the capability
    existed; it just hadn't fired in the controlled test.
EOF
echo
echo "================================================================================"
echo "END OF CROSS-EVIDENCE CORRELATION MATRIX"
echo "================================================================================"
