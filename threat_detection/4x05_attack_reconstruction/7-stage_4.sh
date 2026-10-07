#!/bin/bash
set -euo pipefail

# Task 7 - Stage 4 Reconstruction.
# Reconstructs lateral movement, credential access, data staging,
# persistence/anti-forensics and the containment moment, integrating
# previous_findings/4x04_hunting_report.txt with the three IR evidence
# sources (memory, disk, firewall) analyzed in Tasks 1-3. (Task 6, a
# planned "Stage 3 Malware Deployment" reconstruction, was not part of this
# batch; Stage 3 facts needed here are cited directly from
# previous_findings/4x03_malware_summary.txt instead.)

echo "================================================================================"
echo "   ATTACK RECONSTRUCTION: Stage 4"
echo "   Lateral Movement, Data Staging, and Containment"
echo "================================================================================"
echo

echo "--------------------------------------------------------------------------------"
echo "LATERAL MOVEMENT CHAIN"
echo "--------------------------------------------------------------------------------"
cat <<'EOF'
  [2026-05-05T08:22:14Z / 03:22:14 CDT] Credential dump #1 on WS-RECV-03
    Tool: debug_tool.exe (stripped Mimikatz fork, C:\Windows\Temp\)
    Target: LSASS process memory (PID 648), GrantedAccess 0x1010
    Result: svc_healthsync credential obtained (confirmed in plaintext,
      4 occurrences, in the partially recovered out.dat dump file)
    Evidence: 4x04 (hunt H4), IR-memory (stale handle, same bitmask),
      IR-disk (file recovered, hash obtained, prefetch timestamp
      2026-05-05 03:22:14 CDT exact match), IR-firewall (24 KB first
      exfil chunk riding the KNOWN_C2 channel at 08:22:14Z, same second)
    Technique: T1003.001 LSASS Memory
    Confidence: CONVERGED (4 independent sources)

  [2026-05-06T07:11:46Z / 02:11:46 CDT] First lateral movement: WS-RECV-03
    -> SRV-HEALTH-DB
    Tool: PsExec64.exe (staged to C:\Users\Public\Tmp\ at 01:58:14 CDT,
      first executed 02:11:42 CDT per prefetch)
    Credential: svc_healthsync (NTLM, not Kerberos -- violates the service-
      account authorization matrix's Kerberos-only rule)
    Evidence: 4x04 (hunt H1), IR-firewall (1,832-second SMB session,
      10.10.3.21 -> 10.10.20.30:445), IR-disk (prefetch + ShellBags),
      IR-memory (exited-process EPROCESS pool tag)
    Technique: T1021.002 SMB/Windows Admin Shares, T1078.002 Valid Accounts:
      Domain Accounts, T1550.002 Pass the Hash (NTLM-on-Kerberos-only
      account is consistent with, but does not on its own prove, hash-based
      credential use -- carried as a deliberate non-overclaim from the
      post-4x04 ATT&CK layer)
    Confidence: CONVERGED (4 sources)
    Followed within 2 minutes by: RPC/WMI recon (wmic.exe, 10.10.20.30:135
      and :49664) and Copy-Item of sync_healthdata.ps1 to
      \\SRV-HEALTH-DB\C$\Users\Public\stage1.ps1 (02:36 CDT)

  [2026-05-07T06:47:33Z / 01:47:33 CDT] Scheduled-task persistence installed
    Task: "HealthSync Update Service," daily 02:00 trigger, Hidden=true
    Evidence: IR-memory (TaskCache hive), IR-disk (full on-disk XML,
      byte-identical EncodedCommand to the live memory capture)
    Technique: T1053.005 Scheduled Task/Job
    Confidence: CONVERGED (2 independent IR collection methods)

  [2026-05-07T06:48:11Z / 01:48:11 CDT] Secondary C2 established (38s later)
    Destination: 203.0.113.47:8443 (Hetzner DE, distinct ASN from primary)
    Evidence: IR-firewall (first session), IR-memory (still ESTABLISHED at
      capture, 8 days later)
    Technique: T1071.001 (secondary channel)
    Confidence: PROBABLE -- see Task 5; this is a Stage 4 event (tied to
      the scheduled task), not a Stage 2 event

  [2026-05-09T07:46:18Z / 02:46:18 CDT] Second lateral movement: WS-RECV-03
    -> SRV-INS-DB
    Tool/credential: same as above (PsExec64.exe, svc_healthsync, NTLM)
    Evidence: 4x04 (hunt H1), IR-firewall (1,704-second SMB session to
      10.10.20.31:445)
    Confidence: CONVERGED (2 sources)
    Followed by: Security event log clear, 03:01:42-03:12:02 CDT (12-min
      gap) -- T1070.001, evidenced by IR-disk ($MFT) and corroborated by
      IR-memory's recovered exfiltrator config fragment (clear_logs:true)

  [2026-05-12T07:45:01Z / 02:45:01 CDT] Credential dump #2 (refresh)
    Evidence: 4x04 (hunt H4, second event), IR-memory, IR-disk (prefetch)
    Confidence: CONVERGED (3 sources)

  [2026-05-13T07:08:58Z / 02:08:58 CDT] Third lateral movement: WS-RECV-03
    -> SRV-DC-01
    Evidence: 4x04 (hunt H1/H3 -- includes Get-ADUser enumeration),
      IR-firewall (1,993-second SMB session to 10.10.20.10:445, higher
      bytes_in than bytes_out consistent with a bulk AD export)
    Confidence: CONVERGED (2 sources)

  NO LATERAL-MOVEMENT STEPS WERE FOUND IN IR EVIDENCE THAT THE 4x04 HUNT
  MISSED. All three pivots (SRV-HEALTH-DB, SRV-INS-DB, SRV-DC-01) and both
  credential dumps that the firewall/memory/disk evidence independently
  reveals match the hunt's own H1/H4 findings exactly -- IR evidence here
  functions as CORROBORATION, not discovery of a missed step. The one
  genuinely new lateral-adjacent finding is the secondary C2 (Stage 4,
  not lateral movement per se) and the scheduled task, neither of which the
  4x04 hunt's own scope included (it explicitly did not query for
  persistence, per its "REMAINING GAPS" section).
EOF
echo

echo "--------------------------------------------------------------------------------"
echo "CREDENTIAL ACCESS"
echo "--------------------------------------------------------------------------------"
cat <<'EOF'
  Credential compromised: svc_healthsync (service account, SRV-HEALTH-DB's
    own service identity, per reference/network_topology.txt's
    administrative authorization matrix -- this account should NEVER
    authenticate interactively from a workstation).
  Obtained via: LSASS memory dump (debug_tool.exe), twice, 7 days apart.
  Evidence: 4x04 (H4 + H5), IR-memory (handle structures + recovered
    plaintext in disk D4), IR-disk (prefetch, $MFT, AppCompat-cache
    RecentFileExecution timestamps).
  No additional credentials were found compromised beyond svc_healthsync in
  any IR evidence source. The AD-enumeration export recovered from
  SRV-DC-01 (D3, 1,184 accounts) is RECONNAISSANCE data about the domain's
  accounts, not evidence that any OTHER credential was itself dumped or
  used. dmarsh's credential (Stage 1) was separately confirmed NOT reused
  post-rotation by 4x00; this reconstruction found no IR evidence
  contradicting that.
EOF
echo

echo "--------------------------------------------------------------------------------"
echo "DATA ACCESS AND STAGING"
echo "--------------------------------------------------------------------------------"
cat <<'EOF'
  Sequence (established by IR-disk's $MFT timeline plus the scheduled
  task's own recovered script body): the exfiltrator (sync_healthdata.ps1)
  ran ON SRV-HEALTH-DB via the staged stage1.ps1 copy (per 4x04 H3) for the
  query-execution step, but the RECOVERED staging artifacts (CSV + ZIP) were
  all found on WS-RECV-03 in C:\Users\Public\Tmp\, not on the database
  servers. The recovered script's own logic ($cmd.CommandText = $query;
  ...Compress-Archive...Move-Item -Destination 'C:\Users\Public\Tmp\')
  confirms the flow was: query executed against the remote SQL Server
  (connecting FROM the trigger host using the inherited svc_healthsync
  auth token), results written locally, compressed, and staged -- meaning
  the SQL query itself ran wherever the scheduled task's PowerShell
  process executed, which the task's own Author/Principal metadata and
  prefetch evidence place on WS-RECV-03, pulling data TO WS-RECV-03 rather
  than staging directly on the database server.

  [2026-05-08T07:36-07:38Z / 02:36-02:38 CDT] First cycle
    Query output: out_20260508023559.csv (14,211,304 bytes, 47,138 rows,
      health_records.dbo.patients schema) -- IR-disk (D1)
    Archive: staging_export_001.zip (14,219,484 bytes) -- IR-disk (D1)
    Transmission: 14,219,484 bytes to 185.220.101.45:443 at 07:38:14Z --
      IR-firewall (EXFIL_BURST), byte-for-byte match to the archive
    Technique: T1005 Data from Local System, T1560.001 Archive via Utility,
      T1074.001 Local Data Staging, T1041 Exfiltration Over C2 Channel
    Confidence: CONVERGED (disk + firewall, exact byte match)

  [2026-05-11T08:14-08:17Z / 03:14-03:17 CDT] Second cycle (insurance_db,
    SRV-INS-DB target) -- same technique set, same confidence, 11,802,944
    bytes, transmitted 08:17:18Z.

  [2026-05-13T07:31-07:34Z / 02:31-02:34 CDT] Third cycle (AD enumeration
    from SRV-DC-01, not patient data) -- 8,419,232 bytes, transmitted
    07:34:14Z.

  STAGING FLOW CONFIRMED: SQL Server (SRV-HEALTH-DB / SRV-INS-DB) -> query
  results written locally on the task's execution host -> compressed ->
  staged in C:\Users\Public\Tmp\ -> transmitted over the primary C2 -> both
  local copies deleted within 3 minutes.
  EXFILTRATION STATUS: COMPLETED, three times, independently confirmed by
  Task 3's byte-exact firewall/disk correlation -- not "interrupted."
EOF
echo

echo "--------------------------------------------------------------------------------"
echo "PERSISTENCE AND OPERATIONAL SECURITY"
echo "--------------------------------------------------------------------------------"
cat <<'EOF'
  Persistence layer 1 (Stage 2->3): HKCU Run-key, installed 2026-04-22,
    survives reboots, re-launches the RAT.
  Persistence layer 2 (Stage 4): scheduled task, installed 2026-05-07,
    independent of the Run-key, re-triggers the exfiltrator daily even if
    the RAT process itself were killed (defense in depth from the
    attacker's side).
  Redundant C2: primary (185.220.101.45:443, continuous since 2026-04-15)
    plus secondary (203.0.113.47:8443, since 2026-05-07) -- a deliberate
    fallback channel, per the firewall export's own key finding F2.
  OPSEC taken: Defender exclusion for C:\Windows\Temp (2026-05-04, ~9h
    before the first credential dump -- preparation, not improvisation),
    event-log clearing (2026-05-09, 12-minute gap), immediate deletion of
    every staging artifact after use.
  OPSEC NOT taken (what exposed them): no VSS/USN-journal/prefetch
    deletion, no timestamp manipulation, no cleanup of UserAssist/AppCompat-
    cache/ShellBags evidence, and -- most consequentially -- a fixed,
    narrow operating window (02:00-04:00 CDT every active night) that never
    varied across 6 distinct nights, which is exactly the kind of
    behavioral regularity a baseline-comparison hunt (4x04) is built to
    catch. The attacker's tradecraft was adequate against signature/hash
    detection but not against behavioral baselining -- this is the
    project's own stated reason the 4x04 hunt succeeded where passive
    detection had not.
EOF
echo

echo "--------------------------------------------------------------------------------"
echo "CONTAINMENT MOMENT"
echo "--------------------------------------------------------------------------------"
cat <<'EOF'
  The 4x04 hunt's H1 finding (anomalous PsExec from a non-admin host) was
  escalated for executive review and authorized isolation of WS-RECV-03 at
  13:38 CDT on 2026-05-15 (verbal authorization by Dr. Morales, confirmed
  by email 13:46 CDT; network ACL applied at 13:42 CDT per
  ir_evidence/ir_team_notes.txt Entry #001).

  Last attacker-attributable activity: the scheduled task's 2026-05-15
  02:00 CDT run, which received an empty/noop C2 config and produced no
  staging output -- the LAST attack-chain event in any evidence source,
  11.5 hours before isolation.

  IF NOT CONTAINED: based on the observed 2-3 day cadence between
  completed exfil cycles (05-08, 05-11, 05-13) and the scheduled task's
  continuing daily trigger, the attacker was positioned to run additional
  query/stage/exfil cycles indefinitely against any database reachable with
  the svc_healthsync credential, and -- per ir_team_notes.txt Entry #004's
  [DISPUTED] claim from Robert Kim about WS-RECV-04/WS-RECV-07 -- possibly
  to extend to other hosts, though no evidence source here confirms that
  claim. The two persistence layers (Run-key + scheduled task) mean
  re-infection on next boot was still possible as of containment; James
  Chen's own Entry #007 note states the RAT remains fully functional on
  disk and would reach out again if the host were ever returned to the
  network without re-imaging.
EOF
echo
echo "================================================================================"
echo "END OF STAGE 4 RECONSTRUCTION"
echo "================================================================================"
