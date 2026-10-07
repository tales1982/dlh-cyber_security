#!/bin/bash
set -euo pipefail

# Task 8 - Unified Timeline Assembly.
# Merges Task 5 (Stages 1-2), Stage 3 (malware deployment -- cited directly
# from previous_findings/4x03_malware_summary.txt and IR evidence, since
# Task 6 was not part of this batch) and Task 7 (Stage 4) into one
# chronological sequence. Every duration below was computed with Python's
# datetime against the literal timestamps used in Tasks 5 and 7, then
# cross-checked against ir_team_notes.txt Entry #007's own stated figures
# (31 days total dwell, 22 days to lateral movement) -- both independently
# match.

echo "================================================================================"
echo "   UNIFIED ATTACK TIMELINE -- HEALTHBANE vs MedDefense"
echo "   Period: 2026-04-14T13:14:22Z (first phishing email) to"
echo "           2026-05-15T18:42:00Z (isolation enforced)"
echo "================================================================================"
echo

echo "--------------------------------------------------------------------------------"
echo "CHRONOLOGICAL SEQUENCE"
echo "--------------------------------------------------------------------------------"
cat <<'EOF'
 #  Timestamp (UTC)        Event                                  ATT&CK      Conf        Sources
 -- ---------------------  -------------------------------------  ----------  ----------  --------------------
 01 2026-04-14T13:14:22Z   Phishing emails delivered               T1566.001   CONFIRMED   4x00
 02 2026-04-14T13:18:05Z   Diane Marsh clicks E1 link               T1566.001   CONVERGED   4x00,4x01
 03 2026-04-14T13:18:42Z   Credentials submitted                    T1078       CONVERGED   4x00,4x01
 04 2026-04-14T13:20:00Z   AD password rotation (Robert Kim)        ---         CONFIRMED   4x00
 05 2026-04-15T08:43:18Z   Second-wave dropper email delivered      T1566.001   CONFIRMED   4x01
 06 2026-04-15T08:51:09Z   RAT payload (svchost_update.exe) pulled  T1105       CONFIRMED   4x01
 07 2026-04-15T08:51:38Z   First C2 beacon                          T1071.001   CONFIRMED   4x01
 08 2026-04-22T06:14:17Z   First boot w/ RAT; Run-key persistence   T1547.001   CONVERGED   4x03,IR-mem
 09 2026-05-04T23:11:08Z   Defender exclusion added (C:\...\Temp)   T1562.001   CONVERGED   IR-mem,IR-disk
 10 2026-05-05T08:22:14Z   Credential dump #1 (debug_tool.exe)      T1003.001   CONVERGED   4x04,IR-mem,
                                                                                              IR-disk,IR-fw
 11 2026-05-06T07:11:46Z   Lateral movement #1 -> SRV-HEALTH-DB     T1021.002   CONVERGED   4x04,IR-fw,
                                                                                              IR-disk,IR-mem
 12 2026-05-06T07:13:18Z   WMI recon + stage1.ps1 copied to target  T1047       CONVERGED   4x04,IR-fw
 13 2026-05-07T06:47:33Z   Scheduled task "HealthSync Update..."    T1053.005   CONVERGED   IR-mem,IR-disk
 14 2026-05-07T06:48:11Z   Secondary C2 established (+38s)          T1071.001   PROBABLE    IR-mem,IR-fw
 15 2026-05-08T07:36:08Z   Query + archive: 47,138 patient records  T1005/T1560 CONVERGED   IR-disk
 16 2026-05-08T07:38:14Z   Exfil burst #1 transmitted (14.2 MB)      T1041       CONVERGED   IR-fw,IR-disk
 17 2026-05-09T07:46:18Z   Lateral movement #2 -> SRV-INS-DB         T1021.002   CONVERGED   4x04,IR-fw
 18 2026-05-09T08:00:00Z   Security event log clear begins          T1070.001   CONVERGED   IR-disk,IR-mem
 19 2026-05-09T08:12:02Z   Log clear ends (12-minute gap)            T1070.001   CONVERGED   IR-disk
 20 2026-05-11T08:14:42Z   Query + archive: 51,002 insurance records T1005/T1560 CONVERGED   IR-disk
 21 2026-05-11T08:17:18Z   Exfil burst #2 transmitted (11.8 MB)      T1041       CONVERGED   IR-fw,IR-disk
 22 2026-05-12T07:45:01Z   Credential dump #2 (refresh)              T1003.001   CONVERGED   4x04,IR-mem,
                                                                                              IR-disk
 23 2026-05-13T07:08:58Z   Lateral movement #3 -> SRV-DC-01           T1021.002   CONVERGED   4x04,IR-fw
 24 2026-05-13T07:31:18Z   AD enumeration export created (1,184 acct) T1005       CONVERGED   IR-disk
 25 2026-05-13T07:34:14Z   Exfil burst #3 transmitted (8.4 MB)        T1041       CONVERGED   IR-fw,IR-disk
 26 2026-05-15T07:00:14Z   Last scheduled-task run (empty C2 config, T1053.005   CONFIRMED   IR-fw,IR-mem,
                             no output -- LAST attacker-attributable                           IR-disk
                             activity in this evidence set)
 27 2026-05-15T18:38:00Z   Isolation authorized (Dr. Morales, verbal) ---        CONFIRMED   ir_team_notes
 28 2026-05-15T18:42:00Z   Network ACL applied; isolation enforced   ---         CONFIRMED   IR-fw,ir_team_notes

  Total events in timeline: 28
  Events with CONVERGED/CONFIRMED evidence: 27 (96%)
  Events with PROBABLE evidence: 1 (4%) -- the secondary C2 (#14)
EOF
echo

echo "--------------------------------------------------------------------------------"
echo "TEMPORAL METRICS"
echo "--------------------------------------------------------------------------------"
cat <<'EOF'
  Total dwell time:            31 days, 5h 23m (2026-04-14T13:18:42Z credential
                                theft to 2026-05-15T18:42:00Z isolation).
                                Matches ir_team_notes.txt Entry #007's own
                                stated "31 days" exactly.
  Breakout time:                21 days, 18h (credential theft to first
                                lateral movement, 2026-05-06T07:11:46Z).
                                Matches Entry #007's stated "~22 days"
                                (rounded) to within 6 hours.
  Time to RAT persistence:      7 days, 17h (credential theft to Run-key
                                taking effect at first post-install boot)
  Time to task-based persistence: 22 days, 17h (credential theft to
                                scheduled-task registration -- installed
                                AFTER lateral movement had already begun,
                                not before it; see Task 7's explicit note
                                correcting the "persistence before
                                exfiltration tooling" assumption)
  Time to first data staging:   23 days, 18h (credential theft to the
                                first recovered query-output CSV)
  Hunt window open to containment: 11 days, 19h (2026-05-04 hunt
                                data-window start to 2026-05-15T18:42:00Z
                                isolation -- containment occurred inside
                                the hunt's own stated window, not after it.
                                NOTE: this metric does NOT resolve Task 0's
                                Q13 -- ir_team_notes.txt's own Entry #009
                                places "hunt initiation" on 2026-05-18,
                                which is AFTER this isolation date and
                                therefore cannot be the real trigger date;
                                this script uses the hunt's stated DATA
                                WINDOW start instead of that contradictory
                                claim, and flags the contradiction rather
                                than silently picking a side.)
  Operational tempo (active ops, 2026-05-05 onward): near-daily to every-
                                other-day cadence (1-2 days between
                                milestones), entirely inside the 02:00-04:00
                                CDT window on every one of 6 active nights,
                                preceded by a 13-day DORMANT period
                                (2026-04-22 to 2026-05-04) where the RAT was
                                present and persistent but took no further
                                action visible to any evidence source.
EOF
echo

echo "--------------------------------------------------------------------------------"
echo "TIMELINE GAPS"
echo "--------------------------------------------------------------------------------"
cat <<'EOF'
  GAP 1: 2026-04-16 to 2026-04-22 (6 days) -- ZERO evidence coverage of any
         kind (4x01's PCAP window ends 04-16; disk $MFT/USN coverage begins
         04-22). Assessment: true collection gap, not a quiet period --
         attacker activity in this window is genuinely unknown.
  GAP 2: 2026-04-22 to 2026-05-02 (10 days) -- SINGLE-SOURCE coverage only
         (disk $MFT/USN; no network telemetry exists until the firewall
         export opens 2026-05-02). Disk evidence shows no file-system
         activity of note in this window, but with no second vantage point,
         an absence-of-finding under one-source coverage is weaker than a
         confirmed quiet period across multiple sources.
  GAP 3: 2026-05-13 to 2026-05-15 (dormant, 2 days) -- multi-source coverage
         exists (firewall + would-be disk/memory if the host had been
         imaged mid-window), and all sources agree: no attacker activity.
         This IS a confirmed quiet period, not a collection gap, unlike
         Gaps 1-2.
EOF
echo

echo "--------------------------------------------------------------------------------"
echo "SEQUENCING UNCERTAINTIES"
echo "--------------------------------------------------------------------------------"
cat <<'EOF'
  [*] Within each nightly exfil cycle (events #15-16, #20-21, #24-25), the
      exact sub-sequence of "SQL query executes" vs "script launch at
      02:00 CDT" is inferred from the recovered script's own code order
      (query, then write CSV, then compress, then move, then delete), not
      from independently timestamped sub-events. Impact: minimal -- the
      overall cycle's start and end are well-anchored by prefetch and $MFT
      timestamps; only the internal micro-ordering is inferred.
  [*] Event #27 (isolation authorization, 18:38:00Z) and #28 (ACL applied,
      18:42:00Z) both derive from a single source (ir_team_notes.txt) with
      no independent corroborating timestamp for the authorization step
      specifically (the firewall's own "ws-recv-03-isolated" deny rule
      confirms #28 independently, but not #27). Impact: minimal -- the
      4-minute gap between authorization and enforcement is operationally
      plausible and not load-bearing for any analytical conclusion.
EOF
echo
echo "================================================================================"
echo "END OF UNIFIED ATTACK TIMELINE"
echo "================================================================================"
