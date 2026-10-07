#!/bin/bash
set -euo pipefail

# Task 5 - Stage 1-2 Reconstruction.
# Reconstructs HEALTHBANE Stages 1 (phishing / initial access) and 2 (C2
# establishment) by integrating previous_findings/4x00_phishing_summary.txt,
# previous_findings/4x01_network_timeline.txt, previous_findings/
# 4x02_attack_mapping.json and the new ir_evidence/firewall_sessions_
# ws_recv_03.json. Every timestamp below is quoted directly from one of
# those four sources.

echo "================================================================================"
echo "   ATTACK RECONSTRUCTION: Stages 1-2"
echo "   Initial Access through C2 Establishment"
echo "================================================================================"
echo

echo "--------------------------------------------------------------------------------"
echo "STAGE 1: INITIAL ACCESS (Phishing Campaign)"
echo "--------------------------------------------------------------------------------"
cat <<'EOF'
  Timeline: 2026-04-14 to 2026-04-21 (campaign active, per 4x00)

  [2026-04-14T13:14:22Z] Phishing email batch delivered to MedDefense staff
    Evidence: 4x00 (8 emails analyzed, 3 confirmed malicious -- E1/E2/E3,
      all SPF hardfail / DKIM missing / DMARC fail, sent from lookalike
      domains meddefense-portal.com, meddefense-benefits.com,
      outlook-protection.com)
    Technique: T1566.001 Spearphishing Link, T1583.001 Acquire
      Infrastructure (lookalike domains registered 2026-04-12, 2 days
      before launch)
    Confidence: CONFIRMED (primary email-header evidence)

  [2026-04-14T13:18:05Z] Diane Marsh (dmarsh, WS-RECV-03) clicks E1's link
    Evidence: 4x00 (URL analysis, domain WHOIS), 4x01 (PCAP DNS query for
      meddefense-portal.com at this exact timestamp)
    Technique: T1566.001 -> user interaction on lookalike credential portal
    Confidence: CONVERGED (2 independent sources, matching timestamp)

  [2026-04-14T13:18:42Z] Credentials submitted to attacker-controlled domain
    Evidence: 4x00 (domain/URL analysis), 4x01 (743-byte POST request
      captured in PCAP to https://meddefense-portal.com/login.aspx)
    Technique: T1078 Valid Accounts (obtained via phishing)
    Confidence: CONVERGED (2 independent sources, exact timestamp match)

  [2026-04-14T13:20:00Z] AD password rotation by Robert Kim
    Evidence: 4x00 (incident response record)
    Note: this closes a 17-minute (not 2-minute) exposure window --
      13:18:42Z to 13:20Z is 78 seconds short of 2 minutes by the clock, but
      4x00's own write-up states "17-minute exposure window" measured from
      the CLICK (13:18:05Z) through session force-revocation at 13:22Z, not
      from credential submission alone. Whether the dmarsh credential was
      USED during that 17-minute window is NOT answered by any source in
      this evidence set -- carried forward as an open question (Task 0 Q3).
    Confidence: CONFIRMED for the rotation action itself; UNRESOLVED for
      credential use during the exposure window.
EOF
echo

echo "--------------------------------------------------------------------------------"
echo "STAGE 2: C2 ESTABLISHMENT"
echo "--------------------------------------------------------------------------------"
cat <<'EOF'
  Timeline: 2026-04-15 (second-wave dropper email) through 2026-04-22
  (first RAT execution at boot) -- approximately 8 days after credential
  theft, NOT hours. This reconstruction corrects a common misreading: the
  Stage 1 credential theft and the Stage 2 RAT delivery are NOT the same
  event chain. 4x00's own "NOTES FOR 4x05" explicitly states the sandbox did
  not capture any post-credential-harvest payload delivery in Stage 1 --
  that came via a SEPARATE follow-up email 24 hours later.

  [2026-04-15T08:43:18Z] Second-wave email delivers Stage-2 dropper
    Evidence: 4x01 (PCAP timeline event T-006): attachment
      April-Invoice-MD2026.docm (= HEALTHBANE_S2_invoice.docm, renamed),
      released from quarantine by a helpdesk operator who did not check it
    Technique: T1566.001 (second spearphishing wave), T1204.002 (pending
      user execution)
    Confidence: CONFIRMED (PCAP + 4x01 timeline)

  [2026-04-15T08:51:09Z - 08:51:11Z] Dropper macro downloads RAT payload
    Evidence: 4x01 (PCAP events T-007/T-008): svchost_update.exe
      (287,444 bytes) pulled from 185.220.101.45
    Technique: T1105 Ingress Tool Transfer, T1059.005 VBA macro execution
    Confidence: CONFIRMED (PCAP byte-for-byte transfer capture)

  [2026-04-15T08:51:38Z] First C2 beacon from WS-RECV-03
    Evidence: 4x01 (PCAP beacon analysis, event T-009)
    Technique: T1071.001 Application Layer Protocol: Web
    Confidence: CONFIRMED (PCAP only -- firewall export (IR) does not begin
      until 2026-05-02, so no firewall corroboration exists for THIS specific
      beacon; the firewall export's own first recorded session is a steady-
      state beacon on 2026-05-02T08:14:08Z, 17 days later)

  [2026-04-22T06:14:17Z] First post-install boot; RAT Run-key persistence
    first takes effect
    Evidence: 4x03 (sample analysis -- RAT writes HKCU Run-key on install),
      IR-memory (printkey shows Run-key last-write exactly 2026-04-22
      06:14:47 UTC, 30 seconds after this boot time)
    Technique: T1547.001 Registry Run Keys
    Confidence: CONVERGED (4x03 capability + IR memory artifact, matching
      timestamp to the half-minute)

  [2026-05-02T08:14:08Z] Earliest beacon INSIDE the firewall export window
    Evidence: IR-firewall (first reproduced KNOWN_C2 session)
    Note: this is NOT "C2 established" -- the channel has been running
      continuously since 2026-04-15 per 4x01. This is simply the first
      event the 14-day firewall export happens to capture, 17 days into an
      already-running beacon. The firewall's own summary confirms the
      beacon was CONTINUOUS and UNBROKEN across its entire 13.5-day
      observed span (3,958 sessions at ~5-minute intervals).
    Technique: T1071.001, T1573.001 (RC4-wrapped TLS, per 4x03's reverse
      engineering of the hardcoded key)
    Confidence: CONFIRMED (IR-firewall), corroborating 4x01's established
      cadence rather than establishing a new one

  [2026-05-07T06:48:11Z] Secondary C2 channel first connects: 203.0.113.47:8443
    Evidence: IR-firewall only (first session), IR-memory (connection still
      ESTABLISHED 8 days later at capture)
    Note: this is 23 DAYS after the primary C2 was established (2026-04-15),
      not part of initial Stage 2 setup. It is directly tied to Stage 4
      (lateral movement / persistence), appearing 38 seconds after the
      scheduled task's own registration timestamp -- see Task 7.
    Technique: T1071.001 (secondary channel), tentatively T1571 Non-Standard
      Port
    Confidence: PROBABLE (IR-firewall + IR-memory agree on existence and
      ESTABLISHED state; neither source captures the delivery mechanism that
      told the RAT about this IP -- carried forward as Task 0's Q5)
EOF
echo

echo "--------------------------------------------------------------------------------"
echo "STAGE 1-2 SUMMARY"
echo "--------------------------------------------------------------------------------"
cat <<'EOF'
  Duration, click to first beacon: 2026-04-14T13:18:05Z to 2026-04-15T08:51:38Z
    = 19 hours 33 minutes (NOT the same day -- the dropper arrived in a
    SEPARATE, second-wave email the following morning).
  Duration, first beacon to persistent boot-time execution: 2026-04-15T08:51:38Z
    to 2026-04-22T06:14:17Z = 6 days 21 hours (the RAT ran once on 04-15 at
    delivery, then relied on the Run-key to survive the next reboot a week
    later -- this is the true gap 4x01 flagged as its "14-day visibility
    gap," now partly explained: the RAT was dormant-but-present for most of
    that window, not freshly installed at the end of it).
  Techniques mapped: T1566.001, T1583.001, T1078, T1204.002, T1105,
    T1059.005, T1071.001, T1573.001, T1547.001
  IOCs: 10 referenced (7 CONVERGED per Task 4, 3 SINGLE-SOURCE)
  Key finding: the secondary C2 (203.0.113.47:8443) was NOT operational
    during Stage 2 at all -- it first appears 23 days later, on 2026-05-07,
    tied to the scheduled-task persistence event, not to initial C2
    establishment. Treating it as part of "Stage 2" would be a timeline
    error; it belongs in Stage 4.
EOF
echo
echo "================================================================================"
echo "END OF STAGE 1-2 RECONSTRUCTION"
echo "================================================================================"
