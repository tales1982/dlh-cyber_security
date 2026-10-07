#!/bin/bash
set -euo pipefail

# Task 0 - Evidence Inventory.
# Catalogs all 13 real evidence sources under ir_evidence/, previous_findings/
# and reference/, builds a temporal coverage matrix, and lists the critical
# questions the reconstruction must answer. Every fact below was read
# directly out of the 13 source files (or computed with jq/grep against
# them) before this script was written -- nothing here is invented.

ANALYST_DATE="2026-05-18"

# ---------------------------------------------------------------------------
# Live cross-checks: recompute a few numbers directly from source JSON
# instead of trusting each file's own stored summary field. This matters --
# two of the four JSON sources below do NOT match their own summaries.
# ---------------------------------------------------------------------------

attck_counts() {
  local file="$1"
  local observed inferred not_covered stored
  observed=$(jq '[.techniques[] | select(.score==3)] | length' "$file")
  inferred=$(jq '[.techniques[] | select(.score==2)] | length' "$file")
  not_covered=$(jq '[.techniques[] | select(.score==0)] | length' "$file")
  stored=$(jq -c '.technique_count_summary' "$file")
  printf '     Recomputed from techniques[]: observed=%s inferred=%s not_covered=%s\n' \
    "$observed" "$inferred" "$not_covered"
  printf '     Stored technique_count_summary: %s\n' "$stored"
}

IOC_COUNT_ARRAY=$(jq '.iocs | length' reference/healthbane_ioc_master.json)
IOC_COUNT_STORED=$(jq '.summary.total_iocs' reference/healthbane_ioc_master.json)

FW_FIRST=$(jq -r '.sessions[] | select(has("session_id")) | .ts_start' \
  ir_evidence/firewall_sessions_ws_recv_03.json | sort | head -1)
FW_LAST=$(jq -r '.sessions[] | select(has("session_id")) | .ts_start' \
  ir_evidence/firewall_sessions_ws_recv_03.json | sort | tail -1)
FW_EXPORT_TS=$(jq -r '.metadata.export_timestamp' \
  ir_evidence/firewall_sessions_ws_recv_03.json)

echo "================================================================================"
echo "  4x05 ATTACK RECONSTRUCTION -- EVIDENCE INVENTORY (TASK 0)"
echo "================================================================================"
echo "  Analyst:             [student]"
echo "  Date prepared:        ${ANALYST_DATE}"
echo "  Campaign:             HEALTHBANE"
echo "  Organization:         MedDefense Health Systems"
echo "  Sources catalogued:   13  (5 previous_findings, 4 ir_evidence, 4 reference)"
echo "  Reliability legend:   HIGH primary/controlled collection |"
echo "                        MEDIUM derived summary from a prior investigation |"
echo "                        LOW preliminary/unverified observation"
echo "================================================================================"
echo

echo "--------------------------------------------------------------------------------"
echo "SOURCE CATALOG"
echo "--------------------------------------------------------------------------------"

cat <<'EOF'
[01] Source:       previous_findings/4x00_phishing_summary.txt
     Phase:        4x00 (Phishing Dissection)
     Type:         Email / phishing-forensics summary (derived)
     Coverage:     2026-04-14 to 2026-04-21
     Reliability:  MEDIUM -- derived write-up of the 4x00 investigation, not
                   the raw email/headers themselves.
     Key findings: dmarsh clicked E1 at 13:18:05Z, submitted credentials at
                   13:18:42Z, AD password rotated 13:20Z (17-min exposure
                   window, usage during it is UNRESOLVED -- see Q3 below).
                   Lookalike domains meddefense-portal.com / -benefits.com /
                   outlook-protection.com. 45 recipients had AD passwords
                   reset out of caution.

[02] Source:       previous_findings/4x01_network_timeline.txt
     Phase:        4x01 (Network Forensics / PCAP)
     Type:         Network/PCAP timeline summary (derived)
     Coverage:     2026-04-14T00:00Z to 2026-04-16T00:00Z (48h collection
                   window only).
     Reliability:  MEDIUM -- derived summary; the file itself flags a
                   14-day visibility gap after its own collection ends.
     Key findings: C2 fingerprint (JA3 72a589da586844d7f0818ce684948eea,
                   SNI sync.healthbane-c2.net, RC4 key baked into the
                   sample). Zero lateral movement observed in-window --
                   explicitly a collection gap, not a negative finding.
                   PCAP timestamps run ~4s AHEAD of firewall timestamps.

[03] Source:       previous_findings/4x02_attack_mapping.json
     Phase:        4x02 (Intelligence / ATT&CK baseline)
     Type:         ATT&CK Navigator layer (structured JSON)
     Coverage:     Point-in-time snapshot, approved 2026-04-21. Not a
                   time-window of observation -- a knowledge baseline.
     Reliability:  MEDIUM -- see live recount below; this file's own
                   stored technique_count_summary does not match a direct
                   count of its own techniques[] array.
EOF
attck_counts previous_findings/4x02_attack_mapping.json
cat <<'EOF'
     -> MISMATCH on all three fields (8/7/14 actual vs 11/5/13 stored).
        Do not cite this file's stored summary in the final report; cite
        the recount, or recompute again at reconstruction time.
     Key findings: pre-malware-triage baseline, 8 OBSERVED techniques
                   (phishing + C2 transport only), the rest INFERRED from
                   advisory/commercial intel or NOT COVERED.

[04] Source:       previous_findings/4x03_malware_summary.txt
     Phase:        4x03 (Malware Triage)
     Type:         Malware reverse-engineering summary (derived)
     Coverage:     Analysis conducted 2026-04-22 to 2026-05-02; describes
                   sample behavior touching 2026-04-14 (dropper) through
                   2026-04-30 (exfiltrator first observed via C2 "drop").
     Reliability:  MEDIUM -- derived summary; sample hashes/capabilities
                   are solid but what 4x05 receives is the write-up.
     Key findings: S1 dropper has a GATED "PersistViaTask" branch the 4x03
                   sandbox never triggered (now CONFIRMED executed at
                   MedDefense -- see source 08). S2 RAT: Run-key
                   persistence, RC4 C2 protocol. S3 exfiltrator: SQL
                   query template hardcoded to match SRV-HEALTH-DB's real
                   schema, implying prior reconnaissance. Capability
                   matrix explicitly lists several items UNCONFIRMED at
                   MedDefense pending 4x05.

[05] Source:       previous_findings/4x04_hunting_report.txt
     Phase:        4x04 (Proactive Threat Hunting)
     Type:         SIEM hunt report (derived synthesis of Sysmon/Wazuh
                   query results)
     Coverage:     Hunt data window 2026-05-04 to 2026-05-18; confirmed
                   anomalous activity clusters 2026-05-05 to 2026-05-13.
     Reliability:  MEDIUM -- derived report; underlying Sysmon/4624
                   events are primary, but 4x05 only has the write-up,
                   not the raw SIEM export.
     Key findings: WS-RECV-03 is the SOLE pivot host (H1-H5 all positive,
                   HIGH/CRITICAL confidence). Explicitly did NOT check for
                   persistence, data staging, or anti-forensics -- those
                   three gaps are exactly what the 4 ir_evidence sources
                   below close.

[06] Source:       ir_evidence/firewall_sessions_ws_recv_03.json
     Phase:        4x05-IR (post-isolation evidence export)
     Type:         Firewall session log, abridged (168 of 39,412 sessions)
     Reliability:  HIGH -- primary PA-3220 export via documented REST API
                   call, named custodian (Mike Torres), explicit export
                   method in metadata.
EOF
printf '     Coverage:     metadata.time_range_utc %s to %s\n' \
  "$(jq -r '.metadata.time_range_utc.start' ir_evidence/firewall_sessions_ws_recv_03.json)" \
  "$(jq -r '.metadata.time_range_utc.end' ir_evidence/firewall_sessions_ws_recv_03.json)"
printf '                   First/last reproduced session: %s / %s\n' "$FW_FIRST" "$FW_LAST"
printf '                   Exported %s by Mike Torres.\n' "$FW_EXPORT_TS"
cat <<'EOF'
     Key findings: continuous KNOWN_C2 beacon (3,958 sessions, unbroken).
                   Secondary C2 to 203.0.113.47:8443 first seen
                   2026-05-07T06:48:11Z -- 38 seconds after the scheduled
                   task's registration timestamp (06:47:33Z): a deliberate
                   redundancy operation, not coincidence. 3 EXFIL_BURST
                   sessions (14.2 / 11.8 / 8.4 MB) match the disk-recovered
                   staging archives byte-for-byte -- the single strongest
                   cross-evidence correlation in the whole investigation.
                   47 LATERAL_MOVEMENT sessions to the server segment.

[07] Source:       ir_evidence/memory_artifacts.txt
     Phase:        4x05-IR
     Type:         Volatile memory triage (Volatility 3 plugin output,
                   consolidated extract)
     Coverage:     Single live capture, 2026-05-15 14:18:42 CDT
                   (19:18:42 UTC). Reflects state accumulated since boot
                   at 2026-04-22 06:14:17 UTC.
     Reliability:  HIGH for raw plugin output (WinPmem 4.0.1, SHA256
                   hashed, chain of custody signed). The file's own
                   [ANALYST] lines are self-flagged as interpretive, not
                   primary -- treat those separately.
     Key findings: scheduled task "HealthSync Update Service" CONFIRMED
                   live in the TaskCache hive (upgrades the 4x03 gated
                   branch from "not triggered in sandbox" to "executed at
                   MedDefense"). Defender exclusion for C:\Windows\Temp
                   added under records03's token 9h before the first LSASS
                   dump. Secondary C2 connection to 203.0.113.47:8443 was
                   STILL ESTABLISHED at capture time. Exfiltrator config
                   residue recovered with clear_logs:true.

[08] Source:       ir_evidence/disk_forensics_report.txt
     Phase:        4x05-IR
     Type:         Disk image forensics (FTK Imager + Autopsy, consolidated
                   extract)
     Coverage:     $MFT / USN journal range 2026-04-22T06:14:18Z to
                   2026-05-15T19:45:11Z (image acquisition).
     Reliability:  HIGH -- E01 image hash-verified twice, named custodian
                   and peer reviewer, chain of custody signed.
     Key findings: recovered 3 deleted staging archives whose byte counts
                   match the firewall EXFIL_BURST sessions EXACTLY --
                   47,138 patient records, 51,002 insurance records, 1,184
                   AD records. Partial recovery (~11 of 23 MB) of the LSASS
                   dump output confirms "svc_healthsync" in plaintext.
                   Full scheduled-task XML recovered (daily 02:00 trigger,
                   Hidden=true). 12-minute Security event log gap on
                   2026-05-09. Anti-forensics assessed as basic (file
                   deletion, log clear, AV exclusion) -- NOT advanced (no
                   VSS/USN/prefetch deletion attempted).

[09] Source:       ir_evidence/ir_team_notes.txt
     Phase:        4x05-IR
     Type:         IR team chronological working notes (human-authored)
     Coverage:     2026-05-15 (isolation) through 2026-05-18 (handoff),
                   10 dated entries.
     Reliability:  MEDIUM -- the file explicitly self-identifies as "a
                   working file, NOT a finished report" and tags every
                   line [HIGH]/[MED]/[LOW]/[DISPUTED]/[TODO]. Overall file
                   confidence must be treated per-line, not as a block.
     Key findings: near-miss where Robert Kim nearly deleted debug_tool.exe
                   before isolation was enforced (blocked only by a stale
                   memory-held file lock -- pure luck, not process). Two
                   [DISPUTED] items unresolved at handoff (see Q4/Q5 below).
                   James Chen's Entry #010 lists 5 explicit questions
                   (A-E) the 4x05 analyst must prove or disprove -- these
                   are reproduced as Q1-Q5 below, verbatim in substance.
EOF
echo

echo "--------------------------------------------------------------------------------"
echo "SOURCE CATALOG (continued -- reference/)"
echo "--------------------------------------------------------------------------------"

cat <<'EOF'
[10] Source:       reference/network_topology.txt
     Phase:        Reference (organizational baseline, effective 2026-05-01)
     Type:         Network segmentation / authorization-matrix reference
     Coverage:     Static baseline, not an attack-window observation.
     Reliability:  HIGH -- revision-controlled (rev. 12), signed
                   distribution, authoritative for "who is authorized to
                   access what."
     Key findings: the ONLY legitimate admin path is WS-ADMIN-01 /
                   robert.kim to the server segment. Any PsExec/WMI/
                   PSRemoting/remote-schtasks from any other host is
                   anomalous by definition -- this is the baseline the
                   4x04 hunt and the firewall LATERAL_MOVEMENT findings
                   were measured against.
     Discrepancy:  lists the server segment (10.10.20.0/24) as VLAN "100".
                   reference/meddefense_asset_inventory.txt labels every
                   server on that same subnet "VLAN-20". See Q6 below.

[11] Source:       reference/meddefense_asset_inventory.txt
     Phase:        Reference (effective 2026-04-01, signed off by 4
                   named officers)
     Type:         Asset / data-sensitivity inventory
     Coverage:     Static baseline -- but explicitly describes WS-RECV-03
                   as a "COMPROMISED HOST... in IR isolation as of
                   2026-05-15," meaning this document was updated during
                   the incident, not frozen at its 2026-04-01 effective
                   date.
     Reliability:  HIGH as an authoritative organizational document; see
                   Q6/Q7 below for IP-mapping discrepancies against other
                   reference material that must be resolved before using
                   it to attribute firewall sessions by IP.
     Key findings: SRV-HEALTH-DB = CRITICAL/PHI (~47k patients),
                   SRV-INS-DB = HIGH (~51k members), SRV-DC-01 = HIGH
                   (catastrophic if NTDS.dit is pulled), SRV-FILE-01 =
                   MEDIUM but holds imaging PHI for ~8,400 patients --
                   a THIRD PHI source no evidence source confirms was
                   ever touched (see domain gap below). records03's
                   local-admin membership (a 2018 misconfiguration never
                   re-baselined) is what allowed the Defender-exclusion
                   write and the elevated scheduled task.

[12] Source:       reference/healthbane_ioc_master.json
     Phase:        Reference (consolidated across 4x00-4x04, generated
                   2026-05-18 -- the same date as the 4x05 handoff)
     Type:         Master IOC database (structured JSON)
     Coverage:     Campaign-wide, 2026-04-14 to 2026-05-13.
EOF
printf '     Reliability:  HIGH -- array length matches its own stored count (%s = %s),\n' \
  "$IOC_COUNT_ARRAY" "$IOC_COUNT_STORED"
echo "                   unlike sources 03 and 13. 30 of 31 IOCs self-rated HIGH"
echo "                   confidence, 1 MEDIUM, 0 LOW."
cat <<'EOF'
     Key findings: 31 IOCs. Its own "ioc_gaps_known_to_4x04" list names 4
                   open items -- secondary C2, scheduled-task persistence,
                   data staging, anti-forensics -- that sources 06, 07 and
                   08 above now directly resolve. This file is the stated
                   baseline for classifying newly-found indicators as
                   KNOWN / NEW / MODIFIED in later 4x05 tasks.

[13] Source:       reference/attck_navigator_80pct.json
     Phase:        Reference (post-4x04 ATT&CK layer, approved 2026-05-14)
     Type:         ATT&CK Navigator layer (structured JSON) -- the CURRENT
                   baseline for 4x05.
     Coverage:     Point-in-time snapshot, not a time-window.
     Reliability:  MEDIUM -- see live recount below.
EOF
attck_counts reference/attck_navigator_80pct.json
cat <<'EOF'
     -> MISMATCH: stored says not_covered=3, but a direct recount gives 4.
        The file's OWN "open_hypotheses_for_4x05" list has exactly 4
        entries, which corroborates the recount (4), not the stored
        summary (3). Use the recount in the final reconstruction report.
     Key findings: 22 OBSERVED (recount) / 3 INFERRED / 4 NOT COVERED. The
                   4 open hypotheses -- T1053.005, T1074.001, T1560.001,
                   T1070.001 -- are ALL FOUR directly resolved by the
                   ir_evidence sources read for this inventory (see Q13).
EOF
echo

echo "--------------------------------------------------------------------------------"
echo "TEMPORAL COVERAGE MATRIX"
echo "--------------------------------------------------------------------------------"
echo "F = full coverage of the window   P = partial / boundary-only   . = none"
echo
cat <<'EOF'
                              W1        W2        W3        W4        W5
                           04-14/20  04-21/27  04-28/05-04 05-05/11  05-12/18
  4x00 phishing              F         P         .         .         .
  4x01 PCAP                  P         .         .         .         .
  4x03 malware triage        P         P         P         .         .
  4x04 threat hunt           .         .         P         F         P
  firewall export (IR)       .         .         P         F         P
  memory capture (IR)        .         .         .         .         P
  disk forensics (IR)        .         P         F         F         P
  ir team notes (IR)         .         .         .         .         F
EOF
echo
echo "GAP 1 (temporal):  2026-04-16 (PCAP collection ends) through"
echo "  2026-04-22T06:14Z (disk \$MFT/USN journal range begins, same moment"
echo "  the RAT first booted). Six days with ZERO host- or network-level"
echo "  telemetry for WS-RECV-03. 4x03's malware summary describes what the"
echo "  dropper/RAT CAN do during this window, not what happened on this"
echo "  specific host. This is the single largest true evidence gap."
echo
echo "GAP 2 (domain):   SRV-FILE-01 holds PHI (imaging data for ~8,400"
echo "  patients, per source 11) and is explicitly listed as a watched"
echo "  'internal pivot target' in the firewall export's own metadata"
echo "  (source 06), but no source -- hunt, firewall, memory, or disk --"
echo "  shows the attacker ever touching it. Absence of evidence is not"
echo "  evidence of absence here; this needs an explicit statement in the"
echo "  final report, not a silent omission."
echo
echo "GAP 3 (single-source):  the 17-minute window between Diane Marsh's"
echo "  credential submission (2026-04-14T13:18:42Z) and AD rotation"
echo "  (13:20Z) is covered ONLY by source 01's claim that the dmarsh"
echo "  credential was 'not reused post-rotation' -- it does not state"
echo "  whether the credential was used DURING those 17 minutes. No second"
echo "  source closes this (see Q3)."
echo

echo "--------------------------------------------------------------------------------"
echo "CRITICAL QUESTIONS FOR RECONSTRUCTION"
echo "--------------------------------------------------------------------------------"

cat <<'EOF'
[Q1] Did the 4x04 hunt (or any earlier layer) miss a workstation besides
     WS-RECV-03? Robert Kim claims (source 09, Entry #004, [DISPUTED]) he
     saw debug_tool.exe on WS-RECV-04 and WS-RECV-07, but could not show a
     timeline, and 4x04's own H4 query found nothing on those hosts. Needs
     explicit disposition -- re-running H1/H2/H3/H5 broader is the
     suggested test (James Chen's own recommendation).

[Q2] The Defender exclusion for C:\Windows\Temp (source 07/08, added
     2026-05-04 18:11 CDT under records03's token) -- attacker action or
     Robert's own claimed "legitimate sysadmin reason"? Robert's
     maintenance schedule shows no work logged for that evening, and a
     sysadmin would normally use a svc-*/domain-admin context, not
     records03's SID. Source 09 Entry #008 flags this [DISPUTED] and
     unresolved at handoff.

[Q3] Was the dmarsh credential used at all during the 17-minute window
     between submission (2026-04-14T13:18:42Z) and AD rotation (13:20Z)?
     Source 01 states it was "not reused post-rotation" but is silent on
     the window itself. Authentication logs from that window are said to
     exist (source 09, Entry #010 item E) and must be cross-checked.

[Q4] Was the 2026-04-22T06:14Z Run-key write ever triaged? Wazuh rule
     100091 was deployed before this date per source 09 Entry #007 (Q&A
     with Dr. Morales), so it SHOULD have fired. James Chen calls this
     "the most important detection-gap question of the entire
     investigation" (source 09, Entry #010 item C) -- requires pulling the
     SOC ticket queue for 2026-04-22, which is outside this evidence set
     and must be flagged as an open follow-up if unavailable.

[Q5] When was the secondary C2 IP (203.0.113.47:8443) actually delivered
     to the RAT? Disk forensics confirms the IP is NOT hardcoded in
     svchost_update.exe, so it must have arrived via a C2 response --
     but no source here captures that specific response packet. The
     connection's first-seen (05-07T06:48:11Z) is 38 seconds after the
     scheduled task's registration, which is a timing correlation, not
     proof of delivery mechanism (source 09, Entry #010 item D).

[Q6] Which IP-to-hostname mapping is authoritative for SRV-HEALTH-DB,
     SRV-INS-DB and SRV-FILE-01? reference/meddefense_asset_inventory.txt
     gives .15 / .25 / .30 respectively; the firewall export's own
     metadata (source 06) gives .30 / .31 / .40 for the SAME three hosts.
     SRV-DC-01 is the only host where the two documents agree (.10). Note
     specifically that asset_inventory's SRV-FILE-01 address (.30) is the
     SAME address the firewall export assigns to SRV-HEALTH-DB -- this
     must be resolved before any lateral-movement target is attributed by
     IP address alone in the final reconstruction.

[Q7] reference/network_topology.txt labels the server subnet
     (10.10.20.0/24) "VLAN 100"; reference/meddefense_asset_inventory.txt
     labels every host on that same subnet "VLAN-20". Both documents are
     signed/revision-controlled reference material -- which VLAN number
     is correct, and does it affect any ACL/detection-rule assumption
     made elsewhere in this project?

[Q8] Did the exfiltrator's C2-upload channel actually transmit the
     staging archives, or does the byte-for-byte match between disk D1/D2
     and firewall EXFIL_BURST sessions only prove correlation, not
     causation? (Disk forensics source 08, OPEN-A, explicitly asks this;
     the match is very strong circumstantial evidence but the two sources
     describe the SAME bytes from two different vantage points, which
     the disk report itself notes is "a smoking gun" but not literally a
     captured upload.)

[Q9] Was the LSASS dump file (out.dat, ~23 MB) exfiltrated in full, or
     only specific extracted credentials? Disk recovery is partial
     (~11 of 23 MB); memory shows debug_tool.exe wrote the file then
     exited; the next ~12 hours of elevated C2 bytes-out sum to ~23 MB.
     Strong inference, no direct proof (source 08, OPEN item; source 07,
     OPEN-2).

[Q10] previous_findings/4x02_attack_mapping.json's own stored
      technique_count_summary (11 observed / 5 inferred / 13 not covered)
      does NOT match a direct recount of its own techniques[] array
      (8 / 7 / 14, verified live by this script). Which numbers should
      the final before/after coverage comparison in the reconstruction
      report use? (Recomputing directly from each file's own array, never
      from a stored summary field, is the standard this project has
      already established and should be followed again here.)

[Q11] reference/attck_navigator_80pct.json has the same problem: stored
      not_covered=3, live recount=4 (verified above). The file's own
      "open_hypotheses_for_4x05" list has 4 entries, corroborating the
      recount. Confirm the final ATT&CK layer in a later 4x05 task is
      built from a fresh recount, not copied from this file's summary.

[Q12] All four of attck_navigator_80pct.json's "open_hypotheses_for_4x05"
      items -- T1053.005 (Scheduled Task), T1074.001 (Local Data
      Staging), T1560.001 (Archive via Utility), T1070.001 (Clear Event
      Logs) -- now appear directly resolved to OBSERVED/CONFIRMED by
      sources 06, 07 and 08 in this inventory. Does any evidence source
      conflict with upgrading all four, or is this a clean sweep for the
      ATT&CK-update task later in 4x05?

[Q13] ir_evidence/ir_team_notes.txt Entry #009 (Sarah Park, [LOW]) states
      the 4x04 hunt was "triggered the day before isolation" on
      "2026-05-18" -- but Entry #001 (James Chen, [HIGH]) dates isolation
      itself to 2026-05-15. 2026-05-18 is three days AFTER 2026-05-15, not
      the day before it. One of these two dates needs verification before
      the final chronology is published; this inventory does not have
      enough information to resolve it and flags it rather than silently
      picking one.
EOF
echo
echo "================================================================================"
echo "END OF EVIDENCE INVENTORY"
echo "================================================================================"
