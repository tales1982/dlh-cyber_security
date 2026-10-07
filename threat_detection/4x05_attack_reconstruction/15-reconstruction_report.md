# HEALTHBANE Attack Reconstruction Report

Prepared for: Dr. Patricia Morales (CISO), James Chen (SOC Lead), Sarah Park
(IT Director), Legal, and the MedDefense Health Systems board.

Prepared by: [student], 4x05 Attack Reconstruction analyst.

## 1. Executive Summary

**What happened.** Between 2026-04-14 and 2026-05-15, a financially
motivated actor ran the HEALTHBANE campaign against MedDefense Health
Systems in four stages: a spearphishing email harvested a records-clerk's
credentials and, a day later, a second-wave email delivered a remote-access
trojan (RAT) that established persistent command-and-control (C2); the RAT
sat dormant for 13 days before the operator returned, dumped a service
account's credentials from memory, and used that credential to move
laterally — via tools indistinguishable from legitimate administration —
into the patient-records database, the insurance-claims database, and the
domain controller; over three nights the operator queried, archived, and
exfiltrated patient and insurance data before a proactive threat hunt
flagged the anomaly and incident response isolated the workstation.

**How far the attacker got.** The attacker reached three production
servers (SRV-HEALTH-DB, SRV-INS-DB, SRV-DC-01) using one stolen service
account (`svc_healthsync`), established two independent persistence
mechanisms (a registry Run-key and a daily scheduled task) and two C2
channels (primary and a standby secondary), and **confirmed-exfiltrated
98,140 records** — 47,138 patient records and 51,002 insurance records —
transmitted over the primary C2 channel with a byte-for-byte match between
the firewall's outbound sessions and the disk-recovered staging archives.
A fourth database (SRV-FILE-01, which holds imaging PHI for ~8,400
patients) was flagged as a watch target in the firewall export's own
metadata but shows no evidence of actual access in any source.

**How it was stopped.** A hypothesis-driven threat hunt (Module 4x04),
triggered by an external advisory rather than an internal alert, found
anomalous PsExec usage from a non-administrative workstation. That finding
was escalated the same day, and MedDefense isolated the workstation,
captured memory, imaged the disk, and exported 14 days of firewall logs —
the evidence base for this reconstruction.

**What happens next.** Rotate the compromised service credential
immediately (if not already done); re-image the workstation before
returning it to service (the RAT and its persistence mechanisms are still
intact on disk); tighten the firewall rule that allowed a records-VLAN
workstation to reach the server segment at all; close the detection gaps
this reconstruction identifies (see Section 7); and begin HIPAA breach
notification — the evidence supports a MET threshold, not an uncertain one.

**Key metrics.** Total dwell time: 31 days, 5 hours (credential theft to
isolation). Breakout time (credential theft to first lateral movement):
21 days, 18 hours. ATT&CK coverage: 28% (post-intelligence) → 76%
(post-hunt) → 97% (post-reconstruction, 28 of the original 29-technique
threat model, plus 3 techniques found that fall outside that model
entirely).

## 2. Methodology

**Evidence sources** (full inventory and reliability assessment in
[0-evidence_index.sh](0-evidence_index.sh)): 13 files across three
categories — five `previous_findings/` summaries (4x00 phishing, 4x01
network forensics, 4x02 intelligence, 4x03 malware triage, 4x04 threat
hunting), four `ir_evidence/` sources gathered after the 2026-05-15
isolation (firewall session export, volatile memory capture, disk
forensics report, IR team working notes), and four `reference/` baseline
documents (network topology, asset inventory, master IOC database, and the
post-4x04 ATT&CK layer).

**Analytical approach.** Each IR evidence source was analyzed individually
first ([1-memory_analysis.sh](1-memory_analysis.sh),
[2-disk_analysis.sh](2-disk_analysis.sh),
[3-firewall_analysis.sh](3-firewall_analysis.sh)), then cross-referenced
against every other source to build IOC, timeline, and technique
correlation matrices ([4-correlation_matrix.sh](4-correlation_matrix.sh)).
Every IOC was classified CONVERGED (2+ independent sources), SINGLE-SOURCE,
or CONFLICTED; every timeline event carries an explicit confidence level
(CONFIRMED / CONVERGED / PROBABLE / SINGLE-SOURCE); and every ATT&CK
technique's status (UNCHANGED / UPGRADED / NEW) is justified against the
specific evidence that supports it. Two of the reference JSON files'
stored summary fields were found, by direct recount of their own data, not
to match their own underlying arrays — this reconstruction recomputes
those figures live rather than citing the stored (incorrect) summaries;
see Section 6 and [0-evidence_index.sh](0-evidence_index.sh)'s Q10/Q11.

**Limitations and assumptions.** The reconstruction is scoped to
WS-RECV-03 only, per the 4x04 hunt's own scoping decision — a disputed
claim that `debug_tool.exe` was seen on two other workstations
(ir_evidence/ir_team_notes.txt Entry #004) was not independently
verifiable from any evidence source available here and is carried forward
unresolved. Several timeline gaps exist where no evidence source has
visibility (Section 5); these are stated explicitly rather than
interpolated. One internal date inconsistency in `ir_team_notes.txt`
(Entry #009 vs. Entry #001, regarding when the hunt was triggered relative
to isolation) could not be resolved from this evidence set and is flagged,
not silently picked one way or the other.

## 3. Attack Reconstruction

Full detail and evidence citations in
[5-stages_1_2.sh](5-stages_1_2.sh) and [7-stage_4.sh](7-stage_4.sh).
(Task 6, a dedicated Stage 3 reconstruction script, was not part of this
exercise batch; Stage 3 below is drawn directly from
`previous_findings/4x03_malware_summary.txt` and the IR memory/disk
evidence instead.)

### Stage 1 — Initial Access (Phishing)

2026-04-14T13:14:22Z: a batch of 8 phishing emails reached MedDefense
staff; 3 were malicious. At 13:18:05Z, Diane Marsh (`dmarsh`, normally on
WS-NURSE-04 but with UNC access patterns tying her to the Records
department) clicked a credential-harvesting link on a lookalike domain
(`meddefense-portal.com`, registered 2 days before the campaign). She
submitted credentials at 13:18:42Z — captured independently in both the
4x00 domain analysis and the 4x01 PCAP's 743-byte POST request, the same
second in both sources. AD rotation followed at 13:20Z. **Open question**:
whether the credential was used during the ~17-minute exposure window
between click and rotation is not answered by any source here (carried as
Q3 in the evidence inventory).

*Techniques: T1566.001 (CONFIRMED), T1583.001 (CONFIRMED), T1078
(CONVERGED).*

### Stage 2 — C2 Establishment

A **separate**, second-wave email on 2026-04-15T08:43:18Z delivered the
actual dropper (`HEALTHBANE_S2_invoice.docm`), released from quarantine by
a helpdesk operator who did not inspect the attachment. Within 2 minutes
the dropper's macro pulled the RAT binary (`svchost_update.exe`, 287,444
bytes) from 185.220.101.45 and the first C2 beacon fired at 08:51:38Z. The
RAT did not take further visible action until its Run-key persistence
re-launched it at the next reboot, 2026-04-22T06:14:17Z — a full week
later. The widely-assumed "secondary C2" is **not** part of Stage 2: it
first appears 23 days later (2026-05-07), tied to Stage 4's persistence
event, not initial C2 setup.

*Techniques: T1566.001, T1105, T1059.005, T1071.001, T1573.001, T1547.001
(all CONFIRMED or CONVERGED).*

### Stage 3 — Malware Deployment (reconstructed from 4x03 + IR evidence)

The RAT (4x03 sample S2) establishes Run-key persistence and beacons every
~5 minutes over a TLS channel wrapped with an RC4-like cipher using a
hardcoded key that embeds the campaign name — poor operational security
that nonetheless went undetected for weeks. 4x03's sandbox analysis found
a **gated** "PersistViaTask" branch in the dropper that never fired under
sandbox conditions; this reconstruction's IR evidence (memory + disk, both
independently) confirms that branch **did** fire in the real environment,
on 2026-05-07 — 22 days after the RAT's initial install, not immediately.
This is the single clearest example in the whole investigation of a
sandbox-vs-reality gap, not a wrong technique call: 4x03 correctly
identified the capability; only its activation state needed IR evidence
to resolve.

*Techniques: T1105, T1059.001/.005, T1547.001, T1027/.010, T1140 (all
CONFIRMED).*

### Stage 4 — Lateral Movement, Data Staging, and Containment

Full chronology in [7-stage_4.sh](7-stage_4.sh). Thirteen days of dormancy
ended 2026-05-05T08:22:14Z with a memory dump of LSASS (via
`debug_tool.exe`, a stripped Mimikatz fork) that yielded the
`svc_healthsync` service credential — a credential that should never
authenticate interactively from a workstation. The operator then moved,
on three separate nights all inside a 02:00–04:00 CDT window, to
SRV-HEALTH-DB (05-06), SRV-INS-DB (05-09), and SRV-DC-01 (05-13), using
PsExec with NTLM authentication on an account the organization's own
authorization matrix restricts to Kerberos-only. A second persistence
mechanism (the scheduled task) and a standby secondary C2 were both stood
up on 05-07, 38 seconds apart — a deliberate redundancy move, not
coincidence. Each of the three nights produced a staged, compressed, and
immediately transmitted data export: 47,138 patient records (05-08),
51,002 insurance records (05-11), and a 1,184-account AD enumeration
export (05-13). A 12-minute Security event log gap on 05-09 is the only
anti-forensics action beyond routine file deletion — no VSS, USN journal,
or prefetch tampering was attempted. The last attacker-attributable event
is the scheduled task's 05-15 02:00 CDT run, which received an empty C2
config and produced nothing; isolation followed roughly 11.5 hours later,
same day.

*Techniques: T1003.001, T1021.002, T1078.002, T1550.002, T1047,
T1053.005, T1071.001, T1074.001, T1560.001, T1005, T1041, T1070.001,
T1562.001, T1070.004 (status for each in Section 6).*

## 4. Unified Timeline

Full 28-event chronology, temporal metrics, gaps, and sequencing
uncertainties in [8-unified_timeline.sh](8-unified_timeline.sh).

| Metric | Value |
|---|---|
| Total dwell time | 31 days, 5h (credential theft → isolation) |
| Breakout time | 21 days, 18h (credential theft → first lateral movement) |
| Time to RAT persistence | 7 days, 17h |
| Time to task-based persistence | 22 days, 17h (after lateral movement had already begun) |
| Time to first data staging | 23 days, 18h |
| Hunt window open → containment | 11 days, 19h |

**Identified gaps**: a true 6-day zero-evidence gap (2026-04-16 to
2026-04-22); a 10-day single-source (disk-only) window with no network
visibility (2026-04-22 to 2026-05-02); and a 2-day confirmed quiet period
(2026-05-13 to 2026-05-15) where multiple sources agree nothing happened.
These three are analytically distinct and are not conflated in this
report: the first two are genuine evidence gaps (attacker activity
unknown), the third is a positive finding (attacker inactivity confirmed).

## 5. ATT&CK Analysis

Full technique-by-technique inventory in
[9-attack_techniques.sh](9-attack_techniques.sh). Coverage of the original
29-technique HEALTHBANE threat model, recomputed live from each reference
file's own technique array at every stage (never from a stored summary
field, two of which were independently found not to match their own
data):

| Stage | Observed | Coverage |
|---|---|---|
| Post-4x02 (intelligence) | 8/29 | 28% |
| Post-4x04 (hunting) | 22/29 | 76% |
| Post-4x05 (reconstruction) | 28/29 | 97% |

Two techniques were upgraded from INFERRED to CONFIRMED by direct IR
evidence (T1041 Exfiltration Over C2, T1005 Data from Local System — the
latter already present in the baseline as INFERRED, not genuinely new,
correcting the generic task template's assumption that it needed adding).
Four techniques were newly confirmed, closing every open hypothesis the
post-4x04 ATT&CK layer itself had flagged (T1053.005, T1074.001,
T1560.001, T1070.001). One technique remains deliberately un-upgraded
(T1048.003, DNS exfiltration — capability exists, never exercised at
MedDefense; see Section 6 for why this is assessed as "not employed," not
a blind spot). Three further techniques were found that fall entirely
outside the original 29-technique threat model (T1562.001 Disable/Modify
Tools, T1070.004 File Deletion, tentatively T1571 Non-Standard Port).

**Gap analysis.** The single remaining in-model gap (T1048.003) is not a
collection limitation — every source capable of showing DNS-tunnel traffic
was available and showed none beyond two reachability-test queries. The
attacker had the capability and chose not to use it operationally,
preferring the HTTPS channel already proven to work.

## 6. Impact Assessment

Full host-by-host mapping and regulatory analysis in
[12-data_exposure.sh](12-data_exposure.sh).

Three of four candidate database targets show **confirmed, completed**
exfiltration — not staged-but-interrupted, not merely accessed: SRV-HEALTH-DB
(47,138 patient records), SRV-INS-DB (51,002 insurance records), and
SRV-DC-01 (1,184-account AD enumeration, reconnaissance rather than PHI).
The fourth candidate, SRV-FILE-01 (which holds imaging PHI for ~8,400
patients and HR records for ~320 employees), shows no access evidence in
any source despite being a flagged watch target — this absence is reported
explicitly, not silently assumed to mean "safe."

**HIPAA breach notification threshold: MET.** The basis is direct,
byte-exact transmission evidence, not inference — this reconstruction
found zero evidence that any of the three confirmed exfil cycles was
interrupted mid-transfer, which rules out "interrupted exfiltration" as a
mitigating factor a less rigorous read of the evidence might have assumed.
Two open items affect final scoping and should be resolved before the
notification is finalized: whether the recovered SSN column values are
still encrypted ciphertext or were decrypted by the SQL query before
export (not determined by any evidence source here), and the
patient/insurance de-duplication Legal has pending (working estimate
78,000–82,000 unique individuals against a raw combined count of 98,140
records).

## 7. Defensive Posture Evaluation

*(Dedicated Tasks 13/14 scripts were not part of this exercise batch; this
section and Section 8 are synthesized directly from findings already
established in Tasks 0-12 and the IR team's own notes, following the same
approach used for the Stage 3 gap in Section 3.)*

**What worked:** the 4x04 hunt's baseline-comparison methodology is the
single reason this intrusion was found at all — none of the Stage 4
tooling (PsExec, WMI, PowerShell Remoting) is malware, and no
signature-based control was ever going to catch it. Once the hunt flagged
the anomaly, escalation to isolation happened within the same day
(ir_evidence/ir_team_notes.txt Entry #001), and a near-miss where Robert
Kim attempted to delete `debug_tool.exe` before formal containment was
caught in time (Entry #004) — pure luck (a stale file lock from the live
memory capture), not process, which is itself a lesson (Section 8).

**What failed:** (1) the Run-key write on 2026-04-22 should have triggered
a detection rule deployed before that date (Wazuh rule 100091, per Entry
#007's Q&A record) — whether it fired and was missed in triage, or never
reached the SIEM, is unresolved and is, in James Chen's own words, "the
most important detection-gap question of the entire investigation." (2)
The firewall rule permitting the records VLAN to reach the server segment
at all (`users-to-server-segment`) is, per the firewall export's own
analyst note, "overly permissive" — it is what made 47 lateral-movement
sessions possible without a single network-layer block. (3) A 2018
local-admin misconfiguration on records-department workstations, never
re-baselined, is what let the attacker add a Defender exclusion and run a
HighestAvailable scheduled task from a non-administrative account. (4) The
service-account authorization matrix's Kerberos-only rule exists but had
no enforcement mechanism — NTLM-on-`svc_healthsync` should have been
structurally impossible, not merely detectable after the fact.

## 8. Remediation Plan

**Immediate:** rotate `svc_healthsync` if not already done (per
ir_team_notes.txt Entry #009, scheduled for 2026-05-18 — confirm it
happened); do not return WS-RECV-03 to the network without re-imaging (the
RAT and both persistence mechanisms remain intact on disk per James
Chen's own Entry #007 warning); resolve the SSN encryption-state question
before finalizing breach notification scope.

**Short-term:** tighten `users-to-server-segment` to deny WS-* sources
against SRV-* destinations except explicit, named application ports;
remove local-admin rights from records-department workstations (reversing
the 2018 misconfiguration); enforce Kerberos-only at the network layer for
every `svc_*` account rather than relying on a documented-but-unenforced
policy; investigate whether Wazuh rule 100091 fired on 2026-04-22 and, if
so, why it was not triaged.

**Medium-term:** extend the 4x04 hunt's baseline-comparison methodology to
a continuous, scheduled discipline rather than an advisory-triggered
one-off; resolve the two outstanding disputed claims from
ir_team_notes.txt (Robert Kim's WS-RECV-04/WS-RECV-07 sighting, and
authorship of the Defender exclusion) since either could change IR scope;
reconcile the IP-address and VLAN-numbering discrepancies found between
`reference/meddefense_asset_inventory.txt` and
`reference/network_topology.txt` (Section 9 Q6/Q7) before they cause a
future misattribution.

**Prioritization rationale:** the immediate items prevent re-compromise of
the same host and credential; the short-term items close the exact three
structural gaps this specific intrusion exploited (permissive firewall
rule, local-admin misconfiguration, unenforced Kerberos policy); the
medium-term items address detection-process maturity rather than any
single technical control.

## 9. Conclusions

**What this module demonstrated about the gap between detection and
understanding:** the 4x04 hunt correctly found that Stage 4 happened. It
could not, by itself, say how much data was at risk, whether persistence
existed beyond what it queried for, or whether the exfiltration succeeded
— each of those answers required a different evidence type (memory, disk,
firewall) that the hunt's own SIEM-based methodology does not collect.
Detection answers "did something happen." Reconstruction answers "exactly
what happened, how far it went, and what it cost" — and the board, Legal,
and the insurance carrier all need the second answer, not the first.

**Why investigation in pieces creates blind spots that only reconstruction
reveals:** 4x01 flagged zero lateral movement in its 48-hour window and
called it a collection gap, not a finding — correctly, as it turned out,
since lateral movement began 20 days after that window closed. 4x03's
sandbox recorded the scheduled-task branch as not triggered — correctly,
for the sandbox, but incompletely for the real host. Each module was
locally correct and globally incomplete; only cross-referencing all of
them against IR evidence surfaced that the secondary C2 and the scheduled
task were the SAME event, 38 seconds apart, or that "data staging" from
disk evidence alone looked interrupted until the firewall export proved
otherwise.

**Why proactive hunting and forensic readiness are not optional
enhancements:** this campaign ran for 31 days before detection, 22 of them
after the attacker's first lateral movement, and was found only because an
external advisory prompted a hunt that had no corresponding internal alert
to react to. Forensic readiness — the ability to capture memory, image
disk, and export 14 days of firewall history on short notice — is what
turned "we think something bad happened" into a defensible, byte-level
evidence chain suitable for a board briefing and a regulatory filing.
Neither capability is a luxury; both were load-bearing for every
conclusion in this report.

**What remains unknown:** whether the dmarsh credential was used during
its 17-minute exposure window; whether the SOC's own detection rule fired
and was missed on 2026-04-22; how the secondary C2's IP was actually
delivered to the RAT; whether SRV-FILE-01 was ever touched; whether
Robert Kim's claim about two other workstations has any substance; and the
true dwell time before 2026-04-16, which no evidence source here can see
at all. Resolving these would require, respectively: authentication logs
from the 17-minute window, the SOC's historical ticket queue, a deeper
reverse-engineering pass on the RAT's C2 response parser, a dedicated hunt
against SRV-FILE-01 specifically, re-running the 4x04 hunt's queries
against WS-RECV-04 and WS-RECV-07, and — for the pre-04-16 window — there
may be no way to resolve it at all, since no collection existed yet.

## Appendix A — IOC Summary

31 baseline IOCs (full table with per-source correlation in
[4-correlation_matrix.sh](4-correlation_matrix.sh)) plus 5 new IOCs from IR
evidence (scheduled task, debug_tool.exe hash, Defender exclusion, staged
filename pattern, secondary C2 IP:port) and 2 identifier conflicts flagged
for resolution (duplicate IDs for the secondary C2; disagreeing IP
addresses for SRV-HEALTH-DB/SRV-INS-DB/SRV-FILE-01 between
`reference/meddefense_asset_inventory.txt` and the firewall export's own
metadata).

## Appendix B — Evidence Citation Index

| Source | Role in this report |
|---|---|
| `previous_findings/4x00_phishing_summary.txt` | Stage 1 |
| `previous_findings/4x01_network_timeline.txt` | Stage 1-2 |
| `previous_findings/4x02_attack_mapping.json` | ATT&CK baseline (pre-malware) |
| `previous_findings/4x03_malware_summary.txt` | Stage 2-3, malware capability |
| `previous_findings/4x04_hunting_report.txt` | Stage 4 discovery, baseline |
| `ir_evidence/memory_artifacts.txt` | Stage 3-4, persistence, secondary C2 |
| `ir_evidence/disk_forensics_report.txt` | Stage 4, staging, anti-forensics |
| `ir_evidence/firewall_sessions_ws_recv_03.json` | Stage 2 & 4, exfiltration proof |
| `ir_evidence/ir_team_notes.txt` | Containment chronology, open questions |
| `reference/network_topology.txt` | Authorization-matrix baseline |
| `reference/meddefense_asset_inventory.txt` | Impact assessment, data sensitivity |
| `reference/healthbane_ioc_master.json` | IOC correlation baseline |
| `reference/attck_navigator_80pct.json` | ATT&CK baseline (post-hunt) |

## Appendix C — ATT&CK Navigator Layer Reference

See [9-attack_techniques.sh](9-attack_techniques.sh) for the complete
29-technique (plus 3 out-of-model) final inventory with per-technique
status and evidence citations.
