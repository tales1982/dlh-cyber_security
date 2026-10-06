# Threat Hunting Report — HEALTHBANE Stage 4

Prepared for: Dr. Patricia Morales (CISO), James Chen (SOC Lead), and the
MedDefense Health Systems board.

## 1. Executive Summary

Following HC3's advisory HEALTHBANE-004, describing a fourth, previously
unreported campaign stage conducted entirely with legitimate Windows
administration tools, MedDefense initiated a 14-day retrospective threat
hunt (2026-05-04 through 2026-05-18) because our documented 55% ATT&CK
coverage had never been tested against this specific attack class and gave
no positive confirmation of safety by itself. **The hunt found direct,
multi-source evidence that HEALTHBANE Stage 4 did happen in the MedDefense
environment.** An attacker operating from WS-RECV-03 — a Records-department
workstation with no administrative role — dumped credential material from
LSASS memory twice, stole and used the `svc_healthsync` service account via
NTLM authentication from that workstation, and used PsExec, WMI and
PowerShell Remoting to reach three servers: **SRV-HEALTH-DB** (patient
health records, HIPAA-protected PHI), **SRV-INS-DB** (insurance claims,
PII and financial data) and **SRV-DC-01** (the domain controller itself,
where the attacker enumerated every Active Directory user account). On two
of those servers, the attacker went further and staged the known HEALTHBANE
exfiltration script directly onto the target — the specific behavior that
precedes data loss. As direct remediation, this hunt independently
confirmed 5 previously-uncovered ATT&CK techniques with real evidence,
raising observed coverage from 48% to 65% (and to 82% including inferred
techniques), and produced 6 draft detection rules — all with very low to
medium expected false-positive rates — that would have alerted
automatically had they existed before this hunt began.

## 2. Hunt Methodology

This hunt followed a hypothesis-driven approach, not alert-driven review: a
detection engineer asks "did a rule fire?"; a hunter asks "has this
specific behavior ever happened, regardless of whether anything alerted?"
(`0-hunt_brief.sh`). The scope was derived directly from two sources: HC3's
advisory, which names the specific TTPs (PsExec, WMI, PowerShell Remoting,
LSASS access, service account abuse, off-hours timing), and the post-4x03
ATT&CK coverage mapping, which showed exactly which of those TTPs' mapped
techniques had zero documented detection. The intersection of "advisory
says this happens" and "we have no coverage for it" became the 5 hunt
priorities (P1–P5).

**Data sources:** `siem_export/wazuh_alerts_14d.json` (6,544 events) and
`siem_export/wazuh_raw_sysmon_14d.json` (3,256 events, a verified subset of
the alerts export — see `3-data_recon.sh`), covering the full 14-day
window with no gaps.

**Baseline establishment** (`2-baseline_profile.sh`) came first, before any
anomaly search: Robert Kim's 93 documented administrative events were
profiled exhaustively and show a closed, consistent pattern — 100% from
WS-ADMIN-01, 100% within 08:00–18:00 Central Time, 100% the named
`robert.kim` account, 0% service-account use. Every later hunt measured
deviation from this exact baseline, not a generic or assumed one.

## 3. Findings per Hypothesis

| Hyp. | Technique | Status | Evidence Summary | Confidence |
|---|---|---|---|---|
| H1 — PsExec | T1021.002 | **POSITIVE** | 6 of 50 PsExec events anomalous: WS-RECV-03, `svc_healthsync`, off-hours, against SRV-HEALTH-DB/SRV-INS-DB/SRV-DC-01 (`4-hunt_psexec.sh`) | HIGH |
| H3 — WMI | T1047 | **POSITIVE** | 5 of 36 WMI events anomalous: WmiPrvSE.exe spawned a shell on all 3 targets, a pattern with no legitimate baseline at all (`5-hunt_wmi.sh`) | HIGH |
| H2 — LSASS | T1003.001 | **POSITIVE** | 2 of 12 LSASS-access events anomalous: `debug_tool.exe` (matches HC3's published IOC path) accessed lsass.exe twice, ~1 week apart (`6-hunt_credentials.sh`) | HIGH |
| H4 — PSRemoting | T1021.006 | **POSITIVE** | 4 of 22 PSRemoting events anomalous: interactive sessions from WS-RECV-03 staged the exfiltrator script onto 2 production databases (`7-hunt_psremoting.sh`) | HIGH |
| H5 — Service Accounts | T1078.002 | **POSITIVE** | 6 of 846 `svc_healthsync` authentications anomalous (workstation-sourced, NTLM); **0 of 1,442** combined events for the other 5 service accounts show any deviation (`9-hunt_svcaccount.sh`) | **CRITICAL** |

## 4. Reconstructed Attack Timeline

Full detail and raw evidence in `10-evidence_correlation.sh`. Summary:

| Date | Phase | Activity |
|---|---|---|
| 2026-05-05 | Credential Access | LSASS memory dump via `debug_tool.exe` on WS-RECV-03 |
| 2026-05-06 | Lateral Movement → Reconnaissance → Staging | `svc_healthsync` auth → PsExec → WMI enumeration → PSRemoting + Copy-Item staging `sync_healthdata.ps1`, all against SRV-HEALTH-DB |
| *(dormant 2 days)* | | |
| 2026-05-09 | Lateral Movement → Reconnaissance → Staging | Same full pattern repeated against SRV-INS-DB |
| *(dormant 2 days)* | | |
| 2026-05-12 | Credential Access | Second LSASS dump (credential refresh) |
| 2026-05-13 | Lateral Movement → Reconnaissance | PsExec + WMI against **SRV-DC-01**, including full Active Directory user enumeration (`Get-ADUser -Filter *`) |

Observed dwell time (within this 14-day window): **7 days, 22 hours**, from
the first credential dump to the final domain-controller reconnaissance.
This cannot be assumed to be *total* dwell time — the hunt window starts
2026-05-04, and there is no evidence to confirm or rule out earlier access.
100% of anomalous activity fell between 01:00 and 04:59 Central Time
(`8-temporal_analysis.sh`), with zero overlap with Robert Kim's documented
08:00–18:00 baseline, in a bursts-separated-by-dormant-periods pattern that
specifically defeats simple frequency-based detection.

## 5. ATT&CK Update

Full detail in `11-attack_update.sh` / `attack_layer_post_hunt.json`.

| | Before Hunt | After Hunt |
|---|---|---|
| OBSERVED | 14 / 29 (48%) | 19 / 29 (65%) |
| OBSERVED + INFERRED | 19 / 29 (65%) | 24 / 29 (82%) |

*(Note: the pre-hunt `4x03_attack_mapping.json` reference file's own stored
summary metadata states "16 observed / 3 inferred," which does not match a
direct recount of its own technique array — 14 observed / 5 inferred. Both
the before and after figures above were recomputed directly from each
file's technique list for a valid, apples-to-apples comparison; see
`11-attack_update.sh`'s header comment.)*

**Newly confirmed OBSERVED:** T1021.002 (PsExec), T1047 (WMI), T1021.006
(PSRemoting), T1003.001 (LSASS Memory), T1078.002 (Domain Accounts) — all
5 upgraded from NOT COVERED with direct SIEM evidence, not assumption.

**Deliberately left unchanged:** T1550.002 (Pass-the-Hash) remains
INFERRED — the NTLM authentication observed is consistent with, but does
not on its own prove, hash-based (as opposed to recovered-plaintext)
credential use. T1053.005 (Scheduled Task) remains NOT COVERED — a direct
search of this dataset for Event 4698 or `Schedule\TaskCache` registry
evidence found none. Upgrading either without that evidence would repeat
the exact overclaiming error this project's OBSERVED/INFERRED discipline
exists to prevent.

## 6. Detection Improvements

Full detail in `13-detection_rules.sh`. **6 draft rules produced**, none
yet deployed to a live system (this project is self-contained): 5
Wazuh-style host rules (PsExec anomalous source/time, LSASS access from a
non-allowlisted process, service account logon from a workstation, WMI
child-process anomaly, PSRemoting file staging) and 1 Suricata-style
network rule (SMB/PsExec service-installation pattern). Expected
false-positive rates range from VERY LOW (service-account rules, which
admit zero legitimate exceptions per the authorization matrix) to MEDIUM
(the WMI rule, pending confirmation that no other legitimate process in
the environment is ever parented by WmiPrvSE.exe).

## 7. Remaining Gaps and Recommendations

**What is still unknown (the remaining ~35% uncovered/unobserved):**
T1550.002's hash-vs-plaintext question (above); whether the attacker
persisted via a mechanism this hunt didn't check for (scheduled tasks,
registry Run keys beyond the one already confirmed in 4x03, new local
accounts); the true pre-2026-05-04 dwell time; and whether data actually
left the 2 staged servers — this hunt found staging, not confirmed
exfiltration, which is a materially different (though still serious)
finding.

**Immediate (incident-response bridge to Module 5):** Treat WS-RECV-03 as
compromised and begin formal incident response — memory capture, disk
imaging, and firewall/session log preservation per HC3's own Recommendation
R5. Rotate the `svc_healthsync` credential immediately; do not wait for a
scheduled rotation window.

**Short-term:** Deploy the 6 draft detection rules from Section 6 after
SOC review. Conduct the same hunt methodology against every other
documented service account's authorized host, not just `svc_healthsync`'s,
in case a second, quieter foothold exists. Review all privileged and
service-account access for every system `svc_healthsync` could reach, per
its documented privilege scope.

**Medium-term:** Implement full Sysmon deployment with behavioral
analytics across all endpoints (HC3's Recommendation R3) so this class of
hunt can run continuously rather than only retrospectively. Formalize the
administrative-baseline-as-detection-filter pattern this hunt used (Task
2) as a standing, versioned reference document, reviewed whenever
`admin_schedule.txt` or the service account matrix changes.

## 8. Lessons Learned

**Why 55% ATT&CK coverage created a false sense of security:** a coverage
percentage measures what the organization *can* detect, not what *has
happened*. MedDefense's 55% figure was true and, at the same time,
completely silent on Stage 4, because every technique Stage 4 depends on
fell in the uncovered 45%. A dashboard number is not a security posture —
it is a map of where the organization has looked, and this hunt is proof
that what lies outside that map is not merely theoretical.

**Why reactive detection alone is insufficient against LOLBin attacks:**
PsExec, WMI and PowerShell Remoting are not malware — they are the same
binaries Robert Kim uses every Tuesday and Thursday. No signature, hash,
or domain-reputation check can distinguish Stage 4 from legitimate
administration, because there is no technical difference between them at
the file or network level. The only distinguishing signal is *context* —
source host, account, time, target — compared against a documented
baseline, which is precisely why Task 2 (building that baseline) had to
happen before any anomaly could even be defined, let alone found.

**Why proactive threat hunting must be a recurring operational
discipline:** this hunt was triggered by an external advisory, not an
internal alert — MedDefense had no idea Stage 4 had occurred until HC3
told the sector it was happening elsewhere. A hunt that only runs after
the next advisory arrives will always be retrospective by definition,
finding attacks that have already run their course. The actual lesson of
this project is not "we found it" — it is that finding it required
*looking*, on a hypothesis, before any tool told us to, and that this
specific class of attack will keep succeeding against any organization
that only hunts when told to.
