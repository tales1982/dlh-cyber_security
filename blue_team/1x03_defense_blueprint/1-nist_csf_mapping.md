# 1. The NIST CSF Mapping MedDefense Health Systems

**Analyst:** Security Analyst
**Date:** Current

## GOVERN (GV)

- **Function:** Govern
- **Current Level:** Not Implemented
- **Evidence:** Sarah Park's own admission at the start of this project "we follow no framework formally" is direct evidence against GV.OC (organizational context) and GV.PO (policy). There is no CISO, only a Deputy (GV.RR, roles/responsibilities/authorities, incomplete by definition the whole reason Task 4 of this project exists). The 1x00 Gap Analysis (G-005) found every Administrative control in the environment is Preventive only no Administrative Detective, Corrective, Compensating or Deterrent control exists anywhere, meaning there is no oversight mechanism (GV.OV) that uses results of security activity to adjust strategy. No documented cybersecurity risk management strategy or risk appetite statement exists (GV.RM) risk decisions to date (1x00 Task 14) were made ad hoc by James against a fixed budget, not against a stated risk tolerance.
- **Key Gaps:** No formal risk management strategy or documented risk appetite (GV.RM), and no assigned cybersecurity authority beyond an unfilled CISO seat (GV.RR) everything downstream (policy, oversight, supply chain risk) depends on these two categories existing first.
- **Target Level:** Managed within 6 months. This project itself (Tasks 4, and the eventual Strategy Document) is the mechanism that gets Govern there a documented strategy, a RACI matrix, and a defined risk acceptance process are all deliverables already scoped in this project, not future work requiring new budget.

## IDENTIFY (ID)

- **Function:** Identify
- **Current Level:** Partial
- **Evidence:** Before this engagement, MedDefense had **no formal asset inventory at all** the entire Asset Registry (1x00 Task 7) had to be reconstructed from a network scan and reconciled against fragmented documentation, uncovering multiple undocumented shadow-IT devices in the process. The same is true of risk assessment: no threat-informed risk analysis existed before 1x01, and no vulnerability-based risk assessment existed before 1x02. The *artifacts* required by ID.AM and ID.RA now exist (Asset Registry, Criticality Matrix, Gap Analysis, Threat Actor Matrix, Vulnerability Assessment) but they exist because an external analyst built them over three projects, not because MedDefense has an internal, repeatable process that produces and maintains them on its own.
- **Key Gaps:** No internal ownership or cadence to keep the asset inventory and risk assessment current after this engagement ends without a defined process, the Asset Registry becomes stale the day after delivery, and the "undocumented shadow IT" problem (1x00 T11) recurs.
- **Target Level:** Managed within 6 months. The artifacts exist; the target is institutionalizing a quarterly asset/risk review cadence owned internally (a Sarah Park/James Chen responsibility, per Task 4's RACI), not building anything from zero.

## PROTECT (PR)

- **Function:** Protect
- **Current Level:** Partial
- **Evidence:** Real preventive controls do exist a default-deny firewall rule (C-003), a password complexity policy (C-006), SSH key-only authentication on `ehr-srv-01` specifically (C-004), and Sophos endpoint protection on workstations (C-008) so Protect is not Not Implemented. But the 1x02 vulnerability scan found 13 of 31 findings were misconfigurations (weak/default settings never hardened), multiple end-of-life systems that can never be fully protected (Task 12), and most significantly **no MFA anywhere in the environment** (GAP-014, cited repeatedly across 1x00 and 1x01 as the single gap that would break the most kill chains). Antivirus explicitly excludes all Windows and Linux servers (GAP-005), meaning the most critical assets have the least endpoint protection.
- **Key Gaps:** Absence of MFA (PR.AA) on any externally-exposed application, remote access path, or administrative account this single missing safeguard appears in nearly every kill chain from 1x01 as the step that would have stopped the attack.
- **Target Level:** Managed within 6 months, driven by CIS Control 6 (Access Control Management) IG1 safeguards MFA on remote access and administrative accounts is achievable with MedDefense's existing O365 licensing (no new procurement needed), making this one of the highest-leverage, lowest-cost improvements available.

## DETECT (DE)

- **Function:** Detect
- **Current Level:** Not Implemented
- **Evidence:** Marcus's own notes (1x00) confirmed zero monitoring capability, and the Gap Analysis (GAP-002, rated Critical) states it directly: "no functioning detection or incident-response capability anywhere in the environment... logs exist... but nothing actively reviews or alerts on them." This is not a theoretical weakness it is exactly why a cryptominer ran undetected on `billing-srv-01` for two weeks (1x00 Task 2), discovered only because the machine slowed down, and why Ghostcat on `ehr-srv-01` (1x02, Finding 031) was found only through manual follow-up rather than automated alerting. A function where the only detection mechanism is "we check manually if something breaks" is not Partial there is no continuous monitoring (DE.CM) and no event correlation (DE.AE) of any kind.
- **Key Gaps:** No SIEM or centralized alerting of any kind logs are collected in isolated pockets (SSH auth logs, firewall logs) but never correlated or reviewed proactively.
- **Target Level:** Partial within 6 months. GAP-002's Phase 1 SIEM deployment (Wazuh, covering critical servers and the firewall first) is already funded in the 1x00 Risk Decisions (~$30,000) six months is enough time to stand up Phase 1 and start generating reviewed alerts, but not enough to reach Managed/Optimized coverage across the full environment including medical IoT and workstations.

## RESPOND (RS)

- **Function:** Respond
- **Current Level:** Not Implemented
- **Evidence:** The same Gap Analysis finding (G-005/GAP-002) that establishes no detection capability also establishes no response capability: "no documented process for detecting policy violations, no formal incident response plan, and no disciplinary/deterrent policy on record." Every prior incident referenced across 1x00 and 1x02 (the ransomware event, the cryptominer, the Patient Portal IDOR, the pharmacy dosage overwrite) was handled improvised, not against a tested playbook there is no RS.MA (incident management), RS.AN (analysis/forensics capability), RS.CO (defined breach-notification communication plan) or RS.MI (mitigation playbook) currently documented anywhere.
- **Key Gaps:** No written Incident Response Plan at all not even a first draft meaning the very first real incident after this assessment would still be improvised.
- **Target Level:** Partial within 6 months drafting and table-top testing a baseline IR plan (incident commander designation, escalation path, breach-notification triggers tied to HIPAA's own timelines) is achievable with existing staff and does not require new tooling, only documented process, which is realistic for a two-person team in this timeframe.

## RECOVER (RC)

- **Function:** Recover
- **Current Level:** Partial
- **Evidence:** A real corrective control exists nightly Veeam backups (C-009) covering the core servers which is why Recover is not Not Implemented. But GAP-003 (1x00, rated Critical) found this backup has never had a full disaster-recovery test performed (only a partial single-server restore, which took 6 hours), the NAS-01 repository holding it is itself unprotected and unencrypted (1x02, Finding 015), and `pacs-srv-01` imaging data for actual patient diagnoses is explicitly **not covered by the nightly backup at all** (1x00 Asset Registry). A recovery capability that has never been tested at scale and excludes a Critical asset entirely is not something an auditor could call Managed.
- **Key Gaps:** No tested Recovery Time Objective (RTO) at the scale of a full environment restore, and a documented, uncovered gap (PACS) in what gets backed up in the first place.
- **Target Level:** Managed within 6 months. Cloud backup replication with immutable storage is already funded in the 1x00 Risk Decisions (GAP-003, ~$14,400/year) implementing it, extending coverage to PACS, and running one full-scale DR test are all realistic within this window since the budget line already exists; the work remaining is execution, not approval.
