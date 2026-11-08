# OCR Desk Audit Evidence Package: MedDefense Health Systems

**Prepared:** 2026-04-27
**Prepared by:** Tales Lima, IT Security
**For:** Dr. Patricia Morales, CISO; Helena Reyes, General Counsel
**Audit request:** `ocr_audit_letter.md` (HHS OCR desk audit, HIPAA Security Rule, eight evidence requests)
**Mapping used:** `hipaa_security_rule_crosswalk.md`
**Rule applied:** an item is **Full** only if a named artifact answers the whole request. Anything less is **Partial**, and no artifact is **None**. The audit treats missing documentation as a missing control.

## Evidence Inventory

| Artifact | Source | Date |
| --- | --- | --- |
| `risk_register_updates.yaml` | Risk register v2026.04, IT Security | 2026-04 |
| `risk_treatment_plan.md` | Risk treatment plan v1.0, unsigned | 2026-04 |
| `forensic_findings_summary.md` | IR Team, Nexus / Cobalt Strike incident | 2026-03-25 to 2026-03-26 |
| `endpoint_hardening_baseline.md` | Baseline v1.4, IT Security | 2026-04-18 |
| `sigma_detection_catalog.md` | Catalog v2.1, SOC Engineering | 2026-04-22 |
| `ir_playbook_index.md` | IT Security, last formal review | 2026-04-12 |
| `recovery_validation_summary.md` | LIS recovery tabletop and partial restore | 2026-04-20 |
| `security_awareness_training_status.md` | Period 2025-05-01 to 2026-04-30 | 2026-04 |
| `prior_policy_inventory.md` | Sarah Park | 2026-04-24 |
| `baa_status_note.md` | Legal | 2026-04-24 |
| `gap_assessment.md` | Produced in this project | 2026-04-27 |
| `acceptable_use_policy.md` (MD-POL-001) | Produced in this project, pending CISO signature | effective 2026-05-04 |
| `vendor_management_policy.md` (MD-POL-003) | Produced in this project, pending CISO signature | effective 2026-05-04 |
| `vendor_risk_assessment.md` | Produced in this project | 2026-04-27 |
| `data_classification_policy.md` | **Not produced in this package.** The policy is still missing (`prior_policy_inventory.md`, R-004) | None |

## Evidence by Request

### Request 1: Security risk analysis

**HIPAA specification:** 164.308(a)(1)(ii)(A)
**Evidence status:** Partial
**Evidence description:** `risk_register_updates.yaml` records five open risks with severity, source, owner and target date. `forensic_findings_summary.md` documents threats and vulnerabilities found during the March 2026 incident. `gap_assessment.md` assesses 21 NIST CSF 2.0 subcategories with named evidence, status and severity for each.
**Gap:** No documented enterprise-wide risk analysis methodology or scope statement exists. Current risk identification is driven by the incident and does not cover the whole ePHI environment: medical devices, Epic, cloud assets and domain controllers are outside every assessed scope (`endpoint_hardening_baseline.md`). The register and the forensic report also use the same IDs R-001 to R-005 for different risks, and the over-privileged service account `svc_epic_int` is not in the register.
**Remediation owner and timeline:** CISO (Dr. Patricia Morales) with IT Security: approve a written risk analysis methodology and scope covering all ePHI systems and reconcile the register with `forensic_findings_summary.md` by 2026-05-22; complete the enterprise risk analysis by 2026-06-05, before the audit interview.

### Request 2: Risk management plan

**HIPAA specification:** 164.308(a)(1)(ii)(B)
**Evidence status:** Partial
**Evidence description:** `risk_treatment_plan.md` assigns a treatment, owner role, target date and success criterion to each of R-001 to R-005, matching the owners and dates in `risk_register_updates.yaml`. Progress is visible for R-004 (`acceptable_use_policy.md` and `vendor_management_policy.md` drafted) and R-001 (`vendor_risk_assessment.md` completed for CloudVault).
**Gap:** The plan is not signed by the CISO and has not been presented to the Board Risk Committee (stated in `risk_treatment_plan.md`, "Governance Gap"). No tracking cadence or status history shows that the risks are actively managed. Privileged access and recovery testing gaps have no treatment entry.
**Remediation owner and timeline:** CISO: sign the plan by 2026-05-08 and present it to the Board Risk Committee by 2026-05-20; IT Security: add treatments for privileged access review and DR retest and keep a dated status log every two weeks from 2026-05-08.

### Request 3: Workforce security awareness and training

**HIPAA specification:** 164.308(a)(5)
**Evidence status:** Partial
**Evidence description:** `security_awareness_training_status.md` shows training delivered between 2025-05-01 and 2026-04-30: 1,460 of 2,000 workforce members (73%) completed modules on phishing, passwords, reporting, minimum necessary, lost devices and remote access. `acceptable_use_policy.md` Section 9 ties annual policy acknowledgment to annual training.
**Gap:** 540 workforce members have no completion record (408 clinical staff, 72 administrative staff, 4 IT staff and 56 contractors), which is below the 95% internal target. Training is not mapped to roles, there are no phishing simulation metrics, and there is no approved plan for the next training cycle (R-002, Critical).
**Remediation owner and timeline:** IT Security: make-up training for all 540 overdue users by 2026-05-27 (30 days); role-based assignment matrix and first phishing simulation results by 2026-06-15 (R-002 target); contractor completion made a condition of access renewal from 2026-05-04.

### Request 4: Audit controls

**HIPAA specification:** 164.312(b)
**Evidence status:** Partial
**Evidence description:** `endpoint_hardening_baseline.md` shows auditd on the 3 Linux support servers, sudo logs forwarded to `log-srv-01`, and Sysmon on 198 of 280 clinical workstations. `sigma_detection_catalog.md` lists six active SIEM rules (SIG-001 to SIG-006) analyzing that activity, and `forensic_findings_summary.md` shows the logs being used to detect and reconstruct the incident.
**Gap:** Logging covers only part of the environment: 82 clinical workstations have no Sysmon, Script Block Logging is missing on clinical OUs, CloudTrail is off in the DR region (R-005), and medical devices send no logs. Log review is weekly but "informal", with no review record, so the "reviewed" half of the request has no evidence.
**Remediation owner and timeline:** SOC Engineering: start a signed weekly log and alert review record by 2026-05-04; Cloud Security: CloudTrail in `us-east-2` forwarding to the SIEM by 2026-06-10 (R-005); IT Security: Sysmon and Script Block Logging on all clinical workstations by 2026-06-05.

### Request 5: Workforce security procedures

**HIPAA specification:** 164.308(a)(3)
**Evidence status:** None
**Evidence description:** No user access provisioning, termination or periodic access review procedure exists among MedDefense artifacts. `endpoint_hardening_baseline.md` states explicitly that it does not prove periodic access review. `acceptable_use_policy.md` (pending signature) only requires a signed acknowledgment before access is granted, which supports provisioning but is not a provisioning procedure.
**Gap:** No documented joiner, mover or leaver process, no termination deadline for access removal, and no record of any access review. `forensic_findings_summary.md` shows the result: `svc_epic_int` held Domain Admin membership and increased the blast radius of the incident.
**Remediation owner and timeline:** IT Director (Sarah Park) with HR: written access provisioning and termination procedure (access removed same day as termination) approved by the CISO by 2026-05-22; IT Security: first documented privileged and clinical access review, including all service accounts, completed and signed by 2026-06-05; recurring quarterly review from then on.

### Request 6: Business Associate Agreement for CloudVault Medical

**HIPAA specification:** 164.308(b)
**Evidence status:** Partial
**Evidence description:** No BAA exists. The request also accepts "documentation showing no ePHI access has begun". `baa_status_note.md` records that the BAA is not executed and lists the required terms. `cloudvault_contract_summary.md` records that the contract is proposed and that ePHI transfer is not allowed until the BAA is executed. `vendor_risk_assessment.md` makes the executed BAA (condition C-1) and three other conditions mandatory before any ePHI transfer. `vendor_management_policy.md` makes the BAA an unconditional gate for Tier A vendors.
**Gap:** No executed BAA. MedDefense also has no positive technical evidence, such as transfer logs or a firewall record, that no backup has reached CloudVault; the "no ePHI access" position rests on contract and approval documents.
**Remediation owner and timeline:** General Counsel (Helena Reyes): BAA executed with all MD-POL-003 Section 6.2 terms before any transfer, target 2026-05-29. Infrastructure Manager: written confirmation, backed by transfer pipeline and firewall logs, that no MedDefense data has been sent to CloudVault, by 2026-05-08.

### Request 7: Technical evaluation

**HIPAA specification:** 164.308(a)(8)
**Evidence status:** Partial
**Evidence description:** Within the last 12 months: `endpoint_hardening_baseline.md` (CIS-aligned assessment of endpoints and Linux servers, 2026-04-18), `recovery_validation_summary.md` (LIS restore test, 2026-04-20), `ir_playbook_index.md` (three tabletops and one live activation in April 2026) and `gap_assessment.md` (framework evaluation, 2026-04-27).
**Gap:** All evaluations were done internally, in response to the incident. None is periodic or independent. There is no MedDefense penetration test or external assessment, Epic and Active Directory recovery was not tested, medical devices were not evaluated, and no evaluation schedule has leadership approval.
**Remediation owner and timeline:** CISO: approve an annual technical evaluation schedule (independent penetration test, DR test, hardening review) by 2026-05-20; IT Security: contract an independent penetration test of the clinical network to start by 2026-06-30, with the engagement letter available for the audit.

### Request 8: Incident response procedures

**HIPAA specification:** 164.308(a)(6)
**Evidence status:** Full
**Evidence description:** `ir_playbook_index.md` lists active procedures (Credential Exposure, Phishing Triage, Ransomware Containment, Data Exfiltration Review) with testing in the last 24 months: tabletops on 2026-04-15, 2026-04-16 and 2026-04-17, and live activation of Phishing Triage on 2026-04-09. `forensic_findings_summary.md` documents a full real activation and analysis for the Nexus / Cobalt Strike incident of 2026-03-25 to 2026-03-26.
**Gap:** None blocking the request. Weaknesses an auditor may note: the playbooks lack formal CISO sign-off, three playbooks are draft (Cloud, Insider Threat, Vendor-Originated), and there is no approved annual exercise schedule.
**Remediation owner and timeline:** Improvement, not required for Full status: CISO sign-off on the active playbooks by 2026-05-15; IT Security plus Procurement test the vendor-originated incident playbook by 2026-06-05.

## Readiness Summary

**Evidence counts:**

- Full: 1 (Request 8)
- Partial: 6 (Requests 1, 2, 3, 4, 6, 7)
- None: 1 (Request 5)

**Overall audit readiness rating:** **Not Ready.** Only one of eight requests is fully answered. Several Partial items depend on documents that are drafted but not signed: the risk treatment plan and both new policies. The remediation dates above fall before the audit interview, roughly six weeks from 2026-04-27. If they are met, the rating moves to At Risk.

**Single biggest gap:** The auditor would focus on Request 5, workforce security. MedDefense has no access provisioning, termination or periodic access review procedure, and its own forensic report shows that an over-privileged service account (`svc_epic_int`, Domain Admin) contributed to a real incident.
