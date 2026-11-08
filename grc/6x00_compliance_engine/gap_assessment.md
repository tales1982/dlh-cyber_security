# NIST CSF 2.0 Gap Assessment: MedDefense Health Systems

**Assessment date:** 2026-04-27
**Assessor:** Tales Lima, IT Security
**Framework version:** NIST CSF 2.0
**Regulatory context:** HIPAA Security Rule, 45 CFR Part 164
**Trigger:** HHS OCR desk audit (`ocr_audit_letter.md`), interview in six weeks
**Evidence base:** the artifacts in the 6x00 material folder, cited by file name. "None" means no MedDefense artifact proves the control.

## Method

- Each subcategory is rated against the project-local interpretation in `nist_csf_2_0_subcategory_reference.md` and linked to HIPAA through `hipaa_security_rule_crosswalk.md`.
- **Implemented:** the control exists across its scope and a named artifact proves it.
- **Partial:** the control exists for part of the scope, or it exists technically but has no approval or review record. An auditor treats missing documentation as a missing control.
- **Not Implemented:** no control and no artifact.
- Severity reflects ePHI exposure, the role of the gap in the Nexus / Cobalt Strike incident, and how likely OCR is to ask for it (`ocr_audit_letter.md`).
- The task names 22 subcategories, but its list contains 21. All 21 listed subcategories are assessed.

## Gap Assessment Matrix

| CSF Function | Subcategory | Title (abbreviated) | Status | Evidence Reference | Gap Severity | Gap Description |
| --- | --- | --- | --- | --- | --- | --- |
| GOVERN | GV.OC-01 | Mission and risk context understood | Partial | `risk_register_updates.yaml`; `risk_treatment_plan.md` | High | Risk register exists and was updated after the incident, but the treatment plan is unsigned by the CISO and was never presented to the Board Risk Committee; no approved risk appetite statement |
| GOVERN | GV.PO-01 | Cybersecurity policies established, communicated | Not Implemented | None | Critical | No approved Acceptable Use, Data Classification or Vendor Management policy; the gap is recorded as R-004 (Critical) in `risk_register_updates.yaml` |
| GOVERN | GV.SC-04 | Suppliers inventoried by criticality | Not Implemented | None | High | No vendor inventory or tiering; `forensic_findings_summary.md` shows "no vendor tiering or security review record" while Nexus was the initial access path and CloudVault is about to hold ePHI backups |
| GOVERN | GV.SC-07 | Supplier risks in risk management | Partial | `risk_register_updates.yaml`; `forensic_findings_summary.md` | High | R-001 records the missing vendor process, but no individual supplier (Nexus, CloudVault) is risk-assessed or tracked, and R-001 lists no BAA gate or questionnaire requirement |
| IDENTIFY | ID.AM-01 | Assets inventoried and maintained | Partial | `endpoint_hardening_baseline.md`; `risk_register_updates.yaml` | Medium | Inventory covers 280 clinical workstations, 26 admin laptops and 3 Linux servers only; medical devices are "Unknown", domain controllers and cloud assets are excluded (R-003) |
| IDENTIFY | ID.RA-01 | Vulnerabilities and threats identified | Partial | `forensic_findings_summary.md`; `risk_register_updates.yaml` | Medium | Threats and weaknesses were identified from the incident only; no enterprise vulnerability scanning record or documented risk analysis methodology exists |
| IDENTIFY | ID.RA-06 | Risk responses prioritized and tracked | Partial | `risk_treatment_plan.md`; `risk_register_updates.yaml` | Medium | Treatments have owners and target dates, but the plan is unsigned, has no review cadence, and the five risks raised in `forensic_findings_summary.md` (e.g. service account over-privilege) do not match the register's R-001 to R-005 |
| PROTECT | PR.AA-01 | Identities and credentials managed | Partial | `endpoint_hardening_baseline.md`; `ir_playbook_index.md` | High | Password and lockout GPO is enforced and a credential exposure playbook exists, but there is no identity lifecycle procedure (joiner, mover, leaver) and service accounts are not governed |
| PROTECT | PR.AA-05 | Access reviewed, least privilege enforced | Not Implemented | None | Critical | No periodic access review record exists (`endpoint_hardening_baseline.md` states it does not prove it), and `svc_epic_int` held Domain Admin rights that increased the incident's blast radius |
| PROTECT | PR.AT-01 | Workforce awareness and training | Partial | `security_awareness_training_status.md` | Critical | 73% completion against a 95% target: 408 clinical staff and 56 contractors untrained, no role mapping, no phishing simulation metrics (R-002, Critical) |
| PROTECT | PR.DS-01 | Data-at-rest protected | Partial | `endpoint_hardening_baseline.md` | High | BitLocker confirmed on only 173 of 306 Windows endpoints; no encryption evidence for servers, medical devices or backup storage |
| PROTECT | PR.PS-01 | Secure configuration baselines applied | Partial | `endpoint_hardening_baseline.md` | Medium | Baseline v1.4 covers 231/280 clinical workstations and 18/26 admin laptops; legacy GPOs override it and monthly review sign-off is not documented |
| PROTECT | PR.PS-04 | Logs generated and reviewed | Partial | `endpoint_hardening_baseline.md`; `sigma_detection_catalog.md` | High | Sysmon on 198/280 clinical workstations (71%), Script Block Logging missing on clinical OUs, CloudTrail off in the DR region; weekly review is informal and unrecorded |
| DETECT | DE.CM-01 | Networks and endpoints monitored | Partial | `sigma_detection_catalog.md`; `endpoint_hardening_baseline.md` | High | Six active Sigma rules depend on incomplete telemetry; 82 clinical workstations, all medical devices and biomedical gateways send no logs to the SIEM |
| DETECT | DE.CM-06 | Service provider activity monitored | Partial | `sigma_detection_catalog.md` | High | No active rule monitors vendor activity: SIG-009 (cloud) and SIG-008 (VPN) are drafts, CloudTrail is missing in the DR region, and vendor update channels are not monitored |
| DETECT | DE.AE-02 | Potentially adverse events analyzed | Partial | `sigma_detection_catalog.md`; `forensic_findings_summary.md` | Medium | Analysis works when an alert fires (incident proved it), but SIG-007 is still in testing and rule tuning has no change-management record |
| RESPOND | RS.MA-01 | Incident response plan executed | Implemented | `ir_playbook_index.md`; `forensic_findings_summary.md` | Low | Four active playbooks, real activation (incident 2026-03-25, phishing 2026-04-09) and three tabletops; playbooks still lack formal CISO sign-off |
| RESPOND | RS.AN-03 | Incident analysis performed | Implemented | `forensic_findings_summary.md`; `ir_playbook_index.md` | Low | Root cause, attack path and contributing factors are documented; cloud analysis was limited by the missing DR-region CloudTrail |
| RESPOND | RS.CO-02 | Incident communication performed | Partial | `ir_playbook_index.md` | Medium | Communication testing evidence is incomplete and the vendor-originated incident playbook, which governs external notification, is draft and untested |
| RECOVER | RC.RP-01 | Recovery plan executed | Partial | `recovery_validation_summary.md` | High | Only LIS was restored and it missed its RTO (41 min vs 30 min); Active Directory was tabletop only, Epic was not tested, retest pending, no annual DR test calendar |
| RECOVER | RC.CO-01 | Recovery communication performed | Partial | `recovery_validation_summary.md` | Medium | Clinical notification language was missing from the recovery process (deviation 4); no documented communication to clinical leadership during recovery |

## Summary

**Implementation counts (21 subcategories):**

- Implemented: 2 (RS.MA-01, RS.AN-03)
- Partial: 16
- Not Implemented: 3 (GV.PO-01, GV.SC-04, PR.AA-05)

**Severity counts:** Critical 3, High 9, Medium 7, Low 2, None 0.

**Top 3 pre-audit priorities:**

1. GV.PO-01 (Critical): approve and distribute the Acceptable Use, Data Classification and Vendor Management policies; today OCR would find no enforceable written policy (R-004, due 2026-06-01).
2. PR.AT-01 (Critical): bring training completion from 73% to at least 95% with role mapping and contractor evidence before the audit (R-002, due 2026-06-15).
3. PR.AA-05 (Critical): run and document a privileged and clinical access review, starting with service accounts such as `svc_epic_int`; no access review evidence exists and this gap is not yet in the risk register.

**Connection to upcoming governance work:**

The Critical and High gaps are not scattered technical defects. Most of them are governance gaps sitting on top of technical work that already exists. MedDefense hardened endpoints, wrote detection rules and ran incident response, but it cannot prove policy adoption, approval, review or vendor control, and an auditor reads missing documentation as a missing control. The rest of this project targets those areas directly. The Acceptable Use Policy and the Vendor Management Policy close most of GV.PO-01. The vendor policy creates the tiering and inventory that GV.SC-04 lacks, and the CloudVault assessment produces the first supplier-level risk record for GV.SC-07. The audit evidence package then shows OCR which gaps are closed and which are still open with an owner and a date. The resilience gaps (PR.AA-05, RC.RP-01, DE.CM-06, PR.PS-04) need technical remediation beyond this project, and the risk register has to be reconciled with the forensic findings so that each of them has a tracked risk entry.
