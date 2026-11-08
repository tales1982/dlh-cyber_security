# Vendor Risk Assessment: CloudVault Medical

**Assessment date:** 2026-04-27
**Assessor:** Tales Lima, IT Security
**Requested by:** Dr. Patricia Morales, CISO (security sign-off required before contract signature)
**Policy applied:** `vendor_management_policy.md` (MD-POL-003), requirements VMP-A1 to VMP-A13 and rating scale in Section 5.4
**Evidence reviewed:** `cloudvault_security_questionnaire.md` (received 2026-04-26), `cloudvault_contract_summary.md`, `cloudvault_subprocessor_list.md`, `baa_status_note.md` (last update 2026-04-24)

## Vendor Overview

| Item | Value |
| --- | --- |
| Vendor name | CloudVault Medical |
| Service type | Clinical backup archive and disaster recovery storage, proposed 3-year contract |
| Data handled | Encrypted backup archives of Epic EHR database exports, LIS backups, PACS/RIS metadata exports, pharmacy dispensing system backups, and operational recovery logs that may contain patient identifiers (`cloudvault_contract_summary.md`) |
| ePHI stored or processed | **Yes, stored.** Backups contain ePHI. MedDefense keeps encryption key ownership in the proposed design, but CloudVault metadata may include patient identifiers and CloudVault support staff can access the backup management console. Encryption by MedDefense does not take CloudVault out of Business Associate status. |
| Access model | Encrypted transfer pipeline into CloudVault; vendor support access to the management console |
| Proposed tier | **Tier A (Critical)** under MD-POL-003 Section 4: stores ePHI and backup data for clinical systems |
| BAA status | Not executed; vendor "willing to execute" (`baa_status_note.md`) |
| ePHI transferred to date | None. No contract is signed and no transfer is authorized (`cloudvault_contract_summary.md`, initial recommendation) |
| Business owner / data owner | Infrastructure Manager / Clinical Applications Manager |

## Findings

| # | Finding (abbreviated response) | Policy requirement | Risk rating | Gap description | Required action |
| --- | --- | --- | --- | --- | --- |
| 1 | SOC 2 Type II, report dated 11 months ago | VMP-A1 | Acceptable | Meets the 12-month rule today but ages out in about one month, before ePHI transfer is likely to start; the report itself has not been provided, only a "Yes" | Provide the full SOC 2 Type II report and, once it passes 12 months, a bridge letter plus the next report; IT Security reviews exceptions and complementary user entity controls |
| 2 | No HITRUST CSF certification | VMP-A1 | Pass | None; MD-POL-003 accepts SOC 2 Type II **or** HITRUST | None |
| 3 | AES-256 at rest | VMP-A7 | Pass | None | Confirm in contract that encryption covers DR copies and that MedDefense keeps key ownership |
| 4 | TLS 1.2 in transit | VMP-A7 | Acceptable | Meets the minimum; TLS 1.3 not offered and cipher configuration not stated | Provide TLS configuration (protocols and cipher suites) for the transfer pipeline and console; weak ciphers disabled |
| 5 | Penetration test 22 months old; findings summary not provided | VMP-A3 | **Critical Concern** | Test is 10 months past the 12-month limit and MedDefense has no view of critical findings or their remediation | Independent penetration test dated within 12 months, with critical/high findings summary and remediation evidence, before any ePHI access |
| 6 | Two sub-processors: US CDN (FastRoute Health CDN), EU analytics (MetricLake Analytics GmbH) | VMP-A4, VMP-A5 | Concern | Sub-processors are named with locations, but it is not stated whether MetricLake receives patient identifiers or linkable metadata, whether either has admin access, or whether they are bound by HIPAA-equivalent terms and breach notification (`cloudvault_subprocessor_list.md` open questions 1-5) | Written data-flow statement per sub-processor; flow-down BAA terms; if any patient identifier or linkable metadata reaches MetricLake, the EU transfer requires written CISO and General Counsel approval or must be switched off for MedDefense tenants |
| 7 | Primary data center in the US; DR site location not disclosed | VMP-A5 | **Critical Concern** | MedDefense does not know where a full copy of its ePHI backups would live, so jurisdiction, physical security and BAA coverage of that copy cannot be assessed | Disclose DR site country, region and operator, and contractually commit to US-only storage of MedDefense data (or obtain written CISO and General Counsel approval) before any ePHI access |
| 8 | Incident notification 72 hours after internal confirmation | VMP-A12, Section 8, BAA 6.2(3) | **Critical Concern** | Three times the 24-hour limit, and the clock only starts after the vendor confirms the breach, so a suspected incident could go unreported for days | BAA and contract must require notification within 24 hours of a confirmed **or suspected** incident affecting MedDefense data |
| 9 | Data deletion within 90 days of written request | VMP-A12, Section 9.2 | Concern | 60 days longer than policy and triggered by a request, not by termination; no certificate of destruction mentioned | Contract: return or certified destruction within 30 days of termination, covering backups, DR site and sub-processors, with a written certificate |
| 10 | Background checks at hire only | VMP-A10 | Concern | No re-screening of staff who hold long-term console access to MedDefense backups | Contract: re-screening at least every 3 years for staff with access to MedDefense data, or a documented compensating control accepted by the CISO |
| 11 | MFA on admin and privileged accounts, TOTP | VMP-A8 | Pass | None. Phishing-resistant MFA (FIDO2) would be stronger and is recorded as a recommendation | Confirm MFA also covers support staff access to the MedDefense management console |
| 12 | Monthly scanning; critical findings remediated quarterly | VMP-A9 | Concern | Critical vulnerabilities may stay open up to 90 days, against the 30-day requirement | Contract: critical vulnerabilities remediated within 30 days, high within 60 days, with quarterly attestation to MedDefense |
| 13 | Right to audit with 60 days written notice | VMP-A12 | Concern | Notice period is double the policy limit, and there is no right to assess during an incident investigation | Contract: right to audit with no more than 30 days notice, and immediate access to evidence during a security incident affecting MedDefense data |
| 14 | BAA: willing to execute (not executed) | VMP-A6, Section 6 | **Critical Concern** | No BAA exists. Under MD-POL-003 the BAA is unconditional: no Tier A vendor receives ePHI without one, and sending ePHI now would be an impermissible disclosure | Executed BAA containing all Section 6.2 terms (including 24-hour notification and sub-processor flow-down) before any ePHI transfer |
| 15 | Annual online PHI handling training | VMP-A11 | Pass | None | Provide completion evidence for staff with access to MedDefense data at each annual review |

**Rating counts:** Pass 4 (items 2, 3, 11, 15), Acceptable 2 (items 1, 4), Concern 5 (items 6, 9, 10, 12, 13), Critical Concern 4 (items 5, 7, 8, 14).

## Critical Findings

### Item 5: Penetration test 22 months old, no findings summary

The risk is undetected exploitable weaknesses in the platform that would hold every MedDefense clinical backup: Epic, LIS, PACS metadata and pharmacy data. A backup provider is a high-value target, because one breach exposes several clinical systems at once, and ransomware groups go after backups to stop recovery. Without a recent independent test, MedDefense cannot show it assessed the vendor's safeguards, which is part of its HIPAA risk analysis (164.308(a)(1)(ii)(A)) and its duty to obtain satisfactory assurances (164.308(b)). After the Nexus compromise, OCR would expect that diligence. **Before approval:** an independent penetration test report dated within 12 months, a summary of all critical and high findings, and evidence that the critical findings are remediated.

### Item 7: Disaster recovery site location not disclosed

A full copy of MedDefense ePHI would sit in a place MedDefense cannot name. MedDefense cannot verify that the copy is covered by US law, by the BAA or by the SOC 2 scope, and in a breach at that site it could not establish jurisdiction or notification duties. It would also be unable to answer an OCR question on where its ePHI is stored. **Before approval:** the DR site country, region and operator, confirmation that the DR site is within the SOC 2 scope, and a contract commitment to US-only storage. Storage outside the US needs explicit written approval from the CISO and General Counsel.

### Item 8: 72-hour incident notification after internal confirmation

MedDefense's breach clock under HIPAA starts when MedDefense or its business associate knows of the breach (45 CFR 164.404 and 164.410). Notification 72 hours after the vendor's own confirmation, which itself can take days, would consume MedDefense's investigation time. It would also delay containment, such as rotating keys or stopping backup transfers, while an attacker may still be active. That is unacceptable after an incident in which the attacker came in through a vendor. **Before approval:** the BAA and contract must require notification within 24 hours of any confirmed or suspected incident affecting MedDefense data, preservation of evidence, and MedDefense's right to investigate independently (MD-POL-003 Section 8).

### Item 14: Business Associate Agreement not executed

CloudVault will store ePHI, so it is a business associate. Sending ePHI before a BAA is signed is an impermissible disclosure under HIPAA, and in itself a reportable compliance failure; it would also leave OCR Request 6 (`ocr_audit_letter.md`) without an answer. "Willing to execute" is not a BAA. **Before approval:** a BAA executed by both parties that contains every term in MD-POL-003 Section 6.2: permitted uses, safeguards, 24-hour notification, sub-processor flow-down, return or destruction within 30 days, evidence on request, and termination support. Under MD-POL-003 Section 5.5 no exception is possible.

## Recommendation

**Approve with Conditions.**

Rationale: the vendor's core technical controls are sound: a current SOC 2 Type II, AES-256 at rest, TLS 1.2 in transit, MFA on privileged accounts, and annual PHI training. MedDefense also keeps ownership of the encryption keys. The service fills a real resilience need. `recovery_validation_summary.md` shows that MedDefense's own recovery capability is unproven for Epic and Active Directory. The four Critical Concerns, however, mean CloudVault does not meet the MD-POL-003 Tier A requirements today. Under Section 5.4 the vendor can only be approved if every Critical Concern is a condition precedent to any ePHI access. "Do Not Approve" is not required because all four gaps can be fixed through contract terms and evidence delivery, and the vendor has already offered to sign a BAA. The approval is **void**, and the decision becomes **Do Not Approve**, if CloudVault refuses any Critical Concern condition or has not met them by 2026-06-20 (R-001 target date).

Until every condition below is verified by IT Security and recorded in the vendor inventory, **no ePHI, no production backup and no test backup containing real patient data may be sent to CloudVault.**

## Required Conditions

### Conditions precedent to any ePHI access (Critical Concerns)

| ID | Condition | Evidence required | Verified by | Due |
| --- | --- | --- | --- | --- |
| C-1 | BAA executed by both parties with all MD-POL-003 Section 6.2 terms | Signed BAA filed by Legal | Helena Reyes, General Counsel | Before any ePHI transfer; target 2026-05-29 |
| C-2 | Incident notification within 24 hours of a confirmed or suspected incident affecting MedDefense data, in the BAA and the master contract | Clause text in signed BAA and contract | Legal and IT Security | With C-1 |
| C-3 | Independent penetration test report dated within the last 12 months, summary of all critical and high findings, and evidence that every critical finding is remediated | Report, findings summary, remediation evidence | IT Security | Before any ePHI transfer; target 2026-06-12 |
| C-4 | DR site country, region and operator disclosed; DR site within SOC 2 scope; contractual commitment that all MedDefense data stays in the United States | Written disclosure and contract clause | IT Security and Legal | Before contract signature |

### Conditions to be written into the contract before signature (Concerns)

| ID | Condition | Due |
| --- | --- | --- |
| C-5 | Data-flow statement for FastRoute Health CDN and MetricLake Analytics GmbH; flow-down of BAA terms; written confirmation that no patient identifiers or linkable metadata reach MetricLake, or written CISO and General Counsel approval of that transfer | Before contract signature |
| C-6 | Return or certified destruction of all MedDefense data (primary, backups, DR, sub-processors) within 30 days of termination | Contract clause |
| C-7 | Remediation of critical vulnerabilities within 30 days and high within 60 days, with quarterly attestation | Contract clause |
| C-8 | Right to audit with no more than 30 days notice and immediate access to evidence during a security incident | Contract clause |
| C-9 | Background re-screening at least every 3 years for staff with access to MedDefense data | Contract clause |
| C-10 | Full SOC 2 Type II report delivered now, and a bridge letter or new report before the current report passes 12 months | Report delivery; annual review |
| C-11 | TLS configuration (protocols, cipher suites) for the transfer pipeline and console provided; weak ciphers disabled | Before first data transfer |

### MedDefense follow-up

- Add CloudVault to the vendor inventory as Tier A with the conditions above, and add a supplier-level risk entry for CloudVault under R-001 in `risk_register_updates.yaml`.
- Annual reassessment under MD-POL-003 Section 7, plus an out-of-cycle review if CloudVault adds or changes a sub-processor or moves the DR site.
- Security sign-off for the contract is given only when C-4 to C-9 are in the contract text. Sign-off for data transfer is given only when C-1 to C-3 and C-11 are verified.
