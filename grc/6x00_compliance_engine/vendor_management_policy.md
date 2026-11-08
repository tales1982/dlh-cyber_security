# Vendor Management Policy

```text
Policy number:   MD-POL-003
Policy title:    Vendor Management Policy
Effective date:  2026-05-04
Review date:     2027-05-04 (annual review; earlier after a vendor-originated incident or a change in law)
Owner:           IT Security and Procurement (joint)
Approved by:     Dr. Patricia Morales, Chief Information Security Officer
Classification:  Internal
Applies to:      All third parties with access to MedDefense systems, networks or data, and every MedDefense employee who selects, contracts or manages them
```

**Approval status:** Drafted 2026-04-27. This policy takes effect on the effective date once it is signed by the CISO. It replaces the procurement checklist recorded as the only vendor control in `prior_policy_inventory.md` and implements treatment R-001 in `risk_treatment_plan.md`.

## 1. Purpose

MedDefense depends on third parties that can reach patient data and clinical systems, and the Nexus compromise showed that a trusted vendor with a signed contract can become the attacker's way in. This policy sets the security requirements every vendor must meet before it gets access, while it has access, and when access ends, so that vendor risk is known, approved and enforceable.

## 2. Scope

This policy applies to every third party that has, or will have, access to MedDefense systems, networks or data, including:

- software-as-a-service (SaaS) providers;
- managed service providers (IT, security, billing, transcription);
- cloud infrastructure, hosting, backup and disaster recovery providers;
- medical device vendors whose products connect to a MedDefense network or receive remote support;
- staffing agencies whose personnel receive MedDefense system accounts;
- any sub-processor that handles MedDefense data on behalf of one of the above.

No contract, purchase order, pilot, free trial or proof of concept that gives a third party access to MedDefense systems or data may start without the steps in this policy. Procurement will not issue a purchase order and IT will not create access until IT Security records the vendor's tier and approval.

## 3. Roles

| Role | Responsibility |
| --- | --- |
| Business owner (requesting department) | Requests the vendor, describes the data and access needed, owns the relationship |
| Procurement | Keeps the vendor inventory, enforces this policy in the purchasing process, holds contracts |
| IT Security | Assigns the tier, runs the security assessment, issues the risk rating and approval decision |
| Legal (General Counsel) | Drafts and executes Business Associate Agreements and security clauses |
| CISO | Approves Tier A vendors, approves exceptions, receives Concern and Critical Concern findings |

## 4. Vendor Risk Tiers

Every vendor is assigned one tier before contract signature, based on the highest level of access or data exposure it will have. If in doubt, the higher tier applies.

| Tier | Definition | Examples |
| --- | --- | --- |
| **Tier A (Critical)** | Stores, processes, transmits or can view ePHI, or has access to clinical systems, even if the access is only for support or the data is encrypted or "metadata" that can be linked to patients | Scheduling platforms, imaging (PACS) vendors, backup and DR providers holding PHI, Epic integration partners, clinical device vendors with remote support |
| **Tier B (Standard)** | Access to MedDefense internal systems or networks, but no ePHI and no clinical system access | IT support contractors on corporate systems, HR or finance SaaS without patient data, network maintenance providers |
| **Tier C (Low)** | No access to MedDefense systems or data | Office suppliers, physical goods vendors, facilities and cleaning contractors without system accounts |

Procurement keeps a vendor inventory listing every vendor's tier, business owner, data handled, access method, BAA status, last assessment date and next review date.

## 5. Pre-Engagement Requirements

### 5.1 Tier A: all of the following before any data or system access

| ID | Requirement |
| --- | --- |
| VMP-A1 | SOC 2 Type II report **or** HITRUST CSF certification, with a report or certification date within the last 12 months. The full report is provided to IT Security, not only a statement that one exists. |
| VMP-A2 | Completed MedDefense vendor security questionnaire, signed by the vendor's security officer. |
| VMP-A3 | Penetration test performed by an independent tester and dated within the last 12 months, with a summary of all critical and high findings and their remediation status. |
| VMP-A4 | Identification of every sub-processor that will handle MedDefense data, with its role, the data it receives and the country where it processes or stores data. |
| VMP-A5 | Disclosure of the location (country and region) of every data center that will store MedDefense data, including backup and disaster recovery sites. ePHI is stored in the United States unless the CISO and General Counsel approve another location in writing. |
| VMP-A6 | An executed Business Associate Agreement meeting Section 6, signed before any ePHI access begins. **No exceptions.** |
| VMP-A7 | Encryption of MedDefense data at rest (AES-256 or equivalent) and in transit (TLS 1.2 or higher, with TLS 1.3 preferred and weak cipher suites disabled). |
| VMP-A8 | Multi-factor authentication on all administrative, privileged and support accounts that can reach MedDefense data. |
| VMP-A9 | Vulnerability management with at least monthly scanning and remediation of critical vulnerabilities within 30 days, high within 60 days. |
| VMP-A10 | Background checks on personnel with access to MedDefense data, at hire and repeated at least every 3 years. |
| VMP-A11 | Annual HIPAA and security training for personnel with access to MedDefense data. |
| VMP-A12 | Contract clauses for: incident notification within 24 hours (Section 8); MedDefense right to audit or assess with no more than 30 days written notice, and without advance notice during a security incident investigation; data return or certified destruction within 30 days of termination (Section 7). |
| VMP-A13 | CISO approval of the assessment result recorded in the vendor inventory. |

### 5.2 Tier B

VMP-A2, VMP-A7, VMP-A8 and VMP-A12, plus a SOC 2 Type II report, ISO 27001 certificate or equivalent independent assessment within 24 months. Approval by IT Security.

### 5.3 Tier C

Business owner confirms no system or data access in the vendor inventory. No security assessment required. If access is later requested, the vendor is re-tiered before access is granted.

### 5.4 Assessment ratings

IT Security rates each requirement for each vendor:

| Rating | Meaning | Effect |
| --- | --- | --- |
| Pass | Requirement fully met with evidence | None |
| Acceptable | Requirement met at the minimum, or a minor weakness that does not increase ePHI risk materially | Recorded; tracked at annual review |
| Concern | Requirement not fully met; risk can be managed by a contract term or a remediation date | Must be resolved or covered by a written contract condition before signature |
| Critical Concern | A Tier A requirement (VMP-A1, A3, A4, A5, A6 or the 24-hour notification in A12) is not met, or ePHI location or exposure is unknown | No ePHI or clinical system access until resolved and re-verified by IT Security |

A vendor with any open Critical Concern may receive, at most, "Approve with Conditions", and only if every Critical Concern is a condition precedent that must be satisfied before any data access. A vendor that refuses to meet a Critical Concern condition is "Do Not Approve".

### 5.5 Exceptions

Exceptions to Section 5 require a written risk acceptance signed by the CISO, with an expiry date of no more than 6 months and an entry in the risk register. **No exception is allowed for the BAA (VMP-A6)** or for the 24-hour incident notification.

## 6. Business Associate Agreement (BAA) Requirements

### 6.1 When a BAA is required

- Every Tier A vendor.
- Any vendor whose service may incidentally expose ePHI (for example on-site IT support on clinical workstations, or a transfer service that carries backup files), even if ePHI access is not the purpose of the contract.
- Every sub-processor of such a vendor that handles ePHI, through a flow-down agreement with the vendor.

### 6.2 Minimum BAA content

1. Permitted and required uses and disclosures of PHI, limited to the contracted service.
2. Obligation to implement HIPAA Security Rule safeguards (administrative, physical and technical) for ePHI.
3. Notification to MedDefense **within 24 hours** of any confirmed or suspected security incident or breach affecting MedDefense data, followed by the details MedDefense needs for its own breach assessment.
4. Disclosure of all sub-processors and flow-down of the same obligations to each of them; no new sub-processor without 30 days prior written notice to MedDefense.
5. Return or certified destruction of all MedDefense data within 30 days of termination, including backups and DR copies.
6. MedDefense right to request evidence and records during an investigation and to audit compliance.
7. Access revocation and termination support at the end of the contract.
8. MedDefense right to terminate the contract if the vendor materially breaches the BAA.

Legal keeps executed BAAs for at least six years after the end of the contract.

## 7. Ongoing Monitoring

1. Tier A vendors are reassessed every year against Section 5.1. Tier B vendors every two years.
2. The following material changes trigger an immediate out-of-cycle review, and the vendor must notify MedDefense in writing within 30 days of the change:
   - ownership change, merger or acquisition;
   - new or changed sub-processors;
   - relocation of a data center or DR site holding MedDefense data;
   - a significant security incident at the vendor or one of its sub-processors, whether or not MedDefense data was affected;
   - loss or qualification of the SOC 2 / HITRUST attestation.
3. IT Security monitors vendor remote access and vendor-supplied update channels into MedDefense systems through SIEM logging.
4. Open Concern findings are tracked in the vendor inventory with an owner and due date; overdue Critical Concern items lead to suspension of access.

## 8. Incident Notification Obligations

1. The vendor must notify MedDefense IT Security **within 24 hours** of a confirmed or suspected security incident or breach that affects or may affect MedDefense data, systems or users. Waiting for internal confirmation is not a reason to delay notification.
2. Notification goes to the IT Security hotline (extension 7233, +1 555 0100 7233, 24/7) and in writing to the security mailbox named in the contract.
3. The vendor must preserve logs and evidence related to the incident and provide them on request.
4. MedDefense retains the right to conduct its own investigation, independent of the vendor's, including requesting logs, interviewing vendor staff and engaging an outside forensic firm.
5. MedDefense, not the vendor, decides whether a breach of MedDefense PHI must be reported to patients, HHS or the media.

## 9. Vendor Offboarding

1. All vendor access (accounts, VPN, API keys, remote support tools, certificates) is revoked **within 24 hours** of contract termination or end of the service, and IT Security records the revocation.
2. The vendor returns or destroys MedDefense data **within 30 days** of termination and provides a written certificate of destruction covering primary storage, backups, DR sites and sub-processors.
3. Contracts, BAAs, assessments, certificates of destruction and offboarding records are kept for at least **six years**, in line with HIPAA documentation retention.

## 10. Enforcement

Employees who contract with or give access to a vendor outside this policy are subject to the HR disciplinary process. Vendors that breach this policy or their BAA are subject to access suspension, contract remedies and termination.

## Acknowledgment

```text
Acknowledgment:
I acknowledge that I have read, understood and agree to comply with this policy.

Employee name:
Signature:
Date:
```
