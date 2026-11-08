# 6x00: The Compliance Engine

Compliance package for MedDefense Health Systems ahead of the HHS Office for Civil Rights (OCR) desk audit of HIPAA Security Rule compliance. The package measures MedDefense's existing security controls against NIST CSF 2.0 and the HIPAA Security Rule, writes the missing governance policies, assesses the CloudVault Medical vendor relationship, and maps the available evidence to the OCR audit requests.

- **Organization:** MedDefense Health Systems (fictional training scenario, DLH Academy)
- **Author:** Tales Lima
- **Assessment date:** 2026-04-27
- **Frameworks:** NIST Cybersecurity Framework 2.0; HIPAA Security Rule, 45 CFR Part 164 Subpart C

## Deliverables

| Task | File | Purpose |
| --- | --- | --- |
| 1 | [gap_assessment.md](gap_assessment.md) | NIST CSF 2.0 gap matrix for 21 subcategories with named evidence, status, severity and gap, plus summary and top 3 priorities |
| 2 | [acceptable_use_policy.md](acceptable_use_policy.md) | MD-POL-001, enforceable Acceptable Use Policy for all users of MedDefense systems |
| 3 | [vendor_management_policy.md](vendor_management_policy.md) | MD-POL-003, vendor tiers, Tier A requirements (VMP-A1 to A13), BAA terms, monitoring, offboarding, incident notification |
| 4 | [vendor_risk_assessment.md](vendor_risk_assessment.md) | CloudVault Medical assessed against MD-POL-003: 15 findings, 4 Critical Concerns, Approve with Conditions |
| 5 | [audit_evidence_package.md](audit_evidence_package.md) | Evidence for the eight OCR requests, with gaps, owners and dates, plus readiness rating |

## Source Materials

The provided evidence artifacts are kept unchanged in [6x00/](6x00/) and are cited by file name in every deliverable:

```text
6x00/
├── prior_controls/   endpoint hardening, Sigma catalog, IR playbooks, forensic summary, recovery validation, training status
├── risk_register/    risk_register_updates.yaml, risk_treatment_plan.md
├── compliance/       CSF 2.0 reference, HIPAA crosswalk, OCR audit letter, prior policy inventory
├── vendor/           CloudVault questionnaire, contract summary, sub-processor list, BAA status note
└── templates/        policy header, audit evidence request, CISO brief
```

## Key Results

- **Gap assessment:** 2 Implemented, 16 Partial, 3 Not Implemented; Critical gaps in policy (GV.PO-01), training (PR.AT-01) and access review (PR.AA-05).
- **CloudVault Medical:** Tier A vendor, **Approve with Conditions**. No ePHI transfer until the BAA is executed, a current penetration test is delivered, the DR site is disclosed, and 24-hour incident notification is in the contract.
- **Audit readiness:** **Not Ready** (1 Full, 6 Partial, 1 None). The biggest gap is workforce security: there are no access provisioning or review procedures.

## Honesty Rules Followed

- Every evidence claim names an artifact from `6x00/` or a document produced in this project. Where no artifact exists, the deliverable says **None**.
- Both policies are drafts awaiting CISO signature and are labelled that way. No BAA, signature, training record or assessment is claimed unless it exists.
- `data_classification_policy.md` was not produced in this package; the policy remains a documented gap (R-004).
