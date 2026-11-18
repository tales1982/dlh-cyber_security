# 6x02: Identity at Scale

Identity and access management package for MedDefense, built after the post-incident review showed that the attacker reached Domain Admin in under two hours through a forgotten service account. It covers SAML SSO federation, least-privilege AWS IAM policies, a scripted audit of the directory account inventory, a CIS AWS Foundations Benchmark assessment and a board-ready brief for the CISO.

- **Organization:** MedDefense (fictional training scenario, DLH Academy)
- **Author:** Tales Lima
- **Date:** 2026-11-18

## Deliverables

| Task | File | Content |
| --- | --- | --- |
| 1 | [keycloak_saml_config.md](keycloak_saml_config.md) | Realm and client settings, test users and roles, annotated d.walsh assertion, replay prevention, signing risk, off-boarding impact |
| 2 | [iam_policies/siem_reader_policy.json](iam_policies/siem_reader_policy.json) | SIEM log reader: S3 read on `meddefense-siemlog-prod`, log writes to its own Lambda log group |
| 2 | [iam_policies/ehr_backup_policy.json](iam_policies/ehr_backup_policy.json) | EHR backup: S3 write/verify on `meddefense-ehr-backup-prod`, two KMS actions on one key via S3, explicit denies |
| 2 | [iam_policies/break_glass_policy.json](iam_policies/break_glass_policy.json) | Break-glass admin: full access only with MFA and from `198.51.100.0/24`, explicit denies on audit tampering and persistence |
| 2 | [iam_policy_analysis.md](iam_policy_analysis.md) | Each violation, the attack surface it creates and how the correction closes it |
| 3 | [iam_audit_report.md](iam_audit_report.md) | 14 findings from the account inventory with evidence, risk, numbered remediation, MFA coverage and roadmap |
| 4 | [cloud_security_assessment.md](cloud_security_assessment.md) | Ten AWS observations mapped to CIS v3.0, severity, status and console/CLI remediation; HIPAA 164.402 analysis of the public ePHI bucket |
| 5 | [iam_program_brief.md](iam_program_brief.md) | One-page, non-technical brief for Dr. Morales and the Board Risk Committee |

Supporting files:

- [audit_iam.py](audit_iam.py): the audit script used for Task 3.
- [iam_findings.json](iam_findings.json): the script's output, the source evidence for the audit report.
- [accounts.csv](accounts.csv): the account inventory the script reads (copy of `materials/iam_audit/accounts.csv`).
- [materials/](materials/): the provided lab materials, unchanged.

## Key Results

- **Directory audit:** 20 accounts, 14 findings (6 Critical, 1 High, 4 Medium, 3 Low). All six Critical findings are standing Domain Admin credentials of the same kind used in the incident: `svc_epic_int`, `svc_backup`, `svc_helpdesk`, `t.morrison`, `j.yamamoto`, `admin.legacy`.
- **MFA:** 6 of 9 enabled privileged user accounts (66.7%); the 3 without MFA are all Domain Admins.
- **Cloud:** 10 findings (2 Critical, 4 High, 4 Medium). The Critical ones are the publicly readable ePHI backup bucket and the root account without MFA and with access keys.
- **Policies:** three wildcard policies replaced with scoped actions, resources and conditions.

## Running the Audit

```bash
python3 audit_iam.py --audit-date 2026-11-18
python3 audit_iam.py --input accounts.csv --output iam_findings.json --dormant-days 90
```

Standard library only (Python 3.8+). The script prints a one-line summary per finding and writes `iam_findings.json`. Findings are ordered by severity, then by closeness to the incident path, so the same input always gives the same IDs.

## Environment Note

The work was done on the analyst workstation from the provided materials archive, using the same file names as `/opt/meddefense/materials`. No live Keycloak or AWS account was queried: the SAML analysis uses the realm export and the captured assertions, and the cloud assessment uses the recorded observations.
