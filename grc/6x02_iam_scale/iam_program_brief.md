# Identity Program Brief for Dr. Morales

**Prepared by:** Tales Lima, IT Security | **Reviewed by:** James Chen, SOC Lead | **Date:** 2026-11-18 | **Confidential**

## Identity Posture Summary

We reviewed every directory account (20) and our cloud account (10 settings). We found **8 Critical and 5 High** problems: 6 Critical and 1 High in the directory (`iam_audit_report.md`), 2 Critical and 4 High in the cloud (`cloud_security_assessment.md`). Six accounts that nobody needs still hold full control of the network, three of them without a second login factor. One cloud storage folder with patient backup files can be opened by anyone on the internet (CLD-06). Our identity posture today is **not acceptable**, but every problem is known, has an owner and has a date.

## Connection to the Incident

The attacker went from one infected computer to full control of our network in under two hours by stealing the password of an old service account with full administrator rights. The same kind of account still exists: `svc_epic_int` (IAM-001) has full control, has not been used in over three years and has no known purpose. Five more accounts give the same shortcut: two other service accounts (IAM-002, IAM-003), a contractor who left in 2025 (IAM-004), an employee who moved to Finance (IAM-005) and an old migration account (IAM-006). Until they are fixed, the same attack works again.

## What Has Been Completed

- **Full account audit with a repeatable tool:** every account was checked and each problem is tied to evidence; the check can now run monthly (`audit_iam.py`).
- **Cloud permissions rewritten:** three over-broad cloud roles were rewritten to allow only their job, including the EHR backup role (CLD-09, `iam_policy_analysis.md`). Ready to deploy.
- **Single sign-on tested:** one login and one switch-off point for all clinical systems, so leavers lose access everywhere at once (`keycloak_saml_config.md`).
- **Short-lived passwords tested:** a vault issues temporary passwords that expire in 15 to 60 minutes; once revoked, a stolen copy is useless (`materials/pam/` test records).

## What Must Be Completed Before the Next Board Meeting

| Action | Owner | Target |
| --- | --- | --- |
| Close public access to the patient backup folder and start the HIPAA breach assessment (CLD-06) | Cloud Administrator, Privacy Officer | 2026-11-19 |
| Remove full-control rights from the six accounts, disable the unused ones (IAM-001 to IAM-006) | Systems Administrator | 2026-11-21 |
| Lock the cloud master account with a hardware key and remove its keys (CLD-01) | Cloud Administrator | 2026-11-19 |

## What Requires Board Authorization or Budget

- **Privileged access management and single sign-on platform:** estimated 9 to 12 months, licenses and one dedicated identity engineer. If deferred, standing administrator passwords remain the main way in for attackers.
- **Breach notification reserve:** if the CLD-06 assessment cannot show that no one downloaded the files, HIPAA requires notifying patients and HHS within 60 days of discovery.

## Board Resolution Requested

The Board Risk Committee authorizes funding for a 12-month identity security program (single sign-on, temporary administrator passwords and quarterly access reviews) and directs the CISO to report the closure of all Critical findings at the next meeting.
