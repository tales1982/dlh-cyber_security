# IAM Audit Severity Model

Critical: direct domain takeover, broad ePHI access, privileged persistence or repeat of prior incident path. Examples: service account with Domain Admins, departed contractor with Domain Admins, public ePHI backup bucket, root without MFA.

High: strong attack path needing one additional condition. Examples: dormant privileged user, privileged user without MFA, broad AWS admin role, CloudTrail missing in clinical backup region.

Medium: meaningful exposure or detection weakness. Examples: high-risk user without MFA and repeated failures, service account with Server Admins, long-lived keys, disabled account retaining groups.

Low: hygiene issues unlikely to independently enable major incident. Every finding needs account, account type, enabled state, last login, MFA state, group/policy and source evidence.
