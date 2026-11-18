# MedDefense IAM Audit Report

**Classification:** Confidential
**Audit date:** 2026-11-18
**Prepared by:** Tales Lima, IT Security
**Reviewed by:** James Chen, SOC Lead
**Approved by:** _________________________ Date: _________

## Executive Summary

MedDefense does not control who holds administrative access to its network. Of the 20 accounts in the directory inventory, 14 produced findings: **6 Critical, 1 High, 4 Medium and 3 Low**. Nine accounts are members of `Domain Admins`, the group that controls every server, workstation and clinical application in the domain; only three of them are active staff whose daily work needs that level of access. Six Domain Admin accounts have no valid business reason to hold it today: three service accounts and three user accounts that belong to a departed contractor, a finished migration and an employee who moved to Finance. None of the three user accounts has multi-factor authentication. In total, 3 of the 9 enabled privileged user accounts (33%) can be used with a password alone.

The most critical finding is **IAM-001, `svc_epic_int`**: a service account that is still enabled, still a member of `Domain Admins`, has not logged in for 1,156 days and, according to its own description, has "no current function identified". Nobody uses it and nobody monitors it, but its password unlocks the whole domain. Two more service accounts (`svc_backup`, IAM-002 and `svc_helpdesk`, IAM-003) hold Domain Admin because of a legacy configuration and a vendor installation that was never reviewed.

These findings are the same path used in the last incident. The intrusion went from one compromised workstation to an extracted credential, to a service account with Domain Admin membership, to control of the domain in under two hours (`materials/iam_audit/incident_identity_path.md`). Every Critical finding in this report (IAM-001 to IAM-006) is a standing Domain Admin credential of the same kind: a credential that exists all the time, is not tied to an active person or job, and gives full control if it is stolen. Until they are removed, the attack can be repeated with the same three steps. This audit changes that in three ways: it gives a complete, evidence-based list of every over-privileged account, a remediation plan with an owner and a date for each, and a repeatable script (`audit_iam.py`) so that the review can be run every month instead of once after an incident.

## Audit Scope and Methodology

**In scope:**

- All 20 accounts in `accounts.csv` (15 user accounts, 5 service accounts): enabled state, account type, last login, MFA enrollment, privileged group membership and description.
- Membership in the privileged groups `Domain Admins`, `Server Admins` and `Workstation Admins`. `Helpdesk` membership was considered for disabled accounts.

**Out of scope:**

- AWS IAM users, roles and policies (covered in `iam_policy_analysis.md` and `cloud_security_assessment.md`).
- Local accounts inside Epic, PACS, pharmacy and other applications, and nested group membership. The inventory does not include them.
- Verification of the inventory against live Active Directory. The inventory is taken as the source of record; `last_login_days_ago` is counted from the date the inventory was extracted.

**Method:**

1. `audit_iam.py` reads every row of `accounts.csv` and applies these checks: service account privilege, leaver de-provisioning, privileged account ownership, dormancy (no login for more than 90 days), MFA enrollment and disabled accounts that kept their groups. Description text is matched for departure ("Contract ended", "Left organization"), missing function ("migration complete", "no current function", "rights not removed") and unreviewed grants ("review later", "per vendor", "legacy config").
2. When several checks fire on one account, the script produces one finding with the highest severity and lists every condition, so each account has one remediation.
3. Findings are ordered by severity, then by closeness to the incident path, then by dormancy. Each finding records the `accounts.csv` line it comes from.
4. The analyst reviewed every finding against the source row before writing this report.

**Severity** follows `materials/iam_audit/severity_model.md`:

| Severity | Rule used | Target |
| --- | --- | --- |
| Critical | Direct domain takeover, privileged persistence or repeat of the incident path: service account in Domain Admins; departed or orphaned account in Domain Admins | Immediate (24 to 72 hours) |
| High | Strong attack path that needs one more condition: departed user still enabled, dormant privileged user, privileged user without MFA | 7 days |
| Medium | Meaningful exposure or detection weakness: service account in Server or Workstation Admins, high-risk user without MFA, disabled account that kept its groups | 30 days |
| Low | Hygiene that does not enable a major incident alone: standing Domain Admin on active, MFA-protected named accounts | 30 days |

## Findings Summary Table

| Finding ID | Account | Category | Severity | Status |
| --- | --- | --- | --- | --- |
| IAM-001 | svc_epic_int | Service account over-privilege | Critical | Open |
| IAM-002 | svc_backup | Service account over-privilege | Critical | Open |
| IAM-003 | svc_helpdesk | Service account over-privilege | Critical | Open |
| IAM-004 | t.morrison | Departed user with privileged access | Critical | Open |
| IAM-005 | j.yamamoto | Orphaned privileged account | Critical | Open |
| IAM-006 | admin.legacy | Orphaned privileged account | Critical | Open |
| IAM-007 | l.okafor | Departed user still enabled | High | Open |
| IAM-008 | svc_monitoring | Service account over-privilege | Medium | Open |
| IAM-009 | svc_av_mgmt | Service account over-privilege | Medium | Open |
| IAM-010 | k.nguyen | MFA gap on high-risk user | Medium | Open |
| IAM-011 | b.carter | Disabled account retains privileged groups | Medium | Open |
| IAM-012 | sarah.park | Standing Domain Admin on named account | Low | Open |
| IAM-013 | robert.kim | Standing Domain Admin on named account | Low | Open |
| IAM-014 | james.chen | Standing Domain Admin on named account | Low | Open |

## Detailed Findings

### IAM-001: Dormant service account with no function holds Domain Admin

**Account:** svc_epic_int
**Severity:** Critical
**Check:** Service account privilege review
**Evidence:** `accounts.csv` line 14: `account_type=service`, `enabled=TRUE`, `last_login_days_ago=1156`, `mfa_enrolled=N/A`, `privileged_groups=Domain Admins`, `description="Post-EHR-migration service account; no current function identified"`. Also listed as Critical in `materials/pam/pam_migration_candidates.csv`.
**Risk:** The password of this account gives full control of the domain. Service account passwords are usually static and stored in scripts, configuration files or memory on the servers that once used them, which is exactly where the last attacker found the credential. Nobody logs in with it, so a malicious logon would stand out only if someone were watching, and nobody is. With it an attacker can deploy ransomware to every server, disable backups and read or alter Epic data. Patient safety: loss of Epic and clinical systems forces downtime procedures across the hospital. Regulatory: unrestricted access to ePHI fails HIPAA 164.308(a)(4) access management and 164.312(a)(1) access control, and a misuse would be a reportable breach.
**Remediation:**

1. Remove `svc_epic_int` from `Domain Admins` today.
2. Reset its password to a random 32-character value and do not record it.
3. Disable the account and add the description "Disabled 2026-11-18, IAM-001, pending deletion".
4. Ask the Clinical Systems Manager to confirm in writing within 7 days that no Epic interface uses it. Watch the SIEM for failed logons by this account during the 30-day hold.
5. Delete the account after 30 days if no dependency is found.
6. If a dependency is found, replace it with a Vault dynamic credential with a short TTL and only the database or interface rights the job needs, not a re-enabled Domain Admin account.

**Owner:** Systems Administrator; Clinical Systems Manager for the dependency confirmation
**Target completion:** Immediate (steps 1 to 3); 30 days (deletion)

### IAM-002: Backup service account holds Domain Admin by legacy configuration

**Account:** svc_backup
**Severity:** Critical
**Check:** Service account privilege review
**Evidence:** `accounts.csv` line 13: `account_type=service`, `enabled=TRUE`, `last_login_days_ago=1`, `mfa_enrolled=N/A`, `privileged_groups=Domain Admins`, `description="Nightly backup automation; DA granted per legacy config"`.
**Risk:** This account logs in every night, so its credential is present on the backup server and in memory there. Whoever compromises the backup server gets Domain Admin, and with it the ability to delete or encrypt both production data and the backups needed to recover it, the standard ransomware sequence. Patient safety: if backups are lost with production, clinical systems cannot be restored within their recovery objectives. Regulatory: HIPAA 164.308(a)(7) contingency plan and 164.308(a)(4).
**Remediation:**

1. List the exact rights the backup software needs (read all files for backup, write for restore, VSS on the servers in scope). Use the vendor's minimum-rights document.
2. Create a group `Backup-Service` and grant only those rights (for example the built-in `Backup Operators` group on the in-scope servers, plus read rights on the backup targets).
3. Add `svc_backup` to `Backup-Service` and remove it from `Domain Admins`.
4. Run the next nightly job and one test restore; record success in the change ticket.
5. Set the account to "deny interactive logon" and "deny logon through Remote Desktop" by Group Policy, and rotate the password every 90 days (move it to Vault).

**Owner:** Systems Administrator
**Target completion:** Immediate (7 days at most, to allow one tested backup cycle)

### IAM-003: Helpdesk automation holds vendor-granted Domain Admin never reviewed

**Account:** svc_helpdesk
**Severity:** Critical
**Check:** Service account privilege review
**Evidence:** `accounts.csv` line 15: `account_type=service`, `enabled=TRUE`, `last_login_days_ago=0`, `mfa_enrolled=N/A`, `privileged_groups=Domain Admins`, `description="Ticket routing automation; DA granted by vendor during install; review later"`.
**Risk:** Ticket routing does not need control of the domain. The account is active every day, so its credential is stored in the helpdesk application and probably in its configuration on disk. A compromise of the helpdesk platform, or of the vendor's remote support connection, becomes a domain compromise. Patient safety and regulatory consequence are the same as IAM-001.
**Remediation:**

1. Remove `svc_helpdesk` from the `Domain Admins` group.
2. Verify that helpdesk automation continues to operate with `Helpdesk` group membership only: create a test ticket, check routing and assignment, and check any password reset or unlock function.
3. If a function fails, grant only that right by delegation on the needed OU (for example "Reset password" on the Users OU), not by group.
4. Document the verification result in the change ticket.
5. Ask the vendor for its written minimum-rights requirement and file it with the change.

**Owner:** Systems Administrator; IT Director for the vendor request
**Target completion:** Immediate

### IAM-004: Departed contractor still enabled as Domain Admin and Server Admin

**Account:** t.morrison
**Severity:** Critical
**Check:** Leaver de-provisioning review
**Evidence:** `accounts.csv` line 8: `account_type=user`, `department=IT Contractors`, `enabled=TRUE`, `last_login_days_ago=248`, `mfa_enrolled=FALSE`, `privileged_groups=Domain Admins;Server Admins`, `description="Contract ended 2025-09-01"`.
**Risk:** A person who no longer works for MedDefense still holds full domain control, protected only by a password and no MFA. The former contractor, or anyone who has their password from an old laptop, a password manager or a breach list, can log in. Patient safety: full control of clinical infrastructure. Regulatory: HIPAA 164.308(a)(3)(ii)(C) requires termination procedures that end access when employment or an engagement ends; this is a direct failure of that standard.
**Remediation:**

1. Disable `t.morrison` immediately.
2. Remove it from `Domain Admins` and `Server Admins`.
3. Reset the password and revoke any VPN certificates, remote access tokens and active sessions.
4. Search SIEM and domain controller logs for any logon by this account since 2025-09-01 and record the result.
5. Delete the account after 30 days if the review is clean.
6. Ask the contract owner to confirm that contractor exits are now sent to IT on the end date.

**Owner:** Systems Administrator; SOC Lead for the log review
**Target completion:** Immediate

### IAM-005: Employee transferred to Finance keeps Domain Admin without MFA

**Account:** j.yamamoto
**Severity:** Critical
**Check:** Privileged account ownership review
**Evidence:** `accounts.csv` line 18: `account_type=user`, `department=Finance`, `enabled=TRUE`, `last_login_days_ago=312`, `mfa_enrolled=FALSE`, `privileged_groups=Domain Admins;Server Admins`, `description="Transferred from IT to Finance 2024-02; elevated rights not removed"`.
**Risk:** A Finance employee holds full domain control with password-only login. Finance users are frequent phishing targets (invoices, payment requests). One successful phish of this user gives the attacker Domain Admin directly, without the credential-extraction step used in the last incident. Regulatory: HIPAA 164.308(a)(4)(ii)(C) requires access to be modified when a role changes.
**Remediation:**

1. Remove `j.yamamoto` from `Domain Admins` and `Server Admins`.
2. Confirm with the Finance manager which groups the Finance role needs and keep only those.
3. Enroll MFA before the next login.
4. Review logons by this account in the last 312 days for any privileged activity and record the result.
5. Add a "role change" step to the HR-to-IT process so that a transfer triggers an access review.

**Owner:** Systems Administrator; Finance manager for the role confirmation
**Target completion:** Immediate

### IAM-006: Migration admin account left enabled as Domain Admin

**Account:** admin.legacy
**Severity:** Critical
**Check:** Privileged account ownership review
**Evidence:** `accounts.csv` line 7: `account_type=user`, `enabled=TRUE`, `last_login_days_ago=187`, `mfa_enrolled=FALSE`, `privileged_groups=Domain Admins`, `description="Created for EHR migration 2021; migration complete"`.
**Risk:** A shared, generic admin account with no owner, no MFA and full domain rights. Because it is not tied to a person, actions taken with it cannot be attributed to anyone, which also fails HIPAA 164.312(a)(2)(i) unique user identification. Its password was probably shared during the 2021 migration among staff and vendors who may have left.
**Remediation:**

1. Remove `admin.legacy` from `Domain Admins`.
2. Disable the account and reset the password.
3. Review its logons in the last 187 days and any scheduled tasks or services running as it on servers; record the result.
4. Delete the account after 30 days if nothing depends on it.

**Owner:** Systems Administrator
**Target completion:** Immediate

### IAM-007: Departed employee account still enabled

**Account:** l.okafor
**Severity:** High
**Check:** Leaver de-provisioning review
**Evidence:** `accounts.csv` line 11: `account_type=user`, `department=Finance`, `enabled=TRUE`, `last_login_days_ago=142`, `mfa_enrolled=FALSE`, `privileged_groups=Finance Users`, `description="Left organization per HR 2025-11-28"`.
**Risk:** No administrative rights, but a working, password-only account of a person who has left. It can be used to access Finance data and email, and as an internal foothold for phishing or for the first hop of an attack like the last one. Severity is High rather than Critical because it holds no privileged group. Regulatory: HIPAA 164.308(a)(3)(ii)(C) termination procedures.
**Remediation:**

1. Disable `l.okafor` and remove `Finance Users`.
2. Confirm the leave date with HR and review logons after 2025-11-28; record the result.
3. Hand over the mailbox and files to the Finance manager as policy requires, then delete the account after the retention period.

**Owner:** Systems Administrator; HR for the leave confirmation
**Target completion:** 7 days

### IAM-008: Monitoring agent holds Server Admins for read-only metrics

**Account:** svc_monitoring
**Severity:** Medium
**Check:** Service account privilege review
**Evidence:** `accounts.csv` line 16: `account_type=service`, `enabled=TRUE`, `last_login_days_ago=0`, `mfa_enrolled=N/A`, `privileged_groups=Server Admins`, `description="Prometheus metrics collection"`.
**Risk:** Metrics collection needs read access; `Server Admins` gives administrator rights on every server. The credential is stored on the monitoring host. A compromise of that host gives admin on all servers, one step from domain compromise.
**Remediation:**

1. Remove `svc_monitoring` from `Server Admins`.
2. Add it to `Performance Monitor Users` and `Event Log Readers` on the monitored servers (or the exporter's documented minimum).
3. Check that all Prometheus targets still report for 24 hours.
4. Move the credential to Vault and rotate it every 90 days.

**Owner:** Systems Administrator
**Target completion:** 30 days

### IAM-009: EDR management agent holds Workstation Admins

**Account:** svc_av_mgmt
**Severity:** Medium
**Check:** Service account privilege review
**Evidence:** `accounts.csv` line 17: `account_type=service`, `enabled=TRUE`, `last_login_days_ago=0`, `mfa_enrolled=N/A`, `privileged_groups=Workstation Admins`, `description="EDR agent management"`.
**Risk:** Admin rights on every workstation, including clinical workstations. A stolen credential allows disabling EDR and moving between workstations, the start of the last incident's path. The function is legitimate, so this is rated Medium.
**Remediation:**

1. Confirm with the EDR vendor whether the console needs a domain account at all (most agents run as local SYSTEM and do not).
2. If it does, restrict the account to the workstation OUs and deny interactive and RDP logon by Group Policy.
3. Move the credential to Vault with scheduled rotation, or use JIT for management tasks.
4. Alert in the SIEM on any logon by this account outside the EDR server.

**Owner:** Security Engineer
**Target completion:** 30 days

### IAM-010: High-risk clinical user has no MFA

**Account:** k.nguyen
**Severity:** Medium
**Check:** MFA enrollment review
**Evidence:** `accounts.csv` line 10: `account_type=user`, `department=Radiology`, `enabled=TRUE`, `last_login_days_ago=1`, `mfa_enrolled=FALSE`, `privileged_groups=Epic Users;PACS Users`, `description="Three phishing simulation failures in 90 days"`.
**Risk:** The user most likely to give a password to a phishing page is the one whose login has no second factor. The account reaches Epic and PACS, both of which hold ePHI. A stolen password gives an attacker patient records and imaging and a foothold inside the network.
**Remediation:**

1. Enroll MFA before the next login.
2. Assign targeted phishing awareness training within 14 days.
3. Add the account to a SIEM watchlist for logins from new devices or locations for 90 days.

**Owner:** IT Director (MFA), Security Awareness lead (training)
**Target completion:** 7 days for MFA; 30 days for the rest

### IAM-011: Disabled account still in Server Admins and Helpdesk

**Account:** b.carter
**Severity:** Medium
**Check:** Leaver de-provisioning review
**Evidence:** `accounts.csv` line 12: `account_type=user`, `enabled=FALSE`, `last_login_days_ago=224`, `mfa_enrolled=TRUE`, `privileged_groups=Server Admins;Helpdesk`, `description="Account disabled; group memberships not removed at offboarding"`.
**Risk:** Disabled, so it cannot log in today. But anyone who re-enables it (by mistake or with Helpdesk rights) restores admin on every server at once. It also shows the off-boarding process disables accounts without removing groups.
**Remediation:**

1. Remove `b.carter` from `Server Admins` and `Helpdesk`.
2. Add "remove all group memberships" to the off-boarding checklist, before the disable step.
3. Alert in the SIEM on any re-enable of a disabled account (Windows event 4722).

**Owner:** Systems Administrator
**Target completion:** 30 days

### IAM-012: IT Director uses a Domain Admin account for daily work

**Account:** sarah.park
**Severity:** Low
**Check:** Privileged access model review
**Evidence:** `accounts.csv` line 3: `account_type=user`, `enabled=TRUE`, `last_login_days_ago=6`, `mfa_enrolled=TRUE`, `privileged_groups=Domain Admins;IT Directors`, `description="IT Director"`.
**Risk:** Active and MFA-protected, but the same account reads email, browses the web and holds Domain Admin. Malware on her workstation runs with Domain Admin rights. Rated Low because the owner is current and MFA is on.
**Remediation:**

1. Create a separate admin account (`adm.sarah.park`) used only from a privileged access workstation.
2. Remove `Domain Admins` from `sarah.park`.
3. Grant Domain Admin to the admin account through JIT elevation with approval and a time limit, once the PAM program is in place.

**Owner:** IT Director
**Target completion:** 30 days

### IAM-013: Security Analyst uses a Domain Admin account for daily work

**Account:** robert.kim
**Severity:** Low
**Check:** Privileged access model review
**Evidence:** `accounts.csv` line 4: `account_type=user`, `enabled=TRUE`, `last_login_days_ago=3`, `mfa_enrolled=TRUE`, `privileged_groups=Domain Admins;Security Operations`, `description="Security Analyst"`.
**Risk:** Same as IAM-012. A security analyst opens suspicious files and links as part of the job, which raises the chance that malware runs under a Domain Admin session.
**Remediation:** Same three steps as IAM-012, with admin account `adm.robert.kim`.
**Owner:** SOC Lead
**Target completion:** 30 days

### IAM-014: SOC Lead uses a Domain Admin account for daily work

**Account:** james.chen
**Severity:** Low
**Check:** Privileged access model review
**Evidence:** `accounts.csv` line 2: `account_type=user`, `enabled=TRUE`, `last_login_days_ago=1`, `mfa_enrolled=TRUE`, `privileged_groups=Domain Admins;Security Operations`, `description="SOC Lead"`.
**Risk:** Same as IAM-012.
**Remediation:** Same three steps as IAM-012, with admin account `adm.james.chen`.
**Owner:** IT Director
**Target completion:** 30 days

## MFA Coverage Analysis

Scope: enabled user accounts in `Domain Admins`, `Server Admins` or `Workstation Admins`. Service accounts are excluded because MFA is not applicable (`N/A`); they are covered in the next section. Disabled `b.carter` is excluded.

| Measure | Count |
| --- | --- |
| Enabled privileged user accounts | 9 |
| With MFA | 6 (`james.chen`, `sarah.park`, `robert.kim`, `m.torres`, `h.reyes`, `a.petrov`) |
| Without MFA | 3 (`t.morrison`, `j.yamamoto`, `admin.legacy`) |
| Coverage | **66.7%** |

All three accounts without MFA are Domain Admins and all three are Critical findings (IAM-004, IAM-005, IAM-006): the accounts with the most power have the weakest login. Across all 14 enabled user accounts, 5 have no MFA: the three above plus `k.nguyen` (IAM-010) and `l.okafor` (IAM-007).

HIPAA comparison:

- **164.312(a)(2)(i) Unique user identification (required):** each person must have a unique ID so actions can be traced. `admin.legacy` is a shared generic account with no owner and fails this. All other user accounts are named.
- **164.312(d) Person or entity authentication (required):** MedDefense must verify that the person using an ID is who they claim to be. A password alone on a Domain Admin account of a departed contractor (`t.morrison`) or a transferred employee (`j.yamamoto`) does not give that assurance. HIPAA does not name MFA, but the HHS Security Rule update proposed in January 2025 would make MFA required, and NIST SP 800-63B treats single-factor authentication as insufficient for privileged access.

Target: 100% MFA on enabled privileged user accounts within 7 days, reached by removing the three accounts' privileges (IAM-004 to IAM-006), not by enrolling them.

## Service Account Risk Summary

| Account | Privileged group | Last login (days) | Documented function | Finding | Recommendation |
| --- | --- | --- | --- | --- | --- |
| `svc_epic_int` | Domain Admins | 1,156 | None ("no current function identified") | IAM-001 Critical | Remove DA, disable, delete after 30 days; Vault dynamic credential if a need is found |
| `svc_backup` | Domain Admins | 1 | Yes: nightly backup | IAM-002 Critical | Replace DA with `Backup-Service` group (backup and restore rights only); deny interactive logon; Vault rotation |
| `svc_helpdesk` | Domain Admins | 0 | Yes: ticket routing (DA granted by vendor, "review later") | IAM-003 Critical | Remove DA, keep `Helpdesk` only, delegate specific OU rights if needed |
| `svc_monitoring` | Server Admins | 0 | Yes: Prometheus metrics | IAM-008 Medium | Replace with `Performance Monitor Users` and `Event Log Readers` |
| `svc_av_mgmt` | Workstation Admins | 0 | Yes: EDR management | IAM-009 Medium | Confirm need; scope to workstation OUs; deny interactive logon; Vault rotation |

Three of five service accounts hold Domain Admin, and none of the three needs it for its function. All five use static passwords. These are the accounts the Vault PAM design targets first (`materials/pam/pam_migration_candidates.csv`): a dynamic credential with a 15-minute to 1-hour TTL is revoked automatically, so a stolen copy expires before it can be reused, as shown in the lease revocation test (`materials/pam/vault_lease_revoke_transcript.md`).

## Remediation Roadmap

| Priority | Action | Owner Role | Target | Success Criterion |
| --- | --- | --- | --- | --- |
| 1 | Disable `t.morrison`, `admin.legacy`, `svc_epic_int`; remove all their groups (IAM-004, IAM-006, IAM-001) | Systems Administrator | Immediate (24 h) | Accounts show `enabled=FALSE` and no privileged groups in the next `audit_iam.py` run |
| 2 | Remove `j.yamamoto` and `svc_helpdesk` from Domain Admins; verify helpdesk automation (IAM-005, IAM-003) | Systems Administrator | Immediate (72 h) | Not in Domain Admins; test ticket routed; change ticket records result |
| 3 | Log review for logons by `t.morrison`, `admin.legacy`, `j.yamamoto`, `svc_epic_int` since departure or last legitimate use | SOC Lead | 7 days | Written result filed; any hit opened as an incident |
| 4 | Replace `svc_backup` Domain Admin with `Backup-Service` group; tested backup and restore (IAM-002) | Systems Administrator | 7 days | Nightly job and test restore succeed without DA |
| 5 | Disable `l.okafor`; enroll MFA for `k.nguyen` (IAM-007, IAM-010) | Systems Administrator, IT Director | 7 days | Account disabled; MFA enrolled |
| 6 | Scope `svc_monitoring`, `svc_av_mgmt`; clean `b.carter` groups (IAM-008, IAM-009, IAM-011) | Systems Administrator, Security Engineer | 30 days | No service account in Server or Workstation Admins without approved exception |
| 7 | Separate admin accounts for `james.chen`, `sarah.park`, `robert.kim` (IAM-012 to IAM-014) | IT Director | 30 days | Daily accounts not in Domain Admins |
| 8 | Fix off-boarding and role-change process: HR notifies IT on exit or transfer date; groups removed before disable | IT Director with HR | 30 days | Next three leavers de-provisioned the same day, verified by audit |
| 9 | Run `audit_iam.py` monthly on a fresh export and report the delta to the SOC Lead | SOC Lead | Monthly from 30 days | Zero open Critical findings; new findings tracked to closure |
| 10 | Move service account credentials to Vault dynamic or rotated secrets | Security Engineer | 90 days | No static service account password older than 90 days |

## Appendix: Audit Script

- **Script:** `audit_iam.py` (Python 3, standard library only). Run: `python3 audit_iam.py --audit-date 2026-11-18`. Options: `--input` (default `accounts.csv`), `--output` (default `iam_findings.json`), `--dormant-days` (default 90).
- **Source data:** `accounts.csv`, a copy of `materials/iam_audit/accounts.csv` (20 rows, unchanged).
- **Output:** `iam_findings.json`. It holds the audit metadata, the summary (14 findings: 6 Critical, 1 High, 4 Medium, 3 Low; 6 incident-path matches; MFA coverage 66.7%) and one object per finding with `finding_id`, the account fields copied from the CSV, `category`, `check`, `severity`, the list of `conditions` that fired, `incident_path_match`, the `evidence` line reference, `remediation` and `status`.
- **Traceability:** each finding in this report uses the same ID, severity and `accounts.csv` line as `iam_findings.json`. Re-running the script on the same input gives the same IDs.

Console output of the audit run:

```text
Accounts reviewed: 20
Findings: 14 (Critical 6, High 1, Medium 4, Low 3)
IAM-001  Critical  svc_epic_int    Service account over-privilege
IAM-002  Critical  svc_backup      Service account over-privilege
IAM-003  Critical  svc_helpdesk    Service account over-privilege
IAM-004  Critical  t.morrison      Departed user with privileged access
IAM-005  Critical  j.yamamoto      Orphaned privileged account
IAM-006  Critical  admin.legacy    Orphaned privileged account
IAM-007  High      l.okafor        Departed user still enabled
IAM-008  Medium    svc_monitoring  Service account over-privilege
IAM-009  Medium    svc_av_mgmt     Service account over-privilege
IAM-010  Medium    k.nguyen        MFA gap on high-risk user
IAM-011  Medium    b.carter        Disabled account retains privileged groups
IAM-012  Low       sarah.park      Standing Domain Admin on named account
IAM-013  Low       robert.kim      Standing Domain Admin on named account
IAM-014  Low       james.chen      Standing Domain Admin on named account
```
