
# Insider Threat Assessment MedDefense Health Systems

## Scenario 1 The Shared Login

- **Classification:** Negligent. This is a systemic operational practice, not an individual act of malice the risk exists because the organization tolerates a shared account, not because any one technician intends harm.
- **Behavioral Indicators:** Multiple simultaneous or overlapping login sessions under the same account from different workstations; sessions left open between patients with no logout; access logs showing continuous activity across shift changes with no corresponding individual identity.
- **Existing Control (from 1x00):** None found. The issue was formally reported to Sarah Park and remains unresolved no compensating technical or administrative control covers it.
- **Gap Exploited (from 1x00):** GAP-010 Shared PACS login removes individual accountability for imaging access. 
- **Recommended Mitigation:** Technical issue individual login credentials per technician on the PACS workstation, paired with an automatic session timeout so idle sessions can't persist between patients.

## Scenario 2 The Ghost Account

- **Classification:** Negligent (systemic) the root cause is an organizational offboarding failure, not intent. The three off-hours authentications after termination are a red flag that would require individual investigation, but nothing in the scenario evidences malicious use, only that unauthorized access remained possible.
- **Behavioral Indicators:** Authentication activity from an account tied to a terminated contract; login timing outside normal business hours; no open ticket or business justification for continued access after the contract end date.
- **Existing Control (from 1x00):** None found. C-006 (password policy) and C-007 (account lockout) govern password strength and failed attempts, but neither triggers on employment/contract status nothing in the Control Matrix ties account state to HR or contract records.
- **Gap Exploited (from 1x00):** GAP-018 No automated account deprovisioning tied to HR/contract termination.
- **Recommended Mitigation:** Administrative a mandatory, systemic offboarding process that automatically disables network and VPN access on contract/employment end date, rather than depending on a manager remembering to file a ticket.

## Scenario 3 The Personal NAS

- **Classification:** Negligent. Dr. Patel's motive is convenience and clinical/research access, not harm but the device sits entirely outside governance, with no encryption, no backup and no IT visibility.
- **Behavioral Indicators:** An unrecognized device (MAC/IP) appearing in a network inventory or scan with no matching asset record; unmanaged, unencrypted network storage traffic; patient data flowing to a device with no associated change request or IT ticket.
- **Existing Control (from 1x00):** None found this is shadow IT by definition, meaning it sits outside every control category in the Task 10 (1x00) matrix.
- **Gap Exploited (from 1x00):** GAP-011 Three confirmed shadow IT systems sit entirely outside governance (Dr. Patel's NAS is one of the systems captured under this gap).
- **Recommended Mitigation:** Technical Network Access Control (NAC) to detect and quarantine unauthorized devices automatically, paired with a clear, enforced policy prohibiting personal storage devices from holding patient data.

## Scenario 4 The Curious Employee

- **Classification:** Malicious. This matches the "curiosity-driven unauthorized access (celebrity/VIP snooping)" pattern the intelligence dossier names explicitly there is no clinical or administrative reason for a registration clerk to view a specific patient's full record and then disclose what she saw socially.
- **Behavioral Indicators:** EHR access to a patient outside the employee's normal workflow or assigned unit; access to a high-profile ("VIP") record with no matching appointment, billing task or registration event; no logged business justification for the lookup.
- **Existing Control (from 1x00):** None found access is governed by broad role permissions, not need-to-know restrictions, and nothing detects access to a specific record as anomalous.
- **Gap Exploited (from 1x00):** GAP-001 EHR database reachable from the entire internal network, with no detection of anomalous access; the clerk's lookup was technically permitted and went completely unflagged.
- **Recommended Mitigation:** Technical role-based access limiting front-desk/registration staff to patients within their active workflow, combined with automated alerting whenever a "flagged" or VIP record is accessed outside a matching clinical or billing event.

## Scenario 5 The Overworked Admin

- **Classification:** Negligent. The sysadmin is trying to solve a real backlog problem, not cause harm but the fix itself creates a serious, entirely avoidable exposure.
- **Behavioral Indicators:** Administrative credentials stored in plaintext in a file rather than a vault; an unreviewed script with elevated privileges shared outside any approval process; credentials distributed via a channel (email) with no audit trail of who else may have accessed them.
- **Existing Control (from 1x00):** C-006 (password complexity/rotation policy) exists but does not prevent credentials from being stored in plaintext once issued no control in the Task 10 matrix governs secrets handling in scripts or files.
- **Gap Exploited (from 1x00):** GAP-016 No formal change management process; an unapproved, untested script that embeds Domain Admin credentials and gets emailed to a colleague is exactly the kind of ad-hoc change this gap describes.
- **Recommended Mitigation:** Technical a credential vaulting/secrets-management solution so scripts call an API instead of embedding plaintext admin credentials, paired with a change-management requirement that any script touching AD admin functions be reviewed before use.

## Pattern Assessment

The systemic weakness underneath all five scenarios is the same one identified twice already in Project 1x00: MedDefense has strong-enough preventive controls (password policy, account lockout, basic file permissions) but almost no detective capability, so none of these behaviors a shared login, a dormant account authenticating at 2 AM, an unrecognized device on the network, an out-of-scope EHR lookup, plaintext credentials in an email would ever surface on their own (GAP-002, "No functioning detection or incident-response capability anywhere in the environment"). Layered on top of that is the credential-and-accountability weakness the Task 9 Data Map called out as MedDefense's single most disproportionate risk relative to its classification: system credentials are shared, unvaulted, and unprotected by any second factor, which is exactly what turns Scenarios 1, 2 and 5 from isolated bad habits into organization-wide exposure. Healthcare's structural need for broad clinical access the same tension James Chen raised directly means MedDefense cannot simply lock everything down; without detection to compensate for that necessarily broad access, insider risk here is not a matter of if but of which of these five patterns produces the next real incident.
