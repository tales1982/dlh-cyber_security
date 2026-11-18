# Security Quick Reference: IT Staff

**[MedDefense Health Systems logo]** | Version 1.0 | 2026-11-18 | Helpdesk, systems engineering, SOC, endpoint engineering

## Your biggest threats

- **Vendor and change-window pretexts that ask for privilege.** Lures arrive as "vendor patch coordination" during maintenance windows, with a plausible ticket number. In March, the IT sample was reported late. `svc_helpdesk` received Domain Admin "per vendor" during an install and nobody reviewed it. *Signal: a request for broad admin rights or remote access that is not in the approved change.*
- **Standing privilege nobody owns.** The 6x02 IAM audit found dormant and over-privileged accounts holding Domain Admin: `svc_epic_int` (no function, years without login), `admin.legacy` (migration account, no MFA), `svc_backup` (more than backups need), and a disabled user (`b.carter`) still in privileged groups. In March, this kind of service account was the attacker's path from one workstation to the domain. *Signal: a service account signing in interactively or outside its documented job.*
- **Insider-like misuse you are first to see.** You see the context tools miss: a dormant account waking up at 02:00, a transferred user (`j.yamamoto` moved to Finance with IT rights) still using admin tools, a contractor (`t.morrison`) active after the contract end. *Signal: access that does not fit the person's current role.*

## What to do right now

- Do every admin action from your separate admin account on a managed device. Never from personal email, a personal device or an untracked session.
- Challenge any service account with no owner, no ticket and no recent expected activity. Open a ticket to remove its privileges or disable it.
- For every privilege change, require a ticket or change reference and the minimum scope. "Vendor said so" is not a scope.

## When something looks wrong

**Report the observable fact to the SOC: ext. 4-SECURITY or security@meddefense.org, with account, host and time.** Example: "`svc_backup` signed in interactively on WST-WS-031 at 02:14, not its documented function." Describe what you saw, not who you suspect.

## What not to do

- Do not grant Domain Admin or broad rights to "make it work" with a plan to review later. Later did not come for `svc_helpdesk`.
- Do not disable an account and leave its group memberships. Remove access, not just sign-in.
- Do not approve access requests, MFA resets or vendor sessions from email alone. Verify by calling back on a known number or checking the ticket.

---

Security Team: **ext. 4-SECURITY** | **security@meddefense.org** | Outlook: **Report Phishing** button (Home tab on desktop; **...** > **Report** > **Report phishing** on web and mobile)
