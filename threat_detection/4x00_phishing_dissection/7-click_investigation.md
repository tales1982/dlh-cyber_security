## Click Investigation — Diane Marsh / WS-NURSE-04

Assessment of Diane Marsh's reported click on the Email 2 link, and the evidence needed to decide whether a compromise occurred. This task uses the email evidence batch only. No Sysmon, Wazuh, Suricata, Windows Security, proxy, DNS or identity logs were searched. Every check under "Endpoint Checks To Perform" and "Account Checks To Perform" is a recommended follow-up that was not run, and the outcome is therefore undetermined. Domains, addresses and IPs are defanged or shown in code formatting; the E2 URL was not visited.

### Confirmed Facts

Source for each fact is the evidence batch (E2 headers and body, the batch notes and the batch footer).

In plain terms: **Diane Marsh** (`dmarsh@meddefense.com`), on **workstation** `WS-NURSE-04` (`10.10.2.15`), clicked the link inside **email** E2 (`noreply@meddefense-portal.com`, "ACTION REQUIRED: Portal re-verification needed within 24 hours") at **click timestamp** 2026-04-14 15:02:33 CDT. The **URL/domain** clicked was `hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1`, on the lookalike domain `meddefense-portal.com`, delivered from **related IP** `91[.]234[.]99[.]107`. These six items — user, workstation, email, URL/domain, click timestamp and related IP — are confirmed directly from the evidence batch; the table below cites the exact source for each one, and everything beyond the click itself is unknown (see Key Unknowns).

| Fact | Value | Source |
|---|---|---|
| User | Diane Marsh, `dmarsh@meddefense.com` | Batch footer, E2 `To:` |
| Workstation | `WS-NURSE-04`, IP `10.10.2.15` | Batch footer |
| Email | E2, "ACTION REQUIRED: Portal re-verification needed within 24 hours", from `noreply@meddefense-portal.com` | E2 headers |
| Clicked URL | `hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1` | E2 body, batch footer says E2 was the email clicked |
| Domain | `meddefense-portal[.]com`, a lookalike of `meddefense.com` | E2 headers and body |
| Related IP | `91[.]234[.]99[.]107`, the mail server `mail.meddefense-portal.com` that delivered E2 | E2 external `Received:` hop |
| Click timestamp | 2026-04-14 15:02:33 CDT (20:02:33 UTC), per the workstation NTP | Batch footer |
| Authentication of the lure | SPF `fail`, DKIM `none`, DMARC `fail` (`action=none`), so it was delivered | E2 `Authentication-Results` |
| Lure content | 24-hour deadline, threat of losing scheduling, EHR gateway and shift-swap access, per-user link with `id=dmarsh` and a token | E2 body |

Timeline (all times CDT unless stated):

| Time | Event |
|---|---|
| 2026-04-14 14:47:48 | E2 created by the sender (`Date` 19:47:48 +0000) |
| 14:47:51 | `mx01.meddefense.com` accepts E2 from `91.234.99.107` |
| 14:47:52 | E2 handed to `inbound-relay.meddefense.com` for `dmarsh` |
| 15:02:33 | Click recorded, 14 min 41 s after the relay timestamp |
| 2026-04-15 about 14:47 | The 24-hour deadline in the lure expires. Nothing in the evidence shows that Diane's access was affected. |
| 2026-04-17 09:15 | Evidence batch collected, 66 h 12 min after the click |

The click is about 66 hours before collection, not the roughly 36 hours in the collector's note. As in the initial triage notes, the workstation NTP timestamp is used as the reference.

The user reported the click and the batch records the timestamp. How that timestamp was obtained (browser history, proxy log, or the user's recollection) is not stated.

### Key Unknowns

- Whether the page loaded at all, and what it showed (a login form, a redirect, a download, an error). The URL was never observed.
- Whether Diane entered her username and password, and whether she approved any MFA prompt. The batch records a click, not a credential submission.
- Whether anything was downloaded or executed on `WS-NURSE-04`.
- The IP address of the web server behind `meddefense-portal.com`. The evidence gives only the mail server IP, and the web and mail hosts may differ.
- Whether the domain was reachable and live at 15:02 CDT, and how long it stayed up.
- Which browser and profile were used, and whether the same account is signed in on other devices, such as a phone.
- Whether her password is reused on other systems, and what access `dmarsh` holds (EHR gateway, scheduling, VPN, email).
- Whether any other MedDefense user received or clicked E2, or the other lookalike-domain emails. Only one recipient per email appears in the batch.
- Whether any sign-in or mailbox activity for `dmarsh` has occurred since 15:02 CDT on 2026-04-14.

### Risk Assessment

A click on the link in a credential-harvesting email is serious even before any credential entry is confirmed.

- The page is assessed, not proven, to be a credential-harvesting portal. The lure asks for "verification", the URL is a personalized `/verify/staff` link with a token, the domain is a lookalike, and the sender failed every authentication check. The most likely next step on that page is a login form styled as the MedDefense portal.
- The click alone already tells the attacker something. The tokenized URL confirms that a live employee opened the link, and the request exposes her IP address, browser and device details.
- A landing page can do more than show a form: prompt a file download, redirect through further pages, or request browser permissions. The HC3 alert (E8) mentions possible Stage 2 activity once credentials are validated, so a click should not be closed on the assumption that nothing further happened.
- The stakes are high because of who was targeted. The lure names the EHR gateway and scheduling system, so a nurse account may reach systems that hold patient data. Misuse of that access could raise privacy and breach-notification questions.
- MFA reduces the risk but does not remove it. A phishing page that relays a login in real time can capture a session as well as a password, so the presence of MFA is not proof of safety.
- Time works in the attacker's favour: 66 hours passed before the batch was collected, and the evidence has no record of what the account did in that time.

Until the checks below are done, this is a confirmed click with unconfirmed impact. The P1-URGENT priority from triage remains.

### Endpoint Checks To Perform

Recommended follow-up. None of these were searched in this task. Where logs are available, review the window from 2026-04-14 15:02:33 CDT forward, and a few minutes before it.

| Check | Where to look | What would be concerning |
|---|---|---|
| Browser history and downloads | Chrome, Edge or Firefox profile on `WS-NURSE-04` (`History`, `places.sqlite`), download list, cache | A visit to `meddefense-portal.com`, redirects to further domains, a form submission, downloaded files |
| Saved-password prompts and autofill | Browser password-manager and form-history data | Signs that credentials were typed into the page |
| DNS and proxy activity from `10.10.2.15` | Proxy, DNS server and firewall logs, Sysmon Event ID 22 if present | Resolution of `meddefense-portal.com`, connections to its web IP, other new external destinations after the click |
| Network connections after the click | Sysmon Event ID 3, firewall and IDS/IPS logs | Repeated outbound connections to new IPs, unusual ports or beaconing intervals |
| Downloaded files | User Downloads folder, `%TEMP%`, Mark-of-the-Web (`Zone.Identifier`) streams, Sysmon Event ID 15 | Executables, scripts, archives, Office documents or shortcuts fetched from the site |
| Process execution | Sysmon Event ID 1, Security Event ID 4688 with command lines | A browser spawning `cmd.exe`, `powershell.exe`, `wscript.exe`, `mshta.exe`, `rundll32.exe`, `certutil.exe` or an installer |
| PowerShell and cmd activity | PowerShell Event IDs 4103 and 4104, `ConsoleHost_history.txt` for the user | Encoded commands, download cradles, network calls |
| File creation | Sysmon Event ID 11 in the user profile, `AppData`, `Temp`, Startup folder | New executables or scripts created after the click |
| Persistence | Sysmon Event ID 13 (Run keys), scheduled tasks (Event ID 4698), new services (Event ID 7045), Startup folder | Anything created after 15:02 that starts at logon |
| Endpoint protection | AV or EDR alerts and quarantine for the host | Detections tied to a browser or download after the click |
| Browser extensions and permissions | Extension list, notification permissions | A newly installed extension, or push notifications allowed for the domain |

### Account Checks To Perform

Recommended follow-up. None of these were searched in this task. Review from 2026-04-14 15:02:33 CDT to the present.

| Check | Where to look | What would be concerning |
|---|---|---|
| Failed logons | Identity provider sign-in logs, domain controller Event IDs 4625, 4771, 4776, VPN logs | Bursts of failures against `dmarsh` from unfamiliar sources |
| Successful logons from unusual sources | Same logs, Event ID 4624, sign-in locations, ASN, user agent | A first-time IP or country, hosting-provider ranges (including `91.234.99.107` or the other sending IPs), impossible travel, legacy protocols |
| MFA activity | MFA and authentication-method logs | Unexpected prompts, approvals Diane did not initiate, a new method or device registered |
| Password changes and resets | Event IDs 4723 and 4724, identity provider audit log | A change or reset that Diane did not perform |
| Inbox rules and forwarding | Mailbox rule and forwarding settings, mailbox audit log | New rules that forward, redirect, delete or mark messages as read, especially ones that hide security or IT mail |
| Mail sent from her account | Message trace, sent items | Messages sent from `dmarsh` to colleagues that she did not write (internal phishing) |
| Application consents and delegates | Identity provider audit log, mailbox permissions | A new OAuth application grant or a delegate added to her mailbox |
| Group membership changes | Event IDs 4728, 4732, 4756, identity provider audit log | `dmarsh` added to privileged or clinical groups |
| System access | EHR gateway, scheduling and VPN access logs for `dmarsh` | Access outside her shift or role, unusual patient-record lookups |
| Other recipients | Mail gateway search for `meddefense-portal.com` and the other lookalike domains, proxy logs for the same domains | Other users who received or visited the pages |

### Decision Matrix

| Outcome | What the checks would show | Interpretation | Response |
|---|---|---|---|
| No compromise found | The page never loaded or was blocked. Browser history shows a visit with no form submission. Diane confirms she typed nothing. No downloads, no unusual processes, no unusual sign-ins, no rule or MFA changes, and logs cover the full window since 15:02 CDT. | A click that led to no observed impact. | Close as a click without compromise. Still complete the low-cost precautions (password reset, session revocation) and monitor for 30 days. Record the gaps in log coverage. |
| Possible credential exposure | Diane says she entered credentials, or the page loaded and a form was submitted, or logs are missing or incomplete for the window, but no attacker activity has been seen yet. | Treat the password as known to the attacker until shown otherwise. | Force a password reset, revoke sessions and tokens, review MFA methods, check for reuse on other systems, increase monitoring on the account, and keep searching. |
| Confirmed compromise | A successful sign-in from an unfamiliar source after the click, or a new inbox rule or forwarding, a changed MFA method, an OAuth grant, unauthorized EHR access, or malware or persistence on the workstation. | The account, the endpoint or both are under attacker control. | Declare an incident. Disable the account, isolate the workstation, preserve evidence, involve the privacy and compliance team if patient data may be involved, hunt for the same activity across the organization, and block the indicators. |
| Undetermined (current state) | Only the evidence batch is available, with no endpoint or identity logs reviewed. | Impact can be neither confirmed nor ruled out. | Act as under "Possible credential exposure" until the checks return results. |

### Recommended Containment

Preserve evidence first where it costs little, then contain. These steps are safe and realistic for a clinical workstation.

1. Preserve evidence: keep the raw E2 message, export the relevant proxy, DNS, mail and sign-in logs, and copy the browser history from `WS-NURSE-04` before any cleanup.
2. Reset Diane's password from a known-clean device using an out-of-band channel, and do not use the original workstation for the reset.
3. Revoke all active sessions and refresh tokens for `dmarsh`, and re-check her registered MFA methods, removing any she does not recognize.
4. Interview Diane in a non-blaming way, and ask:
   - What appeared after the click?
   - Did she type a username or password?
   - Did she approve any MFA prompt?
   - Did any file download or open?
   - Did she use another device?
   - Does she reuse that password elsewhere?
   - Has she forwarded or replied to the message?
5. Run an endpoint protection scan on `WS-NURSE-04`. If the checks show a download or execution, isolate the workstation from the network but leave it powered on, and coordinate with clinical operations because it supports patient care. Without such evidence, targeted monitoring is more proportionate than isolation or reimaging.
6. Block the indicators at the proxy, DNS, firewall and mail gateway: `meddefense-portal[.]com` and the sending IP `91[.]234[.]99[.]107`, and the other domains and IPs listed in `4-url_attachment_autopsy.md`.
7. Search the mail gateway for other recipients of E2 and of the lookalike-domain emails E3, E5 and E7, and remove those messages from mailboxes.
8. Monitor `dmarsh` for at least 30 days for sign-ins from new locations or hosting ranges, inbox rule creation, MFA method changes, and any access to the four lookalike domains from other hosts.
9. Report the click to the incident lead and, if patient-data access is possible, to the privacy officer.
10. Reinforce awareness for the staff who received the lures once containment is complete, and submit the indicators to HC3 as its alert suggests.

### Conclusion

The evidence confirms that Diane Marsh clicked the personalized E2 link from `WS-NURSE-04` (`10.10.2.15`) at 2026-04-14 15:02:33 CDT, about 14 minutes after delivery, and about 66 hours before the batch was collected. The link points to `meddefense-portal[.]com`, a lookalike domain served by a sender that failed SPF, DKIM and DMARC. The evidence does not show whether credentials were entered, whether MFA was approved or whether anything ran on the workstation, so compromise is neither confirmed nor excluded.

The working assumption should be possible credential exposure. Containment that does not depend on further evidence (password reset, session revocation, MFA review, monitoring, indicator blocking) should proceed now. The endpoint and account checks above will decide whether this case closes as a click without compromise or escalates to a confirmed incident.
