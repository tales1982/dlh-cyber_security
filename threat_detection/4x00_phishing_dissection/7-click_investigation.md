## Click Investigation — Diane Marsh / WS-NURSE-04

Assessment of Diane Marsh's reported click on the Email 2 link, based only on the email evidence batch. No Sysmon, Wazuh, Suricata, Windows Security, proxy, DNS or identity log was searched to produce this report; every item under Endpoint Checks and Account Checks below is a recommended follow-up, not something already done. The E2 URL was not visited.

### Confirmed Facts

Confirmed directly from the evidence batch (E2 headers, E2 body, and the batch footer):

- **User:** Diane Marsh, `dmarsh@meddefense.com` (batch footer, E2 `To:`)
- **Workstation:** `WS-NURSE-04`, IP `10.10.2.15` (batch footer)
- **Email:** E2, "ACTION REQUIRED: Portal re-verification needed within 24 hours", from `noreply@meddefense-portal.com` (E2 headers)
- **URL/domain:** `hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1`, on the lookalike domain `meddefense-portal.com` (E2 body; batch footer names E2 as the email clicked)
- **Click timestamp:** 2026-04-14 15:02:33 CDT (20:02:33 UTC), per the workstation NTP — 14 minutes 41 seconds after `mx01.meddefense.com` accepted E2 from the sender at 14:47:51 CDT, and about 66 hours before the batch was collected on 2026-04-17 09:15 CDT (the collector's note said roughly 36 hours; the NTP timestamp is used as the reference, as in the initial triage notes)
- **Related IP:** `91[.]234[.]99[.]107`, the external mail server (`mail.meddefense-portal.com`) that delivered E2, per its `Received:` hop

Supporting context: E2 failed authentication (SPF `fail`, DKIM `none`, DMARC `fail`, delivered under `action=none`) and carried a 24-hour lockout threat naming the scheduling system, the EHR gateway and shift-swap access. The batch records that Diane reported the click; how the exact timestamp was captured (browser history, proxy log, or her own recollection) is not stated.

### Key Unknowns

What happened after the click is not in the evidence:

- Whether the page loaded, and what it showed — a login form, a redirect, a download, or an error. The URL was never observed.
- Whether Diane entered her username and password, or approved an MFA prompt. The batch records a click, not a credential submission.
- Whether anything was downloaded or executed on `WS-NURSE-04`.
- The IP of the web server behind `meddefense-portal.com` — the evidence only gives the mail server IP, and the two hosts may differ.
- Whether any sign-in or mailbox activity for `dmarsh` has occurred since the click, and whether any other MedDefense user clicked E2 or the related lookalike-domain emails.

This uncertainty is why the click is treated as serious rather than dismissed. The lure is a personalized, tokenized link (`id=dmarsh`) on a domain that failed every authentication check, styled as a credential-harvesting "verification" page, so the most likely next step for the click was a login form. A click alone already confirms to the attacker that a live employee opened the link and exposes her IP and device; a landing page can also prompt a download or a permissions request, and the HC3 alert (E8) notes possible Stage 2 activity once credentials are validated, so nothing beyond the click should be assumed. Because the lure names the EHR gateway and scheduling system, a compromised nurse account could reach systems holding patient data, which raises privacy and breach-notification stakes. MFA lowers but does not remove the risk, since a real-time relay phishing page can capture a session as well as a password. With 66 hours already elapsed and no logs reviewed yet, this is a confirmed click with unconfirmed impact, and the P1-URGENT priority from triage stands.

### Endpoint Checks To Perform

Recommended follow-up only; none of these were run. If logs are available, review from 2026-04-14 15:02:33 CDT onward (and a few minutes before):

- **Browser history and downloads** (`WS-NURSE-04` browser profile, download list, cache) — a visit to `meddefense-portal.com`, redirects, a form submission, or downloaded files.
- **Downloaded files** (Downloads folder, `%TEMP%`, Mark-of-the-Web streams) — executables, scripts, archives or documents fetched from the site.
- **Process execution** (Sysmon Event ID 1, Security 4688) — a browser spawning `cmd.exe`, `powershell.exe`, `mshta.exe`, `rundll32.exe` or an installer.
- **PowerShell/cmd activity** (Event IDs 4103/4104, command history) — encoded commands or download cradles.
- **File creation and persistence** (Sysmon 11/13, scheduled tasks, new services, Startup folder) — anything created after the click that runs at logon.
- **DNS/proxy activity from `10.10.2.15`** — resolution of the domain and any new external destinations after the click.
- **Endpoint protection alerts** — AV/EDR detections tied to a browser or download around the click time.

### Account Checks To Perform

Recommended follow-up only; none of these were run. Review from the click timestamp to the present:

- **Failed logons** (sign-in logs, Event IDs 4625/4771/4776, VPN logs) — bursts against `dmarsh` from unfamiliar sources.
- **Successful logons from unusual sources** (Event ID 4624, sign-in location/ASN/user agent) — a first-time country, hosting-provider IP range (including `91.234.99.107`), or impossible travel.
- **MFA activity** — prompts or approvals Diane did not initiate, or a newly registered method or device.
- **Password changes/resets** (Event IDs 4723/4724) — a change Diane did not make.
- **Inbox rules and forwarding** — new rules that forward, redirect, delete or hide messages, especially security/IT mail.
- **Group membership changes** (Event IDs 4728/4732/4756) — `dmarsh` added to privileged or clinical groups.
- **System access** (EHR gateway, scheduling, VPN logs) — access outside her shift or role.
- **Other recipients** — mail-gateway search for `meddefense-portal.com` and the other lookalike domains, to find who else received or visited them.

### Decision Matrix

| Outcome | What the checks would show | Response |
|---|---|---|
| No compromise found | Page never loaded or was blocked; no form submission; no downloads, unusual processes, unusual sign-ins, or rule/MFA changes; logs cover the full window. | Close as a click without compromise. Still do the low-cost precautions (password reset, session revocation) and monitor 30 days. |
| Possible credential exposure | Diane says she entered credentials, or a form was submitted, or logs for the window are missing/incomplete, with no confirmed attacker activity yet. | Treat the password as known to the attacker: force a reset, revoke sessions/tokens, review MFA, check for password reuse, increase monitoring. |
| Confirmed compromise | A successful sign-in from an unfamiliar source after the click, a new inbox rule, a changed MFA method, unauthorized EHR access, or malware/persistence on the workstation. | Declare an incident: disable the account, isolate the workstation, preserve evidence, involve privacy/compliance if patient data may be affected, hunt organization-wide, block indicators. |
| Undetermined (current state) | Only the evidence batch is available; no endpoint or identity logs reviewed yet. | Act as under "Possible credential exposure" until the checks above return results. |

### Recommended Containment

1. Preserve evidence: keep the raw E2 message, export available proxy/DNS/mail/sign-in logs, and copy `WS-NURSE-04` browser history before any cleanup.
2. Reset Diane's password from a known-clean device over an out-of-band channel; do not use the original workstation.
3. Revoke active sessions and refresh tokens for `dmarsh`; review her MFA methods and remove any she does not recognize.
4. Interview Diane without blame: what appeared after the click, did she type credentials or approve MFA, did anything download, did she use another device, does she reuse that password, did she forward the message.
5. Run an endpoint scan on `WS-NURSE-04`; isolate it only if the scan or checks show download/execution, coordinating with clinical operations since it supports patient care — otherwise targeted monitoring is more proportionate.
6. Block the indicators (`meddefense-portal[.]com`, `91[.]234[.]99[.]107`, and the related domains/IPs in `4-url_attachment_autopsy.md`) at proxy, DNS, firewall and mail gateway.
7. Search the mail gateway for other recipients of E2, E3, E5 and E7, and remove those messages from mailboxes.
8. Monitor `dmarsh` for 30 days for new-location sign-ins, inbox-rule creation, and MFA changes.
9. Report the click to the incident lead and, if patient-data access is possible, to the privacy officer.

### Conclusion

The evidence confirms Diane Marsh clicked the personalized E2 link from `WS-NURSE-04` (`10.10.2.15`) at 2026-04-14 15:02:33 CDT, about 14 minutes after delivery and about 66 hours before the batch was collected. The link points to `meddefense-portal[.]com`, a lookalike domain served by a sender that failed SPF, DKIM and DMARC. Whether credentials were entered, MFA was approved, or anything ran on the workstation is not shown by the evidence, so compromise is neither confirmed nor excluded — the working assumption is possible credential exposure. Containment that does not depend on further evidence (password reset, session revocation, MFA review, monitoring, indicator blocking) should proceed now, while the endpoint and account checks above decide whether this closes as a click without compromise or escalates to a confirmed incident.
