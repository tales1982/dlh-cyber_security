# URL and Attachment Autopsy

Safe investigation of the URLs, IP addresses and attachment indicators found in the four suspicious emails (E2, E3, E5, E7), plus the spam indicator `203.0.113.228` from E6. Every value was taken from the raw email evidence batch. No link was visited, no attachment was opened or rendered, and no live DNS, WHOIS or reputation lookup was run for this report. The commands listed under each indicator are the methods an analyst would use; they were not executed here, and the findings rest on the evidence file.

## Handling rules

- Values are defanged: `http` becomes `hxxp` and every `.` becomes `[.]`. Original values are kept in code formatting so they stay non-clickable and exactly as they appear in the evidence.
- Run the commands from an isolated analysis host, never from a workstation with a browser session or corporate credentials.
- Use passive sources first (WHOIS, DNS from a resolver, certificate transparency, existing VirusTotal or urlscan.io results). Active steps (`curl -I`, submitting a new urlscan.io scan) contact or expose the analyst to the attacker's server, so they need approval and isolated egress.
- Do not request or submit the E2 URL with its `token` value. The token is per-recipient and lets the sender see who clicked. For any external lookup use the bare domain or the URL without the query string.
- Set urlscan.io scans to `unlisted` or `private` so the submission does not advertise the investigation.
- Do not open the E5 attachment on a desktop. The PDF was inspected only as base64 text inside the evidence (see Indicator 8).

## Risk rating scale

| Rating | Meaning |
|---|---|
| CRITICAL | Malicious per the evidence and linked to a confirmed user interaction. |
| HIGH | Malicious per the evidence (phishing URL, attachment or mail server), no interaction reported. |
| MEDIUM | Supporting infrastructure or an indicator whose role is unclear. |
| LOW | Spam or informational content, not attacker infrastructure. |

## Indicator summary

| # | Email | Type | Defanged value | Risk |
|---|---|---|---|---|
| 1 | E2 | URL | `hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1` | CRITICAL |
| 2 | E2 | IP address | `91[.]234[.]99[.]107` | HIGH |
| 3 | E3 | URL | `hxxps://outlook-protection[.]com/verify` | HIGH |
| 4 | E3 | IP address | `51[.]38[.]42[.]17` | HIGH |
| 5 | E3 | IP address (lure content) | `41[.]203[.]72[.]188` | LOW |
| 6 | E5 | URL | `hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891` | HIGH |
| 7 | E5 | URL | `hxxps://medequip-supplies[.]net/portal/login` | HIGH |
| 8 | E5 | Attachment | `INV-2026-04891[.]pdf` | HIGH |
| 9 | E5 | IP address | `185[.]176[.]43[.]22` | HIGH |
| 10 | E7 | URL | `hxxps://meddefense-benefits[.]org/enroll` | HIGH |
| 11 | E7 | IP address | `164[.]90[.]218[.]73` | HIGH |
| 12 | E6 | IP address and URL | `hxxp://203[.]0[.]113[.]228/shop?ref=pwhite` | LOW |

---

## Indicator 1

- Source email: E2, "ACTION REQUIRED: Portal re-verification needed within 24 hours", delivered to `dmarsh@meddefense.com`
- Original value: `https://meddefense-portal.com/verify/staff?id=dmarsh&amp;token=a8f3e2d1` (as written in the HTML `href`; `&amp;` decodes to `&`)
- Defanged value: `hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1`
- Domain or IP: `meddefense-portal.com`
- Indicator type: URL, assessed credential-harvest landing page
- Evidence from email:
  - The link is the "VERIFY MY ACCESS NOW" button. The same domain is used for the sender address, the `Return-Path`, and the logo (`hxxps://meddefense-portal[.]com/assets/logo[.]png`).
  - `meddefense-portal.com` is a lookalike of `meddefense.com`. The genuine internal notice (E4) says the portal is internal or VPN-only and that IT never emails password links.
  - The path is `/verify/staff` and the query string holds `id=dmarsh` and a `token`, so the link is unique to Diane Marsh.
  - Mail was sent with SPF `fail`, no DKIM and DMARC `fail` from `91.234.99.107`.
  - Diane Marsh's click on this link is recorded at 2026-04-14 15:02:33 CDT (see `7-click_investigation.md`).
  - The logo is a remote image on the same domain. If the mail client loaded it, the request reached the attacker's server when the message was rendered.
- Safe investigation method:
  ```
  whois meddefense-portal.com                        # registrar, creation date, registrant
  dig +short A meddefense-portal.com                 # web host IP (may differ from the mail host)
  dig +short NS meddefense-portal.com
  dig +short TXT meddefense-portal.com               # SPF record
  dig +short TXT _dmarc.meddefense-portal.com
  curl -s "https://crt.sh/?q=meddefense-portal.com&output=json"     # certificate first-seen dates
  curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/domains/meddefense-portal.com"
  curl -s "https://urlscan.io/api/v1/search/?q=domain:meddefense-portal.com"   # existing scans only
  # Active, only with approval and isolated egress, and never with the token:
  curl -sI --max-time 10 https://meddefense-portal.com/
  ```
  Also search proxy, DNS and firewall logs for `meddefense-portal.com` and for requests to `/assets/logo.png`, to find every host that loaded the message or the page.
- Finding: the URL is a personalized credential-harvest link on a lookalike domain, delivered by a sender that fails every authentication check. The domain is assessed as attacker-controlled infrastructure. What the page displays, and whether credentials were entered, is not in the evidence.
- Risk rating: CRITICAL

## Indicator 2

- Source email: E2
- Original value: `91.234.99.107` (external `Received:` hop, `mail.meddefense-portal.com`)
- Defanged value: `91[.]234[.]99[.]107`
- Domain or IP: `91.234.99.107`
- Indicator type: IP address, sending mail server
- Evidence from email:
  - Recorded by `mx01.meddefense.com` at 2026-04-14 14:47:51 -0500 over plain ESMTP with no TLS.
  - SPF `fail`: the IP is not authorized for `meddefense-portal.com`.
  - The sender identifies the host as `mail.meddefense-portal.com`, running PHPMailer 6.6.0.
  - The IP is not shared with any other email in the batch.
- Safe investigation method:
  ```
  whois 91.234.99.107                                # network owner, abuse contact, allocation date
  dig -x 91.234.99.107 +short                        # reverse DNS, compare with mail.meddefense-portal.com
  curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/ip_addresses/91.234.99.107"
  curl -s "https://urlscan.io/api/v1/search/?q=ip:91.234.99.107"
  ```
  Search mail-gateway logs for other messages from this IP, and firewall or proxy logs for any connection to it.
- Finding: the mail server that delivered the confirmed-click phishing email. Whether the web host for `meddefense-portal.com` is the same machine is unknown until DNS is checked, so this IP should not be assumed to be the click destination.
- Risk rating: HIGH

## Indicator 3

- Source email: E3, "Unusual sign-in activity detected on your Microsoft 365 account", delivered to `rmendez@meddefense.com`
- Original value: `https://outlook-protection.com/verify`
- Defanged value: `hxxps://outlook-protection[.]com/verify`
- Domain or IP: `outlook-protection.com`
- Indicator type: URL, assessed credential-harvest landing page (Microsoft impersonation)
- Evidence from email:
  - The "Verify account" button points to this URL. The logo is loaded from `hxxps://outlook-protection[.]com/img/ms_logo[.]png`.
  - `outlook-protection.com` is not `microsoft.com` or `outlook.com`, although the email presents itself as Microsoft.
  - SPF, DKIM and DMARC all pass, but only for `outlook-protection.com` (see `2-authentication_analysis.md`).
  - The URL has no per-user token, so the same link would serve every recipient.
  - No click on this link has been reported.
- Safe investigation method:
  ```
  whois outlook-protection.com                       # creation date: HC3 describes lookalikes under 30 days old
  dig +short A outlook-protection.com
  dig +short MX outlook-protection.com
  dig +short TXT outlook-protection.com
  dig +short TXT _dmarc.outlook-protection.com
  dig +short TXT default._domainkey.outlook-protection.com   # DKIM selector from the message
  curl -s "https://crt.sh/?q=outlook-protection.com&output=json"
  curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/domains/outlook-protection.com"
  curl -s "https://urlscan.io/api/v1/search/?q=domain:outlook-protection.com"
  # Active, only with approval and isolated egress:
  curl -sI --max-time 10 https://outlook-protection.com/verify
  ```
  Search proxy and DNS logs for the domain to check whether anyone has visited it.
- Finding: a brand-impersonation login lure on a domain that authenticates cleanly but is not Microsoft's. The lookup should confirm registration age and record ownership. Until then, the evidence classification stands.
- Risk rating: HIGH

## Indicator 4

- Source email: E3
- Original value: `51.38.42.17` (external `Received:` hop, `mail.outlook-protection.com`)
- Defanged value: `51[.]38[.]42[.]17`
- Domain or IP: `51.38.42.17`
- Indicator type: IP address, sending mail server
- Evidence from email:
  - Recorded by `mx01` at 2026-04-15 09:13:43 -0500 over ESMTPS (TLS 1.2).
  - SPF `pass`: the IP is listed for `outlook-protection.com`, which shows the domain owner and the IP operator are connected. It does not make the sender Microsoft.
  - Mail was generated by a PHPMailer process on a host named `wp-admin.outlook-protection.com`.
  - The IP is not shared with any other email in the batch.
- Safe investigation method:
  ```
  whois 51.38.42.17
  dig -x 51.38.42.17 +short
  curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/ip_addresses/51.38.42.17"
  curl -s "https://urlscan.io/api/v1/search/?q=ip:51.38.42.17"
  ```
- Finding: sending infrastructure for the Microsoft-impersonation lure. Whether other domains are hosted on this IP (a common sign of shared attacker hosting) needs passive-DNS or urlscan.io checks.
- Risk rating: HIGH

## Indicator 5

- Source email: E3
- Original value: `41.203.72.188` (body table row "IP address", labelled "Lagos, Nigeria (approximate)")
- Defanged value: `41[.]203[.]72[.]188`
- Domain or IP: `41.203.72.188`
- Indicator type: IP address, lure content
- Evidence from email:
  - It appears only in the body, as the alleged source of an unrecognized sign-in, together with an "unknown Windows device" and a time of 10:47 AM UTC on April 15, 2026.
  - It does not appear in any `Received:` header, so it is not part of the sending path.
  - Nothing in the evidence confirms that any sign-in from this IP happened.
- Safe investigation method:
  ```
  whois 41.203.72.188
  curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/ip_addresses/41.203.72.188"
  ```
  As a follow-up check, search identity sign-in logs for this IP for `rmendez@meddefense.com` on 2026-04-15. A hit would suggest a real attempt and change the assessment; no hit is the expected result for a fabricated alert.
- Finding: an unverifiable detail chosen to create fear, not attacker infrastructure. It should not be used as a block-list entry on the strength of this email alone.
- Risk rating: LOW

## Indicator 6

- Source email: E5, "Invoice INV-2026-04891 - Payment required within 7 days", delivered to `arivera@meddefense.com`
- Original value: `https://medequip-supplies.net/invoices/pay?id=INV-2026-04891`
- Defanged value: `hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891`
- Domain or IP: `medequip-supplies.net`
- Indicator type: URL, invoice payment portal (payment fraud and credential harvesting)
- Evidence from email:
  - It appears twice in the HTML body (as the link target and as visible text) and a third time inside the PDF attachment (Indicator 8).
  - The invoice is for USD 24,716.38, due 2026-04-23, with a 2% late fee.
  - Sender authentication: SPF `softfail`, DKIM `none`, DMARC `fail`.
  - The Accounts Payable recipient says the invoice looks wrong and the vendor is unverified.
  - The email offers to take payment "directly through our invoice portal", not through any remittance details.
- Safe investigation method:
  ```
  whois medequip-supplies.net
  dig +short A medequip-supplies.net
  dig +short MX medequip-supplies.net
  dig +short TXT medequip-supplies.net               # SPF record; expect a soft-fail ending
  dig +short TXT _dmarc.medequip-supplies.net
  curl -s "https://crt.sh/?q=medequip-supplies.net&output=json"
  curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/domains/medequip-supplies.net"
  curl -s "https://urlscan.io/api/v1/search/?q=domain:medequip-supplies.net"
  # Active, only with approval and isolated egress, without the invoice id in the request:
  curl -sI --max-time 10 https://medequip-supplies.net/
  ```
  Verify the vendor separately in the vendor master and by phone using a number MedDefense already holds, not the number in the email.
- Finding: the URL is the payment step of an unverified invoice from a sender that fails authentication. It fits invoice fraud and possible payment-detail or credential capture.
- Risk rating: HIGH

## Indicator 7

- Source email: E5
- Original value: `https://medequip-supplies.net/portal/login`
- Defanged value: `hxxps://medequip-supplies[.]net/portal/login`
- Domain or IP: `medequip-supplies.net`
- Indicator type: URL, login page (credential harvesting)
- Evidence from email:
  - Offered as a fallback: "If the attached invoice is not viewable, please log in to retrieve a copy". A login page for an invoice a customer never asked for is a standard credential-capture step.
  - Same domain and sender as Indicator 6.
- Safe investigation method: same domain lookups as Indicator 6, plus a urlscan.io search restricted to this path (`page.url:"medequip-supplies.net/portal/login"`) for existing results.
  ```
  curl -s "https://urlscan.io/api/v1/search/?q=page.domain:medequip-supplies.net"
  ```
- Finding: a second route to the same domain that leads to a credential prompt. Even if the invoice were ignored, a reader who could not open the PDF is sent here.
- Risk rating: HIGH

## Indicator 8

- Source email: E5, MIME part `Content-Type: application/pdf; name="INV-2026-04891.pdf"`, `Content-Disposition: attachment; filename="INV-2026-04891.pdf"`, base64
- Original value: `INV-2026-04891.pdf`
- Defanged value: `INV-2026-04891[.]pdf` (embedded link `hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891`)
- Domain or IP: `medequip-supplies.net` (the link inside the file)
- Indicator type: Attachment (PDF) with an embedded URL
- Evidence from email: the base64 body was decoded as a plain byte stream and read as text only. It was not saved as a `.pdf`, opened in a viewer or parsed by a PDF library. What it shows:
  - Header `%PDF-1.4` with `Producer (wkhtmltopdf 0.12.6)`. This is a tool that turns HTML pages into PDFs, typical of a web application generating documents.
  - `CreationDate` and `ModDate` are both `D:20260416162834+00'00'`, which is 2026-04-16 16:28:34 UTC. The email's `Date` is 16:28:35 +0000, one second later. The attachment was generated when the message was sent, while the body claims delivery on April 9.
  - One link annotation (object 10, rectangle `[175 185 450 205]`) with a `/URI` action pointing to `hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891`, the same payment URL as the body.
  - No `/JavaScript`, `/OpenAction`, `/Launch` or embedded-file keyword appears in the decoded text. The file is short (622 bytes as reproduced) and incomplete: objects 7 (font) and 9 (page content) are referenced but absent, and there is no cross-reference table or trailer. A missing keyword in an incomplete reproduction does not show the original is harmless.
  - After the last object there is an extra text string starting `xxxSHA-256:` followed by 62 hexadecimal characters in a regular ascending pattern. A SHA-256 has 64 characters and a file cannot contain its own hash, so this is unverified text and not a usable indicator.
  - SHA-256 of the decoded stream as reproduced in the batch: `49558e1500b82d6758379f44ce6104442ec3a5cc08912737db5584640f4b9cad`. It may differ from the original file if the batch was normalized.
- Safe investigation method:
  ```
  # Extract without opening, on an isolated analysis VM only
  ripmime -i E5.eml -d ./out
  sha256sum ./out/INV-2026-04891.pdf
  file ./out/INV-2026-04891.pdf
  exiftool ./out/INV-2026-04891.pdf                  # Producer, CreationDate
  pdfid.py ./out/INV-2026-04891.pdf                  # /JS /JavaScript /OpenAction /Launch /URI counts
  pdf-parser.py --search URI ./out/INV-2026-04891.pdf
  strings -a ./out/INV-2026-04891.pdf | grep -i -E 'http|uri|javascript'
  # Reputation by hash, no file upload needed
  curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/files/<sha256>"
  ```
  Never double-click or preview the file. Search the mail gateway and endpoints for this filename and hash.
- Finding: an on-demand-generated invoice PDF whose only visible function is to carry the payment link, with an unverified embedded hash string. It reinforces the invoice pretext and gives a third click path to the same domain. It also matters for filtering: URLs inside attachments are inspected less often than URLs in message bodies.
- Risk rating: HIGH

## Indicator 9

- Source email: E5
- Original value: `185.176.43.22` (external `Received:` hop, `mail.medequip-supplies.net`)
- Defanged value: `185[.]176[.]43[.]22`
- Domain or IP: `185.176.43.22`
- Indicator type: IP address, sending mail server
- Evidence from email:
  - Recorded by `mx01` at 2026-04-16 11:28:37 -0500 over plain ESMTP with no TLS.
  - SPF `softfail` for `medequip-supplies.net`.
  - Mail was generated by a PHPMailer process on a host named `billing-svc.medequip-supplies.net`.
  - The IP is not shared with any other email in the batch.
- Safe investigation method:
  ```
  whois 185.176.43.22
  dig -x 185.176.43.22 +short
  curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/ip_addresses/185.176.43.22"
  curl -s "https://urlscan.io/api/v1/search/?q=ip:185.176.43.22"
  ```
- Finding: sending infrastructure for the invoice lure. Its relationship to the web host for `medequip-supplies.net` is unknown until DNS is checked.
- Risk rating: HIGH

## Indicator 10

- Source email: E7, "Open Enrollment closes TOMORROW - action required", delivered to `lpatterson@meddefense.com`
- Original value: `https://meddefense-benefits.org/enroll`
- Defanged value: `hxxps://meddefense-benefits[.]org/enroll`
- Domain or IP: `meddefense-benefits.org`
- Indicator type: URL, assessed credential and personal-information harvesting page
- Evidence from email:
  - The "COMPLETE ENROLLMENT" button points here. The visible sender domain is the same.
  - `meddefense-benefits.org` is a lookalike of `meddefense.com`: benefits keyword, `.org` in place of `.com`.
  - SPF `fail`, DKIM `none`, DMARC `fail`.
  - The recipient, in Billing, says she never signed up for anything, and the email tells people who already enrolled to "still verify on the portal".
  - No click on this link has been reported.
- Safe investigation method:
  ```
  whois meddefense-benefits.org
  dig +short A meddefense-benefits.org
  dig +short MX meddefense-benefits.org
  dig +short TXT meddefense-benefits.org
  dig +short TXT _dmarc.meddefense-benefits.org
  curl -s "https://crt.sh/?q=meddefense-benefits.org&output=json"
  curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/domains/meddefense-benefits.org"
  curl -s "https://urlscan.io/api/v1/search/?q=domain:meddefense-benefits.org"
  # Active, only with approval and isolated egress:
  curl -sI --max-time 10 https://meddefense-benefits.org/enroll
  ```
  Confirm with the real HR team whether an enrollment window is open and which URL it uses.
- Finding: a lookalike of the company's own brand used for an HR lure. The URL is the enrollment step of a message that fails all authentication.
- Risk rating: HIGH

## Indicator 11

- Source email: E7
- Original value: `164.90.218.73` (external `Received:` hop, `mail.meddefense-benefits.org`)
- Defanged value: `164[.]90[.]218[.]73`
- Domain or IP: `164.90.218.73`
- Indicator type: IP address, sending mail server
- Evidence from email:
  - Recorded by `mx01` at 2026-04-16 15:22:05 -0500 over plain ESMTP with no TLS.
  - SPF `fail`: not authorized for `meddefense-benefits.org`.
  - Mail was generated by a PHPMailer process on a host named `wp-portal.meddefense-benefits.org`.
  - The IP is not shared with any other email in the batch.
- Safe investigation method:
  ```
  whois 164.90.218.73
  dig -x 164.90.218.73 +short
  curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/ip_addresses/164.90.218.73"
  curl -s "https://urlscan.io/api/v1/search/?q=ip:164.90.218.73"
  ```
- Finding: sending infrastructure for the HR lure. HC3's alert (E8) describes PHPMailer-based sending from budget VPS hosting; a WHOIS lookup would show whether this and the other sending IPs are hosting-provider ranges.
- Risk rating: HIGH

## Indicator 12

- Source email: E6, "90% OFF Viagra, Cialis, Xanax - No prescription needed!!!", delivered to `pwhite@meddefense.com`
- Original value: `http://203.0.113.228/shop?ref=pwhite` (body link) and `203.0.113.228` (external `Received:` hop, `bulk-mail-07.canadian-pharma-discount.org`)
- Defanged value: `hxxp://203[.]0[.]113[.]228/shop?ref=pwhite` and `203[.]0[.]113[.]228`
- Domain or IP: `203.0.113.228` (sender domain `canadian-pharma-discount.org`)
- Indicator type: IP address and URL, spam pharmacy landing page
- Evidence from email:
  - The link uses a raw IP instead of a domain. The spam tests `NORMAL_HTTP_TO_IP` and `NUMERIC_HTTP_ADDR` fired, with an overall `X-Spam-Score` of 9.8 against a 5.0 threshold.
  - The link IP is the same as the sending host: the sender mails and serves the shop from one address, which is the only IP reuse in this batch.
  - The `ref=pwhite` parameter tags the recipient, so a click confirms a live address.
  - SPF `softfail`, DKIM `none`, DMARC `fail` with `action=quarantine`. The mailer is `XPedia Bulk Mailer 4.2`.
  - No MedDefense impersonation, no credential request, no attachment.
  - The range `203.0.113.0/24` is reserved for documentation (RFC 5737, TEST-NET-3). A live WHOIS or reverse-DNS lookup would return no real operator, and on a production network this address would not be routable. The same applies to the legitimate newsletter's `198.51.100.42` (E1, TEST-NET-2), so parts of the batch look sanitized.
- Safe investigation method:
  ```
  whois 203.0.113.228                                # expect an IANA documentation-range answer
  dig -x 203.0.113.228 +short
  whois canadian-pharma-discount.org
  dig +short A bulk-mail-07.canadian-pharma-discount.org
  dig +short TXT _dmarc.canadian-pharma-discount.org
  curl -s "https://urlscan.io/api/v1/search/?q=domain:canadian-pharma-discount.org"
  ```
  Do not fetch the URL. If the live lookups return nothing useful, record that and rely on the evidence above.
- Finding: ordinary bulk spam, low risk to the organization beyond nuisance. Nothing in the evidence links this IP or domain to E2, E3, E5 or E7. It is listed so the block list covers it, and so it is not mistaken for campaign infrastructure.
- Risk rating: LOW

---

## Findings across indicators

- Lookalike pattern: three of the four campaign domains reuse the company brand or a Microsoft brand plus a security or business keyword: `meddefense-portal.com`, `meddefense-benefits.org`, `outlook-protection.com`. The fourth, `medequip-supplies.net`, imitates a supplier name.
- Sending IP reuse: no IP is shared among E2, E3, E5 and E7. The only reuse in the batch is E6, where the sending host and the link target are the same address. Absence of shared IPs does not rule out a common operator: all four campaign emails share the PHPMailer 6.6.0 toolchain, `PHP-<8 hex>` Message-IDs and `X-Priority: 1` (see `1-header_analysis.md`).
- Per-recipient link tracking: E2 carries `id` and `token` in the URL and E6 carries `ref=pwhite`, so the senders can identify who clicked. E3, E5 and E7 use generic URLs.
- Multiple routes to one domain: E5 sends the reader to `medequip-supplies.net` through the body link, a login fallback and the PDF.
- Not yet known: registration dates, hosting providers, whether the web hosts match the mail hosts, and whether any other MedDefense host has contacted these domains. Those are the outputs of the lookups above and of log searches that were not part of this task.

## Indicators for blocking and hunting (defanged)

Domains:

- `meddefense-portal[.]com`
- `outlook-protection[.]com`
- `medequip-supplies[.]net`
- `meddefense-benefits[.]org`
- `canadian-pharma-discount[.]org`

Sending IPs:

- `91[.]234[.]99[.]107`
- `51[.]38[.]42[.]17`
- `185[.]176[.]43[.]22`
- `164[.]90[.]218[.]73`
- `203[.]0[.]113[.]228` (spam, low priority)

File name: `INV-2026-04891[.]pdf`

Not for blocking: `41[.]203[.]72[.]188` (lure content only).

Before blocking IPs at a network level, check whether the address is shared hosting, to avoid blocking unrelated sites.
