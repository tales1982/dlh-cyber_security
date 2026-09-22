# IOC Extraction

Indicators of compromise extracted from the evidence batch for E2, E3, E5 and E7, the E5 attachment, and the HC3 alert pattern in E8, structured for sharing with other defenders. Not every row is equally actionable: domains, IPs, URLs and sender addresses tied directly to a specific malicious message are high-confidence and safe to block; tooling fingerprints and hosting-tier notes are context that helps correlation but would cause false positives if blocked on their own (see IOC Quality below). All values are defanged. E6 (bulk pharmacy spam) is out of scope for this report — it is unrelated to the targeted campaign (see `9-campaign_thread.md`) and was already handled as low-priority spam in `8-verdict_matrix.md`.

## 1. Structured IOC Table

| # | IOC Type | IOC Value (defanged) | Source Email | Context | Confidence | Recommended Action |
|---|---|---|---|---|---|---|
| 1 | Domain | `meddefense-portal[.]com` | E2 | Lookalike of MedDefense's own domain; hosts the credential-harvest landing page Diane Marsh clicked | HIGH | Block |
| 2 | IP | `91[.]234[.]99[.]107` | E2 | External mail server (`mail.meddefense-portal.com`) that delivered E2; SPF fail | HIGH | Block |
| 3 | URL | `hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1` | E2 | Personalized credential-harvest link; the `token` is per-recipient and will differ for other victims | HIGH (domain/path); token is single-use | Block domain and `/verify/staff` path; do not expect the exact token to recur |
| 4 | URL | `hxxps://meddefense-portal[.]com/assets/logo[.]png` | E2 | Remote-loaded logo image; functions as an open/tracking indicator | MEDIUM | Monitor (covered by blocking #1) |
| 5 | Email address | `noreply@meddefense-portal[.]com` | E2 | From address | HIGH | Block / alert on sender |
| 6 | Email address | `no-reply@meddefense-portal[.]com` | E2 | Reply-To address (note the hyphen difference from the From address) | HIGH | Block / alert on sender |
| 7 | Domain | `outlook-protection[.]com` | E3 | Impersonates Microsoft; authenticates cleanly for itself, not for Microsoft | HIGH | Block |
| 8 | IP | `51[.]38[.]42[.]17` | E3 | External mail server (`mail.outlook-protection.com`) that delivered E3; SPF/DKIM/DMARC pass for this domain only | HIGH | Block |
| 9 | URL | `hxxps://outlook-protection[.]com/verify` | E3 | Generic (non-tokenized) credential-harvest link | HIGH | Block |
| 10 | URL | `hxxps://outlook-protection[.]com/img/ms_logo[.]png` | E3 | Remote-loaded fake Microsoft logo; tracking indicator | MEDIUM | Monitor (covered by blocking #7) |
| 11 | Email address | `security@outlook-protection[.]com` | E3 | From address | HIGH | Block / alert on sender |
| 12 | Email address | `no-reply@outlook-protection[.]com` | E3 | Reply-To address | HIGH | Block / alert on sender |
| 13 | Domain | `medequip-supplies[.]net` | E5 | Vendor-style lookalike; hosts both the invoice-payment page and a fallback login page | HIGH | Block |
| 14 | IP | `185[.]176[.]43[.]22` | E5 | External mail server (`mail.medequip-supplies.net`) that delivered E5; SPF softfail | HIGH | Block |
| 15 | URL | `hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891` | E5 | Payment-fraud / credential-capture link; same URL is also embedded in the PDF attachment | HIGH (domain/path); invoice id specific to this wave | Block domain and `/invoices/pay` path |
| 16 | URL | `hxxps://medequip-supplies[.]net/portal/login` | E5 | Fallback credential-harvest login page | HIGH | Block |
| 17 | Email address | `invoices@medequip-supplies[.]net` | E5 | From address | HIGH | Block / alert on sender |
| 18 | Email address | `billing@medequip-supplies[.]net` | E5 | Reply-To address | HIGH | Block / alert on sender |
| 19 | File name | `INV-2026-04891[.]pdf` | E5 attachment | Invoice PDF filename delivered as a base64 MIME attachment | LOW | Monitor only — a filename is trivially renamed |
| 20 | URL (embedded in file) | `hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891` | E5 attachment | `/URI` link annotation inside the PDF, same destination as #15 | HIGH | Block (same as #15) |
| 21 | File hash (SHA-256) | `49558e1500b82d6758379f44ce6104442ec3a5cc08912737db5584640f4b9cad` | E5 attachment | Hash of the decoded attachment stream **as reproduced in the evidence batch**; may not match the original file bit-for-bit if the batch was normalized (see `4-url_attachment_autopsy.md`, Indicator 8) | LOW | Monitor / investigative lead only — do not treat a non-match as "safe" |
| 22 | Tool / infrastructure note | `Producer: wkhtmltopdf 0.12.6` (PDF metadata) | E5 attachment | Shows the invoice was machine-generated from HTML at send time, one second before the message `Date` | LOW | Context only — a common open-source tool, not unique to this actor |
| 23 | Domain | `meddefense-benefits[.]org` | E7 | Lookalike of MedDefense's own domain; hosts the enrollment credential-harvest page | HIGH | Block |
| 24 | IP | `164[.]90[.]218[.]73` | E7 | External mail server (`mail.meddefense-benefits.org`) that delivered E7; SPF fail | HIGH | Block |
| 25 | URL | `hxxps://meddefense-benefits[.]org/enroll` | E7 | Credential and personal-information harvest link | HIGH | Block |
| 26 | Email address | `hr-notifications@meddefense-benefits[.]org` | E7 | From address | HIGH | Block / alert on sender |
| 27 | Email address | `no-reply@meddefense-benefits[.]org` | E7 | Reply-To address | HIGH | Block / alert on sender |
| 28 | Tool | `X-Mailer: PHPMailer 6.6.0` | E2, E3, E5, E7 | Identical mailer fingerprint across all four; also appears in each `Received:` clause | LOW | Context only — do not alert on this string alone (see IOC Quality) |
| 29 | Infrastructure note | Message-ID pattern `PHP-<8 hex>@<sender-domain>` | E2, E3, E5, E7 | Shared naming convention, repeats the `Received:` queue id, no timestamp | LOW | Context only — correlation aid, not a blockable value |
| 30 | Infrastructure note | `X-Priority: 1 (Highest)` on all four; E2 also adds `X-MSMail-Priority: High` and `Importance: High` | E2, E3, E5, E7 | Shared urgency-header habit | LOW | Context only — common in legitimate urgent mail too |
| 31 | Infrastructure note (HC3 pattern) | Newly-registered `.com`/`.net`/`.org` domains containing "portal", "benefits", "supplies" or "login" | E8 (HC3 alert) | Matches #1, #13, #23 exactly; useful as a domain-registration monitoring heuristic | LOW | Context only — feed a scoring rule, do not block on keyword match alone |
| 32 | Infrastructure note (HC3 pattern) | PHPMailer-based sending on budget VPS hosting (Hostinger/DigitalOcean pricing tier) | E8 (HC3 alert) | Consistent with the sending IPs above, but the specific hosting provider was not confirmed by live WHOIS in this evidence-only exercise | LOW | Context only — never block a whole hosting-provider range on this alone |
| 33 | Infrastructure note (HC3 pattern) | 24–48 hour urgency deadlines, lockout threats, enrollment cutoffs, role-targeted lures | E8 (HC3 alert) | Matches the pretexts in E2, E5 and E7 (see `9-campaign_thread.md`) | LOW | Context only — a social-engineering pattern for user-awareness content, not a technical IOC |

## 2. Coverage Check

Minimum-required sources are all represented: E2 (#1–6), E3 (#7–12), E5 (#13–18), the E5 attachment (#19–22), E7 (#23–27), and the HC3 alert patterns from E8 (#31–33).

## 3. Attack-Phase Categorization

**Delivery** — the sending infrastructure and sender identities that got each message into the mailbox: #2, #5, #6 (E2); #8, #11, #12 (E3); #14, #17, #18 (E5); #24, #26, #27 (E7).

**Credential harvesting** — the landing pages the lures try to drive a click to: #3, #9, #15, #16, #20, #25.

**Attachment or lure artifact** — indicators tied specifically to the E5 PDF: #19, #21, #22 (plus #20, which is also listed under credential harvesting since it is the URL embedded inside the file).

**Infrastructure** — the registered domains themselves, as durable campaign infrastructure separate from any one URL path: #1, #7, #13, #23; plus the tracking/logo images #4, #10, which load from the same infrastructure when the message is rendered.

**Context-only indicators** — signals useful for correlation, scoring or awareness content, but not safe to act on alone: #28, #29, #30, #31, #32, #33.

## 4. IOC Quality

**High-confidence, safe to block:** the four domains (#1, #7, #13, #23), the four sending IPs (#2, #8, #14, #24), the primary credential-harvest URLs by domain-plus-path (#3, #9, #15, #16, #25, #20), and the eight From/Reply-To sender addresses (#5, #6, #11, #12, #17, #18, #26, #27). Each is unique to a confirmed malicious message in this batch, and no legitimate MedDefense traffic has any reason to reach a lookalike domain, so the collateral-damage risk of blocking them is effectively zero.

**Monitor only, not a standalone block:**
- The E2 URL's `token` parameter (#3) and the E5 invoice id in the query string (#15) are specific to this wave and will differ for other victims or future sends; block the domain and path, but do not expect the literal query string to reappear.
- The tracking/logo images (#4, #10) are collateral of simply rendering the phishing email and add nothing beyond what blocking the domain already covers.
- The PDF filename (#19) is trivially renamed by the attacker and proves nothing by itself.
- The SHA-256 hash (#21) was computed from the batch's reproduction of the attachment, which may not be byte-identical to the real original file (see `4-url_attachment_autopsy.md`). Use it as a hunting lead, not as proof that a non-matching file is safe.

**Should not be used alone — false-positive risk:**
- `X-Mailer: PHPMailer 6.6.0` (#28) and the `PHP-<8 hex>` Message-ID pattern (#29) are defaults of a widely used, entirely legitimate open-source library. Countless benign websites and small businesses send mail this way; alerting on the string alone would generate high false-positive volume. It is useful only combined with other signals (a lookalike or newly-registered domain, a failed DMARC result).
- `X-Priority: 1` (#30) is common in legitimate urgent mail (IT outage notices, HR deadlines) and is not a threat indicator on its own.
- The HC3 domain-keyword pattern (#31) — "portal", "benefits", "supplies", "login" — matches plenty of legitimate domains too; it belongs in a domain-registration monitoring or scoring rule, not a direct block list.
- The "budget VPS hosting" note (#32) describes a hosting tier used by an enormous number of legitimate small sites; blocking a whole provider's IP ranges on this basis would cause broad collateral blocking.
- The urgency/role-targeting pattern (#33) describes social-engineering style, not a technical artifact — it is meant to inform user-awareness training and detection-rule design (see `13-phishing_investigation_report.md`), not to be fed into a blocklist.

## 5. HC3-Ready Summary

For submission alongside MedDefense's report to HC3's regional phishing advisory (referencing E8, advisory reference `HC3-2026-PRELIM-001`):

**Domains:** `meddefense-portal[.]com`, `outlook-protection[.]com`, `medequip-supplies[.]net`, `meddefense-benefits[.]org`

**IPs:** `91[.]234[.]99[.]107`, `51[.]38[.]42[.]17`, `185[.]176[.]43[.]22`, `164[.]90[.]218[.]73`

**Sender addresses:** `noreply@meddefense-portal[.]com`, `security@outlook-protection[.]com`, `invoices@medequip-supplies[.]net`, `hr-notifications@meddefense-benefits[.]org`

**URLs:** `hxxps://meddefense-portal[.]com/verify/staff`, `hxxps://outlook-protection[.]com/verify`, `hxxps://medequip-supplies[.]net/invoices/pay`, `hxxps://medequip-supplies[.]net/portal/login`, `hxxps://meddefense-benefits[.]org/enroll`

**File reference:** `INV-2026-04891[.]pdf`, embedded payment URL as above, SHA-256 `49558e1500b82d6758379f44ce6104442ec3a5cc08912737db5584640f4b9cad` (labelled unverified — computed from a batch reproduction of the attachment, not the original file)

**Narrative for HC3:** MedDefense Health Systems observed four phishing emails between 2026-04-14 and 2026-04-16 that match the pattern described in HC3-2026-PRELIM-001: newly-styled lookalike domains using "portal", "benefits" and "supplies" keywords, PHPMailer-based sending consistent with budget VPS infrastructure, 24-hour to next-day urgency deadlines with account-lockout or coverage-lapse threats, and role-targeted lures aimed at clinical, finance and HR-adjacent staff. One recipient (clinical staff, workstation-based) clicked the credential-harvest link in the most urgent of the four messages; credential compromise is not yet confirmed and is under active investigation (see `7-click_investigation.md`). No shared sending infrastructure was found between the three MedDefense-specific messages, suggesting either rotating VPS infrastructure or multiple operators using the same toolkit.
