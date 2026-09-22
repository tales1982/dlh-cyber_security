# Phishing Campaign Investigation Report

**MedDefense Health Systems — Security Operations**
**Prepared for:** SOC Lead review; suitable for sharing with HC3
**Evidence base:** 8-email raw SMTP evidence batch, collected 2026-04-17 09:15 CDT by Mike Torres (Network Engineer)
**Scope:** Evidence-based analysis only — no live Wazuh, Sysmon, Suricata, Windows Security, proxy, DNS or identity-provider log was queried for this report. Every follow-up check named below is a recommendation, clearly labeled as not yet performed.

---

## 1. Executive Summary

Between April 14 and April 16, 2026, MedDefense staff received four coordinated phishing emails that impersonated internal IT, Microsoft, a medical-supply vendor, and HR benefits to steal login credentials or payment information. One employee, a clinical staff member, clicked the most urgent of these links about 15 minutes after it arrived; whether her password was actually entered or her account compromised is not yet confirmed and is under active investigation. Three of the four phishing emails show clear signs of being a single, deliberately MedDefense-targeted campaign, and they closely match a regional healthcare-sector warning issued by the federal Health Sector Cybersecurity Coordination Center (HC3) during the same window. No malware or system compromise has been confirmed; the immediate risk is credential theft and possible unauthorized access to systems that touch patient data. This report recommends immediate containment steps that do not depend on further log review, alongside a short list of detection and process gaps to close over the next 30 days.

## 2. Investigation Timeline

| Item | Value |
|---|---|
| Collection window | 2026-04-14 07:22 CDT → 2026-04-16 15:22 CDT (about 57 hours) |
| Batch collected | 2026-04-17 09:15 CDT |
| E1 (legitimate newsletter) sent | 2026-04-14 07:22 CDT |
| **E2 (phishing, clicked) sent** | **2026-04-14 14:47 CDT** |
| **Diane Marsh's reported click on E2** | **2026-04-14 15:02:33 CDT (14 min 41 s after delivery, per workstation NTP)** |
| E3 (phishing, Microsoft impersonation) sent | 2026-04-15 09:13 CDT |
| E4 (legitimate, internal IT) sent | 2026-04-15 10:00 CDT |
| E5 (phishing, invoice fraud) sent | 2026-04-16 11:28 CDT |
| E6 (spam) sent | 2026-04-16 13:04 CDT |
| E7 (phishing, HR benefits) sent | 2026-04-16 15:22 CDT |
| E8 (HC3 sector alert) received | 2026-04-16 08:47 CDT |

The click is roughly 66 hours before the batch was collected, not the approximately 36 hours mentioned in early reporting; this report uses the workstation NTP timestamp as authoritative, consistent with `0-initial_triage.md`. Investigation scope covers header, authentication, content, URL/attachment and click analysis of all 8 emails, plus a campaign-linkage and IOC-extraction pass; it does not include any endpoint or identity-provider log review, which is recommended as follow-up (Sections 5 and 7).

## 3. Email-by-Email Analysis

Full detail and reasoning is in `8-verdict_matrix.md`; summarized here.

| Email | Classification | Confidence | Key Evidence |
|---|---|---|---|
| E1 | LEGITIMATE-WITH-ISSUE | HIGH | Aligned SPF/DKIM/DMARC for `healthcare-education-weekly.com`; benign newsletter content; unverified subscription claim worth a quick check. |
| **E2** | **PHISHING-TARGETED** | **HIGH** | Lookalike `meddefense-portal.com`; SPF fail/DKIM none/DMARC fail; personalized `/verify/staff?id=dmarsh&token=...` link naming Diane Marsh's real workflows; **confirmed click**. |
| E3 | PHISHING-OPPORTUNISTIC | MEDIUM | Impersonates Microsoft from `outlook-protection.com`; authenticates cleanly for its own domain only; generic, non-personalized template; no click reported. |
| E4 | LEGITIMATE | HIGH | Internal Exchange relay, aligned authentication for `meddefense.com`, plain-text policy reminder with no links. |
| E5 | PHISHING-TARGETED | HIGH | `medequip-supplies.net` invoice fraud; SPF softfail/DKIM none/DMARC fail; PDF generated at send time; AP recipient flags the invoice as unrecognized. |
| E6 | SPAM | HIGH | Bulk pharmacy spam, `X-Spam-Score 9.8`, no MedDefense targeting. |
| E7 | PHISHING-TARGETED | HIGH | `meddefense-benefits.org` mimics MedDefense's own brand; SPF fail/DKIM none/DMARC fail; recipient denies signing up for anything. |
| E8 | LEGITIMATE | HIGH | Aligned authentication for `hhs.gov`; genuine HC3 sector alert describing a pattern that matches E2, E3, E5 and E7. |

## 4. Campaign Analysis

Full detail in `9-campaign_thread.md`; summarized here.

**Why E2, E5 and E7 are likely connected:** all three use PHPMailer 6.6.0 with an identical `PHP-<8 hex>@<domain>` Message-ID convention and `mail.<lookalike-domain>` sending-host naming; all three fail authentication for their own domain in the same way (unsigned, DMARC `action=none`); all three pair an urgency deadline with a named consequence tied to a real MedDefense process (portal access, an invoice, benefits enrollment); and all three were sent within a roughly 48-hour window (April 14–16) with deliveries clustering on April 16. No sending IP is reused between them, so this is a shared playbook and toolchain, not shared infrastructure in the strict sense.

**How E8 supports the campaign hypothesis:** the HC3 alert describes, almost point for point, the same four traits found in E2/E5/E7 — newly-styled lookalike domains using "portal", "benefits" and "supplies" keywords; PHPMailer sending on budget VPS-style hosting; 24–48 hour urgency deadlines with lockout or coverage-lapse threats; and role-targeted lures for clinical, billing and HR-adjacent staff. E8 arrived on April 16 at 08:47 CDT, between the E2 and E5/E7 deliveries, meaning MedDefense's own three emails are a concrete, local data point for the same regional pattern HC3 was still calling "not yet IOC-confirmed."

**How E3 should be interpreted:** E3 shares tooling traits with the trio (PHPMailer, the same Message-ID format, `X-Priority: 1`) but was sent from a different IP, authenticates cleanly for its own domain, requires no MedDefense-specific knowledge, and carries no per-recipient token. It is assessed as a separate, more generic phishing operation — possibly the same operator using a second, more polished kit against a broader target list, possibly unrelated — and should not be assumed to be part of the confirmed MedDefense-targeted thread. It should still be blocked and reported; the distinction affects attribution confidence, not the response.

## 5. Click Incident Assessment

Full detail in `7-click_investigation.md`; summarized here.

**What is known:** Diane Marsh (`dmarsh@meddefense.com`, workstation `WS-NURSE-04`, `10.10.2.15`) clicked the link in E2 at 2026-04-14 15:02:33 CDT, about 15 minutes after delivery. The link (`hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1`) is a personalized credential-harvest page on a lookalike domain delivered by a sender that failed every authentication check.

**What cannot be concluded from the evidence batch alone:** whether the page actually loaded, what it displayed, whether Diane entered a username or password, whether she approved any MFA prompt, and whether anything was downloaded or executed on her workstation. The batch records a click, not a credential submission or an endpoint event, and no endpoint or identity log was reviewed for this report.

**Recommended safe next actions** (do not require further evidence to start):
1. Reset Diane Marsh's password from a known-clean device, out of band, and revoke her active sessions and refresh tokens.
2. Review and, where unrecognized, remove her registered MFA methods.
3. Interview her without blame about what she saw and did after the click.
4. Block the E2 domain and sending IP at the gateway and firewall.
5. Run an endpoint scan on `WS-NURSE-04`; escalate to isolation only if that scan or later log review shows a download or execution.
6. Monitor her account for 30 days for unfamiliar sign-in locations, new inbox rules, or MFA changes.

Until endpoint and identity logs are reviewed, treat this as **possible credential exposure** rather than either "no compromise" or "confirmed compromise" (see the decision matrix in `7-click_investigation.md`).

## 6. IOC Summary

Full structured table, attack-phase breakdown and quality notes are in `11-ioc_extraction.md`; the safe-to-block core is:

- **Domains:** `meddefense-portal[.]com`, `outlook-protection[.]com`, `medequip-supplies[.]net`, `meddefense-benefits[.]org`
- **IPs:** `91[.]234[.]99[.]107`, `51[.]38[.]42[.]17`, `185[.]176[.]43[.]22`, `164[.]90[.]218[.]73`
- **Sender addresses:** `noreply@meddefense-portal[.]com`, `security@outlook-protection[.]com`, `invoices@medequip-supplies[.]net`, `hr-notifications@meddefense-benefits[.]org`
- **URLs:** `hxxps://meddefense-portal[.]com/verify/staff`, `hxxps://outlook-protection[.]com/verify`, `hxxps://medequip-supplies[.]net/invoices/pay`, `hxxps://medequip-supplies[.]net/portal/login`, `hxxps://meddefense-benefits[.]org/enroll`
- **File indicator:** `INV-2026-04891[.]pdf`, SHA-256 `49558e1500b82d6758379f44ce6104442ec3a5cc08912737db5584640f4b9cad` (unverified — computed from a batch reproduction, treat as a hunting lead, not a blocking hash)

Tooling fingerprints (PHPMailer 6.6.0, the `PHP-<8 hex>` Message-ID pattern, `X-Priority: 1`) and the HC3 hosting/keyword notes are context-only and should not be blocked on their own; see `11-ioc_extraction.md` Section 4 for why.

## 7. Detection and Control Gaps

**What existing controls did not prevent:** the mail gateway delivered all four phishing emails despite each one failing SPF and/or DMARC (three with `action=none`, effectively no enforcement on a failed result), and despite E2 and E7 spoofing lookalikes of MedDefense's own domain. Nothing in the evidence shows a link-rewriting or attachment-sandboxing control that would have neutralized the E2 click or flagged the E5 PDF's freshly generated payment link.

**What should improve:**
- Move DMARC handling from `p=none`-equivalent monitoring to `quarantine` (and eventually `reject`) for mail claiming to be from `meddefense.com` and its close lookalikes, so a spoofed or unauthenticated message does not reach the inbox on delivery.
- Add a rule that flags any inbound domain that is a small edit-distance away from `meddefense.com` (added word, swapped TLD), independent of its authentication result — this would have caught E2 and E7 even though their DMARC failures were already visible.
- Sandbox or defer first-seen links from newly observed external domains before allowing a click, particularly on messages carrying `X-Priority: 1` combined with a failed or absent DKIM/DMARC result.
- Confirm whether the corporate mailbox platform is genuinely Microsoft 365; if not, block sign-in-alert-style lures referencing Microsoft outright, since none should be expected from that platform.

**Detection ideas worth building from this investigation** (the referenced "Task 12" detection-engineering deliverable was not part of the file set provided for this report, so these are proposed here directly rather than cited from it):
- A correlation rule that scores a message higher when it combines: (a) DMARC fail or none, (b) a domain registered or first-seen recently, (c) `X-Priority: 1`, and (d) `X-Mailer: PHPMailer` — none of these alone is a safe blocklist entry (see `11-ioc_extraction.md`), but the combination matched all four phishing emails here and nothing in E1/E4/E8.
- A watchlist for domains containing "portal", "benefits", "supplies", "login" plus the organization's own brand string, sourced from certificate-transparency logs, per HC3's described pattern.
- An alert on any inbound mail whose `Received:` chain shows a hostname of the form `mail.<domain>` with no MX-consistent reverse DNS, paired with a from-domain that string-matches (fuzzy) the organization's own domain.
- A click-time control (URL rewriting with sandboxed detonation) specifically for links carrying a per-recipient token or id parameter, since that pattern (seen in E2 and E5) indicates a targeted, tracked lure rather than bulk spam.

## 8. Recommendations

**Immediate (next 24 hours)**
- Reset Diane Marsh's password and revoke her sessions/MFA as described in Section 5; interview her.
- Block the four domains, four IPs, and eight sender addresses in Section 6 at the mail gateway, proxy, DNS and firewall.
- Search the mail gateway for any other recipients of E2, E3, E5 and E7, and remove those messages from mailboxes.
- Run an endpoint protection scan on `WS-NURSE-04`.

**Short-term (next 7 days)**
- Complete the endpoint and account follow-up checks listed in `7-click_investigation.md` (browser history, downloads, process execution, sign-in logs, MFA activity, inbox rules) using whatever Sysmon/Wazuh/Suricata/identity-provider tooling is available, and update the decision matrix outcome for Diane Marsh's account accordingly.
- Verify the MedEquip Supplies vendor relationship and payment status through the vendor master and a known phone number; confirm with Angela Rivera that no payment was made.
- Confirm with the real HR team whether any benefits enrollment window was open in this period, and notify staff broadly that the E7 email was not genuine.
- Submit the IOC package in `11-ioc_extraction.md` to HC3 against advisory `HC3-2026-PRELIM-001`.
- Run a brief awareness reminder to clinical, finance and HR-adjacent staff describing the four pretexts used.

**Medium-term (next 30 days)**
- Implement the DMARC enforcement, lookalike-domain and correlation-rule improvements described in Section 7.
- Continue monitoring Diane Marsh's account (and any other confirmed recipients) for unusual sign-ins, MFA changes or inbox-rule creation through the full 30-day window recommended in `7-click_investigation.md`.
- Review whether the mail gateway's spam/quarantine action for failed-DMARC mail should change from `action=none` to `quarantine`, based on the fact that three of four phishing emails here were delivered specifically because of that setting.
- Close the loop with HC3 on whether other regional organizations report matching indicators, to help firm up the attribution assessment in `9-campaign_thread.md` beyond its current MEDIUM confidence.
