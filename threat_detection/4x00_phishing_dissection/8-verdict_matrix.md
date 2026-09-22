# The Verdict Matrix

Final, evidence-based classification of all 8 emails, replacing the surface-level initial triage (`0-initial_triage.md`) with verdicts drawn from header analysis (`1-header_analysis.md`), authentication analysis (`2-authentication_analysis.md`), social engineering analysis (`3-social_engineering.md`), URL/attachment autopsy (`4-url_attachment_autopsy.md`) and the click investigation (`7-click_investigation.md`).

## Classification labels

- **SPAM** — unsolicited bulk mail, no targeting, no MedDefense impersonation.
- **PHISHING-OPPORTUNISTIC** — a credential-harvesting or fraud lure using a generic template that does not require knowledge of MedDefense specifically; the same message could plausibly be sent to any organization.
- **PHISHING-TARGETED** — a credential-harvesting or fraud lure built around MedDefense's own brand, a real supplier, or an internal business process, addressed to a named individual whose role fits the pretext.
- **LEGITIMATE** — authenticated, benign, no red flags.
- **LEGITIMATE-WITH-ISSUE** — authenticated and benign, but with a minor unresolved question (for example an unverified claim) that a recipient or IT should still follow up on.

## Verdict Table

| Email | Initial Class | Final Class | Confidence | Key Evidence | Recommended Action |
|---|---|---|---|---|---|
| E1 | LEGITIMATE | LEGITIMATE-WITH-ISSUE | HIGH | SPF/DKIM/DMARC pass and aligned for `healthcare-education-weekly.com`; MailChimp bulk sender with one-click unsubscribe; content is educational with no credential request. Claims a 2024-08-11 subscription not yet checked against Jennifer Moore's mailbox history. | No block needed. Ask Jennifer Moore to confirm the subscription; unsubscribe if unwanted. Treat as graymail, not a threat. |
| E2 | SUSPICIOUS (P1-URGENT) | PHISHING-TARGETED | HIGH | Lookalike domain `meddefense-portal.com`; SPF fail, DKIM none, DMARC fail (`action=none`); PHPMailer 6.6.0 from `91.234.99.107`; personalized `/verify/staff?id=dmarsh&token=...` link naming Diane Marsh's real workflows (scheduling, EHR gateway, shift swaps); confirmed click at 2026-04-14 15:02:33 CDT. | Already contained per `7-click_investigation.md`: block domain/IP, reset Diane Marsh's password, revoke sessions, monitor her account 30 days. Treat as the highest-priority incident in the batch. |
| E3 | SUSPICIOUS (P2-HIGH) | PHISHING-OPPORTUNISTIC | MEDIUM | Domain `outlook-protection.com` impersonates Microsoft, not MedDefense; SPF, DKIM and DMARC all pass for the attacker's own domain; PHPMailer 6.6.0 from `51.38.42.17`; generic template with no per-recipient token, requires no MedDefense-specific knowledge beyond Rafael Mendez's name and address. No click reported. | Block domain/IP. Alert Rafael Mendez and remind staff that Microsoft never sends sign-in alerts from a non-Microsoft domain. Lower urgency than E2/E5/E7 since it is not MedDefense-specific, but still block. |
| E4 | LEGITIMATE | LEGITIMATE | HIGH | Internal Exchange 2019 relay from `10.10.1.15`; SPF/DKIM/DMARC pass and aligned for `meddefense.com`; plain-text policy reminder, no links, no attachment, no credential request; explicitly states IT never emails password-change links. | No action. Useful as the internal baseline for genuine MedDefense mail. |
| E5 | SUSPICIOUS (P2-HIGH) | PHISHING-TARGETED | HIGH | Domain `medequip-supplies.net` mimics a medical-supplies vendor; SPF softfail, DKIM none, DMARC fail; PHPMailer 6.6.0 from `185.176.43.22`; USD 24,716.38 invoice with a 7-day/2%-late-fee threat and a PDF generated at send time carrying the same payment link; Accounts Payable recipient (Angela Rivera) reports the invoice looks wrong and the vendor is unverified. | Block domain/IP. Do not pay the invoice. Verify MedEquip Supplies against the vendor master using a known phone number, not the one in the email. Alert Angela Rivera and the AP team. |
| E6 | SPAM | SPAM | HIGH | `X-Spam-Score: 9.8` against a 5.0 threshold, `XPedia Bulk Mailer 4.2`, link to a raw IP that is also the sending host (`203.0.113.228`, an RFC 5737 TEST-NET-3 documentation address in this reproduced batch); no MedDefense impersonation, no credential request. | Add to the spam/block list at low priority. No user follow-up needed. |
| E7 | SUSPICIOUS (P2-HIGH) | PHISHING-TARGETED | HIGH | Domain `meddefense-benefits.org` is a lookalike of MedDefense's own brand; SPF fail, DKIM none, DMARC fail; PHPMailer 6.6.0 from `164.90.218.73`; "closes tomorrow" enrollment deadline with a coverage-lapse threat; recipient (Linda Patterson, Billing) reports she never signed up for anything. | Block domain/IP. Alert Linda Patterson and confirm with the real HR team whether any enrollment window is actually open. Broadcast an awareness note, since the HR pretext likely targeted more than one recipient. |
| E8 | LEGITIMATE (P3-MEDIUM) | LEGITIMATE | HIGH | SPF/DKIM/DMARC pass and aligned for `hhs.gov`; sender IP `134.174.47.82` authorized; TLS 1.3; plain text, TLP:CLEAR, no links, no attachment, no credential request. Describes a regional pattern that matches E2, E3, E5 and E7 closely. | No action beyond normal handling. Use as the reference pattern for the campaign comparison (`9-campaign_thread.md`) and for the HC3 IOC submission (`11-ioc_extraction.md`). |

## Where Final Differs From Initial

- **E1** (LEGITIMATE → LEGITIMATE-WITH-ISSUE): the initial triage only checked authentication and content, both of which are clean. Deeper reading of the body surfaced an unverified claim ("you are receiving this because you subscribed on 2024-08-11") that the triage table flagged but did not resolve. The email is still not a threat, but it is not fully closed either, hence the "-WITH-ISSUE" qualifier rather than a plain LEGITIMATE.
- **E2** (SUSPICIOUS → PHISHING-TARGETED): initial triage correctly flagged it as suspicious from authentication failures alone. Deeper analysis added the targeting evidence — a personalized URL token, nursing-specific consequences (scheduling, EHR gateway, shift swaps), and a confirmed click — that justifies the more specific TARGETED label over a generic phishing bucket.
- **E3** (SUSPICIOUS → PHISHING-OPPORTUNISTIC): initial triage flagged the Microsoft impersonation, but authentication alone could not distinguish E3 from E1/E4/E8 (all four pass SPF/DKIM/DMARC). Content analysis (`3-social_engineering.md`) showed E3 is the only one of the four malicious emails with no per-recipient token and no MedDefense-specific detail, meaning it does not require the same reconnaissance as E2, E5 and E7. It is reclassified as opportunistic rather than targeted, separating it from the MedDefense-specific campaign.
- **E5** (SUSPICIOUS → PHISHING-TARGETED): initial triage flagged the authentication softfail and the AP recipient's own suspicion. Deeper analysis added that the PDF attachment was generated one second before the message was sent (not a genuine pre-existing invoice) and that the pretext matches a real MedDefense business process (medical-supply purchasing), supporting TARGETED over a generic label.
- **E7** (SUSPICIOUS → PHISHING-TARGETED): initial triage flagged the lookalike domain and the recipient's denial of any enrollment. Deeper analysis confirmed the domain directly imitates MedDefense's own brand (not a third party) and matches an internal HR process, which is a stronger targeting signal than E3's generic Microsoft template.
- **E4, E6, E8**: final class matches initial class. No new evidence changed the direction of the call, only added supporting detail.

## Triage Accuracy Assessment

Measured at the coarse level the initial triage actually worked at (LEGITIMATE vs SUSPICIOUS vs SPAM, i.e. "is this a problem or not"), **8 of 8 emails (100%) were classified in the correct direction** during initial triage. No malicious email was missed and no legitimate email was wrongly flagged as a threat.

| Measure | Result |
|---|---|
| Correct direction (malicious/spam vs legitimate) | 8 / 8 (100%) |
| Correctly separated targeted from opportunistic phishing | 0 / 3 — initial triage had no label for this distinction; all of E2, E3, E5, E7 were grouped as one undifferentiated "SUSPICIOUS" bucket |
| Flagged the E1 subscription caveat | 1 / 1 — noted in the initial triage's evidence column, though not resolved into a separate label |
| Priority ranking (P1–P4) later contradicted by deeper evidence | 0 — E2's P1-URGENT priority was confirmed and never downgraded |

What the initial triage got right: authentication results and obvious content red flags (urgency, credential requests, spam scoring) were enough to sort all 8 emails into the correct broad bucket on the first pass, and the P1 priority correctly anticipated that E2 was the most serious item before the deeper analysis was even done.

What the initial triage could not do: it had no way to tell PHISHING-TARGETED from PHISHING-OPPORTUNISTIC, since that distinction depends on content analysis (personalization, tokens, internal-process knowledge) that a header/authentication pass does not capture. It also could not resolve E1's subscription-verification question, since that requires checking the recipient's mailbox history rather than the email itself. Both gaps were closed only by the deeper, task-by-task analysis in this batch.
