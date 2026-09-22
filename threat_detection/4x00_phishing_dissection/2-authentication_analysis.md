# Email Authentication Analysis

SPF, DKIM and DMARC results for all 8 emails in the evidence batch, and what each result means for the investigation. Values are the verdicts stamped in the `Authentication-Results` header by `mx01.meddefense.com`. No DNS record was re-queried and no signature was re-verified; this task uses the email evidence batch only.

## What each result answers

| Mechanism | Question it answers | What it does not tell you |
|---|---|---|
| SPF | Is the connecting IP listed in the SPF record of the envelope (`smtp.mailfrom`) domain? | It does not check the visible `From:` address, and it says nothing about who owns the domain. |
| DKIM | Was the message signed with a key published by the signing domain (`d=`), and is it unchanged since signing? | A valid signature proves the signer controls that domain's DNS, not that the domain is trustworthy. |
| DMARC | Did SPF or DKIM pass and align with the visible `From:` domain? What does that domain's policy say to do with a failure? | It protects the exact `From:` domain only. A lookalike domain is a different domain with its own DMARC record. |

`action=none` in the DMARC result means no enforcement action was applied to the message. Either the sender domain publishes a monitor-only policy or the gateway did not enforce one; the header does not say which. In both cases a DMARC failure with `action=none` is delivered to the mailbox.

---

## Email 1 — healthcare-education-weekly.com

- SPF: `pass`. Sender IP `198.51.100.42` is authorized in the SPF record of `healthcare-education-weekly.com`. The connecting server is one the domain owner listed.
- DKIM: `pass` (`d=healthcare-education-weekly.com`, `s=mail01`). The message was signed with a key that domain publishes and was not altered after signing.
- DMARC: `pass`, `action=none`. SPF (`smtp.mailfrom`) and DKIM (`d=`) both match the visible `From:` domain, so alignment is complete.
- Authentication verdict: supports legitimacy. Fully aligned on one domain.
- Investigation meaning: the sending domain is who it claims to be. Whether Jennifer Moore actually subscribed on 2024-08-11 is a separate check against her mailbox history. One loose end: `X-Mailer` names MailChimp while the Received chain shows the sender's own Postfix host, which is worth a glance but does not change the verdict given the aligned authentication and benign content.
- Final verdict: LEGITIMATE (graymail newsletter), P4-LOW.

## Email 2 — meddefense-portal.com

- SPF: `fail`. Sender IP `91.234.99.107` is not authorized for `meddefense-portal.com`. The domain's own SPF record does not list the server that sent the message. Note that the failing domain is the lookalike, not `meddefense.com`, so this is not a spoof of our domain.
- DKIM: `none` (message not signed, `header.d=none`). There is nothing to validate. Absence is not a failure, but it means no cryptographic link between the message and any domain.
- DMARC: `fail`, `action=none`. Neither SPF nor DKIM produced an aligned pass for `meddefense-portal.com`. No enforcement was applied, so the message was delivered.
- Authentication verdict: contradicts legitimacy. No authentication evidence ties this message to `meddefense.com`.
- Investigation meaning: confirms E2 did not come from MedDefense IT. It also shows why the user saw it: the gateway let a fully failing message through under `action=none`. Gateway handling of DMARC failures from unknown lookalike domains is worth reviewing.
- Final verdict: SUSPICIOUS (credential-harvest phishing), P1-URGENT because of the confirmed click.

## Email 3 — outlook-protection.com

- SPF: `pass`. Sender IP `51.38.42.17` is listed in the SPF record of `outlook-protection.com`. This means only that whoever controls DNS for `outlook-protection.com` listed that IP. It says nothing about Microsoft.
- DKIM: `pass` (`d=outlook-protection.com`, `s=default`). The message was signed with a key published in the DNS zone of `outlook-protection.com`. That proves integrity and control of that domain, not identity or brand.
- DMARC: `pass`, `action=none`, `header.from=outlook-protection.com`. SPF and DKIM both align with the visible `From:` domain. This answers "does this mail belong to `outlook-protection.com`?" with yes. It cannot answer "is `outlook-protection.com` Microsoft?".
- Authentication verdict: valid, but not evidence of legitimacy. All three checks pass for the wrong domain.
- Investigation meaning:
  - `outlook-protection.com` is not `microsoft.com` and it is not `outlook.com`. It is a separate domain that anyone can register for a few dollars, and SPF, DKIM and DMARC for it can be configured correctly in minutes. The words "outlook" and "protection" were chosen to look right at a glance; the trust comes from the Microsoft name in the display name and body, not from the domain.
  - DMARC protects the exact domain in the `From:` header. Whatever policy `microsoft.com` or `outlook.com` publishes only applies to mail that uses those domains in `From:`. This message never does, so those policies are never consulted.
  - Everything is aligned: `From:`, `Return-Path`, SPF `smtp.mailfrom` and DKIM `d=` are all `outlook-protection.com`. That is consistent ownership, which is not the same as being legitimate.
  - A filter that treats `dmarc=pass` as a trust signal would deliver E3 as good mail. Authentication alone catches E2, E5 and E7 but not E3. The decision has to come from the brand-to-domain mismatch, the domain's registration age (HC3 describes lookalike domains under 30 days old), the PHPMailer and `wp-admin` sending fingerprint, and the content (fake Lagos sign-in, 48-hour lock threat).
  - Evidence caveat: the DKIM `b=` values are truncated in the batch, and in E3, E4 and E8 they contain readable placeholder text instead of signature data. The `t=` timestamps for E1, E3, E4 and E8 also fall in 2025, a year before their `Date` headers. The same pattern appears on legitimate and malicious mail, so it is treated as a batch artifact. The `pass` verdict is taken from `mx01` and could not be re-verified offline.
- Final verdict: SUSPICIOUS (Microsoft impersonation), P2-HIGH. Authentication is valid only for the attacker's own domain.

## Email 4 — meddefense.com

- SPF: `pass` (sender IP `10.10.1.15`, `smtp.mailfrom=meddefense.com`). The IP is the internal Exchange hub `exchange-hub.meddefense.local`. It is a private address, so the pass reflects the trusted internal path, not a public SPF lookup.
- DKIM: `pass` (`d=meddefense.com`, `s=selector1`). Signed for our own domain.
- DMARC: `pass`, `action=none`. Aligned with `header.from=meddefense.com`.
- Authentication verdict: supports legitimacy.
- Investigation meaning: authentication, the internal relay path, the Exchange 2019 `X-Mailer`, the distribution-list `List-ID` and the content (no links, no attachment, no credential request) all agree. An internal sender can still be a compromised account, so content matters as well; nothing here is out of pattern. E4 is the baseline for genuine internal mail, and its statement that IT never emails password links and that the portal is internal or VPN-only contradicts the E2 pretext.
- Final verdict: LEGITIMATE, P4-LOW.

## Email 5 — medequip-supplies.net

- SPF: `softfail`. Sender IP `185.176.43.22` is softfail for `medequip-supplies.net`. The domain's SPF record ends with a soft-fail rule and does not list this IP. Softfail is a weaker negative than `fail`, but a vendor's own billing system would normally be listed.
- DKIM: `none` (message not signed).
- DMARC: `fail`, `action=none`. Nothing aligned for `medequip-supplies.net`, and the message was still delivered.
- Authentication verdict: contradicts legitimacy.
- Investigation meaning: small vendors do misconfigure SPF, so the softfail alone would not prove fraud. The weight comes from the combination: unsigned, DMARC fail, PHPMailer sending, a 7-day payment demand, and an AP recipient who does not recognize the invoice. Authentication also cannot say whether MedEquip Supplies is a real vendor. That must be checked against the vendor master and a contact number MedDefense already holds, not the number in the email.
- Final verdict: SUSPICIOUS (invoice fraud and credential harvesting), P2-HIGH.

## Email 6 — canadian-pharma-discount.org

- SPF: `softfail`. The result does not show the sender IP.
- DKIM: `none` (no `header.d`).
- DMARC: `fail`, `action=quarantine`. This is the only message in the batch where the header shows a quarantine action, meaning the policy or gateway asked for the message to be held. The batch does not say which two emails were pulled from Proofpoint quarantine, so it is not established that E6 was one of them.
- Authentication verdict: contradicts legitimacy of the sender, in the ordinary way a throwaway bulk-spam domain does.
- Investigation meaning: consistent with the SPAM classification (`X-Spam-Score: 9.8` against a 5.0 threshold). It does not impersonate MedDefense or request credentials, and its authentication, mailer (`XPedia Bulk Mailer 4.2`) and sending host share nothing with E2, E3, E5 or E7 in this evidence.
- Final verdict: SPAM, P4-LOW.

## Email 7 — meddefense-benefits.org

- SPF: `fail`. Sender IP `164.90.218.73` is not authorized for `meddefense-benefits.org`. As with E2, the failing domain is the lookalike, not `meddefense.com`.
- DKIM: `none` (message not signed).
- DMARC: `fail`, `action=none`. Delivered without enforcement.
- Authentication verdict: contradicts legitimacy. Nothing ties the message to `meddefense.com`, the domain genuine HR mail would use.
- Investigation meaning: the failure pattern is identical to E2. A real MedDefense HR notice would be relayed from the internal Exchange hub and pass for `meddefense.com`, as E4 does. The recipient's statement that she never signed up for anything fits the authentication picture.
- Final verdict: SUSPICIOUS (lookalike-domain HR lure), P2-HIGH.

## Email 8 — hhs.gov

- SPF: `pass`. Sender IP `134.174.47.82` is authorized for `hhs.gov`.
- DKIM: `pass` (`d=hhs.gov`, `s=hhs2026`).
- DMARC: `pass`, `action=none`. Aligned with `header.from=hhs.gov`.
- Authentication verdict: supports legitimacy.
- Investigation meaning: the mail is authenticated for the domain it claims. That does not prove the alert's content is accurate, and a compromised legitimate sender would also pass. Other evidence agrees: TLS 1.3, plain text, no links to act on, no attachment, no credential request. Because the alert asks the SOC to submit indicators, the request should be verified through the ISAC liaison or a known HC3 contact, not through details inside the message.
- Final verdict: LEGITIMATE, P3-MEDIUM (drives follow-up).

---

## Summary

| Email | Sender domain | SPF | DKIM | DMARC | Authentication supports legitimacy? | Final verdict |
|---|---|---|---|---|---|---|
| E1 | `healthcare-education-weekly.com` | pass | pass | pass | Yes | LEGITIMATE |
| E2 | `meddefense-portal.com` | fail | none | fail (`none`) | No | SUSPICIOUS |
| E3 | `outlook-protection.com` | pass | pass | pass | Valid, but for the attacker's domain only | SUSPICIOUS |
| E4 | `meddefense.com` | pass | pass | pass | Yes | LEGITIMATE |
| E5 | `medequip-supplies.net` | softfail | none | fail (`none`) | No | SUSPICIOUS |
| E6 | `canadian-pharma-discount.org` | softfail | none | fail (`quarantine`) | No | SPAM |
| E7 | `meddefense-benefits.org` | fail | none | fail (`none`) | No | SUSPICIOUS |
| E8 | `hhs.gov` | pass | pass | pass | Yes | LEGITIMATE |

## What the pattern shows

- Authentication on its own would separate three of the four suspicious emails (E2, E5, E7 fail DMARC) but would rank E3 alongside the legitimate E1, E4 and E8.
- Three suspicious emails failed DMARC and were still delivered because the result was `action=none`.
- None of the four suspicious emails authenticates as `meddefense.com` or `microsoft.com`. They use lookalike domains, so a rule keyed on the real domains would never have fired.
- Follow-up worth considering: treat DMARC failures from unfamiliar lookalike domains as quarantine, add a check that compares display-name brands to the sending domain, and use domain age as an input, so that `dmarc=pass` from a newly registered domain is not treated as a trust signal.
