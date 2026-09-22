# Header Analysis

Parse of the SMTP header chain for the four emails classified SUSPICIOUS in triage: E2, E3, E5 and E7. Source is the raw email evidence batch only (collected 2026-04-17 09:15 CDT). No live Wazuh, Sysmon, Suricata or endpoint data was used, no link was visited and no attachment was opened. Domains, addresses and IPs are shown in code formatting so they stay exactly as they appear in the headers.

## How the Received chain was read

- `Received:` lines are added on top by each server, so the chain is read bottom-up to follow the message in time order. Each summary below is listed oldest first.
- Only the hop written by our own `mx01.meddefense.com` is trusted evidence, because our server recorded the connecting IP itself. The line below it, written by the sender's own host, is what the sender claims and can be forged.
- All four messages arrived directly from the sender's own mail host to `mx01.meddefense.com`. There is no third-party relay or email service provider in any chain.

## Baseline: what genuine mail looks like in this batch

| Item | E4 (internal) | E1 (external, legitimate) | E8 (external, legitimate) |
|---|---|---|---|
| Sending host | `exchange-hub.meddefense.local` (`10.10.1.15`) | `mail-out.healthcare-education-weekly.com` (`198.51.100.42`) | `mail.hhs.gov` (`134.174.47.82`) |
| MTA / X-Mailer | Microsoft Exchange Server 2019 | Postfix / MailChimp Mailer v12.4 | HHS Secure Mail Gateway |
| Message-ID | `<20260415100010.2D7A3F9B@meddefense.com>` | `<20260414072210.8F3D4E1A@healthcare-education-weekly.com>` | `<HC3-20260416-0847@hhs.gov>` |
| DKIM | pass, `d=meddefense.com` | pass, own domain | pass, `d=hhs.gov` |
| TLS on the hop | internal relay | TLS 1.3 | TLS 1.3 |

The four suspicious emails share none of these traits. Real MedDefense mail is relayed from Exchange on the internal network, so anything claiming to be MedDefense IT or HR that arrives from an external IP is already out of pattern.

---

## Email 2 — meddefense-portal.com

### Header Evidence

- From: `"MedDefense IT Security" <noreply@meddefense-portal.com>`
- Return-Path: `<noreply@meddefense-portal.com>` (same domain as From)
- Sending IP: `91.234.99.107` (`mail.meddefense-portal.com`, plain ESMTP, no TLS, recorded by `mx01` at 2026-04-14 14:47:51 -0500)
- X-Mailer: `PHPMailer 6.6.0 (https://github.com/PHPMailer/PHPMailer)`
- Message-ID: `<PHP-5D7E2F4A@meddefense-portal.com>`
- Reply-To: `<no-reply@meddefense-portal.com>`
- Authentication-Results: SPF `fail`, DKIM `none`, DMARC `fail` (`action=none`), all against `meddefense-portal.com`
- Priority headers: `X-Priority: 1 (Highest)`, `X-MSMail-Priority: High`, `Importance: High`

### Received Chain Summary

1. Origin (claimed by sender): `from localhost (localhost [127.0.0.1]) by mail.meddefense-portal.com (PHPMailer 6.6.0) id PHP-5D7E2F4A`, 2026-04-14 19:47:48 +0000. A PHP script on the sender's host handed the message to its own mail service.
2. External hop (recorded by MedDefense): `from mail.meddefense-portal.com ([91.234.99.107]) by mx01.meddefense.com with ESMTP id 6E4A1B23`, 14:47:51 -0500 (19:47:51 UTC). This is the trusted origin indicator.
3. Internal hand-off: `mx01.meddefense.com ([10.10.1.20])` to `inbound-relay.meddefense.com`, id `7F8D3C9B`, for `dmarsh@meddefense.com`, 14:47:52 -0500. Three to four seconds end to end, sender connected straight to our MX.

### Claimed Sender vs Sending Infrastructure

The message presents itself as MedDefense internal IT Security (display name, logo, ticket number in the body). The infrastructure is an external host `91.234.99.107` operating under `meddefense-portal.com`, which is not `meddefense.com`. Nothing in the chain touches `meddefense.com` or `*.meddefense.local` except our own MX. The genuine internal sender in this batch (E4) uses Exchange 2019 on `10.10.1.15` and signs as `d=meddefense.com`.

### Anomalies

- [HIGH] Lookalike sender domain: `meddefense-portal.com` imitates `meddefense.com` by adding a plausible word. From, Return-Path and Reply-To all use it.
- [HIGH] Claims to be internal IT but originates from an external IP with no internal relay in the chain, unlike the E4 baseline.
- [HIGH] No authenticated identity at all: SPF `fail` (IP not authorized for the sender's own domain), DKIM `none`, DMARC `fail`. Delivered because DMARC returned `action=none`.
- [MEDIUM] `PHPMailer 6.6.0` appears both in the `by ... (PHPMailer 6.6.0)` clause of `Received:` and in `X-Mailer:`. PHPMailer is a PHP library used by web applications, not a mail server, and it is not what MedDefense IT uses. The same string appears in E3, E5 and E7.
- [MEDIUM] Message-ID format `PHP-<8 hex>@domain` has no timestamp and repeats the `id` from the sender's `Received:` line. Postfix (E1) and Exchange (E4) use `<YYYYMMDDHHMMSS.QUEUEID@domain>`.
- [MEDIUM] Three stacked high-priority flags (`X-Priority`, `X-MSMail-Priority`, `Importance`), consistent with the 24-hour urgency in the body. Only E2 carries all three.
- [LOW] Reply-To (`no-reply@`) differs from From (`noreply@`) by one hyphen, two different addresses for one "automated" sender.
- [LOW] No TLS on the external hop, while the legitimate external senders E1 and E8 negotiated TLS 1.3.

### Conclusion

E2 was not sent by MedDefense. The true origin is `91.234.99.107` running `mail.meddefense-portal.com` with PHPMailer 6.6.0, delivered directly to our MX with no authentication. Header evidence alone is enough to classify it as phishing, which supports the P1 rating given the click recorded at 2026-04-14 15:02:33 CDT (14 min 41 s after delivery). Who registered the domain and which provider hosts the IP cannot be determined from headers and is left to the lookups in `4-url_attachment_autopsy.md`.

---

## Email 3 — outlook-protection.com

### Header Evidence

- From: `"Microsoft Account Protection" <security@outlook-protection.com>`
- Return-Path: `<security@outlook-protection.com>` (same domain as From)
- Sending IP: `51.38.42.17` (`mail.outlook-protection.com`, ESMTPS TLS 1.2 `ECDHE-RSA-AES128-GCM-SHA256`, recorded by `mx01` at 2026-04-15 09:13:43 -0500)
- X-Mailer: `PHPMailer 6.6.0 (https://github.com/PHPMailer/PHPMailer)`
- Message-ID: `<PHP-9F2D7E1B@outlook-protection.com>`
- Reply-To: `<no-reply@outlook-protection.com>`
- Authentication-Results: SPF `pass`, DKIM `pass` (`d=outlook-protection.com`, `s=default`), DMARC `pass` (`action=none`), all for `outlook-protection.com`
- Priority headers: `X-Priority: 1 (Highest)`

### Received Chain Summary

1. Origin (claimed by sender): `from wp-admin.outlook-protection.com (localhost [127.0.0.1]) by mail.outlook-protection.com (PHPMailer 6.6.0) id PHP-9F2D7E1B`, 2026-04-15 14:13:40 +0000.
2. External hop (recorded by MedDefense): `from mail.outlook-protection.com ([51.38.42.17]) by mx01.meddefense.com with ESMTPS (TLS1.2) id 5D7A2B1C`, 09:13:43 -0500 (14:13:43 UTC).
3. Internal hand-off: `mx01` to `inbound-relay.meddefense.com`, id `8A2B4E7C`, for `rmendez@meddefense.com`, 09:13:44 -0500.

### Claimed Sender vs Sending Infrastructure

The display name, body text, logo and footer (`© 2026 Microsoft Corporation ... One Microsoft Way, Redmond`) all claim to be Microsoft. The infrastructure belongs to `outlook-protection.com`, which is not `microsoft.com` and not `outlook.com`. Every identity field lines up on that one domain: From, Return-Path, SPF `smtp.mailfrom` and DKIM `d=`. The message is internally consistent, and it is consistent about being from `outlook-protection.com`, not from Microsoft. The logo is loaded from `outlook-protection.com/img/ms_logo.png`, not from a Microsoft host.

### Anomalies

- [HIGH] Brand impersonation: a "Microsoft Account Protection" display name on a domain Microsoft does not own. Authentication passes only for the attacker's own domain, so this mismatch is visible in the headers and content, not in the authentication result.
- [HIGH] Microsoft security alerts are not sent through PHPMailer from a third-party domain. `PHPMailer 6.6.0` in `X-Mailer` and in the `by` clause of `Received:` is the same fingerprint as E2, E5 and E7.
- [MEDIUM] The originating host is named `wp-admin.outlook-protection.com`, a WordPress admin-style hostname. It suggests a WordPress/PHP site used to inject mail, not a mail platform. Also seen in E7 as `wp-portal.meddefense-benefits.org`.
- [MEDIUM] Message-ID `PHP-9F2D7E1B@...` follows the same `PHP-<8 hex>` pattern with no timestamp.
- [LOW] Reply-To (`no-reply@`) differs from From (`security@`), both on the sender's domain.
- [LOW] TLS 1.2 and a valid DKIM signature show a more carefully configured sender than E2, E5 and E7. TLS and DKIM say nothing about who owns the domain.
- [INFO] The body lists a "sign-in" IP `41.203.72.188` (Lagos, Nigeria). It is lure content, not sending infrastructure, and it has no place in the Received chain.

### Conclusion

E3 was sent from `51.38.42.17` on infrastructure for `outlook-protection.com`, not by Microsoft. It is the only one of the four that authenticates cleanly, so its header value is in showing the sender-versus-claim mismatch, not in an authentication failure. Combined with the PHPMailer and `wp-admin` fingerprint, this is brand-impersonation phishing.

---

## Email 5 — medequip-supplies.net

### Header Evidence

- From: `"MedEquip Supplies Billing" <invoices@medequip-supplies.net>`
- Return-Path: `<invoices@medequip-supplies.net>` (same domain as From)
- Sending IP: `185.176.43.22` (`mail.medequip-supplies.net`, plain ESMTP, no TLS, recorded by `mx01` at 2026-04-16 11:28:37 -0500)
- X-Mailer: `PHPMailer 6.6.0 (https://github.com/PHPMailer/PHPMailer)`
- Message-ID: `<PHP-7C2D4E1A@medequip-supplies.net>`
- Reply-To: `<billing@medequip-supplies.net>`
- Authentication-Results: SPF `softfail`, DKIM `none`, DMARC `fail` (`action=none`), all against `medequip-supplies.net`
- Priority headers: `X-Priority: 1 (Highest)`
- MIME: `multipart/mixed` with an HTML body and a base64 PDF attachment named `INV-2026-04891.pdf`

### Received Chain Summary

1. Origin (claimed by sender): `from billing-svc.medequip-supplies.net (localhost [127.0.0.1]) by mail.medequip-supplies.net (PHPMailer 6.6.0) id PHP-7C2D4E1A`, 2026-04-16 16:28:35 +0000.
2. External hop (recorded by MedDefense): `from mail.medequip-supplies.net ([185.176.43.22]) by mx01.meddefense.com with ESMTP id 1E4F2B8D`, 11:28:37 -0500 (16:28:37 UTC).
3. Internal hand-off: `mx01` to `inbound-relay.meddefense.com`, id `6B3E7A2C`, for `arivera@meddefense.com`, 11:28:39 -0500.

### Claimed Sender vs Sending Infrastructure

The message claims to be the billing department of a medical-supplies vendor. Angela Rivera (Accounts Payable) reports the invoice looks wrong, and nothing in the evidence establishes MedEquip Supplies as an existing vendor. A vendor's billing system would normally send from a signed, SPF-listed platform. Here the billing "service" (`billing-svc`) is a PHPMailer script on a host whose own SPF record does not list it, and the message is unsigned.

### Anomalies

- [HIGH] SPF `softfail`, DKIM `none`, DMARC `fail`: nothing authenticates the message to `medequip-supplies.net`, and an invoice system for a real vendor would normally do both.
- [HIGH] Unverified sender relationship: the AP recipient does not recognize the invoice, and the domain is a `.net` lookalike style name with no established vendor history in the evidence.
- [MEDIUM] `PHPMailer 6.6.0` as X-Mailer and in `Received:`, the same toolchain as E2, E3 and E7.
- [MEDIUM] Message-ID `PHP-7C2D4E1A@...` uses the same `PHP-<8 hex>` pattern.
- [MEDIUM] Attachment timing: the PDF metadata records creation at 2026-04-16 16:28:34 UTC, one second before this message's `Date` (16:28:35 +0000), while the body says the goods were delivered on April 9. The attachment was generated at send time (details in `4-url_attachment_autopsy.md`).
- [MEDIUM] `X-Priority: 1 (Highest)` on a vendor invoice, matching the 7-day payment pressure in the body.
- [LOW] Reply-To (`billing@`) differs from From (`invoices@`), both on the sender's domain.
- [LOW] No TLS on the external hop.

### Conclusion

E5 originates from `185.176.43.22` under `medequip-supplies.net`, using the same PHPMailer fingerprint as the other lures. It fails or only softfails every authentication check and comes from a sender the recipient cannot place. The headers support the triage call of a payment-fraud and credential-harvesting lure.

---

## Email 7 — meddefense-benefits.org

### Header Evidence

- From: `"MedDefense HR Benefits" <hr-notifications@meddefense-benefits.org>`
- Return-Path: `<hr-notifications@meddefense-benefits.org>` (same domain as From)
- Sending IP: `164.90.218.73` (`mail.meddefense-benefits.org`, plain ESMTP, no TLS, recorded by `mx01` at 2026-04-16 15:22:05 -0500)
- X-Mailer: `PHPMailer 6.6.0 (https://github.com/PHPMailer/PHPMailer)`
- Message-ID: `<PHP-2E4A7B1C@meddefense-benefits.org>`
- Reply-To: `<no-reply@meddefense-benefits.org>`
- Authentication-Results: SPF `fail`, DKIM `none`, DMARC `fail` (`action=none`), all against `meddefense-benefits.org`
- Priority headers: `X-Priority: 1 (Highest)`

### Received Chain Summary

1. Origin (claimed by sender): `from wp-portal.meddefense-benefits.org (localhost [127.0.0.1]) by mail.meddefense-benefits.org (PHPMailer 6.6.0) id PHP-2E4A7B1C`, 2026-04-16 20:22:02 +0000.
2. External hop (recorded by MedDefense): `from mail.meddefense-benefits.org ([164.90.218.73]) by mx01.meddefense.com with ESMTP id 7D2F4B9A`, 15:22:05 -0500 (20:22:05 UTC).
3. Internal hand-off: `mx01` to `inbound-relay.meddefense.com`, id `3C8E4A7B`, for `lpatterson@meddefense.com`, 15:22:07 -0500.

### Claimed Sender vs Sending Infrastructure

The message claims to be MedDefense Human Resources. It comes from an external host under `meddefense-benefits.org`, a different top-level domain from the real `meddefense.com`. Internal HR mail would follow the E4 pattern (Exchange on `10.10.1.15`, signed for `meddefense.com`). Linda Patterson (Billing) reports she never signed up for anything, which does not fit the "you have not yet completed your re-enrollment" claim.

### Anomalies

- [HIGH] Lookalike of the company's own brand: `meddefense-benefits.org` adds a benefits keyword and swaps `.com` for `.org`.
- [HIGH] SPF `fail` (IP not authorized for the sender's own domain), DKIM `none`, DMARC `fail`; delivered under `action=none`.
- [MEDIUM] The originating host is `wp-portal.meddefense-benefits.org`, a WordPress-style hostname, comparable to `wp-admin` in E3.
- [MEDIUM] `PHPMailer 6.6.0` and `PHP-<8 hex>` Message-ID, the same fingerprint as E2, E3 and E5.
- [MEDIUM] `X-Priority: 1 (Highest)` on an HR notice, consistent with the "closes tomorrow" deadline.
- [LOW] Reply-To (`no-reply@`) differs from From (`hr-notifications@`).
- [LOW] No TLS on the external hop.

### Conclusion

E7 was sent from `164.90.218.73` under `meddefense-benefits.org`, not by MedDefense HR. It fails every authentication check and shares the PHPMailer, message-ID and priority fingerprint of E2, E3 and E5. The headers support classifying it as a lookalike-domain credential lure.

---

## Cross-Email Comparison

| Field | E2 | E3 | E5 | E7 |
|---|---|---|---|---|
| Sender domain | `meddefense-portal.com` | `outlook-protection.com` | `medequip-supplies.net` | `meddefense-benefits.org` |
| Sending IP | `91.234.99.107` | `51.38.42.17` | `185.176.43.22` | `164.90.218.73` |
| Sender MTA name in `Received:` | `mail.meddefense-portal.com` | `mail.outlook-protection.com` | `mail.medequip-supplies.net` | `mail.meddefense-benefits.org` |
| Inner (origin) host | `localhost` | `wp-admin.` host | `billing-svc.` host | `wp-portal.` host |
| TLS on external hop | none | TLS 1.2 | none | none |
| SPF / DKIM / DMARC | fail / none / fail | pass / pass / pass | softfail / none / fail | fail / none / fail |
| X-Mailer | PHPMailer 6.6.0 | PHPMailer 6.6.0 | PHPMailer 6.6.0 | PHPMailer 6.6.0 |
| Message-ID | `PHP-5D7E2F4A@` | `PHP-9F2D7E1B@` | `PHP-7C2D4E1A@` | `PHP-2E4A7B1C@` |
| Date header zone | +0000 | +0000 | +0000 | +0000 |
| Priority | 1 + High + High | 1 | 1 | 1 |

Observations:

- No sending IP or domain is shared across the four emails. The headers do not show infrastructure reuse.
- The link between them is the toolchain fingerprint: PHPMailer 6.6.0, the `PHP-<8 hex>` Message-ID that repeats the `Received` id, `mail.<domain>` naming, `X-Priority: 1`, and a `+0000` clock. The legitimate senders in the batch show none of these together.
- E3 is configured more carefully than the others (valid DKIM, SPF and TLS), while E2, E5 and E7 are unsigned and fail SPF against their own domains. This may indicate different setup effort or operators. Headers alone do not settle that.

## Notes and Limits

- The Date and Received timestamps are internally consistent for all four messages: the sender's `Date` matches the `mx01` hop within one to three seconds once the +0000 and -0500 offsets are applied, so the timeline is usable.
- Some weekday names in the batch do not match the 2026 calendar (for example E5 says Wednesday for 16 April 2026, which is a Thursday) and the DKIM `t=` values fall in 2025. As in the triage notes, this is treated as a batch artifact affecting legitimate and malicious messages alike, and not as a signal.
- Reverse DNS, WHOIS, registration age, hosting provider and geolocation are not in the evidence and were not looked up. They are listed as follow-up methods in `4-url_attachment_autopsy.md`.
