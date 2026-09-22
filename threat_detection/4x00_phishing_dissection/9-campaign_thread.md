## Campaign Thread Analysis

Assessment of whether E2, E5 and E7 form one coordinated phishing campaign against MedDefense, using shared infrastructure, timing and targeting patterns drawn from `1-header_analysis.md`, `3-social_engineering.md` and `4-url_attachment_autopsy.md`, compared against the healthcare-sector alert in E8. E3 and E6 are referenced for contrast but are not treated as part of the E2/E5/E7 trio (see Attribution Assessment).

### Shared Indicators

| Indicator | E2 | E5 | E7 |
|---|---|---|---|
| Domain relates to MedDefense's brand or supply chain | `meddefense-portal.com` (brand lookalike) | `medequip-supplies.net` (vendor-style lookalike) | `meddefense-benefits.org` (brand lookalike) |
| X-Mailer / sending software | PHPMailer 6.6.0 | PHPMailer 6.6.0 | PHPMailer 6.6.0 |
| Message-ID format | `PHP-<8 hex>@meddefense-portal.com` | `PHP-<8 hex>@medequip-supplies.net` | `PHP-<8 hex>@meddefense-benefits.org` |
| Sender hostname pattern | `mail.meddefense-portal.com` | `mail.medequip-supplies.net` | `mail.meddefense-benefits.org` |
| Priority headers | `X-Priority: 1` + `X-MSMail-Priority: High` + `Importance: High` | `X-Priority: 1` | `X-Priority: 1` |
| Authentication | SPF fail, DKIM none, DMARC fail (`action=none`) | SPF softfail, DKIM none, DMARC fail (`action=none`) | SPF fail, DKIM none, DMARC fail (`action=none`) |
| TLS on delivery | No | No | No |
| Reply-To differs from From by a small variant | `no-reply@` vs `noreply@` | `billing@` vs `invoices@` | `no-reply@` vs `hr-notifications@` |
| Urgency paired with a concrete consequence | 24-hour lockout → loses scheduling/EHR/shift-swap access | 7-day deadline → 2% late fee, delivery suspension | "Closes tomorrow" → coverage lapse to a basic plan |
| Lure matches a real MedDefense business process | IT portal / staff access | Vendor invoice payment | Benefits open enrollment |

No sending IP is shared between the three (`91.234.99.107`, `185.176.43.22`, `164.90.218.73` are all different), so this is not infrastructure reuse in the narrow sense. The link is a consistent toolchain and template fingerprint — same mailer version, same Message-ID and hostname conventions, same priority-header habit, same "urgency plus a named consequence" structure, each retargeted at a different real MedDefense process — which reads as one playbook applied three times rather than three unrelated senders coincidentally resembling each other.

### Targeting Map

| Email | Recipient | Department / Role | Pretext Theme | Business Process Referenced |
|---|---|---|---|---|
| E2 | Diane Marsh (`dmarsh@meddefense.com`) | Clinical / nursing staff (workstation `WS-NURSE-04`) | IT portal re-verification | Scheduling system, EHR gateway, shift-swap requests |
| E5 | Angela Rivera (`arivera@meddefense.com`) | Accounts Payable / Finance | Vendor invoice payment | Medical-supply purchasing and payment |
| E7 | Linda Patterson (`lpatterson@meddefense.com`) | Billing | HR benefits open enrollment | Annual benefits re-enrollment |

Each lure's *content* is role-appropriate for the department it names (clinical workflows for E2, an invoice for AP), which matches HC3's description of role-targeted lures. E7 is the one mismatch worth flagging: its content addresses a company-wide HR process (benefits enrollment), not a Billing-specific one, yet it landed in a Billing inbox. That is consistent with a lure meant for anyone on the payroll rather than one written specifically for Linda Patterson's job function — the targeting is by *recipient list*, not necessarily by *department-matched content*, for this one message. It does not weaken the campaign link; it just shows E7's pretext is organization-wide rather than role-specific the way E2 and E5 are.

### Timing Map

| Email | Date (evidence batch) | Delivery time (CDT) | Gap from previous |
|---|---|---|---|
| E2 | 2026-04-14 | 14:47:51 | — (first of the three) |
| E5 | 2026-04-16 | 11:28:37 | +44 h 41 min after E2 |
| E7 | 2026-04-16 | 15:22:05 | +3 h 54 min after E5 (same day) |

E2 was delivered on April 14; E5 and E7 were both delivered on April 16, about four hours apart, per the `Received:` timestamps recorded by `mx01.meddefense.com`. There is no April 15 delivery among these three in the evidence — a one-day gap separates E2 from the E5/E7 pair, and E5 and E7 then arrive close together on the same afternoon. (E3 falls inside that gap, on April 15, but is assessed separately — see Attribution Assessment.) The two-per-day clustering on April 16 is consistent with a single sender working through a short target list in one sitting, rather than three independently timed, unrelated senders.

### Comparison With HC3 Alert

E8 (HC3, received 2026-04-16 08:47 CDT — after E2, before E5 and E7) describes a regional healthcare-sector campaign with four observed patterns. All four are present in E2, E5 and E7:

| HC3-described pattern | Match in E2 / E5 / E7 |
|---|---|
| Newly-registered `.com`/`.net`/`.org` domains using "portal", "benefits", "supplies" or "login" in the hostname | `meddefense-**portal**.com` (E2), `medequip-**supplies**.net` (E5), `meddefense-**benefits**.org` (E7) — all three keyword categories HC3 names are represented exactly |
| PHPMailer-based sending on budget VPS hosting | PHPMailer 6.6.0 confirmed in all three `X-Mailer` headers and `Received:` clauses; the sending IPs (`91.234.99.107`, `185.176.43.22`, `164.90.218.73`) are consistent with small/VPS-style external hosts, though the specific hosting provider was not queried live in this evidence-only exercise |
| 24–48 hour deadlines, account-lockout threats, open-enrollment cutoffs | E2: 24-hour lockout; E7: enrollment "closes tomorrow"; E5 uses a longer 7-day deadline but the same late-fee/suspension threat structure |
| Role-appropriate lures for clinical, billing and HR-adjacent staff | E2 → clinical/nursing; E5 → Accounts Payable/Finance (HC3's "billing staff"); E7 → HR-themed content, delivered to a Billing recipient |

The match is close enough on every one of HC3's four observed traits that E2, E5 and E7 read as local instances of the same regional pattern HC3 is tracking, not as a coincidental resemblance. E8 itself was still TLP:CLEAR and "not yet IOC-confirmed" at the time it arrived, so MedDefense's own evidence (this batch) is a concrete, organization-specific data point that would strengthen HC3's pattern if submitted (see `11-ioc_extraction.md`).

### Attribution Assessment

**What can be inferred:** E2, E5 and E7 were very likely built and sent using the same operational playbook — identical mailer version and Message-ID convention, identical hostname pattern (`mail.<lookalike-domain>`), identical priority-header habit, and a consistent "urgency plus a named consequence, tied to a real MedDefense process" template, applied to three different pretexts aimed at three different departments within a roughly 48-hour window. The domain choices (the company's own brand twice, a real-sounding supplier once) show the sender had researched MedDefense specifically — its name, at least one internal process per target, and the names, email addresses and departments of at least two real employees.

**What cannot be proven from this evidence alone:**
- **A single human or group, as opposed to a shared kit.** PHPMailer is a widely available open-source library, and "the same toolchain" is weaker evidence than "the same infrastructure." No sending IP, hosting account or registrar is shared among E2, E5 and E7 in the evidence, so infrastructure-level attribution is not possible here.
- **Ownership or hosting-provider identity.** WHOIS, registrar and hosting-provider data were not queried live for this task; without them, claims about who registered these domains or which provider hosts them are unconfirmed.
- **A named threat-actor group.** Nothing in the headers or content is a unique enough fingerprint to attach a known group name. HC3's own alert (E8) describes the broader regional pattern as "not yet IOC-confirmed" and does not name an actor either.
- **Whether E3 belongs to the same operation.** E3 shares some traits with the trio (PHPMailer 6.6.0, `PHP-<8 hex>` Message-ID, `X-Priority: 1`), but it was sent from a different IP, is better configured (valid SPF/DKIM/DMARC, TLS 1.2), targets no MedDefense-specific process, and needed no reconnaissance beyond a name and email address (see `8-verdict_matrix.md`, classified PHISHING-OPPORTUNISTIC). It may be the same operator running a second, more generic kit against a wider target list, or an entirely unrelated sender. The evidence does not settle it either way, so E3 is treated as possibly related but not counted as part of the confirmed E2/E5/E7 thread.

**Assessment:** MEDIUM confidence that E2, E5 and E7 are one coordinated, MedDefense-targeted campaign, based on tooling, template and timing consistency. No specific threat actor, group or country is named or implied — that claim would go beyond what header and content evidence can support.

### Conclusion

The evidence supports treating E2, E5 and E7 as a single coordinated phishing campaign against MedDefense: the same mailer fingerprint and messaging template, domains deliberately chosen to reference the organization's own brand or its supply chain, role-appropriate pretexts matched to three different departments, and delivery clustered inside a roughly 48-hour window (April 14–16) with no unrelated gap. The pattern also lines up point-for-point with HC3's regional healthcare-sector alert (E8), which strengthens the case that this is not an isolated, one-off incident at MedDefense but a local instance of a broader tracked campaign. E3 is plausibly connected through shared tooling but is assessed separately as opportunistic, generic phishing rather than part of the confirmed thread, and E6 is unrelated bulk spam. This conclusion should be read as "coordinated campaign, operator unidentified" — strong enough to justify IOC sharing and continued monitoring, not strong enough to name an actor.
