# Review 17 — Campaign Identification

**Question:** An analyst investigates 5 phishing emails received over 48 hours. Three of them share:

- domains registered on the same day at the same registrar
- the same email-sending software, PHPMailer 6.6.0
- targets in different departments: clinical, finance, HR
- the same social engineering pattern: urgency with a deadline

Explain why these indicators strongly suggest a coordinated phishing campaign instead of unrelated spam emails.

## Answer

No single indicator here would prove coordination on its own, but the four together rule out coincidence, because unrelated spam operators would not be expected to share any of them, let alone all four at once.

1. **Domains registered the same day at the same registrar.** This is a provisioning-pattern signal, not a content signal — it points to a single registration event (one actor or one purchase batch) rather than three independent spammers who each separately decided to register a lookalike domain. Unrelated spam campaigns draw on domains of varying ages from varying registrars, often bought in bulk over time through different resellers; a shared registration date *and* registrar means these three domains were very likely acquired together, as deliberate pre-campaign setup.

2. **Identical sending software — PHPMailer 6.6.0, the exact same version.** PHPMailer itself is a common, legitimate library, so this alone is weak. But an *exact version match* across three otherwise-unrelated senders is a toolchain fingerprint: it means the same script, template or kit built and sent all three messages. Independent spam operators running different botnets or affiliate kits would be expected to show more varied mailer signatures, not an identical version.

3. **Role-matched targeting across departments (clinical, finance, HR).** This is the strongest signal. Ordinary spam is broad and generic — the same message blasted to everyone regardless of who they are. Here, three *different* pretexts were each matched to a *different* department's real function within the *same* organization. That requires the sender to already know the organization's departmental structure and to have picked recipients accordingly — reconnaissance that random spam does not involve.

4. **The same social-engineering template — urgency with a deadline — reused across all three.** A shared psychological structure applied consistently, just re-skinned for each department's context, is a playbook, not three people independently landing on the same idea.

**Why this points to one coordinated campaign rather than unrelated spam:** each indicator is individually explainable by chance, but the joint probability of three independent, unrelated senders coincidentally sharing a registration date and registrar, an identical mailer version, role-appropriate targeting inside one organization, and the same urgency template — all within a 48-hour window — is vanishingly small. The far more parsimonious explanation is a single operator (or a single toolkit) running a reconnaissance-informed, multi-pretext campaign against this organization specifically. This is exactly the clustering logic threat intelligence analysts use to group separate incidents into one campaign for tracking and response, even before a specific actor can be named: shared infrastructure provisioning, shared tooling/TTPs, and temporal clustering, layered on top of targeting that could only work with prior knowledge of the target.

This is the same reasoning applied to E2, E5 and E7 in this investigation's `9-campaign_thread.md`.
