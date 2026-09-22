# Review 15 — Email Authentication Paradox

**Question:** An analyst investigates a suspicious email sent to the hospital CFO. The email claims to be from "Microsoft 365 Security" and warns of unusual sign-in activity. The Authentication-Results header shows SPF: pass, DKIM: pass, DMARC: pass. The sending domain is `outlook-protection.com`, not `microsoft.com` or `outlook.com`.

Explain why the email can still be malicious even though all authentication checks passed.

## Answer

SPF, DKIM and DMARC only verify domain *control*, not organizational *identity*. Each protocol checks whether the sending infrastructure is authorized to send mail on behalf of the specific domain named in the message — SPF checks the envelope-from domain's DNS record, DKIM verifies a cryptographic signature against a public key published in the signing domain's own DNS, and DMARC checks that these two results align with the visible From domain. All three protocols were designed to stop domain *spoofing* — someone sending mail while forging a domain they do not control — not to stop domain *impersonation*, where someone registers and legitimately controls a brand-new, similar-looking domain.

In this case, the attacker owns `outlook-protection.com` outright. They can configure a correct SPF record, generate their own DKIM key pair and publish it in their own DNS zone, and publish a DMARC policy that aligns cleanly with their own From address — because it's their domain and they control its DNS. Every check passes honestly, exactly as the protocols are supposed to work, for that domain. Nothing in SPF, DKIM or DMARC ever asks "is this domain owned by Microsoft?" or "is this organization who it claims to be?" — that is entirely outside their scope. `outlook-protection.com` is not `microsoft.com` and not `outlook.com`; it is a separate domain anyone could register for a few dollars, with no trademark vetting involved.

The deception is therefore social and visual, not technical: the display name ("Microsoft 365 Security"/"Microsoft Account Protection"), the copied logo and footer text, and the urgent tone are what create the false impression of legitimacy — not the authentication result. A "pass" on SPF/DKIM/DMARC only proves the message is authentically from `outlook-protection.com`; it says nothing about whether that domain has any relationship to Microsoft. That's why authentication results must always be paired with a domain-identity check (does the From/DKIM domain actually match the brand being claimed?) plus reputation, domain age, and content analysis — authentication alone cannot catch a well-configured lookalike domain.

This is the same paradox documented for Email 3 in this investigation's `2-authentication_analysis.md`.
