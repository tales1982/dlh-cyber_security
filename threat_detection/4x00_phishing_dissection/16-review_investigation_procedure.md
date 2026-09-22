# Review 16 — Investigation Procedure

**Question:** A SOC analyst receives a suspicious email containing a link to:

`hxxps://portal-update.meddefense-health.com/verify`

The analyst needs to determine if the URL is malicious.

Describe the safe investigation process the analyst should follow without directly visiting the URL.

## Answer

The analyst should never open the link in a browser, not even in a sandboxed or incognito session on a work machine — doing so still delivers a real connection to the attacker's server, which can log the analyst's IP, trigger a redirect chain, drop an exploit, or serve a credential page tuned specifically for the click. The correct process is passive-first, active-last:

1. **Defang and document the URL immediately.** Rewrite `hxxps://portal-update[.]meddefense-health[.]com/verify` so it can't be clicked by accident, and record it exactly as received (subdomain `portal-update`, domain `meddefense-health.com`, path `/verify`).

2. **Compare the domain to the real brand.** `meddefense-health.com` is a separate, standalone domain from the organization's actual domain — the extra hyphenated word ("health") and the `portal-update` subdomain are classic lookalike/typosquat construction, not proof of maliciousness by themselves, but a strong reason to keep investigating.

3. **Run passive, read-only lookups from an isolated analysis host, never the corporate network:**
   - **WHOIS** — registrar and creation date. A domain registered days or weeks ago is a major red flag for a lookalike phishing domain.
   - **DNS** (`dig`/`nslookup` against a public resolver) — A, MX, NS and TXT/SPF records, to see where it resolves and whether it has real mail infrastructure or DMARC/SPF configured.
   - **Certificate Transparency logs** (crt.sh) — when a TLS certificate was first issued for the domain/subdomain; a cert issued right around the WHOIS creation date reinforces "newly registered."
   - **VirusTotal / urlscan.io** — search for *existing* scans and detections first (read-only). If nothing exists and a live rendering is genuinely required, submit only the bare domain as a new **unlisted/private urlscan.io scan** — a sandboxed, non-attributable environment that safely captures a screenshot, page content, redirect chain and outbound connections — instead of visiting it directly with a browser or `curl`.

4. **Correlate with internal evidence without touching the external site:** search the mail gateway for the sender and any other recipients of this message, and search proxy/DNS/firewall logs to see whether anyone in the organization has already resolved or connected to this domain.

5. **Decide from the totality of passive evidence** — recently registered domain, failing or absent authentication, brand-adjacent lookalike structure, and (if a sandbox scan was run) a credential-harvesting page — and document the verdict with defanged IOCs.

6. **Act on the verdict:** block the domain (and any resolved IP) at the mail gateway, DNS, proxy and firewall, and alert/investigate any user who may have already clicked, without ever having connected to the site from an identifiable or corporate asset.

This follows the same passive-first, sandboxed-second methodology documented in this investigation's `4-url_attachment_autopsy.md`.
