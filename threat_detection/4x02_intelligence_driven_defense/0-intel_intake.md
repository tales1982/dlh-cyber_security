# Intelligence Intake — HEALTHBANE Campaign

This document parses the four intelligence sources provided for the HEALTHBANE
campaign into a normalized, comparable format. All indicator counts below were
extracted programmatically from the actual source files (regex extraction from
the two `.txt` sources, `json.load()` on the commercial feed), not transcribed
by hand, and cross-checked byte-for-byte against the raw files. Every count
matches the lab's per-source reference exactly (23 / 41 / 14 / 11 / 89 total
raw) — see the methodology note at the end of Section 2 for the one figure
that does not match the reference (unique count after deduplication).

## 1. Per-Source Summary

### Source 1: HC3 Sector Advisory

1. **Source name:** HC3-2026-HEALTHBANE-001, "HEALTHBANE Campaign - Multi-Stage Attacks Against US Healthcare Providers"
2. **Source type:** Government advisory (HHS Health Sector Cybersecurity Coordination Center)
3. **Date published:** 2026-04-25
4. **TLP classification:** TLP:CLEAR (unrestricted distribution)
5. **Number of indicators provided:** 23
6. **Types of indicators:** domains (8), IPs (6), file hashes/SHA-256 (5), URLs (4)
7. **One-line summary of the intelligence claim:** A three-stage campaign (credential harvesting → macro-document malware delivery → DNS-tunneled exfiltration) has hit at least 14 US healthcare organizations since 2026-04-14, confirmed via direct telemetry from 6 partner organizations, with attribution to a named threat actor explicitly UNCONFIRMED.
8. **Key limitations/caveats stated by the source:** Attribution confidence is explicitly rated LOW; visibility is limited to 6 of the ≥14 known-targeted organizations; the "VITALSCORE" label used by a commercial provider is noted but not endorsed; two additional ATT&CK techniques (T1078, T1021) are assessed as likely but deliberately excluded from the formal TTP table pending confirmation.

### Source 2: Commercial CTI Feed (Acme)

1. **Source name:** Acme CTI Commercial Feed (lab simulation), extract ACME-HEALTH-2026-0426-117
2. **Source type:** Commercial feed
3. **Date published:** 2026-04-26 (extract timestamp 08:14 UTC)
4. **TLP classification:** TLP:AMBER, "authorized use: internal defense at MedDefense Health Systems only"
5. **Number of indicators provided:** 41
6. **Types of indicators:** domains (12), IPs (15), file hashes/SHA-256 (9), URLs (5)
7. **One-line summary of the intelligence claim:** The same operational activity HC3 calls HEALTHBANE is tracked under Acme's proprietary label VITALSCORE, with a substantially larger indicator set than HC3's, including several additional domains/IPs/hashes not present in any other source.
8. **Key limitations/caveats stated by the source:** The feed's own metadata discloses that indicators are "auto-tagged by Acme's clustering engine" with only a SAMPLED (not full) human analyst review, and that the VITALSCORE attribution label "does not necessarily correspond to externally-tracked threat actor names." Multiple individual indicators carry explicit `acme_note` fields warning of shared/CDN hosting, ML-clustering-only association, or "LIKELY NOISE" / "DO NOT BLOCK" guidance for specific IPs (Cloudflare, Azure CDN, Microsoft Outlook.com infrastructure).

### Source 3: Researcher Blog Analysis

1. **Source name:** "The Phishing Kit Behind The HEALTHBANE Campaign: A Technical Walkthrough" by Marcus Weller (@mwresearch)
2. **Source type:** Open-source research (personal, self-hosted blog)
3. **Date published:** 2026-04-24, 14:22 UTC (one day before the HC3 advisory)
4. **TLP classification:** N/A — public blog post, no TLP marking
5. **Number of indicators provided:** 14
6. **Types of indicators:** domains (5), IPs (3), file hashes/SHA-256 (4), URLs (2)
7. **One-line summary of the intelligence claim:** The author obtained the actual phishing kit source (via a misconfigured directory listing) and, based on kit/tooling fingerprint overlap with three campaigns tracked privately since 2024, assesses with MEDIUM confidence that the operator is the same actor behind those campaigns, privately labeled APT-MEDAGENT by the author.
8. **Key limitations/caveats stated by the source:** The author states explicitly: "I am a solo researcher. I do not have visibility into victim telemetry. Everything in the attribution section is open-source-derived." Attribution confidence is self-rated MEDIUM and is "based entirely on tooling + infrastructure overlap... NOT based on telemetry, signals intelligence, or insider reporting." The author also states uncertainty about whether their APT-MEDAGENT label corresponds 1:1 with Acme's VITALSCORE label.

### Source 4: MedDefense Internal 4x00 Findings

1. **Source name:** MD-2026-IR-0414-001, MedDefense Health Systems Internal Investigation Summary (4x00 Phishing Dissection extract)
2. **Source type:** Internal investigation
3. **Date published:** 2026-04-16
4. **TLP classification:** INTERNAL ("TLP not applicable — not for external share"); an indicator-only extract was authorized for HC3 submission
5. **Number of indicators provided:** 11
6. **Types of indicators:** domains (3), IPs (3), file hashes/SHA-256 (1), URLs (1), email addresses (3)
7. **One-line summary of the intelligence claim:** One MedDefense nurse (dmarsh) clicked a Stage-1 phishing link and is assessed LIKELY (not confirmed at time of report) to have submitted credentials; no Stage 2/3 activity was observed at MedDefense as of report close.
8. **Key limitations/caveats stated by the source:** The report explicitly avoids attribution entirely. It states credential submission is "LIKELY" based on circumstantial evidence (a 47-second HTTPS session, absence of a Sysmon file-download event, and a post-incident user statement) but "NOT CONFIRMED via packet evidence as of 4x00 close." It also lists open questions it could not answer, including whether the attacker attempted a follow-on login and whether the campaign is broader than the three emails MedDefense caught — both explicitly deferred to later investigation (4x01/4x02).

## 2. Consolidated View

### 2.1 Total raw indicators across all sources

| Source | Domains | IPs | Hashes | URLs | Emails | Raw Total |
|---|---|---|---|---|---|---|
| HC3 Advisory | 8 | 6 | 5 | 4 | 0 | **23** |
| Commercial Feed | 12 | 15 | 9 | 5 | 0 | **41** |
| Researcher Blog | 5 | 3 | 4 | 2 | 0 | **14** |
| MedDefense 4x00 | 3 | 3 | 1 | 1 | 3 | **11** |
| **Total raw (all sources)** | | | | | | **89** |

This matches the lab's stated reference exactly (23 + 41 + 14 + 11 = 89).

### 2.2 Total unique indicators after deduplication

**Unique count (exact-literal-value deduplication): 50**

Methodology: an indicator is deduplicated when its **(type, exact literal value)** pair is byte-identical across sources — e.g., the domain `meddefense-portal.com` reported by all four sources collapses to one unique entry. This was computed programmatically (not by hand) directly against the source files, so it is exactly reproducible.

Per-type breakdown:

| Type | Raw (sum) | Unique |
|---|---|---|
| Domains | 28 | 13 |
| IPs | 27 | 15 |
| Hashes | 19 | 11 |
| URLs | 12 | 8 |
| Emails | 3 | 3 |
| **Total** | **89** | **50** |

**Methodology note on the reference count:** the lab materials' stated reference figure for this step is 64 unique indicators. This intake's programmatic, exact-literal-value deduplication produces **50**, not 64 — the raw per-source and total-raw counts (23 / 41 / 14 / 11 / 89) all match the lab reference exactly, confirming the source data was parsed correctly; the discrepancy is specifically in how aggressively values are merged across sources. 64 unique from 89 raw implies only 25 duplicate mentions were removed, while exact-literal matching finds 39 legitimate duplicate mentions (24 distinct indicator values independently corroborated by 2-4 sources each — see Section 2.3). Several alternative, less-aggressive merge policies were tested (e.g., deduplicating domains/IPs/emails but never merging hashes or URLs across sources, to preserve per-source provenance for indicator types most vulnerable to false corroboration) and land in the 54-62 range depending on which types are exempted from merging — none reproduces exactly 64 either. Rather than force-fit the reference number, this intake reports the fully reproducible **50** as the primary figure and documents the exact multi-source overlaps in Section 2.3 below, so a reader can re-derive any alternative merge policy's total directly from that table. **Task 1's triage operates on this same set of 50 unique indicators.**

### 2.3 Indicators that appear in multiple sources (24)

| Type | Value | Sources |
|---|---|---|
| domain | meddefense-portal.com | HC3, Commercial, Researcher, MedDefense |
| domain | medequip-supplies.net | HC3, Commercial, Researcher, MedDefense |
| domain | meddefense-benefits.org | HC3, Commercial, MedDefense |
| domain | outlook-protection.com | HC3, Commercial, Researcher |
| domain | healthbane-c2.net | HC3, Commercial, Researcher |
| domain | portal-secure-meddefense.com | HC3, Researcher |
| domain | data-sync.healthbane-c2.net | HC3, Commercial |
| domain | update-healthbane.net | HC3, Commercial |
| ip | 91.234.99.107 | HC3, Commercial, Researcher, MedDefense |
| ip | 185.176.43.22 | HC3, Commercial, MedDefense |
| ip | 164.90.218.73 | HC3, Commercial, MedDefense |
| ip | 51.38.42.191 | HC3, Commercial, Researcher |
| ip | 51.38.42.17 | HC3, Commercial |
| ip | 45.77.218.9 | HC3, Commercial |
| ip | 167.71.222.30 | Commercial, Researcher |
| hash | 2f4a6c8e...b9d1f (62-char, see §2.5) | HC3, Researcher, MedDefense |
| hash | a1b2c3d4...ef123456 (HEALTHBANE_S2_invoice.docm) | HC3, Commercial, Researcher |
| hash | c7d6e5f4...b4c5d6 (sync_healthdata.ps1) | HC3, Commercial, Researcher |
| hash | b9c8a7d6...ba987654 (svchost_update.exe) | HC3, Commercial |
| hash | dd5efb6d...ef12345678 (dropper variant) | HC3, Commercial |
| url | https://meddefense-portal.com/verify/staff?id=\<user\>&token=\<8hex\> | HC3, Researcher |
| url | https://medequip-supplies.net/invoices/pay?id=INV-\<YYYY-NNNNN\> | HC3, Commercial |
| url | https://meddefense-benefits.org/enroll | HC3, Commercial |
| url | https://healthbane-c2.net/update/svchost_update.exe | HC3, Commercial |

### 2.4 Indicators that appear in only one source (26)

Breakdown by source (verified programmatically):
- **Commercial-only (20 indicators):** 5 domains (`rx-benefits-portal.com`, `healthcare-login.com`, `verify-health-portal.net`, `secure-insurance-login.com`, `claims-verify-portal.net`), 8 IPs — all shared-hosting/CDN/cloud (`159.89.112.45`, `23.94.138.222`, `104.168.34.58`, `192.99.207.114`, `20.83.144.56`, `13.107.42.14`, `172.67.192.40`, `104.21.35.7`), 5 hashes (2 explicitly tagged `unrelated-cluster` by Acme itself, 3 tagged `clustered_by_similarity`/`healthcare-kw` with LOW `acme_confidence`), 2 URLs (`.../verify/staff?id=<user>&token=<hex>` and `https://outlook-protection.com/verify`).
- **Researcher-only (2 indicators):** the kit ZIP hash (`ffaabbccdd...778899`) and the exfil API endpoint URL (`https://healthbane-c2.net/api/ingest`), both only visible because the researcher had direct kit access no other source had.
- **MedDefense-only (4 indicators):** the 3 sender email addresses (a type no other source reports at all) and the real-token phishing URL instance specific to the dmarsh click event.

### 2.5 Source conflicts that must be resolved later

1. **Attribution labels conflict directly.** HC3 states attribution is UNCONFIRMED (LOW confidence) and explicitly does not endorse any commercial label. The commercial feed applies its own proprietary label VITALSCORE via an automated clustering engine with only sampled human review. The researcher privately tracks the same infrastructure as APT-MEDAGENT at MEDIUM confidence, based purely on open-source tooling/infrastructure overlap with three prior campaigns, and explicitly states uncertainty about whether APT-MEDAGENT and VITALSCORE refer to the same actor. MedDefense's own report avoids attribution entirely. **This needs formal reconciliation in Task 2 (source credibility) and Task 6 (kill chain) — the safest posture is to treat "HEALTHBANE" as the neutral, evidence-grounded campaign designation and treat all three attribution labels as unconfirmed aliases, not facts.**
2. **Confidence differences on the same indicators.** The same domains/IPs carry HIGH confidence from HC3 and MedDefense (direct victim telemetry) but a numeric `acme_confidence` score from the commercial feed that ranges from 15 to 96 depending on the indicator — meaning the commercial feed's own internal confidence signal must be used to triage its indicators (Task 1), not just its inclusion in the feed.
3. **Commercial-feed noise.** At least 8 of the commercial feed's 15 IPs carry explicit internal warnings (`"LIKELY NOISE"`, `"DO NOT BLOCK"`, `"Cloudflare front IP. Not actionable."`, `"This is a Microsoft Outlook.com cloud IP. Clustering model noise."`) — these cannot be treated as equivalent to HC3's 6 HIGH-confidence IPs despite appearing in the same feed.
4. **Indicators present in one source but missing from stronger sources.** `portal-secure-meddefense.com` and `167.71.222.30` appear in HC3/Researcher but are corroborated by the researcher's direct kit access, not by victim telemetry, and are flagged LOW/MEDIUM confidence in the researcher's own report — these need a distinct handling from indicators with direct victim-telemetry backing. Conversely, several commercial-feed-only indicators (`rx-benefits-portal.com`, `healthcare-login.com`) predate the confirmed HEALTHBANE window and are self-flagged by Acme as only "possibly" related to a prior campaign by the same operator — these should not be treated with the same confidence as the 24 multi-source, cross-corroborated indicators above.
5. **Data-quality issue found during parsing (not a source disagreement, but must be tracked):** the SHA-256 hash reported identically by HC3, the researcher, and MedDefense for the Stage 1 lure PDF (`2f4a6c8e0b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f`) is only **62 hexadecimal characters long**, two short of a valid SHA-256 (64 hex chars). All three sources reproduce the same truncated value, meaning this is a genuine upstream data-entry artifact, not a copy error introduced during this intake. This hash **cannot be deployed as-is to an EDR/AV hash blocklist** and should be flagged for correction/re-acquisition from the original sample before operational use.
