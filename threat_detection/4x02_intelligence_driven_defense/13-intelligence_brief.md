# HEALTHBANE Intelligence Brief

Prepared for: Dr. Patricia Morales (CISO), James Chen (SOC Lead), MedDefense
Health Systems leadership, and healthcare-sector partners via HC3 channels.

**Scope note:** this brief synthesizes Tasks 0, 1, 2, 6, 7, 8, 9, 10, and 11
of this project. Tasks 3, 4, 5, and 12 (infrastructure clustering, pivot
analysis, formal indicator database, and a standalone adversary-profile
document) were not produced in this batch; Sections 2 and 6 below draw the
equivalent content directly from Tasks 1, 2, and 6's real findings rather
than from those missing deliverables, and that substitution is noted at each
point it occurs.

## 1. Executive Summary

HEALTHBANE is a three-stage cybercrime campaign — spear-phishing credential
theft, macro-malware delivery, and DNS-tunneled data exfiltration — that has
targeted at least 14 US healthcare organizations since 2026-04-14, confirmed
via direct government (HC3) telemetry at 6 of them. At MedDefense, one
nurse's credentials were harvested via a phishing link on 2026-04-14, but a
mass endpoint scan confirmed the follow-on malware stage never reached
MedDefense — we were not one of the two organizations that experienced
malware delivery or data exfiltration. No source has confirmed the identity
of the operator behind HEALTHBANE with high confidence, despite two
competing commercial/research labels (VITALSCORE, APT-MEDAGENT) circulating.
Our current detection posture directly covers 4 of 22 mapped attacker
techniques and partially covers 10 more, with the strongest gap concentrated
in Stage 2 (malware execution and persistence), where the government
advisory has already published ready-to-deploy detection logic we have not
yet operationalized. Two YARA detection rules were built and tested this
cycle: one is ready to deploy now with a perfect test result, the other
needs one small, already-diagnosed fix before deployment. The top three
recommended actions are: (1) deploy the three HC3-published Stage 2
detection rules (scheduled task, registry run-key, and generalized
credential-reuse alerting) that require no new tooling, only configuration
work; (2) require macro attestation and disable Office macros by default
org-wide; (3) request HC3 coordinate outreach to the ≥8 targeted
organizations with no current visibility, since MedDefense's own risk
picture is limited by that same sector-wide blind spot.

## 2. Adversary Profile

*(Substituting for Task 12, which was not produced in this batch — this
section is drawn directly from the real source material assessed in
`2-source_assessment.md` and `6-kill_chain.md`.)*

No source in this intelligence package confirms a named threat actor at
HIGH confidence. Three distinct, non-overlapping-confirmed postures exist:

- **HC3** (government, source reliability A): attribution explicitly
  UNCONFIRMED, LOW confidence. Assesses the operator as a "financially
  motivated mid-tier cybercrime actor" based on infrastructure pattern
  (Namecheap registrar, Hostinger/DigitalOcean/OVH hosting, PHPMailer 6.6.0
  sender) — a profile, not an identity.
- **Commercial feed (Acme, reliability C)**: applies the proprietary label
  **VITALSCORE** via an automated clustering engine with only sampled human
  review; explicitly states this label "does not necessarily correspond to
  externally-tracked threat actor names."
- **Independent researcher (reliability B, self-rated MEDIUM confidence)**:
  privately tracks the operator as **APT-MEDAGENT**, based entirely on
  tooling/infrastructure fingerprint overlap (PHPMailer 6.6.0, Njalla
  operator-domain registration, a consistent `config.php` structure with
  `EXFIL_ENDPOINT`/`OPS_CONTACT` keys, `<word>-c2.net` naming) with three
  campaigns the same researcher tracked independently in 2024–2025
  (RXBRIDGE, CLAIMBRIDGE, MEDNEXUS). The researcher explicitly states
  uncertainty whether APT-MEDAGENT and VITALSCORE name the same operator.

**Operating characteristics (higher confidence than the naming question):**
the operator runs a mass-production phishing kit that auto-templates
target-organization branding rather than hand-customizing lures (a quality
indicator of scale, not a bespoke operation); reuses infrastructure
patterns across campaigns; and — per the researcher's kit access — left
`portal-secure-meddefense.com` pre-staged with a live copy of the kit,
suggesting planned infrastructure rotation once current domains are
detected and burned.

**MedDefense's position:** treat "HEALTHBANE" (the neutral HC3 designation)
as the operative campaign name in all MedDefense communications and
detection engineering. Do not state VITALSCORE or APT-MEDAGENT as
confirmed identity in any external-facing MedDefense document.

## 3. Campaign Analysis

Full detail in `6-kill_chain.md`. Summary:

| Stage | Window | Mechanism | MedDefense Status |
|---|---|---|---|
| 1 — Credential Harvesting | 2026-04-14 – 04-16 | Spear-phishing from lookalike domains; PHPMailer-served credential form | **CONFIRMED** — dmarsh clicked 2026-04-14 15:02:33 UTC (100% of the 6 HC3-visible orgs hit this stage) |
| 2 — Malware Delivery | 2026-04-16 – 04-22 | Stolen creds → follow-up email from compromised account → `.docm` macro → `svchost_update.exe` + persistence | **CONFIRMED NOT EXPERIENCED** — mass EDR scan 2026-04-16 found no matching hash (observed at only 2 of 6 visible orgs sector-wide) |
| 3 — Data Exfiltration | 2026-04-23 – 04-26 | DNS TXT-tunneling, base32/base64 encoding, to `data-sync.healthbane-c2.net` | **NO DATA EITHER WAY** at MedDefense — not assessable since Stage 2 didn't occur here; confirmed via packet capture at 2 orgs sector-wide |

**Evidence confidence:** Stage 1 is HIGH confidence (direct multi-source
telemetry, including MedDefense's own). Stage 2 and 3 are HIGH confidence
*where observed* (HC3 rates both on sandbox/packet-capture evidence) but
the true sector-wide prevalence beyond the 2 directly-observed
organizations is unknown — HC3's own visibility covers only 6 of ≥14
targeted organizations.

## 4. ATT&CK Mapping

Full detail and machine-readable layer in `7-attack_navigator.md` /
`healthbane_layer.json`. **22 techniques mapped: 19 OBSERVED, 3 INFERRED.**

Key techniques by detection relevance:
- **T1566.002 (Spearphishing Link)** — the universal chokepoint; 100% of
  visible victim organizations were compromised here first.
- **T1078 (Valid Accounts, INFERRED)** — HC3 itself could not confirm this
  despite assessing it as likely; it is the pivot from Stage 1 to Stage 2
  and currently under-detected everywhere, including at MedDefense.
- **T1053.005 / T1547.001 (Scheduled Task / Registry Run Key)** — HC3
  publishes ready-to-deploy detection logic for both; neither is currently
  operationalized at MedDefense.
- **T1071.004 / T1132.001 (DNS C2 / Standard Encoding)** — the actual
  data-loss chokepoint; the only phase-group with strong existing detection
  coverage (from 4x01's DNS-tunneling work).

Zero techniques are mapped to Discovery, Privilege Escalation, Collection,
or Impact — either a genuine tradecraft gap in this operator's approach
(a single-hop DNS exfiltration path doesn't require extensive internal
discovery) or a visibility gap in the available sources; this cannot be
distinguished from the intelligence in hand.

## 5. Detection Gap Assessment

Full detail in `8-detection_gaps.md`. Of 22 mapped techniques:

| Status | Count |
|---|---|
| DETECTED | 4 (18%) |
| PARTIALLY DETECTED | 10 (46%) |
| NOT DETECTED | 8 (36%) |

**Priority 1 (OBSERVED, NOT DETECTED) — 7 techniques**, of which **3 have a
ready-made fix**: HC3 already published detection logic for T1053.005
(scheduled task naming) and T1547.001 (Registry Run-key monitoring) that
MedDefense has simply not deployed yet — the single highest-leverage,
lowest-effort action available from this entire analysis. The remaining 4
Priority 1 gaps (T1589.002, T1585.002, T1587.001, T1204.002) either occur
entirely outside MedDefense's visibility (pre-attack reconnaissance and
malware development) or require a policy change (macro attestation) rather
than a new detection rule.

**Priority 2 (INFERRED, NOT DETECTED) — 1 technique** (T1036, Masquerading):
lower urgency since the underlying technique is itself unconfirmed.

**Priority 3 (Partially Detected) — 10 techniques**, with the highest-value
upgrade being generalizing Wazuh rule 100082 from a single-account
(dmarsh-only) rule into org-wide anomalous-authentication-geography
detection.

## 6. Indicator of Compromise Table

*(Substituting for Task 5's formal indicator database, not produced in this
batch — this table reproduces the real triage results from
`1-indicator_triage.sh`, organized by HC3-assigned campaign phase rather
than by source.)*

| Phase | Indicator | Type | Confidence | Recommended Action |
|---|---|---|---|---|
| Stage 1 | meddefense-portal.com | domain | HIGH | Block (email + network) |
| Stage 1 | medequip-supplies.net | domain | HIGH | Block |
| Stage 1 | meddefense-benefits.org | domain | HIGH | Block |
| Stage 1 | outlook-protection.com | domain | HIGH | Block (note: passes SPF/DKIM/DMARC — do not rely on auth-failure detection alone for this one) |
| Stage 1 | portal-secure-meddefense.com | domain | MEDIUM | **Monitor** — staged, not yet active; add to watch-list |
| Stage 1 | 91.234.99.107 | IP | HIGH | Block |
| Stage 1 | 185.176.43.22 | IP | HIGH | Block |
| Stage 1 | 164.90.218.73 | IP | HIGH | Block |
| Stage 1 | 51.38.42.17 | IP | HIGH | Block |
| Stage 1 | 2f4a6c8e...b9d1f | hash | MEDIUM | **Do not deploy as-is** — value is 62 hex chars, malformed SHA-256; re-acquire from source sample first |
| Stage 1 | noreply@meddefense-portal.com | email | HIGH | Block sender (already in Wazuh 100080) |
| Stage 1 | invoices@medequip-supplies.net | email | HIGH | Block sender (already in Wazuh 100080) |
| Stage 1 | hr-notifications@meddefense-benefits.org | email | HIGH | Block sender (already in Wazuh 100080) |
| Stage 2 | healthbane-c2.net | domain | HIGH | Block |
| Stage 2 | update-healthbane.net | domain | MEDIUM | Block |
| Stage 2 | 51.38.42.191 | IP | HIGH | Block |
| Stage 2 | 45.77.218.9 | IP | MEDIUM | Block |
| Stage 2 | a1b2c3d4...ef123456 (HEALTHBANE_S2_invoice.docm) | hash | HIGH | Deploy to EDR/AV blocklist |
| Stage 2 | b9c8a7d6...ba987654 (svchost_update.exe) | hash | HIGH | Deploy to EDR/AV blocklist |
| Stage 2 | dd5efb6d...ef12345678 (dropper variant) | hash | MEDIUM | Deploy to EDR/AV blocklist |
| Stage 3 | data-sync.healthbane-c2.net | domain | HIGH | Block + DNS-tunneling detection rule (already built, 4x01) |

**Explicitly excluded from this table** (classified NOISE in Task 1): 13
indicators, mostly shared-hosting/CDN IPs (Cloudflare, Azure CDN,
DigitalOcean, Microsoft cloud) that the commercial feed's own metadata
flags as "DO NOT BLOCK" or "LIKELY NOISE," plus several ML-clustering-only
hashes/domains with no human review. See `1-indicator_triage.sh`'s full
output for the complete 50-indicator triage with justifications.

## 7. YARA Rule Summary

Two rules developed and tested against the full 8-file sample corpus (real
`yara` execution, not simulated — see `9-yara_phishing_pdf.yar` and
`10-yara_arsenal.yar` for full test-result comments):

| Rule | Target | TP | TN | FP | FN | Detection Rate | Precision | Status |
|---|---|---|---|---|---|---|---|---|
| HEALTHBANE_Phishing_PDF | PDF lures | 2 | 6 | 0 | 0 | 100% | 100% | **DEPLOY** |
| HEALTHBANE_Email_Headers | Phishing emails | 2 | 5 | 0 | 1 | 66.7% | 100% | **TUNE** |

`HEALTHBANE_Phishing_PDF` detects lures by PDF-generation tooling
fingerprint (wkhtmltopdf 0.12.6) plus credential-harvesting URL pattern —
deliberately not tied to specific campaign domains, so it should keep
working after infrastructure rotation.

`HEALTHBANE_Email_Headers` has one diagnosed false negative: it requires
the exact literal `"PHPMailer 6.6.0"` (space-separated) in the X-Mailer
header, but one sample email uses `"PHPMailer-6.6.0"` (hyphen-separated) —
every other signal (SPF/DKIM/DMARC failure, urgency-language subject) fired
correctly. Fix: split the mailer string into two independently-required
substrings (`"PHPMailer"` and `"6.6.0"`) so the rule no longer depends on
the separator character. Zero false positives were observed for either
rule, so both are safe to run in their current form while the email rule's
fix is applied.

## 8. Recommendations

**Immediate (48 hours):**
- Deploy HC3's two published, ready-to-use Stage 2 detection rules:
  scheduled-task-naming alert ("Sync"/"Update"/"Service" by non-admins) and
  Registry Run-key monitoring outside installer context.
- Deploy `HEALTHBANE_Phishing_PDF` (Task 9) to the mail-gateway attachment
  scanner — it is DEPLOY-ready with a perfect test result.
- Add the 20 Stage 1–3 ACTIONABLE indicators from Section 6 to the existing
  Wazuh CDB lists (extending rules 100080/100081).

**Short-term (2 weeks):**
- Fix and redeploy `HEALTHBANE_Email_Headers` (Task 10) per the diagnosed
  separator-character issue in Section 7.
- Disable Office macros by default org-wide; require attestation for
  macro-enabled documents from external senders (closes T1204.002).
- Generalize Wazuh rule 100082 from a single-account (dmarsh) rule to an
  org-wide anomalous-authentication-geography rule (closes part of T1078).
- Add `portal-secure-meddefense.com` to a monitoring watch-list per the
  researcher's staged-infrastructure finding.

**Medium-term (30 days):**
- Operationalize HC3's PowerShell base64-payload hunting query (Section
  5.5 of the advisory) as an automated alert rather than a manual
  procedure.
- Extend the DNS-tunneling detection concept (4x01) to other protocols —
  the underlying technique (encoded-payload smuggling) is not inherently
  DNS-specific, even though this campaign happened to use DNS.
- Build the formal indicator database (Task 5) and infrastructure-cluster
  analysis (Tasks 3–4) not completed in this cycle, to support faster
  triage of the next sector advisory update (HC3 states one is expected
  2026-05-09 or sooner).

## 9. Intelligence Gaps and Collection Priorities

| Gap | What Would Answer It | Who/What to Ask |
|---|---|---|
| Outcomes at the ≥8 targeted organizations with no HC3 visibility | Direct outreach and telemetry sharing | HC3 (HC3@hhs.gov), via James Chen's existing reporting channel |
| Whether APT-MEDAGENT and VITALSCORE name the same operator | Independent technical comparison of kit/infrastructure fingerprints | Direct contact with the researcher (contact info in their blog's About page) and/or a formal Acme vendor inquiry |
| True sector-wide Stage 3 data volume exfiltrated | Full packet capture or DNS resolver logs at the 2 confirmed Stage 3 organizations | HC3, if those organizations authorize sharing |
| Whether the 62-character malformed lure-PDF hash is a transcription error or reflects a genuinely different sample | Re-acquire and re-hash the original INV-2026-04891.pdf from any organization that has it | HC3 or the affected partner organization |
| Whether `portal-secure-meddefense.com` has since gone live | Passive DNS / certificate-transparency monitoring | Ongoing automated watch (no ask needed — implement directly) |
| Real-world deployability of Task 10's fix | Re-test `HEALTHBANE_Email_Headers` after the proposed string-split fix is applied | Internal — SOC detection engineering, next sprint |
