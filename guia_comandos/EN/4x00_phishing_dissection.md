# 4x00 – Phishing Dissection

Every task in this module is a written analysis deliverable (Markdown), not a script — a desk-based investigation of 8 raw phishing/legitimate emails collected after a staff report and gateway quarantine. Safe-handling rules apply throughout: no suspicious URL is ever visited, no attachment is ever opened, every value referenced is defanged (`http` → `hxxp`, `.` → `[.]`), and every conclusion must cite specific evidence rather than intuition.

## Task - 0-initial_triage.md

What it does: A first-pass triage table across all 8 raw emails (E1-E8), scoring SPF/DKIM/DMARC, classifying each into SPAM/SUSPICIOUS/LEGITIMATE, and assigning a priority — with E2 pinned to P1-URGENT specifically because the evidence batch already records a confirmed user click on it. Result: 1 SPAM, 4 SUSPICIOUS, 3 LEGITIMATE.
How to use it: read `0-initial_triage.md` (also available under `PT/`)
Commands:

- Parsing `Authentication-Results` header values (`spf=pass/fail`, `dkim=pass/none`, `dmarc=pass/fail`) directly from the raw email source, before reading any body content — authentication verdicts are checked first because they're objective and can't be spoofed as easily as a subject line.
- A fixed triage rubric (SPAM/SUSPICIOUS/LEGITIMATE × priority) applied uniformly to all 8 emails in one table, rather than a bespoke paragraph per email — the same discipline as a Tier 1 analyst's real triage queue, where consistency across items matters as much as accuracy on any one.
- Overriding the mechanical priority score for E2 based on external evidence (a confirmed click) already present in the batch — triage isn't a pure header-score function; known real-world impact reprioritizes regardless of what the headers alone suggest.

## Task - 1-header_analysis.md

What it does: A deep SMTP header-chain analysis for the four SUSPICIOUS emails (E2, E3, E5, E7): visible `From` vs `Return-Path`, the actual sending IP from the external hop (not a claimed one), `X-Mailer` string, `Message-ID` format, and a ranked list of anomalies per email. Result: all four originate directly from external hosts using PHPMailer 6.6.0 with a matching `PHP-<8 hex>` Message-ID pattern — no shared IP or domain, but a shared toolchain fingerprint links them.
How to use it: read `1-header_analysis.md`
Commands:

- Reading the `Received:` header chain from bottom to top (the order mail hops were actually added) to find the first external hop, instead of trusting the visible `From:` field — the standard technique for recovering the true sending infrastructure behind a spoofed display name.
- Comparing `From:` against `Return-Path:` — a mismatch between who a message claims to be from and where bounces actually go is one of the cheapest, highest-signal spoofing tells available without any external lookup.
- Fingerprinting the mailer toolchain itself (`X-Mailer: PHPMailer 6.6.0`, the `Message-ID` format it generates) as a *linking* signal across emails that otherwise share no infrastructure — the same idea as JA3/JA3S TLS fingerprinting, applied to mail headers instead of a TLS handshake.

## Task - 2-authentication_analysis.md

What it does: Formal SPF/DKIM/DMARC interpretation for all 8 emails — what each protocol actually verifies (SPF: the sending IP is authorized for the envelope domain; DKIM: a cryptographic signature over the message wasn't tampered with; DMARC: policy enforcement when SPF/DKIM disagree with the visible From domain) — with a per-email verdict. Result: authentication alone correctly flags E2/E5/E6/E7, but E3 *passes* because it authenticates as `outlook-protection.com`, a domain the attacker legitimately owns and configured correctly — proving valid authentication is not the same as a safe sender.
How to use it: read `2-authentication_analysis.md`
Commands:

- Treating SPF/DKIM/DMARC as three separate, independently-failable checks rather than one pass/fail signal — a message can pass SPF and DKIM while still failing DMARC alignment (or vice versa), and each combination has a different meaning worth spelling out.
- The specific "E3 passes because it's genuinely `outlook-protection.com`, not `microsoft.com`" finding — the core lesson that a lookalike domain can legitimately configure SPF/DKIM/DMARC for *itself*, so a green authentication result only proves the domain is who it says it is, never that the domain is trustworthy.

## Task - 3-social_engineering.md

What it does: A non-technical analysis of the four suspicious emails' psychological manipulation — the pretext used, the specific action requested, how individually-targeted each one is, red flags in the language itself, and what the pretext reveals about the attacker's prior knowledge of MedDefense. Result: E2 is assessed TARGETED (uses the real employee's name and role); E3, E5, and E7 are SEMI-TARGETED (industry/company-appropriate but not individually personalized); all four pair a deadline with a consequence and drive the reader to an external lookalike domain.
How to use it: read `3-social_engineering.md`
Commands:

- A fixed set of analysis dimensions (pretext, requested action, targeting level, red flags, attacker knowledge) applied identically across all four emails — turns "this email feels sketchy" into a structured, comparable assessment instead of a gut reaction.
- Distinguishing "targeted" from "semi-targeted" specifically by whether the pretext could only work against this one named individual, versus working against any employee at a healthcare company — a distinction that matters operationally, since a targeted lure implies the attacker did real reconnaissance on MedDefense specifically.
- Naming the deadline-plus-consequence structure as the one manipulation lever all four emails share, independent of their different pretexts — the actual psychological mechanism (urgency suppressing careful verification) is the constant; the story wrapped around it is what varies.

## Task - 4-url_attachment_autopsy.md

What it does: A fully safe indicator autopsy of every URL, IP, and attachment across the suspicious emails (12 indicators total) — every value taken only from the raw evidence, every URL/IP defanged (`hxxps://`, `[.]`), and a "safe investigation method" written in prose for each one (naming WHOIS, `dig`/`nslookup`, crt.sh, VirusTotal, urlscan.io) without ever running a live command against attacker infrastructure. Result: 12 indicators cataloged, including a PDF attachment whose embedded creation timestamp is one second before the email's send time (evidence it was generated specifically for this send, not a reused decoy).
How to use it: read `4-url_attachment_autopsy.md`
Commands:

- A strict handling rule against even a `curl -I` HEAD-only request to a suspicious domain — explicitly documented as still a real connection to attacker infrastructure that can leak the analyst's IP or trigger a tracking pixel, the same operational-security discipline a live IR engagement would require.
- Defanging every value at the point of writing (`http` → `hxxp`, `.` → `[.]`) so the document itself can never be copy-pasted into a browser by accident — a convention that costs nothing and prevents one specific, common analyst mistake.
- Stripping the per-recipient `token` query parameter before naming any URL for lookup — the token uniquely identifies Diane Marsh to the attacker's tracking, so even a "safe" passive lookup of the bare URL (not just visiting it) needs the token removed first to avoid confirming her click to the attacker's infrastructure.
- Extracting attachment metadata (PDF creation timestamp) from the evidence batch's base64-encoded copy instead of opening the file — proves a fact about the attachment (it was freshly generated) without ever rendering attacker-controlled content on an analyst machine.

## Task - 7-click_investigation.md

What it does: A structured assessment of what is and isn't known about Diane Marsh's confirmed click on the E2 phishing link from `WS-NURSE-04` — separating confirmed facts (the click itself, its timestamp) from unknowns (whether credentials were entered, whether the endpoint was compromised), listing the endpoint and account checks that *should* happen next (without performing them, since this is a desk-based investigation), a decision matrix, and containment recommendations. Result: click confirmed, downstream impact undetermined — the working assumption defaults to possible credential exposure until proven otherwise.
How to use it: read `7-click_investigation.md`
Commands:

- A hard separation between "confirmed facts" and "unknowns" as two distinct labeled sections, rather than one narrative blending them — the discipline of never letting a plausible inference get reported with the same confidence as a directly observed fact.
- Listing recommended follow-up actions (EDR process history on `WS-NURSE-04`, a forced password reset, checking for anomalous logins from Diane Marsh's account) as *recommendations*, explicitly not performed here — this task is evidence review, not live incident response, and the report is honest about that boundary instead of implying actions were taken.
- Defaulting to the worse-case working assumption (possible credential exposure) when the evidence is genuinely inconclusive — the same "guilty until proven innocent" posture used elsewhere in this curriculum for high-stakes, low-certainty findings.

## Task - 8-verdict_matrix.md

What it does: Revisits every one of the 8 emails with a final, fully evidence-based verdict (versus the mechanical initial triage from Task 0), explaining every case where the final classification differs from the initial one, plus a self-assessment of the initial triage's accuracy. Result: initial triage was 8/8 correct at the coarse malicious/legitimate/spam level, but had no mechanism to distinguish targeted from opportunistic phishing — a distinction only Tasks 1-4's deeper analysis could surface — and one legitimate-looking email (E1) gets downgraded to LEGITIMATE-WITH-ISSUE.
How to use it: read `8-verdict_matrix.md`
Commands:

- Explicitly grading the *initial* triage against the *final* one, not just reporting the final answer — makes visible exactly what deeper analysis bought over a first-pass header check, instead of silently discarding the earlier work.
- Separating "was the coarse call right" (spam/phishing/legitimate) from "was the nuance right" (targeted vs. opportunistic) as two different accuracy questions — a triage process can be mechanically correct and still miss the detail that actually determines the response.
- The `LEGITIMATE-WITH-ISSUE` verdict category for E1 — a label that doesn't fit a clean binary, used deliberately instead of forcing an ambiguous finding into "safe" or "malicious."

## Task - 9-campaign_thread.md

What it does: Tests whether E2, E5, and E7 (and separately E3) form one coordinated campaign rather than three unrelated attacks, by comparing shared indicators, a targeting map, a timing map, and a direct comparison against the traits named in the HC3 sector alert — while explicitly stopping short of naming a specific threat actor, since attribution requires evidence this desk review doesn't have. Result: MEDIUM confidence that E2/E5/E7 are one MedDefense-targeted campaign spanning April 14-16, matching all four traits the HC3 alert describes; E3 shares the same toolchain but is assessed as a separate, more generic operation.
How to use it: read `9-campaign_thread.md`
Commands:

- Building an explicit shared-indicator matrix (infrastructure, timing, targeting, toolchain) across candidate campaign members — the same "does A relate to B" comparison logic as this project's own cross-source anomaly correlation (3x01 Task 13), just applied to phishing emails instead of security telemetry.
- Treating "shares the same PHPMailer/Message-ID toolchain" and "is part of the same targeted campaign" as two *different* claims that need separate evidence — E3 shares one but not the other, and the report says so explicitly instead of lumping all four together because they look similar.
- A confidence level (MEDIUM) attached to the campaign-linkage conclusion instead of a bare yes/no — mirrors how this project's other correlation work (3x05's `10-campaign_correlation.sh`) always ships a confidence alongside a linkage verdict, never the verdict alone.

## Task - 11-ioc_extraction.md

What it does: Converts every finding from Tasks 1-9 into one structured, categorized IOC table (33 entries: domains, IPs, sender addresses, URLs, plus toolchain fingerprints and the HC3 alert's own hosting/keyword notes) tagged by attack phase and by IOC quality, with an explicit call-out of which indicators are safe to block outright versus which are context-only and would cause false positives if blocked in isolation. Result: 4 domains, 4 IPs, 8 sender addresses, and 6 URLs are high-confidence block candidates; toolchain fingerprints and HC3's generic hosting/keyword notes are explicitly marked context-only.
How to use it: read `11-ioc_extraction.md`
Commands:

- Tagging every IOC with both an attack-phase label and a quality/confidence tier in the same table — an indicator being *real* (it appeared in confirmed-malicious evidence) is a different question from an indicator being *safe to act on unilaterally* (blocking it won't collaterally break something legitimate).
- Explicitly flagging low-specificity indicators (a mailer fingerprint, a generic keyword pattern from the HC3 alert) as context-only rather than omitting them — still useful for detection engineering (matching this project's own Sigma-rule philosophy of stable, low-cardinality signature fields from 3x02's `0-detection_matrix.sh`) even though they're wrong to put directly on a block list.
- Structuring the table as HC3-shareable output from the start — an IOC list meant to leave the organization (shared with a sector ISAC) needs a different bar for "confirmed" than one used only for internal blocking, and the table format reflects that.

## Task - 13-phishing_investigation_report.md

What it does: The final synthesis deliverable — pulls every prior task's findings into one report meant for SOC-lead review and external HC3 sharing: executive summary, timeline, per-email verdicts, campaign analysis, the click assessment, an IOC summary, detection/control gaps found along the way, and phased recommendations (24 hours / 7 days / 30 days). Explicitly documents where its own reasoning had to diverge from a plan: a referenced "Task 12" detection-ideas file doesn't exist in this batch, so those ideas are proposed directly in the report instead of cited from an external source.
How to use it: read `13-phishing_investigation_report.md`
Commands:

- Structuring recommendations into three explicit time horizons (24h / 7 days / 30 days) instead of one flat list — separates "block these IOCs today" from "fix the SPF policy this week" from "reconsider the vendor-invoice approval workflow this month," each requiring a different owner and urgency.
- A synthesis document that reuses, not repeats, every earlier task's conclusions by reference — the report is a pointer graph over the investigation's own artifacts as much as it is new prose, the same "cite your evidence, don't restate it" discipline the whole module's Safe Handling Rules require.
- Naming the "Task 12" gap explicitly in the text instead of silently working around it — a small but real example of documenting a limitation of the investigation itself (a missing planned input) rather than quietly absorbing it.
