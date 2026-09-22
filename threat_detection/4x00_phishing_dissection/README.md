# 4x00 - Phishing Dissection

MedDefense Health Systems phishing investigation. Eight raw emails (full SMTP headers) were collected after staff reports and gateway quarantine over 2026-04-14 to 2026-04-16. The goal is to triage them, decide whether the malicious ones belong to one coordinated campaign, and determine whether the user who clicked (Diane Marsh, `WS-NURSE-04`) was compromised.

## Safe handling rules

- Never navigate directly to a suspicious URL. Use defanging, sandbox services and command-line tools.
- Never open an attachment on the analyst workstation. Use metadata extraction and online sandboxes only.
- Every conclusion must cite specific evidence from headers, authentication results or OSINT findings.

## Tasks

### 0 - 0-initial_triage.md

First-pass triage table for E1 through E8 (SPF, DKIM, DMARC, class, priority, evidence) plus a summary. E2 is fixed at P1-URGENT because the batch records the click at 2026-04-14 15:02:33 CDT.

Result: 1 SPAM (E6), 4 SUSPICIOUS (E2, E3, E5, E7), 3 LEGITIMATE (E1, E4, E8).

### 1 - 1-header_analysis.md

SMTP header chain analysis for E2, E3, E5 and E7: visible From, Return-Path, sending IP from the external hop, X-Mailer, Message-ID format, claimed sender versus sending infrastructure, and ranked anomalies.

Result: all four arrive directly from external hosts (`91.234.99.107`, `51.38.42.17`, `185.176.43.22`, `164.90.218.73`) using PHPMailer 6.6.0 and a `PHP-<8 hex>` Message-ID. No IP or domain is shared, so the link between them is the toolchain fingerprint.

### 2 - 2-authentication_analysis.md

SPF, DKIM and DMARC results for all 8 emails, what each means, and a verdict per email.

Result: authentication alone flags E2, E5, E7 and E6 but passes E3 with the legitimate E1, E4 and E8, because `outlook-protection.com` (not `microsoft.com` or `outlook.com`) authenticates for itself.

### 3 - 3-social_engineering.md

Psychological levers, pretext, requested action, targeting level, red flags and attacker knowledge for E2, E3, E5 and E7.

Result: E2 is TARGETED; E3, E5 and E7 are SEMI-TARGETED. All four pair a deadline with a consequence and send the reader to an external lookalike domain.

### 4 - 4-url_attachment_autopsy.md

Defanged URL, IP and attachment indicators with safe investigation commands and findings from the email evidence. No live lookups were run.

Result: 12 indicators, including the E5 invoice PDF (generated one second before sending, embedded link to the payment URL). The only IP reuse in the batch is E6 (`203.0.113.228`, sender and link host).

### 7 - 7-click_investigation.md

Assessment of Diane Marsh's click on E2 from `WS-NURSE-04`: confirmed facts, unknowns, endpoint and account checks (recommended follow-up, not performed), decision matrix and containment.

Result: click confirmed, impact undetermined. Working assumption is possible credential exposure.

### 8 - 8-verdict_matrix.md

Final evidence-based verdict for all 8 emails (initial class, final class, confidence, key evidence, recommended action), where final differs from initial, and a triage accuracy assessment.

Result: E1 becomes LEGITIMATE-WITH-ISSUE, E2/E5/E7 become PHISHING-TARGETED, E3 becomes PHISHING-OPPORTUNISTIC; initial triage was 8/8 correct on the coarse malicious/legitimate/spam call, but had no way to separate targeted from opportunistic phishing.

### 9 - 9-campaign_thread.md

Shared indicators, targeting map, timing map and HC3 comparison for E2, E5 and E7, plus an attribution assessment that stops short of naming an actor.

Result: MEDIUM confidence E2/E5/E7 are one coordinated, MedDefense-targeted campaign (April 14-16), matching all four traits in the HC3 alert. E3 shares tooling but is assessed as a separate, more generic operation.

### 11 - 11-ioc_extraction.md

Structured IOC table (33 entries) covering E2, E3, E5, E7, the E5 attachment and the HC3 alert patterns, categorized by attack phase, with an IOC-quality breakdown and an HC3-ready summary.

Result: 4 domains, 4 IPs, 8 sender addresses and 6 URLs are high-confidence and safe to block; PHPMailer/Message-ID/X-Priority fingerprints and HC3's hosting/keyword notes are context-only and would cause false positives if blocked alone.

### 13 - 13-phishing_investigation_report.md

Final synthesis report for SOC-lead review and HC3 sharing: executive summary, timeline, per-email verdicts, campaign analysis, click assessment, IOC summary, detection/control gaps, and phased recommendations (24h / 7 days / 30 days).

Note: Section 7 references detection ideas that the report calls "Task 12"; no such file exists in this batch, so those ideas are proposed directly in the report rather than cited from an external file.

## Notes on the evidence batch

- The click timestamp (2026-04-14 15:02:33 CDT) is about 66 hours before the batch was collected (2026-04-17 09:15 CDT), not the roughly 36 hours quoted in the briefing. Later tasks should use the workstation NTP timestamp as the reference.
- The DKIM `t=` timestamps on the signed emails (E1, E4, E8) fall in 2025, and several `Date` headers carry weekday names that do not match 2026 (2026-04-14 is a Tuesday). This affects legitimate and malicious messages alike, so it was treated as a batch artifact and not as a triage signal.
