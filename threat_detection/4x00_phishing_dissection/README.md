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

## Notes on the evidence batch

- The click timestamp (2026-04-14 15:02:33 CDT) is about 66 hours before the batch was collected (2026-04-17 09:15 CDT), not the roughly 36 hours quoted in the briefing. Later tasks should use the workstation NTP timestamp as the reference.
- The DKIM `t=` timestamps on the signed emails (E1, E4, E8) fall in 2025, and several `Date` headers carry weekday names that do not match 2026 (2026-04-14 is a Tuesday). This affects legitimate and malicious messages alike, so it was treated as a batch artifact and not as a triage signal.
