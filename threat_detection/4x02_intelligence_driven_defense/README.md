# 4x02 — Intelligence-Driven Defense: HEALTHBANE Campaign

MedDefense Health Systems intelligence analysis of the HEALTHBANE campaign,
synthesizing an HC3 sector advisory, a commercial CTI feed, an independent
researcher's technical blog, and MedDefense's own 4x00 phishing-dissection
findings into triaged indicators, a source-credibility assessment, a
reconstructed kill chain, an ATT&CK mapping, a detection-gap analysis, two
tested YARA rules, and a final intelligence brief.

## Deliverables

| # | File | Summary |
|---|---|---|
| 0 | [0-intel_intake.md](0-intel_intake.md) | Parses all 4 sources; 89 raw indicators confirmed, 50 unique after exact-literal-value deduplication (see file for the documented discrepancy against the lab's 64-indicator reference figure) |
| 1 | [1-indicator_triage.sh](1-indicator_triage.sh) | Classifies all 50 unique indicators as ACTIONABLE (27) / CONTEXTUAL (10) / NOISE (13), with justification, confidence, and uncertainty flag per indicator |
| 2 | [2-source_assessment.md](2-source_assessment.md) | Admiralty Code (reliability A–F, credibility 1–6) assessment of all 4 sources; analyzes the 3-way attribution conflict (HEALTHBANE / VITALSCORE / APT-MEDAGENT) |
| 6 | [6-kill_chain.md](6-kill_chain.md) | Full 3-stage campaign timeline and reconstruction, with an evidence-quality table and an explicit "what is not known" section |
| 7 | [7-attack_navigator.md](7-attack_navigator.md) / [healthbane_layer.json](healthbane_layer.json) | 22 ATT&CK techniques mapped (19 OBSERVED, 3 INFERRED); valid ATT&CK Navigator layer JSON |
| 8 | [8-detection_gaps.md](8-detection_gaps.md) | Every Task 7 technique assessed as DETECTED / PARTIALLY DETECTED / NOT DETECTED against MedDefense's actual documented detection inventory, with a prioritized, actionable gap list |
| 9 | [9-yara_phishing_pdf.yar](9-yara_phishing_pdf.yar) | `HEALTHBANE_Phishing_PDF` rule; real `yara` test: 2 TP, 2 TN, 0 FP, 0 FN against `samples/` |
| 10 | [10-yara_arsenal.yar](10-yara_arsenal.yar) | `HEALTHBANE_Email_Headers` rule (see note below); real `yara` test: 2 TP, 1 TN(+3 out-of-scope TN), 0 FP, 1 FN — the false negative is a genuine, diagnosed bug (mailer-string separator character), not a simulated one |
| 11 | [11-yara_testing.sh](11-yara_testing.sh) | Runs both rules against the full 8-file sample corpus, computes detection rate / FPR / precision per rule, explains the false negative and proposes a fix, issues a DEPLOY/TUNE recommendation per rule |
| 13 | [13-intelligence_brief.md](13-intelligence_brief.md) | Final synthesis brief for MedDefense leadership and sector partners: executive summary, adversary profile, campaign analysis, ATT&CK mapping, detection gaps, IOC table, YARA summary, tiered recommendations, and collection priorities |

## Scope note

Tasks 3, 4, 5, and 12 (infrastructure clustering, pivot-point analysis, a
formal indicator database, and a standalone adversary-profile document)
were not part of this batch and are **not** included here. Where later
deliverables would normally depend on them (Task 8's detection inventory,
Task 11's rule count, Task 13's IOC table and adversary profile), this is
explicitly noted at the point of use, and the real content of Tasks 0–2 and
6–7 is substituted where a reasonable equivalent exists. Task 10 was not
part of the original pasted batch either; it was reconstructed from context
(`samples/samples_manifest.txt`'s stated match expectations, the pattern
established by Task 9, and email-header evidence in
`meddefense_4x00_findings.txt`) rather than a verbatim task prompt — see
that file's header comment.

## Materials

Source intelligence files (`HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt`,
`commercial_feed_extract.json`, `researcher_blog_analysis.txt`,
`meddefense_4x00_findings.txt`) and the `samples/` corpus are the
unmodified lab materials, copied here from `materials/4x02/` per the
project's "do not modify the provided source files in place" requirement.
All indicator counts and YARA test results in this project's deliverables
were derived programmatically from these files, not transcribed by hand.

## Requirements checklist

- Bash scripts start with `#!/bin/bash` and pass `shellcheck` — verified for
  `1-indicator_triage.sh` and `11-yara_testing.sh`.
- `healthbane_layer.json` validated as well-formed JSON via `json.load()`.
- Both YARA rules compile and were tested with real `yara` execution
  (via `yara-python`) against the full sample corpus, not predicted output.
- All files end with a trailing newline.
- No live SIEM/Wazuh/Suricata dependency — all detection logic here is
  local rule files, scripts, or documentation, consistent with the
  project's "no live infrastructure" requirement.
