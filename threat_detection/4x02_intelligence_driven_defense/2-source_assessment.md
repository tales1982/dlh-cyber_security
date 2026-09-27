# Source Credibility Assessment — HEALTHBANE Intelligence

## 1. Assessment Methodology

This assessment uses the **Admiralty Code** (NATO System), adapted for cyber
threat intelligence, which rates two *independent* dimensions separately —
conflating them is the most common analyst error the system is designed to
prevent (a highly reliable source can report a low-credibility claim, and a
one-off anonymous source can report something that turns out to be
independently confirmed).

**Source reliability (A–F)** — a judgment about the *reporting channel*
itself: its track record, institutional accountability, and access to
firsthand evidence.

| Grade | Meaning |
|---|---|
| A | Completely reliable — no doubt of authenticity, trustworthiness, competency |
| B | Usually reliable — minor doubt; history of valid information most of the time |
| C | Fairly reliable — doubt exists; has provided valid information in the past |
| D | Not usually reliable — significant doubt; more often invalid than valid |
| E | Unreliable — lacks authenticity/trustworthiness/competency |
| F | Cannot be judged — no basis for evaluation |

**Information credibility (1–6)** — a judgment about the *specific claim*,
independent of who reported it:

| Grade | Meaning |
|---|---|
| 1 | Confirmed by other independent sources; logical; consistent |
| 2 | Probably true; logical; consistent; not independently confirmed |
| 3 | Possibly true; reasonably logical; agrees with some other information |
| 4 | Doubtful; not logical but possible; no other corroborating information |
| 5 | Improbable; not logical; contradicted by other information |
| 6 | Cannot be judged |

**Confidence levels (HIGH / MEDIUM / LOW)** are used throughout this project
as the plain-language output of combining reliability + credibility for a
given claim — e.g., an A1 or B1 claim is reported as HIGH confidence, a C3 or
B4 claim as MEDIUM, and anything resting on D/E reliability or 4–6
credibility as LOW, regardless of how the source itself phrases its
certainty.

## 2. Per-Source Assessment

### 2.1 HC3 Sector Advisory

- **Source reliability: A.** HC3 is the HHS sector-coordination body for
  healthcare, drawing on full telemetry from 6 partner organizations plus
  sensor deployment at 2 regional ISAOs — direct, multi-organization,
  institutionally accountable reporting, not single-source or anonymous.
- **Information credibility: 1** for Stage 1/2/3 technical findings
  (explicitly labeled HIGH confidence, corroborated across multiple
  independently-visible organizations, sandbox-validated, packet-capture
  confirmed). **Credibility drops to 4** specifically for the attribution
  claim, which HC3 itself rates LOW confidence and declines to name a
  specific actor.
- **Timeliness:** Published 2026-04-25, 11 days after first observed
  activity (2026-04-14) — appropriately timely for a synthesized,
  multi-organization formal advisory rather than raw first-alert speed.
- **Relevance to MedDefense:** Direct and high — MedDefense is one of the
  contributing organizations (its 4x00 indicators were submitted to HC3),
  and the advisory describes the exact campaign MedDefense experienced.
- **Limitations:** Visibility limited to 6 of ≥14 known-targeted
  organizations; attribution explicitly unconfirmed; next update pending
  further development.
- **Bias/visibility constraints:** Institutional bias toward broadly
  actionable, sector-wide guidance over deep technical/attribution detail;
  visibility is structurally limited to organizations mature enough to
  detect and report to HC3 in the first place (selection bias toward
  better-defended victims).

### 2.2 Commercial CTI Feed (Acme)

- **Source reliability: C.** A real commercial vendor with genuine
  infrastructure, but the feed's own metadata discloses indicators are
  "auto-tagged by Acme's clustering engine" with only **sampled** (not
  complete) human analyst review — and several of the feed's own entries
  carry self-authored warnings such as "LIKELY NOISE" and "DO NOT BLOCK."
  A source that flags roughly half its own extract as questionable is, by
  definition, only fairly reliable as a channel, even though the
  high-confidence portion of its content is good.
- **Information credibility: highly variable, 2–5 depending on the specific
  indicator** — the feed embeds a numeric `acme_confidence` per item
  (observed range: 15–96), so credibility must be assessed per-indicator
  (done in Task 1), not as a blanket property of "the commercial feed."
  Indicators that also appear in HC3/researcher data reach credibility 1–2;
  ML-clustering-only entries with no external corroboration sit at 4–5.
- **Timeliness:** Extract dated 2026-04-26 — the most recent of all four
  sources, reflecting a continuously-updated commercial feed rather than a
  point-in-time report.
- **Relevance to MedDefense:** High potential relevance (largest raw
  indicator volume, 41 of 89 total) but only realized after triage — see
  Task 1, where 20 of the feed's 41 indicators were classified CONTEXTUAL
  or NOISE.
- **Limitations:** TLP:AMBER restricts redistribution to internal defense
  use only; the proprietary VITALSCORE label is explicitly stated to "not
  necessarily correspond to externally-tracked threat actor names."
- **Bias/visibility constraints:** Commercial incentive structurally favors
  broader indicator coverage (more indicators marketed as more value to
  subscribers), which biases toward over-inclusion of weakly-evidenced
  items — visible directly in this extract's noise fraction.

### 2.3 Researcher Blog Analysis

- **Source reliability: B.** A single independent researcher, self-hosted
  platform, with no institutional accountability chain — but this specific
  report is grounded in **direct primary evidence** (the researcher
  obtained actual phishing-kit source code and its config file via a
  misconfigured directory listing), which is unusually strong firsthand
  access for an open-source report. The demonstrated ethical handling
  (voluntary 72-hour coordinated-disclosure delay at HC3's request,
  declining to publish kit source code publicly) is a positive reliability
  signal specific to this author.
- **Information credibility: 1** for the kit-structure and tooling findings
  (directly extracted from the operator's own config.php — as close to
  ground truth as any source in this package). **Credibility 3** for the
  APT-MEDAGENT attribution, which the author self-rates MEDIUM confidence
  and states explicitly is "based entirely on tooling + infrastructure
  overlap... NOT based on telemetry, signals intelligence, or insider
  reporting."
- **Timeliness:** Published 2026-04-24 — the earliest formal write-up of
  the four (one day ahead of HC3), with the underlying kit access dated
  2026-04-18.
- **Relevance to MedDefense:** High technical relevance — literal
  configuration values (`EXFIL_ENDPOINT`, `OPS_CONTACT`) and a distinctive
  tooling fingerprint (wkhtmltopdf 0.12.6, PHPMailer 6.6.0) are directly
  reusable for detection engineering (Tasks 9–10).
- **Limitations:** Explicitly no victim telemetry; a solo researcher with no
  peer review of the attribution claim.
- **Bias/visibility constraints:** A research-blog author has some
  incentive to claim novel attribution ("first to name the actor"), which
  is exactly why the author's own MEDIUM-confidence, evidence-basis-only
  framing should be taken at face value rather than upgraded.

### 2.4 MedDefense Internal 4x00 Findings

- **Source reliability: A** for MedDefense's own operational facts — this
  is MedDefense's own investigation, reviewed by the SOC Lead and approved
  by the CISO, with an internal accountability chain. It is the origin of
  several indicators later corroborated by HC3 and the researcher, not a
  secondary retelling of someone else's data.
- **Information credibility: 1** for directly-observed facts (the phishing
  emails, domains, IPs, the dmarsh click event timestamp). **Credibility 3**
  for the specific claim of credential submission, which the report itself
  states is "LIKELY... NOT CONFIRMED via packet evidence as of 4x00 close"
  (subsequently resolved with direct packet evidence in 4x01, which
  postdates this report).
- **Timeliness:** Dated 2026-04-16 — the earliest of all four sources,
  reflecting real-time incident response rather than retrospective
  analysis.
- **Relevance to MedDefense:** Maximum — this is MedDefense's own incident.
- **Limitations:** Explicitly scoped to Stage 1 only; network packet
  analysis, endpoint forensics, and follow-on authentication correlation
  were all deliberately deferred to 4x01, so this source cannot speak to
  Stage 2/3 at all.
- **Bias/visibility constraints:** An internal incident report carries some
  structural incentive toward conservative, liability-conscious framing —
  but this report is notably transparent about open questions (Q1–Q5) it
  could not yet answer, which argues against significant downplaying bias.

## 3. Source Comparison Matrix

| Dimension | HC3 Advisory | Commercial Feed | Researcher Blog | MedDefense 4x00 |
|---|---|---|---|---|
| Source reliability | **A** | **C** | **B** | **A** (own scope) |
| Information credibility (core findings) | **1** | 2–5 (variable) | **1** (kit), 3 (attribution) | **1** (facts), 3 (submission claim) |
| Attribution stance | Explicitly UNCONFIRMED, no label endorsed | VITALSCORE (proprietary, ML-assisted) | APT-MEDAGENT (MEDIUM, tooling-based) | No attribution offered |
| Indicator volume | 23 | 41 (largest) | 14 | 11 (smallest) |
| Timeliness | 2026-04-25 | 2026-04-26 (rolling) | 2026-04-24 (earliest write-up) | 2026-04-16 (earliest overall) |
| TLP / distribution | CLEAR (share broadly) | AMBER (internal only) | Public, no TLP | INTERNAL (indicator extract shared to HC3) |
| Stage coverage | 1, 2, 3 (all three) | Mostly Stage 1/2/3 indicators, no phase narrative | 1 deep, 2/3 shallow | 1 only |
| Primary evidence basis | 6-org telemetry, sandbox, packet capture | Automated clustering + external corroboration count | Direct kit/config access | Direct SIEM/user-report evidence |
| Best used for | Sector-wide confirmed scope and stage timeline | Volume/breadth, continuous updates (after triage) | Deep technical/tooling detail, detection engineering | MedDefense-specific ground truth |

## 4. Analytical Note: The Attribution Conflict

Four sources, four different postures on attribution, and this is **normal**,
not a data-quality failure:

- **HC3** explicitly declines to attribute and explicitly declines to
  endorse VITALSCORE — the most conservative posture, appropriate for a
  government advisory meant for broad sector distribution regardless of
  attribution certainty.
- **Acme (commercial feed)** applies VITALSCORE via an automated clustering
  engine with disclosed, only-sampled human review. The label is a
  **proprietary tracking tag**, not a vetted named-actor attribution — Acme
  itself states it "does not necessarily correspond to externally-tracked
  threat actor names."
- **The researcher** privately tracks APT-MEDAGENT at self-rated MEDIUM
  confidence, based entirely on infrastructure/tooling overlap with three
  prior campaigns (RXBRIDGE, CLAIMBRIDGE, MEDNEXUS) the author documented
  independently in 2024–2025. Critically, the researcher **explicitly
  states uncertainty** about whether APT-MEDAGENT and VITALSCORE refer to
  the same actor — so even the two non-government sources do not confirm
  each other.
- **MedDefense** avoids attribution entirely, correctly, since it has no
  independent basis to assess it.

**Recommendation:** Treat "HEALTHBANE" (HC3's designation) as the neutral,
campaign-level label for all MedDefense reporting and detection engineering.
Treat VITALSCORE and APT-MEDAGENT as **unconfirmed aliases** that may or may
not refer to the same operator as each other, cited with their originating
source and confidence level whenever mentioned, and never presented as a
settled identity. No MedDefense-authored document in this project should
state "the attacker is APT-MEDAGENT" or "this is a VITALSCORE actor" as
fact — both are one source's working hypothesis, not a confirmed finding.

## 5. Weighting Recommendation

- **Prioritize for confirmed healthcare-sector facts:** HC3. It is the only
  source with multi-organization, institutionally-coordinated visibility
  and the only one explicitly designed to give a balanced, non-vendor-biased
  account of campaign scope and staging.
- **Prioritize for technical/detection-engineering detail:** The researcher
  blog. Its direct kit and config.php access provides literal strings
  (endpoint paths, tooling version fingerprints) that are immediately
  reusable for YARA rule development (Tasks 9–10) in a way no other source
  offers.
- **Treat carefully — noise and weak clustering:** The commercial feed.
  Valuable for volume and update cadence, but roughly half of its
  single-source-only content (20 of 41 raw indicators) is either
  explicitly self-flagged as noise/do-not-block or based on unreviewed
  ML-similarity clustering. Never treat "present in the Acme feed" alone as
  sufficient justification for a defensive action — always check the
  per-indicator `acme_confidence` score and `acme_note` field first (see
  Task 1's triage, which did exactly this).
- **Use as MedDefense's own system of record for Stage 1:** The 4x00
  findings — authoritative for what actually happened inside MedDefense,
  but must be supplemented by HC3 and 4x01 for anything past Stage 1, since
  4x00 explicitly did not investigate further stages.
- **How to handle conflicting claims generally:** when sources disagree,
  report the disagreement itself as a finding (as this document does),
  anchor factual/technical claims to the highest-reliability,
  highest-credibility source available for that specific claim (which is
  not always the same source for every claim), and never silently pick the
  most convenient or most alarming version when sources conflict.
