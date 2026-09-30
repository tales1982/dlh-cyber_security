# 1x05 – Board Briefing

## Task - 0-advisory_analysis.md
Concept: Shows how to turn a threat intelligence advisory (generic CISA/CTI language) into a concrete analysis by mapping each attack phase to specific assets, vulnerabilities, and gaps in the actual environment. This is the core of threat intelligence contextualization: an active campaign is only useful to the business once translated into "this affects us, here, this way." The output is a phase-by-phase exposure scorecard, not a theoretical reading of the report.

## Task - 1-cve_deep_dive.md
Concept: Teaches the process of deep CVE research — the technical description (NVD/CWE), calculating the CVSS base score plus its environmental and temporal adjustments, and checking real-world exploit availability (KEV, Exploit-DB, Metasploit). The key point is that the absence of a public exploit does not lower urgency when the CVE is already being actively exploited by sophisticated actors; real risk scoring must reflect organizational context, not just the raw NVD number.

## Task - 2-kill_chain_overlay.md
Concept: Compares a hypothetical kill chain built in advance against the real attack chain observed in an active campaign, identifying where the original model was correct and where it diverged (e.g., predicted entry vector vs. actual). This overlay also maps which planned controls actually intercept each phase of the real attack, exposing the gap between the security plan and effective protection.

## Task - 3-emergency_plan.md
Concept: Covers incident response planning under severe time and staffing constraints, organizing actions into tiers (immediate, short-term, medium-term) with owners, prerequisites, and an explicit risk-of-action vs. risk-of-inaction analysis. It also addresses how to resolve resource conflicts when a small team must execute multiple critical changes at once without creating new instability.

## Task - 4-crypto_emergency.md
Concept: Connects specific cryptographic weaknesses (missing encryption in transit/at rest, broken algorithms) to the real techniques used in an active attack, and reprioritizes remediation based on current threat intelligence rather than the originally planned order. It reinforces a core defense-in-depth principle: encryption alone does not stop an attacker who already has sufficient host privileges — it must be paired with access controls and segmentation.

## Task - 5-ale_update.md
Concept: Demonstrates how Annualized Loss Expectancy (ALE) must be recalculated when new threat intelligence arrives, adjusting the Annual Rate of Occurrence (ARO) and Exposure Factor (EF) to reflect a confirmed active campaign instead of a generic sector base rate. It also shows how this financial risk update can shift budget decisions, turning previously "marginal" controls into clearly justified ones.

## Task - 6-technical_proof.md
Concept: Brings together practical technical checks that back up a security analysis: TLS certificate inspection with OpenSSL, hash-based integrity verification via SHA-256 (the avalanche effect), public exploit research, and system hardening audits (Lynis). The key lesson is that security claims must be proven with real commands and evidence, not just described.

## Task - 7-risk_register_update.md
Concept: Explains the governance of a living risk register — how to update an existing entry with new intelligence, create a new dedicated risk entry, define Key Risk Indicators (KRIs), and formally apply the triggers that mandate an out-of-cycle review. A risk register is not static; it must react to events such as a new critical CVE or a confirmed incident.

## Task - 8-comprehensive_assessment.md
Concept: Consolidates several prior assessments (assets, threats, vulnerabilities, risk, cryptography) into a single coherent executive report, highlighting the gap between what was planned/approved and what has actually been implemented. This is the synthesis exercise that turns weeks of scattered technical analysis into a security posture narrative leadership can understand.

## Task - 9-board_presentation.md
Concept: Focuses on communicating technical risk to an executive board — condensing everything into a one-page brief and tailoring the message to different stakeholders (CEO, CFO, legal, board chair) using each one's own language and priorities. It is the skill of translating technical findings into actionable, fundable business decisions.
