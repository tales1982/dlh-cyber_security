# 1x00 – First Watch

## Task - 0-environment_summary.md

Concept: Environment/asset discovery is the starting point of any security assessment: mapping sites, infrastructure, systems, data, and organizational structure before analyzing risk. Without this documented baseline, it is impossible to know what needs protecting or to identify gaps. The exercise also introduces the concept of "known unknowns" — explicitly acknowledging what has not yet been verified, rather than assuming security where there is no evidence.

## Task - 1-incident_classification.md

Concept: The CIA Triad (Confidentiality, Integrity, Availability) is the foundational model for classifying the impact of a security incident. Each incident must be evaluated for which pillar was primarily violated, with a secondary impact noted only when there is explicit textual evidence — never speculation. This classification drives incident prioritization and response.

## Task - 2-root_cause_analysis.md

Concept: Root Cause Analysis (RCA) is the technique of investigating the underlying cause of an incident rather than treating only the visible symptom (such as high CPU usage). The exercise also covers cryptojacking (unauthorized cryptocurrency mining using compromised resources) and reinforces that fixing the symptom without eliminating the entry-point vulnerability (e.g., an unpatched RCE flaw) allows the same attack to recur.

## Task - 3-physical_assessment.md

Concept: A physical security assessment breaks each observation down into four formal risk components — Vulnerability, Threat, Impact (mapped to the CIA Triad pillars), and Severity. This framework shows that physical and logical security are interconnected: uncontrolled physical access to a network closet or server room can compromise the confidentiality, integrity, and availability of critical systems.

## Task - 4-control_inventory.md

Concept: A security control inventory organizes existing controls along two dimensions: Category (Technical, Administrative, Physical) and Function (Preventive, Detective, Corrective, Compensating, Deterrent). This matrix is the foundation for any security maturity analysis, since it makes it immediately visible where the organization invests in protection and where it does not.

## Task - 5-control_gaps.md

Concept: Control gap analysis compares the existing control matrix against what should exist, revealing empty or insufficient Category x Function combinations. The exercise demonstrates a common pattern in real organizations: heavy investment in preventive controls paired with a scarcity of detective, corrective, and compensating controls — meaning successful attacks go unnoticed for long periods.

## Task - 6-compensating_controls.md

Concept: Compensating controls are alternative measures applied when a system cannot be directly patched, upgraded, or replaced (for example, legacy medical equipment running an unsupported operating system). Instead of eliminating the vulnerability, a compensating control reduces exposure to risk — typically through network segmentation, a formal governance process, or physical access restriction — and should be prioritized by whichever control reduces the most likely attack vector.

## Task - 7-asset_registry.md

Concept: An asset registry (CMDB) is the formal inventory of all systems, devices, and services in an organization, tracking owner, location, criticality, and status. The exercise introduces reconciliation — comparing existing documentation against an independent network scan — which exposes real discrepancies, such as Shadow IT (undocumented systems) and documented assets that no longer actually exist.

## Task - 8-criticality_assessment.md

Concept: Asset criticality assessment applies the CIA Triad to each asset category to determine its overall importance level (Critical, High, Medium, Low). This ranking drives investment and protection prioritization, focusing limited resources on the assets whose compromise would cause the greatest business or patient-safety impact.

## Task - 9-data_map.md

Concept: Data mapping identifies where each data category resides, how it moves, and how it is used — data at rest, in transit, and in use — along with its sensitivity classification (Restricted, Confidential, etc.). This mapping is essential for identifying protection gaps specific to each data type, since different data requires different controls based on its value and risk.

## Task - 10-complete_control_matrix.md

Concept: Control effectiveness assessment goes beyond simply inventorying controls — it assigns a maturity rating (Strong, Adequate, Weak) to each one and maps its coverage onto the most critical assets. This cross-reference reveals "partially protected" or "unprotected" assets even when controls exist on paper, showing that a documented control does not equal real protection.

## Task - 11-shadow_systems.md

Concept: Shadow IT refers to systems, devices, or services deployed by users or departments without IT/security approval or visibility. Each Shadow IT case requires a response proportional to its risk and the legitimate need behind it: legitimize and secure, migrate to an already-sanctioned alternative, or decommission — with the root cause usually being an IT process too slow to meet real needs.

## Task - 12-gap_analysis.md

Concept: Prioritized gap analysis combines asset criticality, data classification, and control coverage to assign a risk level (Critical, High, Medium, Low) to each identified gap. This structured methodology avoids subjective prioritization by applying consistent rules (for example, the absence of both a detective AND a corrective control raises the risk to Critical) to decide what to act on first.

## Task - 13-reality_check.md

Concept: Validating an internal assessment against real-world breach cases (threat intelligence / lessons learned) confirms whether identified gaps actually lead to serious incidents, and surfaces "blind spots" — real risks the original analysis missed. This correlation with external incidents increases confidence in the defined "blind spots""blind spots"

## Task - 14-risk_decisions.md

Concept: Risk treatment is the formal decision on how to handle each identified risk, following standard strategies: Mitigate, Transfer, Accept, or Avoid. Each decision should be paired with proposed controls, estimated cost, implementation effort, and expected risk reduction, enabling rational budget prioritization within a limited security budget.

## Task - 15-predecessor_review.md

Concept: Peer review of a security assessment compares independent conclusions on the same findings, resolving agreements, disagreements, and gaps that one analyst caught and the other did not. This cross-validation process strengthens the quality of the final assessment and highlights how different analysts can disagree on severity even when facing the same facts — requiring an explicit justification for every disagreement.

## Task - 16-security_posture_assessment.md

Concept: A security posture assessment is the formal report that consolidates all prior work — assets, data, controls, gaps, and risk decisions — into a structured document with an executive summary, scope, methodology, findings, and recommendations. It is the final product that turns fragmented technical analyses into a coherent narrative about the organization's security state.

## Task - 17-ciso_briefing.md

Concept: An executive briefing (for a CISO/board) translates complex technical findings into business language, focusing on financial impact, operational risk, and priority actions with clear cost and timeline. Communicating with leadership requires stripping away technical jargon and using cost-benefit comparisons (e.g., cost of the fix vs. cost of a real incident) to justify security investment.
