# 1x03 – Defense Blueprint

## Task - 0-framework_landscape.md
Concept: Compares the three major information security frameworks — NIST CSF, CIS Controls and ISO/IEC 27001 — explaining that each operates at a different "altitude": NIST CSF is strategic (what to achieve), CIS Controls is operational (how to implement, in priority order), and ISO 27001 is governance/certification (how to formally prove the program is managed). Mature organizations typically use all three together rather than as competitors.

## Task - 1-nist_csf_mapping.md
Concept: NIST CSF 2.0 organizes cybersecurity into six Functions (Govern, Identify, Protect, Detect, Respond, Recover), each broken into Categories and Subcategories describing desired outcomes rather than prescriptive technical steps. The exercise applies a "Current Profile vs. Target Profile" maturity analysis, rating each function's current level (Not Implemented, Partial, Managed) with supporting evidence and setting realistic improvement targets.

## Task - 2-cis_controls_audit.md
Concept: CIS Controls v8 is a prescriptive set of 18 defensive controls, prioritized from real-world attack data and organized into three cumulative Implementation Groups (IG1, IG2, IG3) based on organizational maturity and size. The exercise audits each control by assigning a maturity score (Implemented, Partial, Not Implemented) grounded in concrete environmental evidence.

## Task - 3-gap_framework_bridge.md
Concept: Shows how to connect specific technical weaknesses (vulnerability scan findings, threat scenarios) to formal framework categories (NIST CSF Functions and CIS Controls), translating raw security findings into an organized, traceable remediation structure that links technical evidence to governance language.

## Task - 4-governance_architecture.md
Concept: Security governance structure built around a RACI matrix (Responsible, Accountable, Consulted, Informed) defining who decides and who executes each security activity, plus the formal data roles (Data Owner, Data Controller, Data Processor, Data Custodian). Also covers the decision between hiring a full-time CISO versus a vCISO (virtual/fractional CISO) based on organizational maturity and budget.

## Task - 5-risk_equation.md
Concept: Introduces the classic quantitative risk calculation: SLE (Single Loss Expectancy) = AV (Asset Value) × EF (Exposure Factor), and ALE (Annualized Loss Expectancy) = SLE × ARO (Annualized Rate of Occurrence). This model turns qualitative risk ("high/medium/low") into an expected annual dollar figure, enabling risks to be compared and investments justified with numbers.

## Task - 6-ale_workshop.md
Concept: Deepens the practical application of the ALE formula to real risk scenarios, including calculating residual ALE after a proposed control is applied and the "Net Benefit" (avoided ALE minus control cost) — the core logic behind any risk-based security investment decision.

## Task - 7-cost_benefit_analysis.md
Concept: Cost-benefit analysis of security controls: compares a control's annual implementation cost against the ALE reduction it delivers, computing "Net Value" to determine whether the investment is justified (Verdict: Justified/Not Justified) and to prioritize controls by return.

## Task - 8-budget_allocation.md
Concept: Budget allocation under a capital constraint — ranking controls by cost-benefit ratio (ALE reduction per dollar spent) and funding them in that order until the budget runs out, maximizing total risk reduction. Introduces opportunity cost: the risk that remains exposed when a control is deferred or rejected.

## Task - 9-cfo_challenge.md
Concept: Executive risk communication to non-technical stakeholders (CFO/finance), rebutting common objections to security investment — no prior incidents, uncertainty in estimates, cyber insurance as a substitute for controls, and fractional budgeting. Teaches how to translate technical risk into business language and ROI.

## Task - 10-risk_register.md
Concept: The Risk Register is a formal risk-management tool documenting each risk with its source, affected asset, likelihood, impact, inherent risk score, ALE, risk owner, treatment decision (Mitigate/Accept/Transfer/Avoid), and KRI (Key Risk Indicator) for ongoing monitoring.

## Task - 11-control_selection.md
Concept: Formal selection of controls for each risk in the register, classifying them by type (Preventive, Detective, Corrective, Compensating) and category (Technical, Administrative, Physical), and mapping each to a specific CIS Controls and NIST CSF reference — connecting risk decisions to concrete implementation.

## Task - 12-acceptable_use_policy.md
Concept: Drafting an Acceptable Use Policy, a formal governance document defining how systems, data and credentials may be used by staff, listing prohibited activities, password/MFA requirements, and proportional consequences for violations — turning security expectations into an enforceable, documented standard.

## Task - 13-quick_wins.md
Concept: "Quick wins" are low-cost (or zero-cost), high-impact security fixes that can be implemented rapidly without budget approval, prioritizing speed of remediation to close the most critical vulnerabilities even before the larger budget plan takes effect.

## Task - 14-segmentation_architecture.md
Concept: Network segmentation — dividing infrastructure into isolated zones (VLANs) under a "default-deny" policy between them, allowing only explicitly necessary traffic. This is a core defense-in-depth technique that limits an attacker's blast radius even after an initial compromise.

## Task - 15-red_team_blueprint.md
Concept: A red team / adversarial-thinking exercise — adopting an attacker's perspective to critically stress-test one's own defense plan and identify attack paths that funded controls don't cover (typically insider threats and third-party/vendor trust), surfacing gaps a purely technical audit would miss.

## Task - 16-risk_appetite.md
Concept: Risk appetite is a formal statement of how much risk an organization is willing to accept, with defined thresholds (e.g., ALE above a certain value requires sign-off from a specific executive), applied to concrete risk-acceptance decisions with mandatory compensating measures and review triggers.

## Task - 17-security_strategy.md
Concept: A security strategy document that synthesizes all prior work (framework, governance, risk analysis, controls, budget) into a single executive report for the Board, connecting technical decisions to business outcomes and return on investment.

## Task - 18-roadmap.md
Concept: An implementation roadmap — sequencing security initiatives over time (by month), with owners, explicit dependencies between steps, and measurable completion criteria, turning a strategy into a realistic execution plan.

## Task - 19-board_pitch.md
Concept: A condensed executive pitch for Board budget approval — reducing a complex security program to a short, high-impact narrative focused on business risk, financial return (ROI), and urgency, suited for a non-technical decision-making audience.
