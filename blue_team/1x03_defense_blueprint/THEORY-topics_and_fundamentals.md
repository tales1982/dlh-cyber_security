# Theory and Topics — 1x03 Defense Blueprint

Study guide with theory + practical examples from the MedDefense scenario, for every exercise in this module. This module is different from 1x01 (which mapped threats) and 1x02 (which scanned vulnerabilities): here the question shifts from "what could attack us" to **"what do we do about it, with what budget, and how do we prove to the Board the decision was rational."** It's the governance, quantitative risk, and strategy (GRC) module.

---

## 0. The Framework Landscape

**What it is:** understanding the three major security frameworks in the market — not as competitors, but as tools that operate at **different altitudes** of the same problem.

**The three frameworks:**
- **NIST CSF 2.0:** a strategic, voluntary, **outcome-based** framework ("what" should be achieved, not "how" to do it technically). Structure: 6 Functions (Govern, Identify, Protect, Detect, Respond, Recover) → 22 Categories → 106 Subcategories. Used to talk to the Board and build a "Current Profile vs. Target Profile" gap analysis.
- **CIS Controls v8:** an operational, prescriptive framework, distilled from real attack data. Structure: 18 Controls → concrete Safeguards, organized into 3 cumulative Implementation Groups — **IG1** (56 safeguards, essential hygiene for any organization), **IG2** (+74, 130 total, more complex environments), **IG3** (+23, 153 total, sophisticated/nation-state threats). It answers exactly the question CSF leaves open: "specifically what do I implement, and in what order?"
- **ISO/IEC 27001:2022:** an international, **certifiable** governance and assurance standard — not a technical checklist, an Information Security Management System (ISMS). Structure: Clauses 4-10 (mandatory management-system requirements) + Annex A (93 candidate controls across 4 themes: Organizational 37, People 8, Physical 14, Technological 34). Used to **prove** to third parties (auditor, insurer, regulator) that security is managed, not just implemented once.

**The "three altitudes" metaphor:** CSF says **what** (strategic) → CIS Controls says **how** (operational) → ISO 27001 guarantees this is being **managed continuously and auditably** (assurance). A mature organization typically uses all three together.

**How to choose for a small organization (the MedDefense exercise):** with only one analyst and a Deputy CISO, no formal CISO, the recommendation is **CSF 2.0 as the strategic backbone + CIS Controls (IG1, then IG2) as the implementation layer**, deferring ISO 27001 certification — because certifying a management system before the controls it would certify even exist would be certifying a program that isn't there yet.

**Example:** Sarah Park admits "we follow no framework formally" → this doesn't mean starting from zero: projects 1x00/1x01/1x02 already generated evidence (Asset Registry, Threat Actor Matrix, Vulnerability Assessment) that directly feeds the CSF Current Profile.

---

## 1. NIST CSF Mapping

**What it is:** applying the CSF 2.0's 6 Functions to MedDefense's real environment, assessing **where the organization is today** (Current Profile) and **where it needs to get to** (Target Profile).

**The 6 Functions:**
| Function | Key question |
|---|---|
| **Govern (GV)** | Is there a documented strategy, roles, policy and risk appetite? |
| **Identify (ID)** | Do we know what assets we have and the risk of each? |
| **Protect (PR)** | Do safeguards exist (MFA, hardening, access control)? |
| **Detect (DE)** | Can we notice an attack in progress? |
| **Respond (RS)** | Do we have a tested plan to act during an incident? |
| **Recover (RC)** | Can we get back to normal after the incident? |

**Maturity scale used in the exercise:** Not Implemented → Partial → Managed (a simplified scale; not to be confused with the official **CSF Implementation Tiers** — Tier 1 Partial, Tier 2 Risk Informed, Tier 3 Repeatable, Tier 4 Adaptive — which describe the maturity of *risk management as a whole*, not each Function individually).

**Golden rule of the exercise:** every assessment needs **concrete evidence** from the prior projects, never a loose opinion.

**Example:** Govern = Not Implemented, evidenced by "we follow no framework formally" (GV.PO), the absence of a CISO (GV.RR), and 1x00's G-005 (only Preventive controls exist, no Detective/Corrective/Compensating/Deterrent) → GV.OV (oversight) doesn't exist because there's no mechanism using the results of security activity to adjust strategy.

---

## 2. CIS Controls Audit

**What it is:** auditing each of the 18 CIS Controls against real evidence, assigning a score (Implemented / Partial / Not Implemented) — a second lens on the same environment, more prescriptive than CSF.

**Pattern discovered in the audit:** **zero controls fully Implemented** — 8 Partial, 10 Not Implemented. This isn't rhetorical exaggeration: every control that exists in some form (backup, training, antivirus) is present but incomplete, unverified, or covers only part of what it should. This mirrors the exact pattern from 1x00's Gap Analysis: MedDefense over-invests in partial preventive measures and has almost nothing tested or actively monitored.

**How to prioritize the 18 controls (the exercise's Top 5):**
1. **Control 6 (Access Control/MFA)** — highest leverage, lowest cost (already-paid O365 licensing).
2. **Control 12 (Network Infrastructure/Segmentation)** — amplifies (or reduces) the risk of *every* other finding by orders of magnitude.
3. **Control 8 + 13 (Log Management + Network Monitoring)** — the organization's core failure pattern ("discovered by accident, not by design") can only be fixed by working detection.
4. **Control 7 (Continuous Vulnerability Management)** — without a recurring remediation process, 1x02's vulnerability scan becomes a snapshot that decays the day after delivery.
5. **Control 11 (Data Recovery)** — ransomware is the #1 threat and the backup has never been tested at scale.

**Example:** Control 4 (Secure Configuration) = Not Implemented, because 7 of 7 BD Alaris infusion pumps keep unchanged default credentials, and 13 of 1x02's 31 findings are misconfigurations/permissive settings.

---

## 3. Gap-to-Framework Bridge

**What it is:** the "bridge" connecting everything already gathered across the three prior projects — turning an isolated gap into a complete traceability chain.

**The traceability chain:** `GAP-XXX (1x00) → vulnerability evidence (1x02) → threat context/kill chain (1x01) → NIST CSF Function → CIS Control → recommended action`.

**Why this bridge matters:** it's what turns "I think we should have MFA" into an auditable sentence: "GAP-014 appears in Kill Chains #1/#2/#5, violates CSF's PR.AA, and CIS Control 6's Safeguard 6.3 — and 1x02's Finding 009 confirms the door is still open today." No single framework citation proves anything alone; the strength is in correlating all four.

**Example:** GAP-002 (no detection capability at all) appears across **all 6 actor types**, 4 of 5 kill chains, and all 3 threat scenarios from 1x01 — the single most universal gap in the entire module — mapping to the Detect Function (DE.CM/DE.AE) and CIS Controls 8 and 13, with the recommended action: deploy a SIEM (Wazuh) with a named owner reviewing alerts daily.

---

## 4. Governance Architecture

**What it is:** designing who decides what — the governance structure that was completely missing before this project (Govern = Not Implemented in Task 1).

**RACI Matrix — the 4 roles:**
- **R (Responsible):** who does the work.
- **A (Accountable):** who answers for the outcome — only one person per activity, never more than one (otherwise the ambiguity of "whoever shouts loudest decides" returns).
- **C (Consulted):** who is asked before the decision.
- **I (Informed):** who is only told afterward.

**Data governance roles (privacy/GDPR terminology applied in a HIPAA context):**
| Role | Who | Responsibility |
|---|---|---|
| **Data Owner** | CEO (org-wide); Dept Heads (domain-specific) | Decides classification, who accesses, protection level — business authority, not technical |
| **Data Controller** | The organization (MedDefense) | Determines **why** and **how** data is processed |
| **Data Processor** | Vendor (e.g., MedTech Solutions) | Processes data **on behalf of** the Controller, no independent authority over purpose |
| **Data Custodian/Steward** | IT Director + Security Analyst | Executes day-to-day protection (backup, access, encryption) — **does not decide** what should be protected, only implements |

**Classic confusion this model resolves:** "Sarah thinks she owns endpoint security because IT manages the endpoints" — Custody and Ownership are different roles; the RACI matrix exists specifically to make that distinction operational, not theoretical.

**The vacant CISO question:** without a CISO, no one has both authority **and** exclusive mandate for final security decisions — this explains why James, Sarah and Dr. Patel each believe they own overlapping pieces of the program. Recommended solution: a **vCISO (virtual/fractional CISO)**, typically $3,000-$8,000/month, rather than a full-time hire (which would cost $150,000-$200,000/year — more than the entire technical budget).

**Example:** Vendor Risk Assessment gives the Security Analyst an "R" (not just "C"), a direct response to 1x01's Scenario 3 ("The MedTech Backdoor") — no one at MedDefense assessed vendor risk before.

---

## 5. The Risk Equation

**What it is:** the core of this module — learning to calculate risk in **dollars**, not color-coded labels (High/Medium/Low), using the classic quantitative risk analysis formula.

**The variables:**
- **AV (Asset Value):** the value at risk — not always the cost of the asset itself, usually the **full cost of the incident** (downtime + recovery + fine + reputation).
- **EF (Exposure Factor):** what percentage of AV materializes when the event happens (0-100%). A binary event ("the server was encrypted or not") has EF = 100%; a partial event would have a lower EF.
- **SLE (Single Loss Expectancy) = AV × EF:** the cost of **one** event.
- **ARO (Annualized Rate of Occurrence):** how many times per year the event is expected (can be < 1, e.g., 0.25 = once every 4 years; or > 1, e.g., 2.5 = two and a half times per year).
- **ALE (Annualized Loss Expectancy) = SLE × ARO:** the expected cost **per year** — the final metric used to compare risks and justify budget.

**Practical rules to avoid getting the math wrong:**
- **Never count the same cost twice.** If a source figure already bundles detection+notification+legal into a "per-record" value, don't also add the itemized notification/litigation items separately.
- **ARO must reflect the organization's real context, not just the sector average.** If the asset has already been compromised before through the same flaw, ARO goes above the sector baseline.
- **Always state a confidence level and which assumption would change the result most.** This is what separates a serious GRC estimate from "a guess dressed up as math."

**Example:** Ransomware on the billing server → AV = $473,000 (downtime $288k + recovery $85k + HIPAA fine $100k) → EF 100% (binary event) → SLE = $473,000 → ARO adjusted to 0.4 (above the sector average of 0.29, because the server **has already been compromised once** and the vulnerable Apache instance remains unpatched) → **ALE = $189,200**.

---

## 6. The ALE Workshop

**What it is:** applying item 5's formula risk after risk, and — the new step here — calculating **ALE after the proposed control**, to measure the real value of investing in mitigation.

**Additional formula:**
- **Estimated ALE After Control:** recalculates SLE × ARO assuming ARO drops (the control usually doesn't eliminate AV, it reduces the probability of the event happening).
- **Net Benefit = ALE(before) − ALE(after) − Control's Annual Cost.**

**Why ALE(before) alone isn't enough:** ranking by raw ALE isn't the same ranking as "which asset matters most" — likelihood × impact math and categorical severity (e.g., patient safety) are **two different lenses**, and a mature risk program needs both, not just one.

**Notable example (Risk 4, medical devices):** the financial Net Benefit is very thin ($1,750) because segmentation is expensive relative to the pure ALE — but this **doesn't** mean the control is bad: patient-safety findings are categorical, not purely financial. The justification here is ethical/clinical, not just the spreadsheet.

---

## 7. Cost-Benefit Analysis

**What it is:** generalizing the ALE Workshop to **any candidate control** (not just the 5 target risks), with a formal verdict.

**Structure of each analysis:**
- **Annual Cost:** the control's recurring cost.
- **ALE Reduction:** how much risk (in $) the control removes, summed across every risk it affects (a control can mitigate more than one risk at once).
- **Net Value = ALE Reduction − Annual Cost.**
- **Verdict:** **Justified** (positive and solid) / **Marginal** (positive but thin, or competes with better options) / **Not Justified** (negative — costs more than the risk it removes).

**Why a control can be "Marginal" even with positive Net Value:** if it consumes the entire budget and blocks four other higher-value controls, the "isolated" positive value doesn't matter — the budget decision is always **relative**, never absolute (Control 7, the 24/7 SOC, is the classic example of this).

**Example of "Not Justified":** Control 8 (premium medical-device isolation with dedicated monitoring) has **negative** Net Value (-$16,300) because Control 1 (basic segmentation) already captures most of the addressable value at a lower cost — paying more for a marginal improvement is not rational risk management.

---

## 8. Budget Allocation

**What it is:** solving security's classic "knapsack problem" — choosing which controls to fund within a **fixed budget** ($120,000), maximizing risk reduction per dollar spent.

**Method:** rank controls by **cost-benefit ratio** (ALE Reduction ÷ cost, or Net Value), fund in that order until the budget runs out — not by arbitrary preference or convenience.

**Key concept — Opportunity Cost:** by **not** funding a control, the organization implicitly accepts the risk that control would have removed. This must be stated in dollars, not hidden — "by deferring the 24/7 SOC, we accept ~$30,000/year in additional exposure that continuous coverage would remove beyond what the SIEM already covers."

**"Surgical scoping" technique:** sometimes a cheaper control, aimed precisely at the documented gap, outperforms the "full" version of the same control. Example: EDR across all ~387 endpoints would cost $30,000 at full value; but since GAP-005 specifically excludes **servers** (workstations already have baseline Sophos), a version scoped to ~15 servers costs $6,000 and captures ~80% of the value — a fix aimed precisely at the actual gap outperforms a broader fix that partly pays for coverage that already exists.

**Example:** a greedy selection by Net Value funds MFA, SIEM, backup replication, segmentation and the Westside firewall for $103,400, leaving $16,600 in reserve — the 24/7 SOC alone would consume the entire budget and is deferred, not because it lacks value, but because **five** higher combined-value controls fit in the same money.

---

## 9. The CFO Challenge

**What it is:** the skill of **defending** risk/budget decisions against real executive objections — risk communication, not just risk calculation.

**Recommended 4-step response structure for every objection:**
1. **Acknowledgment:** genuinely validate the concern, without being defensive.
2. **Counter-Evidence:** bring the specific fact/data that resolves the objection.
3. **Business Framing:** translate into the language the executive already uses (e.g., insurance, ROI, budget precedent).
4. **Recommendation:** a concrete action, not a generic restatement.

**Classic CFO/Board objections (and the logic behind each answer):**
- *"We've never been breached"* → counter-evidence: there have already been two real incidents (ransomware + cryptominer), through the same door that's still open.
- *"Your ALE numbers are just estimates"* → the right answer isn't to defend the number's precision, it's to show the decision **survives** even if the number is wrong by a wide margin (a sensitivity check).
- *"Insurance is cheaper than controls"* → insurance and controls don't compete for the same dollar: missing controls (MFA) are increasingly grounds for a **denied claim** by the insurer — the investment protects the enforceability of the policy itself.
- *"This should be regular IT budget, not a special ask"* → it's precisely because security never had its own line item that the critical gaps exist; a distinct budget line is itself a governance control.
- *"Can we start with $60,000?"* → data-driven phasing: the highest-value items are already the cheapest ones, so a budget cut captures disproportionately little lost value.

**Example closing statement:** the combined ALE of doing nothing = ~$1,097,200/year; the $103,400 program reduces this by ~$587,750 → **roughly $5.68 returned for every $1 invested**, calculated with the same rigor any other capital investment would be evaluated.

---

## 10. The Risk Register

**What it is:** the formal, living document consolidating **every** identified risk into a single traceable register, with an owner, treatment, and monitoring indicator — the central GRC (Governance, Risk & Compliance) tool.

**Formal scales:**
- **Likelihood (1-5):** Rare (>10 yrs) → Unlikely (5-10) → Possible (2-5) → Likely (1-2) → Almost Certain (<1 yr or already ongoing).
- **Impact (1-5):** Negligible → Minor → Moderate → Major → Severe/Catastrophic (patient safety or existential financial/regulatory exposure).
- **Inherent Risk Score = Likelihood × Impact** (raw score, before any control).

**Mandatory fields per entry:** description, category (Strategic/Financial/Operational/Compliance), threat source, vulnerability, affected asset, likelihood, impact, score, ALE, **Risk Owner** (a named person, never "the team"), **Treatment Decision** (see item 16), planned control, residual risk, **KRI (Key Risk Indicator)**, and review date.

**KRI (Key Risk Indicator):** a measurable, specific metric that **anticipates** the risk materializing — not the same thing as a generic log. E.g.: "number of failed MFA attempts per week" (a spike indicates an active credential attack); "active accounts whose termination date has passed by more than 24h" (should always be zero).

**Register governance:** monthly review by two owners (Deputy CISO + IT Director); any KRI breach triggers **immediate** review, not waiting for the monthly cycle — the entire purpose of tracking a KRI is catching a risk drifting toward its next incident before the calendar does.

**Example:** RISK-008 (unidentified shadow-IT device at Westside) can't have a formal Treatment Decision yet, because **a risk on an asset that isn't even inventoried cannot be formally accepted, transferred, or mitigated** — containment (network block) must precede any longer-term treatment decision.

---

## 11. The Control Selection

**What it is:** for each risk in the register (item 10), choosing the specific control and classifying it technically — the bridge between "we decided to mitigate" and "here is exactly the mechanism."

**Control Types — the classic security classification:**
| Type | What it does | Example in this module |
|---|---|---|
| **Preventive** | Stops the event before it happens | MFA, patching, resetting default credentials |
| **Detective** | Notices the event happening | SIEM, bulk-export alerting |
| **Corrective** | Restores after the event | Immutable backup replication |
| **Compensating** | Reduces risk without eliminating the underlying vulnerability | Medical device segmentation (the device flaw still exists, it just becomes unreachable) |
| **Deterrent** | Discourages the attempt (mentioned as an absent category in 1x00) | Policy + visible training |

**Control Category (a dimension orthogonal to type):** **Technical** vs **Administrative** vs **Physical**.

**Mandatory cross-mapping:** every selected control must cite a **CIS Control/Safeguard** + **NIST CSF Function** — returning to item 3's "bridge," now at the individual-control level rather than the gap level.

**Dependency Mapping (implementation layers):** some controls only work if another is already live. E.g.: "SIEM depends on a current asset inventory"; "vendor-account MFA depends on core MFA already being active." This organizes rollout order into layers (Layer 0 = no prerequisite, Layer 1 = depends on Layer 0, etc.) and reveals which control is the **architectural foundation** others build on (here, MFA).

**Example:** MFA is flagged as the control with the most dependents in the map — it's a direct prerequisite for extending MFA to vendor accounts and reduces the SIEM's triage load (fewer credential-based alerts to review).

---

## 12. Acceptable Use Policy (AUP)

**What it is:** the organization's first formal, signable policy — turning "please don't do that" into a documented, enforceable standard everyone agreed to upon joining.

**Typical AUP structure:** Purpose and Scope → Acceptable Use → Prohibited Activities → Personal Devices/Removable Media → Password/Authentication Requirements → Data Handling → Monitoring and Enforcement → Acknowledgment/Signature.

**Good-practice principle used in the exercise:** **every prohibition must map to a real, already-documented risk**, not be a generic list copied from elsewhere — this makes the policy defensible and easy to justify to anyone asking "why does this rule exist?"

**Proportional enforcement:** an unintentional violation with no real data exposure (e.g., a misplaced, empty USB drive) results in a documented conversation + refresher training; a violation with actual data exposure, or deliberate circumvention of controls, escalates to HR and disciplinary action; suspected bad-faith activity (e.g., a bulk export before a resignation) goes straight to the Deputy CISO as an incident, independent of any HR process.

**Example:** the prohibition on "connecting a personal or vendor device to the clinical or server network without prior approval" exists because MedDefense **already found** a personal laptop bypassing network controls for three weeks and a Raspberry Pi connected to the medical device network "just to monitor performance" — neither malicious, both creating real, unmanaged risk.

---

## 13. The Quick Wins

**What it is:** fixes that require no new budget, no vendor contract, and no dependency on another project — quick proof that the security program already delivers results before the bigger builds (SIEM, segmentation) even finish their first phase.

**Criteria that define a "quick win" (all must be true):**
1. Near-zero cost (uses existing access/licensing).
2. No dependency on another not-yet-implemented control.
3. Short timeline (days, not months).
4. Disproportionately high risk reduction for the effort.

**The step that can never be skipped: Verification.** Every quick win in the exercise has an explicit technical verification step (e.g., attempting to connect to the now-blocked port and confirming the connection is refused) — the discipline of **confirming a fix actually worked**, instead of assuming it did, is the same discipline the program will need at much larger scale once the SIEM and segmentation arrive.

**Example:** disabling the Tomcat AJP connector on `ehr-srv-01` (Quick Win #1) costs $0, takes 2 days, and alone closes the most severe finding (CVSS 9.8, Ghostcat) in 1x02's entire scan — the single highest risk-reduction-per-effort action in the whole program.

---

## 14. The Segmentation Architecture

**What it is:** the network design replacing MedDefense's completely flat `/16` with **isolated zones under a default-deny policy** between them — the opposite of "open by omission everywhere" that existed before.

**Core principle: default-deny.** Any zone-to-zone path not explicitly permitted is **denied by default** — the rule list is the complete list of allowed exceptions, not a list of blocks layered over an otherwise-open base.

**The typical 5 zones (VLANs):** Server Zone, Clinical Workstation Zone, Medical Device Zone, Management Zone (the one zone with broad reach, since it's the trusted administrative plane — every session there is MFA-gated), and Guest/IoT Zone.

**Related concept — Zero Trust:** never automatically trust anything, not even internal traffic; every communication must be explicitly permitted.

**Evaluation methodology: Kill Chain Disruption Analysis.** After designing the architecture, you **walk through each step of every already-documented kill chain** (from 1x01) and ask: "does this specific step still work against the new architecture?" This proves (or disproves) segmentation's value with concrete evidence, not a generic claim of "we improved security."

**Segmentation's honest limit:** it's a **network** control. It doesn't stop phishing (Step 1) or DNS/egress-based C2 (Step 2) in a kill chain — and it can't, by definition, stop an insider using access **already legitimately authorized** within their own zone (Kill Chain #3) — that's an access-governance problem, not a network-architecture one, and requires a different control (item 11).

**Example:** Kill Chain #1 (ransomware) breaks decisively at Step 3 (Discovery) — the compromised workstation, now stuck in the Clinical Workstation Zone, can only reach port 443 on the Server Zone; the network-mapping step that fed every subsequent step simply finds nothing to map.

---

## 15. Red Team Your Blueprint

**What it is:** the **adversarial self-critique** exercise — putting on the attacker's own hat and asking "given everything we just built, what still works against us?"

**Why this is a formal step, not an extra:** every defense blueprint has blind spots that only surface when someone actively tries to break it — the same logic behind a pentest, applied to the plan itself rather than to an already-deployed system.

**Critical distinction this exercise teaches:** there's a difference between a gap that's **closed**, a gap that was **never funded** (identified, costed, but never actually competed for the budget), and a gap that's **structurally unreachable** by a given type of control (e.g., network segmentation can't, by its nature, stop someone who already has legitimate access within their own zone). Confusing these three categories produces false confidence.

**How to reach a residual risk verdict:** not "everything's fixed, risk is Low" nor "nothing's fixed, risk is Critical" — it's an honest reading of **which paths, specifically, remain open** after the proposed controls, and why.

**Example:** even after MFA, SIEM and segmentation, Kill Chain #3 (insider exfiltration) remains **completely untouched**, because its specific control (RISK-004, $8,000) was identified and costed in Task 6, but never actually competed for funding in the Task 7/8 process — despite $16,600 left over that would have covered it twice. This is the exercise's sharpest finding: not every known gap ends up funded, even when money is left unspent.

---

## 16. The Risk Appetite Debate

**What it is:** formalizing **how much risk the organization is willing to tolerate**, and who has the authority to accept each level — without this, "accepting the risk" becomes an informal excuse rather than a recorded governance decision.

**The 4 formal risk treatment strategies:**
- **Mitigate:** reduce the probability or impact with a control.
- **Accept:** tolerate the risk as-is, consciously and with sign-off at the right level.
- **Transfer:** shift the financial cost to a third party (e.g., cyber insurance).
- **Avoid:** eliminate the activity/asset generating the risk entirely.

**Structure of a Risk Appetite Statement:** defines numeric authority thresholds — e.g., any risk acceptance above a stated ALE amount, or touching a Critical asset, requires the Deputy CISO's sign-off; above a higher amount, or touching **patient safety**, requires the CEO's personal sign-off. **Patient safety is treated as an absolute limit:** it may be temporarily accepted, but never without a measurable compensating measure — "accept and move on" with no associated control is not a governance decision, it's neglect wearing a governance decision's clothing.

**Every accepted risk needs 3 elements, no exceptions:** sign-off authority at the right level, a named **Compensating Measure**, and a specific **Review Trigger** (an event that forces immediate reassessment, not a distant fixed date).

**Example (Decision 1, Windows XP on the MRI control workstation):** accepting the risk for a bounded period (18 months, until the equipment lease expires) is justifiable because breaking the lease would cost more than the mitigated risk itself — but the acceptance is only valid with segmentation **verified operational** (not just funded) as the compensating measure, and an immediate review trigger on any confirmed segmentation failure.

---

## 17. Security Strategy Document

**What it is:** the final executive document that **consolidates** all the work from Tasks 0-16 into a single Board-facing report — governance, quantitative risk, control selection, architecture and policy, all tied together.

**Recommended structure:** Executive Summary (ROI in one sentence) → Governance Framework → Quantitative Risk Analysis → Control Strategy → Architecture Recommendations → Policy Foundation → Residual Risk Assessment → Implementation Roadmap → Next Steps.

**Why this isn't "just stapling the prior files together":** an executive report needs to **translate** technical artifacts (RACI, ALE, CIS scorecard) into a narrative the Board can evaluate and approve in a single meeting — the same discipline as 1x01's item 18 Threat Landscape Report, now applied to the strategy/budget layer instead of the threat layer.

**An element that can't be missing: honesty about residual risk.** A strategy report that claims "we fixed everything" loses credibility at the first audit; explicitly including what the Red Team (item 15) found still open is what makes the document trustworthy.

**Example of the "Next Steps":** the document explicitly connects this project to the curriculum's next one (1x04, Cryptographic Foundation) — showing that "Restricted data must be encrypted" (a policy statement from item 12) still needs to become a specific implemented technical standard, this isn't the end of the journey.

---

## 18. The 6-Month Security Roadmap

**What it is:** turning the strategy (item 17) into a **month-by-month executable schedule**, with an explicit owner, dependency, and completion criterion for every action — without this, an approved strategy dies in a drawer.

**Mandatory elements per month:** Actions → Owner (a named person) → Dependencies (what must be ready first) → Completion Criteria (how to know, objectively, the month was fulfilled — never "we think it's good").

**Dependency Chain as a sequencing tool:** some work **has to** come before other work for structural reasons, not preference — e.g., the network-zone architecture (Month 3) must exist before a specific zone (medical device) can be isolated within it (Month 4); a freshly-deployed SIEM produces noise, not signal, so alert-response drills only make sense after months of tuning.

**Milestones vs. day-to-day actions:** a milestone is a high-level checkpoint with a binary, measurable success indicator (e.g., "0 failed reachability tests across all zones"), distinct from a task list — it lets the Board track progress without getting into operational detail.

**Managing risk to the schedule itself (Risk to Timeline):** a mature roadmap anticipates **what could delay it** (clinical staff resistance to workflow changes; vendor/procurement delays) and already builds in the contingency (a small pilot rollout before mandatory; starting every dependency-free action in Month 1 with built-in slack for hardware delays).

**Example:** PACS badge authentication has already been rejected once on workflow grounds — the contingency is reusing the same 48-hour pilot pattern used for the USB GPO, and using the training responsibility already assigned to department heads (item 4) to build buy-in **before** announcing a mandatory rollout date.

---

## 19. Board Pitch

**What it is:** the most compressed version of everything — a one-page executive communication, built to last just a few minutes of a budget-approval meeting.

**Structure of an effective board pitch:** Current State (the problem, no jargon) → The Risk (a single ALE number the Board recognizes as having already happened, not hypothetical) → The Plan (a few named actions, not generic "more security") → The Return (ROI in one sentence, comparable to any other capital decision the Board already evaluates).

**Why "it already happened" is more persuasive than "it could happen":** a risk number anchored to a real incident the organization already lived through (not a generic sector statistic) is much harder to dismiss as fear-mongering — the same logic used in item 9's Objection 1.

**Style rule:** zero untranslated technical jargon, zero large tables — every sentence needs to stand on its own if read aloud in a meeting room.

**Example:** "we are not unlucky — we are unprotected, and it has already cost us twice" sums up, in one sentence, the entire module's central finding (zero fully-implemented controls, two real incidents through the same door) without needing a single table.

---

## Dependency order across the files

```
0 landscape overview of the 3 frameworks (CSF, CIS, ISO)
 └─ 1 CSF Current/Target Profile · 2 CIS Controls Audit  (two lenses on the same environment)
     └─ 3 gap-to-framework bridge (connects 1x00/1x01/1x02 to the frameworks)
         └─ 4 governance (RACI, data roles, CISO/vCISO)
             └─ 5 risk equation (AV/EF/SLE/ARO/ALE) · 6 ALE workshop (5 risks + control)
                 └─ 7 cost-benefit (every candidate control) · 8 budget allocation (fixed budget)
                     └─ 9 CFO challenge (defending the decision)
                         └─ 10 formal risk register (consolidates everything with likelihood×impact)
                             └─ 11 control selection (type/category/dependency per risk)
                                 └─ 12 AUP · 13 quick wins · 14 segmentation  (concrete execution)
                                     └─ 15 red team (blueprint self-critique)
                                         └─ 16 risk appetite (mitigate/accept/transfer/avoid, formally)
                                             └─ 17 security strategy (consolidated executive document)
                                                 └─ 18 6-month roadmap (execution, month by month)
                                                     └─ 19 board pitch (final communication, 1 page)
```

## Framework reference table (quick review before repeating the module)

| Framework/Concept | Used in | Core idea |
|---|---|---|
| NIST CSF 2.0 | Items 0, 1, 17 | 6 Functions, outcome-based, strategic "what" |
| CIS Controls v8 | Items 0, 2, 11 | 18 Controls + Safeguards, IG1/IG2/IG3, operational "how" |
| ISO/IEC 27001 | Item 0 | Certifiable ISMS, continuous assurance |
| RACI Matrix | Item 4 | Responsible/Accountable/Consulted/Informed — only one "A" per activity |
| Data Owner/Controller/Processor/Custodian | Item 4 | Who decides vs. who processes vs. who executes the protection |
| SLE / ARO / ALE | Items 5, 6 | AV×EF=SLE; SLE×ARO=ALE — risk in dollars per year |
| Net Value / Verdict | Items 6, 7 | ALE Reduction − Cost = net value; Justified/Marginal/Not Justified |
| Budget Allocation (knapsack) | Item 8 | Maximize risk reduction within a fixed budget; opportunity cost |
| Acknowledge-Counter-Frame-Recommend | Item 9 | Structure for responding to an executive objection |
| Likelihood × Impact (1-5) | Item 10 | Inherent Risk Score; KRI as an early warning |
| Control Type (Preventive/Detective/Corrective/Compensating/Deterrent) | Item 11 | Functional classification of any control |
| Default-deny / Zero Trust | Item 14 | Network segmentation, never trust by omission |
| Kill Chain Disruption Analysis | Item 14 | Testing the architecture step by step against already-mapped kill chains |
| Risk Treatment: Mitigate/Accept/Transfer/Avoid | Item 16 | The 4 formal strategies, with sign-off authority by threshold |
| Risk Appetite Statement | Item 16 | Numeric limits + the absolute patient-safety limit |

---

*Study guide — not part of the deliverable. Use as a theory checklist before reviewing or expanding any exercise in this module.*
