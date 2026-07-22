# 9. The CFO Challenge — MedDefense Health Systems

**Analyst:** Security Analyst
**Date:** Current

## Objection 1: "We have never been breached. Why spend $120,000 now?"

**Acknowledgment:** It's fair to ask for evidence, not fear — no attacker has yet stolen or destroyed patient data at MedDefense, and that distinction matters.

**Counter-Evidence:** MedDefense has already had two real intrusions, not zero: the January ransomware event encrypted billing systems, and a cryptominer ran undetected on the same server for two weeks (1x00, Tasks 1-2) — both through the exact same unpatched Apache instance that remains open today (1x02, Findings 001/002). Sector data independently puts ransomware frequency at similar hospitals at once every 3-4 years, and MedDefense's own gap chain (no MFA, no detection, no AD tiering) is still fully intact.

**Business Framing:** The question isn't "will we be breached," it's "we already have been, twice, at a smaller scale, through a door that is still unlocked" — the $300,000 ransomware ALE is the actuarial cost of that door staying open, not a prediction of certainty.

**Recommendation:** Fund the two lowest-cost, highest-return items first — MFA ($4,000) and the SIEM ($28,000) — as low-risk proof that this investment produces measurable results before committing further.

## Objection 2: "Your ALE numbers are estimates, not facts."

**Acknowledgment:** Completely valid — ALE is a modeled estimate, and a 30% swing in ARO or exposure factor does move the final number meaningfully. I should not have presented a single point figure without showing how sensitive it is.

**Counter-Evidence:** Run the sensitivity check: even if the ransomware ARO were cut in half (0.125 instead of 0.25) and the exposure factor dropped to 40%, the ALE would still be roughly $100,000 — and MFA costs $4,000. The decision to fund MFA doesn't depend on the estimate being precise; it depends on the gap between cost and potential loss being large enough to survive being wrong by a wide margin, and it is.

**Business Framing:** This is the same logic behind every insurance and capital-reserve decision the finance team already makes — decisions under uncertainty are normal, and the right question is not "is the number exact" but "is the decision robust if the number is off."

**Recommendation:** I'll build a best-case/expected-case/worst-case range into the formal Risk Register (Task 10) going forward, rather than a single number, so this uncertainty is visible on its face instead of implied.

## Objection 3: "Insurance is cheaper than controls."

**Acknowledgment:** Correct that MedDefense should keep the cyber insurance policy — Transfer is a legitimate risk treatment strategy, and I'm not suggesting otherwise.

**Counter-Evidence:** The $1 million aggregate limit is smaller than Risk 1's own modeled realized loss ($2,000,000 at full severity) — a bad-enough event exceeds the policy outright. More importantly, cyber insurers increasingly deny or reduce claims when basic controls (MFA specifically) were absent at the time of the incident — and MedDefense currently has none. Insurance and controls are not substitutes competing for the same dollar; a policy with no underlying controls behind it is a policy at real risk of a disputed or reduced payout exactly when it's needed most.

**Business Framing:** The $120,000 investment isn't competing with the $38,000 premium — it's what keeps that premium's payout enforceable rather than contestable, and MFA specifically is now a common underwriting requirement for full coverage.

**Recommendation:** Keep the policy. Fund MFA and the other baseline controls as the condition that protects the policy's own value, not as a redundant expense against it.

## Objection 4: "This should be IT's regular budget, not a special ask."

**Acknowledgment:** The concern about budget precedent is legitimate — approving a special line item for one department does invite the same request from others.

**Counter-Evidence:** Security has effectively been part of Sarah's operational budget for years already, informally — and that arrangement is exactly why GAP-002 (zero detection capability) and GAP-014 (no MFA anywhere) exist: security always loses the day-to-day budget fight against keeping email and clinical systems running when it isn't protected as its own line. This isn't a new department asking for special treatment; it's the direct, documented consequence of never having one.

**Business Framing:** A distinct, traceable security budget is itself a governance control — it's specifically what Sarah told the auditors MedDefense was missing when she said "we follow no framework formally," and a separately reportable line item is easier to defend to HIPAA auditors and the cyber insurer alike, not harder.

**Recommendation:** Fund this year's request as a distinct line item for traceability during this initial build-out; going forward, security funding can be folded into a structured, recurring line within IT's broader governance rather than a one-time special ask every year.

## Objection 5: "Can we start with $60,000 and see if it works?"

**Acknowledgment:** This is a completely reasonable, standard approach for a new program, and it deserves a straight answer, not a defense of the full number on principle.

**Counter-Evidence:** The math already supports this almost exactly. MFA ($4,000) + SIEM ($28,000) + backup replication ($14,400) totals **$46,400** — under the $60,000 offer — and captures **$462,000 of the total $587,750 in identified risk reduction, roughly 79% of the value for under half the cost.** What gets deferred at $60,000 (segmentation, the Westside firewall, and the EDR upgrade) totals roughly $125,750 in remaining risk reduction — a meaningful amount, but concentrated in the lower-ROI half of the plan, not the half that matters most in year one.

**Business Framing:** Phasing isn't a concession forced by budget pressure here — the data independently shows the highest-value items are also the cheapest ones, which is the ideal case for a "prove it, then scale" argument.

**Recommendation:** Fund Phase 1 (MFA, SIEM, backup replication, $46,400) this cycle, with the remaining ~$13,600 of the $60,000 offer applied to the Westside firewall; commit Phase 2 (segmentation and the remaining EDR scope, ~$57,000) to next fiscal year once Phase 1's SIEM alert and response metrics demonstrate results — exactly the proof point the Board asked for.

## Closing Statement

Across the five highest-priority risks identified in this analysis, the combined Annualized Loss Expectancy of doing nothing is approximately **$1,097,200 per year** — not a worst-case scenario, but the actuarially expected annual cost of leaving the currently open gaps exactly as they are. The proposed $103,400 program (or its $46,400 first-phase subset, per Objection 5) reduces that exposure by roughly $587,750 — meaning every dollar spent returns approximately $5.68 in avoided expected annual loss, calculated the same way any other capital investment at MedDefense would be evaluated. The cost of inaction is not hypothetical; it is a number already built from two incidents MedDefense has actually lived through, and it will keep recurring on the same schedule, at the same or greater expense, for as long as the underlying gaps remain open.

## Repo

- **GitHub repository:** `dlh-cyber_security`
- **Directory:** `blue_team/1x03_defense_blueprint`
- **File:** `9-cfo_challenge.md`
