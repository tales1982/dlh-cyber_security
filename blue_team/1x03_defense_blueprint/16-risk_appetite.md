# 16. The Risk Appetite Debate — MedDefense Health Systems

**Analyst:** Security Analyst
**Date:** Current

## Part 1: Risk Appetite Statement

MedDefense accepts risk only when the cost of mitigation is genuinely disproportionate to the exposure it removes, or when an operational or contractual constraint makes immediate mitigation impossible — never as a substitute for a mitigation MedDefense can actually afford. **Risks to patient safety are an absolute limit: they may be temporarily accepted only when a compensating control measurably reduces the exposure in the interim, never accepted outright with no offsetting action.** Any risk with an Annualized Loss Expectancy above $50,000, or any risk touching a Critical asset (per the 1x00 Criticality Matrix), requires the Deputy CISO's documented sign-off to accept; any acceptance above $150,000 in ALE, or any acceptance touching patient safety at all, requires the CEO's personal sign-off, consistent with the Task 4 RACI matrix's own assignment of risk-acceptance accountability. Every accepted risk must carry a named compensating measure and a specific review trigger — an accepted risk with no monitoring attached is not a governance decision, it is neglect wearing a governance decision's clothing.

## Part 2: The Three Decisions

### Decision 1 — Windows XP EOL on the MRI Control Workstation

```
Risk: RISK-005 (extended) -- WS-RAD-01, Windows XP SP3, 1x02 Finding 004
Treatment Decision: Accept (for a bounded 18-month period)
Authority: CEO (Dr. Morales), per the Risk Appetite Statement above --
  this risk touches patient safety directly and exceeds the CISO-level
  sign-off threshold, requiring the highest authority in the
  organization.
Justification: The device cannot be replaced before the $2.1M MRI
  scanner lease expires in 18 months without incurring an early-
  termination cost that would almost certainly exceed this risk's own
  mitigated ALE many times over. Task 6 already reduces this risk's
  practical exposure substantially once the medical-device
  segmentation (Task 14, already funded in Task 8) is verified
  operational -- the residual exposure, not the raw pre-control
  exposure, is what is actually being accepted here.
Compensating Measure: Network segmentation restricting WS-RAD-01 to
  communicate only with pacs-srv-01 (Control 1, already funded);
  physical access restriction and USB port lockdown (Control 3 from
  the original 1x00 Task 6 strategy, not yet costed in this project
  and worth funding alongside this acceptance, since it is inexpensive
  and closes the one path segmentation cannot: physical access).
Review Trigger: Immediately upon confirmed segmentation failure (any
  reachability test showing WS-RAD-01 accessible from outside the
  medical device zone), any active exploitation attempt detected
  against this host, or 60 days before the scanner lease renewal date,
  whichever comes first.
```

### Decision 2 — Residual Medical Device DoS/Patient-Safety Risk Beyond Basic Segmentation

```
Risk: RISK-005 (residual, post-Control-1 segmentation)
Treatment Decision: Accept
Authority: Deputy CISO (James Chen) -- this residual sits below the
  CEO-level ALE threshold once segmentation is applied ($11,250
  combined, per Task 6), and does not represent a net-new patient
  safety exposure beyond what Decision 1 already covers for the MRI
  specifically.
Justification: Task 7's own cost-benefit analysis found the "premium"
  version of this control -- full medical device isolation with
  dedicated protocol-aware monitoring (Control 8) -- carries a
  negative net value (-$16,300): its incremental cost exceeds the
  incremental risk reduction it provides over segmentation alone.
  Paying for a control that costs more than the risk it removes is not
  rational risk management regardless of how appealing "more security"
  sounds in the abstract.
Compensating Measure: The segmentation already funded under Control 1
  remains in place and is periodically verified (Task 11's
  verification methodology); default credentials are reset
  fleet-wide (already a funded Quick Win, Task 13).
Review Trigger: Any confirmed compromise attempt against the medical
  device zone, or the emergence of a lower-cost dedicated-monitoring
  option that would flip Control 8's net-value calculation positive.
```

### Decision 3 — After-Hours Detection Gap (Deferring 24/7 SOC Coverage)

```
Risk: RISK-002 (residual, the portion of ransomware/domain-compromise
  risk that continuous human monitoring would additionally catch
  beyond Phase 1 SIEM)
Treatment Decision: Accept (for this fiscal year)
Authority: Deputy CISO (James Chen), with CFO (Robert Kim) informed
  given the direct budget trade-off involved.
Justification: Task 7 found the 24/7 outsourced SOC (Control 7) has a
  positive standalone net value ($60,000), but funding it would
  consume the entire $120,000 budget alone, leaving zero funding for
  five other justified controls that together deliver more total risk
  reduction for less combined money (Task 8). Accepting this
  particular residual is the direct, documented consequence of a
  higher-value budget allocation elsewhere, not an oversight.
Compensating Measure: Phase 1 SIEM (Wazuh) with business-hours analyst
  review, plus the monthly Risk Register review cadence (Task 10's own
  governance note) as a backstop against anything the SIEM flags but
  no one has yet reviewed.
Review Trigger: Any incident that occurs or is discovered outside
  business hours and was not caught until the following business day
  -- a single such event should trigger an immediate re-evaluation of
  this acceptance ahead of the next annual budget cycle, not a wait
  for next year's Board meeting.
```

## Part 3: The Debate

**James's argument (mitigate):** "This workstation runs three independently weaponized, self-propagating exploits — the same families that powered Conficker and WannaCry — and every one of them is listed in CISA's own actively-exploited catalog. This isn't a data risk, it's a patient-safety risk: a successful compromise doesn't just cost us money, it can interrupt an MRI scan on a real patient. Eighteen months is a long time for a wormable exploit to sit exposed, and 'the lease hasn't expired yet' is a financial calendar, not a security boundary. We should be finding a way to replace or fully isolate this device now, lease penalty or not."

**Robert's argument (accept):** "Breaking a $2.1 million equipment lease early to solve a risk whose own mitigated numbers — $11,250 in combined annual expected loss after segmentation — are a rounding error next to the termination penalty is not a rational trade. We already funded the segmentation that cuts this risk to a fraction of its raw exposure. The device is on a scheduled, budgeted replacement path in 18 months. Spending capital today to solve a problem that's already substantially reduced and already has an end date is not prudence, it's paying twice for the same outcome."

**My verdict:** I find Robert's financial reasoning more compelling on the numbers as they stand today — breaking a multi-million-dollar lease to address an already-mitigated $11,250/year residual is genuinely disproportionate, and Decision 1 above formalizes exactly this as an accepted risk. But James is right that "accept" cannot mean "accept and move on" here: my recommendation is conditional acceptance, not open-ended acceptance — the segmentation must be verified operational (not just funded) before this acceptance is valid, and the review trigger in Decision 1 (immediate re-evaluation on any confirmed reachability failure) is what keeps this from quietly becoming complacency. Both are right about different halves of the same decision: Robert about the math, James about the discipline required to make that math still hold six months from now.

## Repo

- **GitHub repository:** `dlh-cyber_security`
- **Directory:** `blue_team/1x03_defense_blueprint`
- **File:** `16-risk_appetite.md`
