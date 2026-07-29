# 5. The ALE Update MedDefense Health Systems

**Analyst:** Security Analyst
**Date:** Current

## Part 1 Original vs Updated ALE

**Original calculation (1x03 Task 6, Risk 1 Ransomware encrypts domain-joined systems):**

```
Asset Value (AV): $2,000,000
Exposure Factor (EF): 60%
SLE: $2,000,000 x 0.60 = $1,200,000
Original ARO: 0.25 (once every 4 years — matched the generic sector rate for ransomware
  against similar-profile hospitals)
Original ALE: $1,200,000 x 0.25 = $300,000
```

**What changed:** the original ARO of 0.25 was built from a *generic sector base rate* "hospitals like this get hit roughly once every 3-4 years," applied before any specific active campaign was known. The Crimson Tide advisory is not a base rate. It is a documented, currently-active, geographically-clustered campaign that has already claimed 3 confirmed victims in MedDefense's own region in the last 10 days one (Hospital C) only 45 miles from MedDefense Central using a playbook that, per Task 0's Overall Exposure Score, matches 6 of 7 of MedDefense's own currently-open gaps exactly. This is not "hospitals in general are at risk." This is "an active affiliate network is confirmed to be running this exact chain against confirmed regional peers this week, and MedDefense is not merely profile-similar, it is precondition-identical."

**Updated ARO: 0.75** (Likely, bordering Almost Certain, per the 1x03 Risk Register's own likelihood scale). This reflects that, absent the emergency actions in Task 3, compromise by this specific campaign or an immediate imitator using the now-public disclosed TTPs should be treated as more likely than not within the current 12-month window. It stops short of 1.0 because the Tier 1 actions already underway tonight (NAS-01 isolation, firmware verification) do meaningfully reduce exposure even before the full 72-hour plan completes.

**Updated Exposure Factor: 85%** (up from 60%). The original 60% was justified by precedent MedDefense's own prior ransomware incident was contained to the billing server, not domain-wide, so "not every event escalates to the worst case" was a reasonable discount. Crimson Tide's confirmed playbook specifically neutralizes the exact mechanism that kept that prior incident contained: it destroys backup infrastructure (Phase 5) *before* deploying ransomware, precisely to remove the "recover from backup, stay contained" outcome. With NAS-01 still unencrypted and on the same flat network as every one of the 5 real victims, the compensating factor behind the original 60% no longer holds against this specific actor.

**Updated SLE:** `$2,000,000 x 0.85 = $1,700,000`

**Updated ALE:** `$1,700,000 x 0.75 = $1,275,000`

**Summary:**

|               | Original (1x03)                           | Updated (Crimson Tide) |
| ------------- | ----------------------------------------- | ---------------------- |
| EF            | 60%                                       | 85%                    |
| SLE           | $1,200,000 | $1,700,000                   |                        |
| ARO           | 0.25                                      | 0.75                   |
| **ALE** | **$300,000** | **$1,275,000** |                        |

The updated ALE is **4.25x** the original figure. This is the intended lesson of a living risk program: the underlying assets, vulnerabilities, and even most of the gaps have not changed since 1x03 what changed is the intelligence, and new intelligence alone moved the Board's single largest quantified risk from $300,000 to $1,275,000 without a single new dollar being spent or a single new system being touched.

## Part 2 Budget Impact

**Does the updated ALE flip any "Not Justified" verdict?** No. Control 8 (full medical-device isolation with dedicated monitoring, 1x03 Task 7, -$16,300 net value) remains Not Justified Crimson Tide's own documented payload does not target medical devices directly ("medical devices: NOT encrypted... the ransomware payload does not target embedded systems"), so this update does not touch Risk 4's ALE or Control 8's math at all.

**Does a previously-Marginal control flip to Justified?** Yes **Control 7, the 24/7 outsourced SOC ($120,000/year), previously rated Marginal (net value $60,000, deferred).** Control 7 defends the same risk set as Control 3 (SIEM), but with continuous human monitoring layered on top. Its original $180,000 ALE-reduction estimate was built against a combined baseline of Risk 1 + Risk 3 + Risk 5 (~$865,000 total), delivering roughly 20.8% of that combined ALE in reduction value beyond what Control 3 alone captures. Applying that same proportional detection-value premium to the new combined baseline (**$1,275,000** updated Risk 1 + $495,000 Risk 3 + $70,000 Risk 5 = $1,840,000): `20.8% x $1,840,000 ≈ $383,000` in ALE reduction. **New net value: $383,000 - $120,000 = $263,000 clearly Justified**, a reversal from "defer, revisit later" to "fund now." This is the direct, mechanical result of Risk 1 more than quadrupling: the control that primarily defends against Risk 1 becomes proportionally more valuable when Risk 1's own ALE grows.

**Does the $2,400 FortiGate support contract renewal have a positive ROI against the updated ALE?** Overwhelmingly yes worked in full in Task 7's new risk entry (RISK-NEW-001): patching this specific, confirmed-active, KEV-listed initial-access vector reduces its own component ALE from $850,000 to $34,000, a net benefit of roughly $813,600 against a $2,400 cost. There is no control anywhere in MedDefense's history, including 1x03's own highest-return item (Ghostcat, $469,750 net benefit), that returns more per dollar spent than this one.

**Should the Board approve emergency spending beyond the $120,000 budget?** Yes, with a specific, bounded number. Of the original $120,000, $103,400 was already allocated (1x03 Task 8), leaving $16,600 uncommitted. The $2,400 FortiGate renewal is funded entirely from that existing reserve no new approval is required for that specific line item, though it does mean the $16,600 reserve's prior informal earmark (extending server antivirus coverage, per 1x00 Task 14) is now superseded by the emergency. Beyond that, this analysis recommends the Board approve **$36,500 in new emergency spend beyond the original $120,000 ceiling**, covering: accelerated segmentation labor and expedited hardware shipping ($8,000), accelerated SIEM deployment compressed from Month 2 into this week ($6,000), and a 90-day interim Managed Detection and Response bridge at a negotiated rate ($22,500) a scoped, time-boxed down payment on Control 7's now-justified status, rather than committing to its full $120,000 annual contract before it has been properly competed and vetted. **Total revised fiscal-year security spend if approved: $120,000 (original) + $36,500 (new emergency ask) = $156,500.**
