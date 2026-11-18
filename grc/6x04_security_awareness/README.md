# 6x04: Security Awareness & Human Defense

Security awareness program for MedDefense, built after the phishing campaign that started the Cobalt Strike incident: 41 emails, 23 clicks (56%), 6 reports (15%), 74 minutes mean time to report. The program trains behavior instead of collecting completion certificates. It runs realistic simulations at the moments attackers use, teaches at the moment of failure without shame, gives each role a one-page guide, and measures reporting as well as clicking.

- **Organization:** MedDefense (fictional training scenario, DLH Academy)
- **Author:** Tales Lima
- **Date:** 2026-11-18

## Deliverables

| Task | File | Content |
| --- | --- | --- |
| 1 | [social_engineering_threat_profile.md](social_engineering_threat_profile.md) | Three most-targeted populations, four attack vectors, top five lures with click-rate ranges, disruption points, five simulation design requirements |
| 2 | [phishing_campaign_plan.md](phishing_campaign_plan.md) | Scope and objectives, six segments (SEG-A to SEG-F), four-wave 90-day schedule (2027-02-01 to 2027-05-01), metrics, escalation, exclusions and ethics |
| 3 | [phishing_templates.md](phishing_templates.md) | T-EPIC-01, T-MFA-02, T-HR-03, T-BEC-04 with header blocks, full emails, attacker notes and operator safety notes |
| 4 | [post_click_intervention.md](post_click_intervention.md) | Landing pages LPV-01 to LPV-04, four 5-minute microtraining modules, repeat-click escalation, positive reinforcement |
| 5 | [guidance_clinical_staff.md](guidance_clinical_staff.md), [guidance_it_staff.md](guidance_it_staff.md), [guidance_executives.md](guidance_executives.md), [guidance_remote_workers.md](guidance_remote_workers.md) | One-page quick references written in each audience's language |

Supporting files: [materials/](materials/), the provided 6x04 material folder, unchanged.

## Safety Boundaries Applied

- Templates are for an approved internal simulation only. The only link is `[SIMULATION_LINK]`; sender domains are `[SIM_DOMAIN_...]` placeholders for training-only domains. No real attacker, vendor or third-party domain is used, and landing pages have no input fields.
- Simulation results never appear in performance reviews. Managers see aggregate data only (groups of 10 or more), and individual results reach a manager only through the four HR conditions in `materials/campaign_design/hr_privacy_rules.md`.
- No prohibited themes (`materials/campaign_design/simulation_ethics_guidelines.md`), no real patient names, no payment or credential collection.

## Gaps Found in the Materials

These are flagged in the documents instead of filled with invented facts:

1. **Population:** segment estimates total 1,610 (`employee_segments.csv`), but the department roster totals 1,311 (`workforce_population_breakdown.csv`). The gap is mostly clinical (SEG-A 115 vs 34, SEG-B 860 vs 689). HRIS reconciliation is required before Wave 1.
2. **Targets:** `lure_effectiveness_benchmarks.md` (18-month) and `metrics_baseline.csv` (12- and 36-month) give different long-term targets, and 90-day training completion is 95% in one and 90% in the other. The plan states which value it uses and asks the CISO to confirm one set.
3. **Not specified:** the simulation platform, the Joint Commission window dates, the CFO's and CEO's names, and the exact Outlook report button deployment. These are placeholders or named prerequisites in the plan.
4. **Finding IDs:** `materials/iam_context/privileged_account_findings.md` numbers the 6x02 IAM findings differently from the 6x02 audit report in this repository. The guidance names the accounts rather than citing IDs.
5. **Templates T-MSG-05 and T-VEND-06** (secure clinical message, vendor support) are required by the campaign plan for SEG-A and SEG-D but are not part of the four templates in Task 3. The plan gives a fallback until they are approved.

## Timing Note

New clinical simulations are not allowed during the November-January flu-season peak. The 90-day window therefore starts on 2027-02-01. Wave days are fixed per segment, so each population waits at least 21 days between simulations.
