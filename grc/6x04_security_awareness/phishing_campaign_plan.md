# Phishing Simulation Campaign Plan: MedDefense Health Systems

**Prepared by:** Tales Lima, IT Security
**Date:** 2026-11-18
**Owner:** IT Security Awareness Lead
**Approval:** CISO (launch), HR Director Maria Santos (privacy and escalation), Clinical Operations Representative (timing)
**Design brief:** `social_engineering_threat_profile.md`
**Templates:** `phishing_templates.md` | **Post-click experience:** `post_click_intervention.md`

This plan is the operating manual for the first 90 days of the MedDefense phishing simulation program. A campaign manager can run every wave from this document. When a material does not give a fact the plan needs, the gap is named and an owner must close it before launch.

## 1. Campaign Overview

### Scope

| Item | Value |
| --- | --- |
| Population in scope | All workforce segments SEG-A to SEG-F: **1,610 estimated** (`employee_segments.csv`). The department roster (`workforce_population_breakdown.csv`) lists **1,311** named staff. The difference (299, mostly SEG-A and SEG-B clinical staff not broken out by department) must be reconciled with HRIS before Wave 1; the HRIS export is the send list |
| Channel | Email simulations only in this plan. Vishing is a separate exercise with its own scripts and approval (CISO + HR + Legal) |
| Simulation platform | **Gap:** no platform is named in the materials. The platform must: send from a training-only domain, use `[SIMULATION_LINK]` landing pages on approved training infrastructure, record delivery, click, report and training completion per recipient, **never capture a password or form data**, integrate with the Outlook Report Phishing button, and restrict individual data to the program manager. Selection owner: IT Security Awareness Lead; approval: CISO |
| 90-day window | **2027-02-01 to 2027-05-01.** The program starts after the flu-season peak (November to January), when new clinical simulations are not allowed. Days 1 to 8 are preparation; waves run on Days 9 to 88 |
| Out of scope | Real phishing response (SOC process), credential collection of any kind, performance management |

### Objectives

| Measure | Baseline (March 2026 incident) | 90-day target | 18-month target |
| --- | --- | --- | --- |
| Click rate | 56% | 35% or lower | 12% or lower |
| Report rate | 15% | 35% or higher | 65% or higher |
| Mean time to report | 74 minutes | 25 minutes or less | 10 minutes or less |

**18-month trajectory:** 56% → 35% (Day 90) → 25% (Month 12) → 12% (Month 18) click rate, with quarterly simulations after the first 90 days. Organizations that run quarterly simulations for 18 months average an 8% click rate and 61% report rate, so these targets are realistic.

**Source note:** `lure_effectiveness_benchmarks.md` sets 12% click and 65% report at 18 months. `metrics_baseline.csv` sets 25% and 50% at 12 months and 12% and 70% at 36 months. This plan uses the benchmark values for Month 18 and the CSV values for Month 12. The CISO should confirm one target set for board reporting.

### Governance

| Step | Who | What |
| --- | --- | --- |
| Template drafting | IT Security Awareness Lead | Writes templates from the threat profile and `phishing_template_constraints.md` |
| Template approval | CISO + HR Director; Clinical Operations Representative for SEG-A/B; Finance Representative for SEG-E/F templates | No template launches without all required signatures (Section 6) |
| Wave go/no-go | IT Security Awareness Lead with Clinical Operations Representative | Checked 48 hours before each send against Section 3 exclusions |
| Reported simulations | SOC Manager | SOC sees reports in the case system; simulation reports are auto-tagged and closed without analyst effort |
| Results review | IT Security Awareness Lead (individual data); CISO (aggregate) | Wave report within 5 business days; quarterly report to CISO and board |
| HR escalation | HR Director | Only through the thresholds in Section 5; the decision to involve a manager is HR's |

## 2. Employee Segmentation

The six segments are the role categories from the 6x02 IAM audit (`role_inventory.csv`, `employee_segments.csv`). Populations are the segment estimates; the department roster figure is shown where it differs.

| Segment | Population (segment / roster) | Departments | Primary risk vectors (threat profile) | Templates and rationale | Exclusions (in addition to the global list below) |
| --- | --- | --- | --- | --- | --- |
| **SEG-A** Clinical leadership | 115 / 34 (only nursing supervisors listed) | Charge nurses, nursing supervisors, clinical leads | Vector 1 (Epic, secure message), Vector 3 (vendor support call) | T-EPIC-01, then T-MSG-05 (secure clinical message, planned) and T-HR-03. Supervisors clicked MSG-004 in March; they also receive vishing exercises | Active patient safety events; accreditation rounding days |
| **SEG-B** General clinical staff | 860 / 689 | ED 145, ICU 92, Med-Surg 310, Radiology 78, Laboratory 64 | Vector 1 (highest click rate: 67% in March); USB and shoulder surfing are covered by guidance, not email | T-EPIC-01 baseline first (exact March lure pattern), then T-MFA-02 and T-MSG-05; T-EPIC-01 retest in Wave 4 | ICU and OR during critical coverage windows; ED only as a limited sample (25% of ED per wave); units with staffing shortage |
| **SEG-C** Administrative and billing | 420 / 391 | Billing 155, Registration 110, HR 42, Remote admin 84 | Vector 2 (63% click in March), HR benefits lure | T-MFA-02 baseline, T-HR-03 intermediate, T-EPIC-01 registration variant, T-MFA-02 retest. HR staff (42) only receive T-HR-03 with HR Director approval and are excluded if they are running real open enrollment | Payroll close for finance-adjacent staff; HR during real open enrollment |
| **SEG-D** IT and security | 105 / 87 | Helpdesk 38, Systems Engineering 31, SOC 18 | Vector 3 (vendor and change-window lures), privileged follow-on action | T-MFA-02 baseline (measures the generic-lure resistance they showed), then T-VEND-06 (vendor patch coordination, planned), then T-HR-03. Clicks by privileged staff trigger an account check (Section 5) | Active incident responders during a live incident; SOC staff on shift who triage reports for the same wave |
| **SEG-E** Finance and procurement | 75 / 75 | Finance 52, Procurement 23 | Vector 4 (BEC, banking change), HR benefits | T-MFA-02 baseline, T-HR-03 intermediate, T-BEC-04 advanced, then T-BEC-04 retest. Measured on verification, not only clicks | Month-end close day; audit submission day |
| **SEG-F** Executives and assistants | 35 / 35 | Executives 12, Executive Assistants 23 | Vector 4 (BEC, confidential documents), travel | T-MFA-02 baseline, T-HR-03, T-BEC-04 advanced, then retest. Executives reported 0 of 4 in March | Board meeting days; every send coordinated with the executive office calendar |

**Planned templates T-MSG-05 and T-VEND-06** are required by this plan but are not in the first template set. They must be written to the same constraints and approved by Day 30. If they are not approved, the fallback is shown in Section 3. No unapproved template is ever sent.

**Global exclusions** (`clinical_schedule_constraints.md`), applied by the platform list filter on each send day: employees on leave; employees in their first week; staff in an active patient safety event; staff assigned to incident response; employees under an HR-approved support plan; any unit during declared downtime or active incident response. The list is refreshed from HRIS 24 hours before each send.

## 3. Wave Schedule

### Fixed send days

Each segment is always sent on the same weekday of the wave week. This keeps the gap for each population at 21 days or more between waves.

| Day | Segments | Delivery time | Rationale |
| --- | --- | --- | --- |
| Tuesday | SEG-B, SEG-A | 07:15-08:30 (day cohort, about 70%) and 19:15-20:30 (evening and night cohort, about 30%) | Shift-start window used by the real attacker (first click 07:07, evening clicks 19:21), inside the safe window; avoids medication pass peak |
| Wednesday | SEG-C, SEG-E | SEG-C 09:00-11:00; SEG-E 10:00-14:00 | Billing clicked at 09:44 in March; finance requests arrive mid-day; mid-week avoids payroll and close |
| Thursday | SEG-D, SEG-F | SEG-D 10:00-11:30 (inside a scheduled change window when one exists); SEG-F time agreed with each executive assistant | IT lures are credible during change windows; executives need calendar coordination |

Sends are spread over the window in small batches (about 50 recipients every 10 minutes) so that one recipient cannot warn a whole unit before others receive the email. Recipients do not all get the same subject line within a segment.

### Preparation (Days 1 to 8: 2027-02-01 to 2027-02-08)

1. Confirm the platform requirements in Section 1 and run a 20-person pilot with the security team.
2. Enable and test the Outlook Report Phishing button for every mailbox; confirm reports reach the SOC case system and that simulation reports are auto-tagged.
3. Send an all-staff announcement (Communications Lead): simulations are training; individual results are protected and never used in performance reviews; reporting after a click is still valuable; how to use the report button.
4. Publish the role guidance documents and confirm the post-click landing pages (LPV-01 to LPV-04) are live.
5. Reconcile the population gap (Section 1) and load segment lists.
6. Collect all signatures in Section 6.

### Waves

| Wave | Dates | Days | Tier | Templates by segment |
| --- | --- | --- | --- | --- |
| **1. Baseline** | Tue 2027-02-09, Wed 02-10, Thu 02-11 | 9-11 | Baseline | SEG-A, SEG-B: **T-EPIC-01**. SEG-C, SEG-D, SEG-E, SEG-F: **T-MFA-02** |
| **2. Baseline to intermediate** | Tue 2027-03-09, Wed 03-10, Thu 03-11 | 37-39 | Baseline and intermediate | SEG-B: **T-MFA-02** (baseline, new cue type). SEG-A: **T-MSG-05** (intermediate; fallback T-MFA-02). SEG-C, SEG-E, SEG-F: **T-HR-03** (intermediate). SEG-D: **T-VEND-06** (intermediate; fallback T-HR-03) |
| **3. Intermediate to advanced** | Tue 2027-04-06, Wed 04-07, Thu 04-08 | 65-67 | Intermediate and advanced | SEG-B: **T-MSG-05** (fallback T-HR-03). SEG-A: **T-HR-03**. SEG-C: **T-EPIC-01** registration variant (registration staff use Epic; SEG-C already had T-HR-03). SEG-D: **T-HR-03** (or **T-VEND-06** if Wave 2 used the fallback). SEG-E, SEG-F: **T-BEC-04** (advanced) |
| **4. Retest** | Tue 2027-04-27, Wed 04-28, Thu 04-29 | 86-88 | Same tier as first exposure | Each segment receives an approved subject and sender variant of its highest-risk template: SEG-A, SEG-B **T-EPIC-01**; SEG-C, SEG-D **T-MFA-02**; SEG-E, SEG-F **T-BEC-04** (second exposure). Measures change against Wave 1 on the same lure |

**Cool-down:** minimum **21 days** between simulations to the same population (actual gaps: 28, 28 and 21 days). Employees who click get microtraining immediately and no further lure in that wave. Clicks within the same wave never count as repeats.

**Wave close:** each wave stays open for 7 days. The wave report is due 5 business days after close. Day 90 (2027-05-01) is the 90-day review.

**Hold conditions:** the Clinical Operations Representative can stop or delay SEG-A/B sends up to the send time for any unit under a staffing shortage, surge, code event, downtime or active incident. A delayed send moves to the next Tuesday only if the 21-day cool-down to the next wave is still respected; otherwise the unit skips that wave. The Joint Commission window is **not dated in the materials**; Clinical Operations must give the dates before Day 1, and no clinical send falls inside it.

## 4. Metrics Framework

"Delivered" excludes bounced and excluded recipients. A click is any visit to `[SIMULATION_LINK]`. A report is use of the Outlook Report Phishing button (or forward to security@meddefense.org) for the simulation email.

| Metric | Formula | Interval | 90-day target | 18-month target | If it deteriorates |
| --- | --- | --- | --- | --- | --- |
| **Click rate** | Recipients who clicked ÷ recipients delivered, per segment and overall | Per wave; trend quarterly | ≤ 35% overall; ≤ 40% clinical (SEG-A/B) | ≤ 12% | Recognition is not improving for that lure type: review microtraining for that template, check whether the segment's guidance reached staff, and do not raise difficulty for that segment in the next wave |
| **Report rate** | Recipients who reported ÷ recipients delivered | Per wave | ≥ 35% | ≥ 65% | Reporting path is unclear or feared: re-communicate that reporting after a click helps; check the report button works on mobile; review whether reporters received feedback |
| **Repeat clicker rate** | Employees who clicked in two consecutive waves ÷ employees who received both waves | From Wave 2 onward | Establish baseline; keep below 12% | ≤ 4% | Microtraining is not changing behavior for a group: review completion data and Section 5 coaching; consider a different module for that role |
| **Mean time to report** | Average of (report time − delivery time) for reports within the wave window | Per wave | ≤ 25 minutes | ≤ 10 minutes | Reports arrive too late to stop a real campaign (March: 74 minutes, after 23 clicks): promote the report button, simplify the path, recognize fast reporters |
| **Post-simulation training completion** | Clickers who completed the microtraining within 72 hours ÷ clickers | Per wave | ≥ 90% within 72 hours | ≥ 95% | The learning moment is lost: check landing page load on phones and clinical kiosks, send one reminder at 48 hours, check the module length |
| **False-positive report rate** | Legitimate emails reported as phishing ÷ all user reports (SOC-confirmed) | Monthly | Measure baseline; no target | Kept within what the SOC triage process can absorb (not zero) | A rising rate means staff are reporting real IT, HR or vendor email. Do not discourage reporting; publish an internal-sender list and pre-announce real campaigns (open enrollment, MFA rollout) |
| Clinical click rate (supporting) | Clicks ÷ delivered in SEG-A and SEG-B | Per wave | ≤ 40% | ≤ 12% | Clinical timing or Epic lure guidance needs rework with nursing leadership |
| BEC verification rate (supporting) | SEG-E/F recipients of T-BEC-04 who verified through a known channel or reported ÷ recipients | Waves 3 and 4 | Establish baseline | ≥ 80% (12-month CSV target) | Finance payment verification step is not being applied: review with Finance Representative |

Training completion: `metrics_baseline.csv` sets 90% at 90 days; `lure_effectiveness_benchmarks.md` suggests 95%. This plan starts at 90% and reaches 95% by Month 12.

Reporting outputs: wave report (per segment, aggregate) to CISO and SOC Manager; department trend (aggregate only) to department managers; quarterly aggregate report to the board. No report shows names except the program manager's working data.

## 5. Escalation Criteria

A click on a simulation is a training event. It becomes something more only through the conditions below. **A simulation result on its own never starts an insider threat case.**

### Training path (no one outside the program manager knows the individual result)

| Stage | Trigger | Response | Who is notified |
| --- | --- | --- | --- |
| 0 | Click in one wave | Immediate landing page and 5-minute microtraining | Program manager only (platform data) |
| 1 | Click in two **consecutive** waves | Second microtraining plus a 15-minute role-specific module; private message from the awareness team offering help | Program manager only |
| 2 | Stage 1 **and** assigned microtraining not completed within 72 hours plus one reminder | Program manager refers to HR; **HR confirms or declines** the escalation trigger | HR Director |
| 3 | HR confirms the trigger (all four conditions in `hr_privacy_rules.md`: two consecutive clicks, training not completed, HR confirmation, coaching purpose) | Coaching conversation led by HR with the manager; documented coaching plan; no disciplinary record | HR, then the employee's manager for coaching only |

### Security hygiene path (security team investigates the account, not the person)

These patterns indicate account risk that the SOC must check with technical controls. They do not involve the employee's manager.

1. **Any click by a privileged user** (SEG-D, or anyone in Domain Admins or Server Admins per the 6x02 audit): the SOC confirms MFA enrollment and phishing-resistant sign-in for that account within 5 business days, and confirms that admin actions are not done from the same mailbox session.
2. **Two consecutive clicks by a privileged user**, or a click by an account flagged in the 6x02 audit (for example dormant or transferred accounts): the SOC reviews the account's recent sign-ins and access; IT reviews whether the privilege is still needed. HR is informed only if Stage 2 also applies.
3. **The same employee reports a real phishing email they clicked**: this is a real incident, handled by the SOC under the credential exposure playbook, not by this program. The employee is thanked for reporting.

### When HR coordination and an insider-threat referral are appropriate

Only when **non-simulation behavior** is observed alongside the simulation pattern, and only through the insider threat reporting model with HR and Legal: for example, deliberately forwarding simulation or real phishing content to personal accounts, attempting to disable the report button or mail protections, or simulation data showing activity from an account that should be dormant. Repeated clicking alone is a training need, not evidence of intent.

## 6. Exclusion and Ethics Policy

### Exclusions

The global and segment exclusions in Section 2 apply to every send. In addition:

- No sends from November to January to clinical segments, during the Joint Commission window, during declared downtime or active incident response, or to a unit with a staffing shortage.
- No themes from the prohibited list in `simulation_ethics_guidelines.md`: personal medical diagnoses, death or personal emergencies, immigration status, payroll termination or disciplinary threats, protected class attributes, real patient names or conditions, active disasters, or threats that employment will end.
- No credential or form capture. Landing pages contain no input fields.

### Disclosure framework

| Data | Who sees it | Retention |
| --- | --- | --- |
| Individual click and training status | IT Security Awareness Lead only | 18 months, then aggregated or deleted, unless part of an active HR coaching process |
| Individual report event | Awareness Lead and SOC metrics (for reinforcement) | 18 months |
| Repeat-click status | Awareness Lead; HR only after Stage 2 | Same |
| Department trend | Department manager, aggregate only, and only for groups of 10 or more recipients so individuals cannot be identified | Per report |
| Executive summary | CISO and board, aggregate only | Per report |

Simulation results never appear in performance reviews and are never used for promotion, compensation, termination or disciplinary decisions.

### Support for employees in distress

Every landing page states that this was a simulation, that the employee is not in trouble, and that reporting after a click helps. It gives a manager-neutral support path: the awareness team (security@meddefense.org, ext. 4-SECURITY) and the HR contact for concerns. No one is named publicly. If an employee reports distress, the program manager excludes them from the next wave on request and HR may place them on an HR-approved support plan.

### Sign-off required before any template is deployed

| Item | Required signatures |
| --- | --- |
| Each template and each subject or sender variant | CISO + HR Director |
| Templates for SEG-A/SEG-B | + Clinical Operations Representative |
| Templates for SEG-E/SEG-F | + Finance Representative |
| Landing pages and microtraining | HR Director + Communications Lead |
| Vishing scripts | CISO + HR + Legal (if recorded) |
| Wave go/no-go (each wave) | IT Security Awareness Lead + Clinical Operations Representative |

The signed record is filed with the wave report. Without it, the platform send is not scheduled.
