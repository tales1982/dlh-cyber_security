# After-Action Report: Nexus Supply Chain Compromise Tabletop

**Exercise ID:** TTX-2026-01
**Exercise date:** 2026-04-24 (designer simulation of the exercise planned for 2026-04-28)
**Report date:** 2026-04-25
**Facilitator:** Tales Lima
**Participants:** James Chen (SOC Lead / IR Commander), Sarah Park (IT Director), Dr. Patricia Morales (CISO), Helena Reyes (General Counsel), Marcus Webb (Communications Director), Robert Kim (Infrastructure Lead), Clinical Director representative
**Evaluators:** Tales Lima (EVAL-LEAD), Lisa Tanaka, Vendor Risk (EVAL-REG), Nursing Quality Officer (EVAL-CLIN)
**Classification:** Internal - Exercise Use Only
**Sources:** execution_record.md (observations), evaluation_criteria.yaml (criteria), capability_map.yaml (capabilities), inject_schedule.yaml

---

## Executive summary

The exercise tested how MedDefense leadership responds when a trusted vendor, Nexus Patient Scheduling, is the attack vector: a malicious but validly signed update installed automatically on the three scheduling servers, with a backdoor that exfiltrated data and altered appointments in Epic. Seven injects over 160 minutes tested eight capabilities, from supply chain detection to a board brief under a 90-minute deadline.

All seven injects produced at least one failed criterion. The most significant gaps were: (1) **nobody holds the authority to take a vendor-operated, business-critical system offline**, so isolation took 18 minutes of debate while the backdoor stayed active (F-001); (2) **MedDefense has no procedure to verify and restore data integrity in Epic** after a partner compromise, and front-desk staff corrected altered records before the audit trail was preserved (F-002); (3) **the team trusted the vendor's code signature twice**, first by leaving automatic updates on and then by approving the "fixed" signed update with no independent verification, repeating the root cause of the compromise (F-007).

**Single most important action:** add a vendor system isolation decision node to the IR playbook, with the IT Director as decision owner, the CISO as approver, the Clinical Director as mandatory consultee and a 30-minute timebox, backed by a pre-written manual scheduling fallback for the three sites (F-001, owner IT Director, 21 days).

---

## Findings table

| ID | Inject | Capability | Gap | Severity | Recommended Action | Owner | Deadline (days) | Validation |
|---|---|---|---|---|---|---|---|---|
| F-001 | INJ-01 (criterion 1) | CAP-02 | No defined authority or process for isolating a vendor-operated critical system; isolation decided after 18 minutes with no named authorizer | P1 | Add a vendor system isolation decision node to the IR playbook (decision owner IT Director, approver CISO, Clinical Director consulted, 30-minute timebox) and a pre-written manual scheduling fallback that prioritizes dialysis and infusion | IT Director | 21 | Playbook review signed by the Clinical Director + INJ-01 re-test at next tabletop decided in under 30 minutes |
| F-002 | INJ-03 (criteria 4, 5) | CAP-06 | No data integrity verification procedure for FHIR-connected systems after suspected compromise; records corrected before audit trail preserved; review limited to 72 h instead of the 21-day advisory window | P1 | Define a data integrity checklist for Epic-connected systems triggered by BA / integration compromise: freeze service principal, preserve audit trail, clinical triage list, front-desk "do not correct" instruction, review window = vendor advisory window | Infrastructure Lead | 30 | Checklist reviewed by the Clinical Director + dry run on Epic test restoring 20 altered appointments from audit data |
| F-003 | INJ-02 (criteria 1, 3) | CAP-03 | Untested vendor communication path (residual risk R3): two parallel MedDefense contacts with Nexus, verbal-only requests, no record of what the vendor said | P2 | Create a vendor incident liaison role and a written vendor information request template (IOCs, versions, discovery date, data accessed, subprocessors); run a joint communication test with Nexus SecOps | Vendor Risk Manager | 30 | Joint test with Nexus completed with response inside the 1-hour SLA; template on file |
| F-004 | INJ-04 (criteria 1, 2, 4, 6) | CAP-05, CAP-04 | Team accepted that the Business Associate "handles all notifications"; four-factor assessment, 60-day notice and 500-individual threshold not addressed; PHI scoping limited to 72 hours with no confirmed / probable / unknown split | P1 | Add a "Business Associate breach" branch to the HIPAA decision node in the IR playbooks and amend the Nexus BAA and the BAA template (who notifies patients, cost allocation, evidence sharing, discovery date definition) | General Counsel | 45 | Amended Nexus BAA signed; playbook branch reviewed by outside counsel |
| F-005 | INJ-00 (criteria 4, 5) | CAP-01 | Vendor agent not considered as the threat vector; hunt limited to SCHED-SVR-02 while SCHED-SVR-01 and -03 ran the same agent | P2 | Add a "vendor agent / supply chain origin" trigger to the severity matrix (SEV2 minimum, scope all hosts with the same agent) and a SOC runbook step to check agent version and last update on every host | SOC Lead | 14 | Runbook review + purple-team replay of the INJ-00 alert hunting all three hosts |
| F-006 | INJ-05 (criterion 3) | CAP-07 | No patient call script or priority line for time-critical patients; call center improvised ("it is a Nexus problem") | P2 | Create a patient call script template for vendor / scheduling incidents with a priority clinical line, plus a pre-approved holding statement library with a 30-minute Legal fast-track | Communications Director | 30 | Script and statements signed off by General Counsel; timed drill producing approved script in under 30 minutes |
| F-007 | INJ-01 (criterion 5), INJ-06 (criterion 5) | CAP-01, CAP-08 | Vendor code signature trusted without verification: automatic updates left on after the advisory, then signed 4.12.4 approved for install with no out-of-band check (repeats residual risk R1) | P1 | Disable automatic vendor updates on clinical-support servers; create a vendor update verification procedure for any vendor with a compromised build or key (out-of-band hash, new certificate check, staging host, SBOM request per residual risk R2) | IT Director | 21 | Procedure applied to Nexus 4.12.4 in staging with evidence on file; auto-update setting verified off on SCHED-SVR-01/02/03 |
| F-008 | INJ-06 (criterion 4) | CAP-08 | Board brief informed but requested no decisions (vendor suspension, outside counsel, notification budget) | P3 | Adopt a one-page executive incident brief template with a mandatory "Decisions requested from the board" section | CISO | 21 | Template used in the next SEV1 / SEV2 board update |

---

## P1 Finding narratives

### F-001: No vendor system isolation decision authority

At INJ-01 the team learned that all three scheduling servers ran a confirmed malicious, signed Nexus update. Security recommended immediate isolation within two minutes, but the decision took 18 minutes: the IT Director would not act without someone "above" her, the CISO said she does not own clinical operations, and the Clinical Director argued to keep the schedule up for 09:30 dialysis. Isolation was finally "agreed in principle" at T+38 with no named authorizer recorded. In a real event this is 18 minutes of an active backdoor with write access to Epic. **Action:** add a vendor system isolation decision node to the IR playbook naming the IT Director as decision owner, the CISO as approver and the Clinical Director as mandatory consultee, with a 30-minute timebox and a pre-written manual scheduling fallback for the three sites that schedules dialysis and infusion first (owner: IT Director, 21 days, validated by Clinical Director sign-off and an INJ-01 re-test).

### F-002: No data integrity procedure for Epic-connected systems

At INJ-03 the team learned that 212 appointments, 38 of them time-critical, were altered through the Nexus FHIR channel. The response to patients was strong, but the West Campus front desk had already corrected records at 09:00 before the audit trail was exported, and the review was limited to the 72 hours since version 4.12.3 although the vendor advisory covered 21 days. Evidence was lost and older alterations could stay in Epic unnoticed, with patients missing treatment. **Action:** create a data integrity checklist for Epic-connected systems, triggered by any Business Associate or integration compromise: freeze the service principal (`svc-nexus-prod`), preserve the Epic audit trail first, instruct front desks not to correct records, build a clinical triage list (infusion, dialysis, oncology), and set the review window to the vendor advisory window (owner: Infrastructure Lead with the Clinical Director, 30 days, validated by a dry run on the Epic test environment).

### F-004: Business Associate breach treated as the vendor's problem

At INJ-04 Nexus wrote that it would "handle all regulatory notifications". The IT Director said this "takes it off our plate" and nobody corrected it in the inject window; the four-factor risk assessment, the 60-day individual notice and the 500-individual threshold for HHS and media were not raised, and PHI scoping was assigned only for the 72-hour window without separating confirmed, probable and unknown exposure. General Counsel knew when probed that MedDefense remains responsible as Covered Entity, and she recorded that Nexus missed its 24-hour BAA notice (discovery 2026-04-24), but the team's default was to wait for the vendor. With up to 41,000 patients potentially in scope, a late or vendor-branded notification exposes MedDefense to OCR penalties. **Action:** add a "Business Associate breach" branch to the HIPAA decision node (CE obligations start at MedDefense discovery or when the BA, acting as agent, discovered it; four-factor assessment owner and date; notification ownership) and amend the Nexus BAA and template to define notification responsibility, costs and evidence sharing (owner: General Counsel, 45 days, validated by outside counsel review and a signed amendment).

### F-007: Vendor code signature trusted without independent verification

The compromise started because MedDefense trusted Nexus updates on code-signing alone, a residual risk accepted in the 2025-11-14 vendor review (R1). In the exercise the team left automatic updates on after the advisory (INJ-01) and then, under pressure to restore scheduling, approved installing signed version 4.12.4 on SCHED-SVR-01 (INJ-06) without knowing whether Nexus had a new signing key. The same trust assumption was applied to the same compromised channel twice in two hours. **Action:** disable automatic vendor updates on clinical-support servers and require a vendor update verification procedure (out-of-band hash from the vendor, confirmation of a new certificate, staging host, SBOM per residual risk R2) before any update from a vendor whose build or key was compromised (owner: IT Director, 21 days, validated by applying the procedure to Nexus 4.12.4 in staging).

---

## What worked

- **Evidence before containment (INJ-00, CAP-01).** The SOC Lead declared SEV2 within two minutes with explicit reasoning, and the CISO held the IT Director's isolation proposal until a memory image of SCHED-SVR-02 was taken. This preservation-first habit carried over from IR-2026-0414-01.
- **Clinical response to altered appointments (INJ-03, CAP-06).** Once the scope was known, the Clinical Director took ownership in one minute: the dialysis patient who missed Saturday was escalated to nephrology on-call, and nurses called the 38 time-critical patients in treatment-date order (31 reached by T+128). The Infrastructure Lead disabled `svc-nexus-prod` within three minutes.
- **Legal control of vendor pressure and public statement (INJ-02, INJ-05).** General Counsel refused the NDA on the call, recorded the vendor discovery date, and shaped a holding statement that was approved 53 minutes before the media deadline without confirming or denying data theft.

---

## Exercise design feedback

- **DF-01:** The patient safety signal arrived 30 minutes after the continuity decision; INJ-01 now includes two patients arriving for cancelled appointments so data integrity shapes the isolation decision.
- **DF-02:** The Nexus role-player volunteered the vendor discovery date; it is now revealed only if a participant asks, so INJ-02 tests whether MedDefense knows to ask.
- **DF-03:** INJ-04 handed over the "41,000 patients" scope; the inject now gives only raw facts and the count is revealed on request, so CAP-04 scoping is actually tested.
- **DF-04:** INJ-05 and INJ-06 overlapped and overloaded the CISO; INJ-06 moved to T+115 and the hotwash to T+140 (160-minute exercise) so the CAP-08 result reflects the organization, not the timing.
