# 18. The 6-Month Security Roadmap — MedDefense Health Systems

**Analyst:** Security Analyst
**Date:** Current

## Month 1

- **Actions:** Execute all 5 Quick Wins (Task 13): disable the Ghostcat AJP connector, restrict `ehr-db-01` to `ehr-srv-01` only, reset BD Alaris default credentials, begin MFA rollout, deploy the USB-restriction GPO pilot. Initiate procurement: SIEM labor allocation, AWS account setup for backup replication, Westside firewall hardware order, segmentation hardware assessment. Begin the vCISO search/engagement process.
- **Owner:** IT Director (Sarah Park) for execution; Security Analyst for verification; CEO (Dr. Morales) for the vCISO search.
- **Dependencies:** None — every Month 1 action was specifically selected in Task 13 for having zero prerequisites.
- **Completion Criteria:** All 5 Quick Wins pass their individual verification steps (Task 13); all four procurement items have a purchase order or contract in motion.

## Month 2

- **Actions:** Complete MFA rollout to 100% of in-scope accounts. Deploy Wazuh SIEM, onboarding log sources from critical servers and the firewall (Phase 1 scope). Complete offsite backup replication setup and run a first test restore. Complete Westside firewall installation. Begin the vendor risk inventory (RISK-010a).
- **Owner:** IT Director (Sarah Park), Security Analyst.
- **Dependencies:** SIEM log source onboarding depends on the existing 1x00 Asset Registry being current (already satisfied).
- **Completion Criteria:** MFA enforcement confirmed at 100% via Azure AD sign-in logs; SIEM dashboard showing live data from 100% of Phase 1 scope; backup test restore succeeds; Westside firewall passes a basic penetration/reachability check.

## Month 3

- **Actions:** Implement the Server, Clinical Workstation, and Management zones from the Task 14 segmentation design (firewall rules deployed, VLANs configured). Begin SIEM alert-rule tuning. Begin PACS badge-authentication rollout following department-head sign-off. Fund and begin implementing the previously-unfunded RISK-004 control (automated deprovisioning + DLP export monitoring) — per Task 15's own finding, this should not wait any longer than it already has.
- **Owner:** IT Director (segmentation, PACS), Security Analyst (SIEM tuning, RISK-004 control).
- **Dependencies:** None new — this is the first zone-infrastructure build, the foundation the next month's work depends on.
- **Completion Criteria:** Server/Clinical/Management zones enforce their Part 2 (Task 14) firewall rules; SIEM alerts are actionable, not just raw log volume; PACS badge readers installed and tested with radiology staff.

## Month 4

- **Actions:** Implement the Medical Device Zone and Guest/IoT Zone, completing the segmentation design. Extend MFA to vendor remote-access accounts (RISK-010b). Complete the RISK-004 deprovisioning/DLP rollout, tested against a sample termination. Draft the Incident Response Plan.
- **Owner:** IT Director (segmentation), Security Analyst (vendor MFA, IR plan draft), Deputy CISO (IR plan review).
- **Dependencies (explicit):**
  1. **Medical Device Zone segmentation depends on the Server/Clinical/Management zone infrastructure from Month 3 being operational first** — you cannot isolate a zone into an architecture that doesn't exist yet.
  2. **Vendor MFA extension depends on the core MFA deployment (Month 1-2) already being live** — it is a scope extension of an existing control, not a new one.
- **Completion Criteria:** Medical Device Zone reachability tests confirm zero unauthorized cross-zone paths; vendor accounts show 100% MFA enforcement; a sample account deprovisioning test completes correctly within 24 hours of a simulated termination date.

## Month 5

- **Actions:** Full reachability testing across all 5 zones. First Incident Response Plan table-top exercise. Full 1x02-style vulnerability re-scan of the entire environment to confirm prior findings remain resolved and no regressions occurred.
- **Owner:** Security Analyst (testing, re-scan), Deputy CISO (IR table-top facilitation).
- **Dependency (explicit):** **SIEM alert-response drilling depends on the SIEM having been deployed and tuned since Month 2/3** — a monitoring drill against a system still generating noise-level alerts would validate nothing meaningful, which is why this step waits until Month 5 rather than running immediately at deployment.
- **Completion Criteria:** Zero Critical findings remain open on the re-scan; the IR table-top produces a documented lessons-learned list with at least one actioned improvement; all 5 zones pass 100% of their planned reachability tests.

## Month 6

- **Actions:** Remediate any findings surfaced in Month 5's validation. Complete vCISO onboarding, including their first monthly Risk Register review. Prepare and deliver the Year 1 results and Year 2 budget request to the Board.
- **Owner:** Deputy CISO, CEO (Board presentation).
- **Dependencies:** None new — this is a wrap-up and reporting phase building on every prior month.
- **Completion Criteria:** Risk Register fully updated with post-implementation residual risk figures; Year 2 proposal (SIEM maturation to application/database-layer monitoring, per Task 15/17) drafted and Board-ready.

## Dependency Chain Summary

1. **Network segmentation (Month 3) must precede medical device isolation (Month 4)** — the zone infrastructure has to exist before any single zone within it can be isolated.
2. **SIEM deployment (Month 2) must precede alert-response monitoring maturity (Month 5)** — a freshly-deployed SIEM produces noise, not signal; meaningful drilling requires months of tuning first.
3. **Core MFA deployment (Month 1-2) must precede vendor account MFA extension (Month 4)** — the vendor rollout is a scope extension of an existing control, not an independent build.

## Milestones

| Milestone | Date | Accomplished | Success Indicator |
|---|---|---|---|
| M1 — Quick Wins Complete | End of Month 1 | All 5 zero-cost fixes from Task 13 verified live | 5/5 Quick Win verification steps passed |
| M2 — Foundational Controls Live | End of Month 2 | MFA, SIEM Phase 1, and backup replication operational | 100% MFA enforcement; SIEM ingesting 100% of Phase 1 log sources; 1 successful test restore |
| M3 — Network Architecture Transformed | End of Month 4 | All 5 segmentation zones live, including Medical Device | 0 failed deny-rule reachability tests across all zones |
| M4 — Program Validated, Year 2 Approved | End of Month 6 | Full re-scan passed, IR plan tested, Year 2 funding secured | 0 open Critical findings on re-scan; Year 2 budget approved by the Board |

## Risk to Timeline

**1. Clinical staff resistance to workflow disruption.** MFA, segmentation, and badge authentication all change how clinical staff log in and reach systems day to day — and PACS badge authentication specifically has already been rejected once before on exactly these grounds (1x00, Task 12 Risk Decisions). **Contingency:** phase every clinical-facing rollout through a small pilot group first (the same 48-hour pilot pattern already used for the USB GPO in Task 13), and use the Task 4 RACI's own assignment of training responsibility to department heads to build buy-in *before* a mandatory rollout date, rather than announcing a mandate and managing the fallout afterward.

**2. Procurement and external dependency delays.** Segmentation hardware, the Westside firewall replacement, and the vCISO engagement all depend on external vendors or candidates outside MedDefense's direct control, and any of the three could slip past its planned month. **Contingency:** initiate all four Month 1 procurement actions immediately rather than waiting for their dependent implementation month, build a 2-4 week buffer into the Month 3-4 segmentation timeline specifically for hardware delivery, and run the vCISO search in parallel starting Month 1 so a delay there does not block any technical milestone.

## Repo

- **GitHub repository:** `dlh-cyber_security`
- **Directory:** `blue_team/1x03_defense_blueprint`
- **File:** `18-roadmap.md`
