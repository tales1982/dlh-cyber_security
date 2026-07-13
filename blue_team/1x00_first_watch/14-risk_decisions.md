# Risk Treatment Decisions MedDefense Health Systems

*Selected: the 6 Critical gaps from Task 12, plus the highest-ranked High gap (GAP-001), as the 7 highest-priority items.*

## GAP-002 No functioning detection or incident-response capability

**Risk Level:** Critical
**Treatment Strategy:** Mitigate
**Justification:** This is the single most systemic gap it's the reason every prior incident (ransomware, cryptominer) went undetected for weeks. No other strategy addresses a root capability gap like this; it cannot be transferred, accepted, or avoided away.

- **Proposed Control(s):** Deploy Wazuh (open-source SIEM, per Marcus's own M-04 recommendation) covering critical servers and the firewall first; draft a formal Incident Response Plan (Administrative/Corrective).
- **Estimated Cost:** $10-50K (labor/consulting-heavy; software itself is free)
- **Implementation Effort:** Short-term (<1 month for Phase 1: critical servers + firewall)
- **Expected Risk Reduction:** High converts "discovered by accident" into "discovered by design" across most other gaps in this list.

**Trade-offs:** Requires someone to actually monitor and respond to alerts once deployed a tool without a process is just more unread logs.

---

## GAP-003 Backup repository (NAS-01) has no protection or redundancy

**Risk Level:** Critical
**Treatment Strategy:** Mitigate
**Justification:** A priced quote already exists ($14,400/year for cloud replication), previously denied on budget grounds alone. This is the cheapest fix, per dollar of risk reduced, on the entire list.

- **Proposed Control(s):** Cloud backup replication with immutable storage (AWS S3 or Azure Blob) Technical/Corrective.
- **Estimated Cost:** $10-50K (annual recurring cost of ~$14,400)
- **Implementation Effort:** Short-term (<1 month once approved)
- **Expected Risk Reduction:** High eliminates the single point of failure where production and backup can be destroyed together.

**Trade-offs:** Recurring annual cost, not one-time; needs to survive future budget cycles, not just this one.

---

## GAP-004 Infusion pump fleet has zero dedicated controls

**Risk Level:** Critical
**Treatment Strategy:** Mitigate
**Justification:** This is the most direct patient-safety exposure on the list. Given the budget, this is treated as Phase 1 of medical device segmentation pumps first, because dosage manipulation is the most severe plausible outcome.

- **Proposed Control(s):** Dedicated VLAN for infusion pumps with firewall rules restricting traffic to clinical workstations and PACS only Technical/Compensating (same pattern as the Task 6 MRI strategy).
- **Estimated Cost:** $10-50K
- **Implementation Effort:** Long-term (>1 month)
- **Expected Risk Reduction:** High for pumps specifically; does not yet cover the rest of the medical IoT fleet (see GAP-007).

**Trade-offs:** Segmenting one device category before the rest creates a temporary false sense of completeness must be communicated as Phase 1, not "done."

---

## GAP-006  Network closet: no lock, exposed credentials, no camera

**Risk Level:** Critical
**Treatment Strategy:** Mitigate
**Justification:** The best-value item in this entire list trivially exploitable, Critical-rated, and fixable almost for free.

- **Proposed Control(s):** Install a physical lock (Physical/Preventive), remove/replace the posted credential sheet and rotate the exposed switch password (Technical/Preventive), extend camera coverage to the closet (Physical/Detective).
- **Estimated Cost:** $0-1K
- **Implementation Effort:** Quick Win (<1 week)
- **Expected Risk Reduction:** High relative to costhis should be done immediately, independent of the rest of the budget cycle.

**Trade-offs:** None significant this is close to a pure win.

---

## GAP-007 Medical IoT devices share a flat network (fleet-wide)

**Risk Level:** Critical
**Treatment Strategy:** Mitigate (phased)
**Justification:** Full IoT segmentation is expensive and shares scope with GAP-004. Given the budget, only the pump VLAN (GAP-004) is funded this year; the rest is deferred.

- **Proposed Control(s):** Extend the VLAN work from GAP-004 to monitors, nurse call, and badge readers Technical/Compensating.
- **Estimated Cost:** $10-50K (deferred to next fiscal year)
- **Implementation Effort:** Long-term (>1 month)
- **Expected Risk Reduction:** Medium this year (pumps only, via GAP-004); High once Phase 2 completes.

**Trade-offs:** Monitors and other non-pump IoT remain exposed on the flat network through the end of this fiscal year an explicit, documented residual risk, not an oversight.

---

## GAP-010 Shared PACS login removes accountability

**Risk Level:** Critical
**Treatment Strategy:** Mitigate
**Justification:** Radiology already rejected individual logins as "too slow" the fix needs to solve the speed problem, not just impose the old solution again.

- **Proposed Control(s):** Proximity badge or smart card authentication for PACS workstations (Technical/Preventive) fast tap-in login without shared credentials, per Marcus's own M-07 recommendation.
- **Estimated Cost:** $1-10K
- **Implementation Effort:** Short-term (<1 month)
- **Expected Risk Reduction:** High restores individual accountability without reintroducing the workflow complaint that blocked the original fix.

**Trade-offs:** Requires radiology staff buy-in; if adoption is resisted again, the technical fix alone won't succeed needs department-head sign-off up front.

---

## GAP-001 EHR database reachable network-wide, no detection

**Risk Level:** High
**Treatment Strategy:** Mitigate
**Justification:** The preventive half of this fix is nearly free (a firewall rule change); the detective half rides on GAP-002's SIEM deployment rather than requiring separate budget.

- **Proposed Control(s):** Restrict `ehr-db-01` port 5432 to `ehr-srv-01` only (Technical/Preventive); include database access logs in the Wazuh scope from GAP-002 (Technical/Detective).
- **Estimated Cost:** $0-1K
- **Implementation Effort:** Quick Win (<1 week)
- **Expected Risk Reduction:** High for the preventive piece immediately; the detective piece completes once GAP-002 is live.

**Trade-offs:** None significant for the firewall change itself; detection benefit is contingent on GAP-002 actually being funded and deployed.

---

## Budget Summary

| Gap                          | Estimated Cost (this fiscal year) |
| ---------------------------- | --------------------------------- |
| GAP-002 (SIEM + IR plan)     | ~$30,000                          |
| GAP-003 (cloud backup)       | ~$14,400                          |
| GAP-004 (pump VLAN, Phase 1) | ~$30,000                          |
| GAP-006 (closet lock/camera) | ~$500                             |
| GAP-007 (remaining IoT VLAN) | **$0 this year deferred**  |
| GAP-010 (PACS badge auth)    | ~$5,000                           |
| GAP-001 (firewall rule)      | ~$500                             |
| **Total**              | **~$80,400**                |

This fits within the **$120,000** annual budget, leaving roughly **$39,600** in reserve. Recommended use of the remaining buffer: begin closing GAP-005 (antivirus coverage for servers), the next-highest-value gap not in this list, rather than starting GAP-007's Phase 2 early patient-safety segmentation (Phase 2) is deferred deliberately to next fiscal year once Phase 1 has proven the approach works, while server AV coverage is a smaller, faster win that reduces risk across multiple Critical assets immediately.
