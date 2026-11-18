# False Positive Governance

Automation tiers:

| Tier | Allowed Action | Example |
|---|---|---|
| Enrich-only | Add context, score and evidence | IOC enrichment |
| Enrich-and-triage | Create case and assign severity | phishing playbook case creation |
| Human-authorized action | Queue action but wait for analyst | isolation_queue.json |
| Automatic action | Execute response without analyst | not approved in this lab |

Before action automation, MedDefense requires measured false-positive rate, exception process, rollback procedure, owner approval, clinical safety review, audit logging, and change-management record.

Healthcare-specific risks include auto-closure masking a real incident, auto-isolation disrupting patient care, and auto-disabling privileged accounts during emergency maintenance.
