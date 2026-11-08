# MedDefense Incident Response Playbook Index

**Owner:** IT Security  
**Last formal review:** 2026-04-12  
**Classification:** Confidential

## Purpose

This index lists the active incident response playbooks currently maintained by MedDefense. These playbooks were created or updated after the Nexus/Cobalt Strike incident.

## Active Playbooks

| Playbook | Filename | Status | Last Tested | Owner |
|---|---|---|---|---|
| Credential Exposure | `playbook_credential_exposure.yaml` | Active | 2026-04-15 tabletop | SOC Manager |
| Phishing Triage | `phishing_triage.md` | Active | 2026-04-09 live incident | SOC Analyst |
| Ransomware Containment | `ransomware_containment.md` | Active | 2026-04-16 tabletop | IR Lead |
| Cloud Incident Response | `cloud_incident_response.md` | Draft | Not tested | Cloud Security |
| Insider Threat Escalation | `insider_threat_workflow.md` | Draft | Not tested | IT Security + HR |
| Vendor-Originated Incident | `vendor_originated_incident.md` | Draft | Not tested | IT Security + Procurement |
| Data Exfiltration Review | `data_exfiltration_review.md` | Active | 2026-04-17 tabletop | IR Lead |

## Tested Response Evidence

- Credential Exposure tabletop completed on 2026-04-15.
- Ransomware containment tabletop completed on 2026-04-16.
- Phishing triage was activated during a real phishing event on 2026-04-09.
- Vendor-originated incident workflow remains untested.

## Known Gaps

1. No formal annual IR exercise schedule is approved by leadership.
2. Vendor-originated incident playbook is draft only.
3. Insider threat escalation workflow has not been approved by HR.
4. Evidence of communication testing is incomplete.
5. Playbooks are maintained by IT Security but lack formal CISO sign-off.

## Audit Mapping Notes

This artifact supports:

- RS.MA-01: incident management execution
- RS.AN-03: analysis performed for incidents
- RS.CO-02: incident reporting and internal communication, partially
- HIPAA 164.308(a)(6): security incident procedures

Evidence is strongest for IR activity and weaker for formal governance approval.
