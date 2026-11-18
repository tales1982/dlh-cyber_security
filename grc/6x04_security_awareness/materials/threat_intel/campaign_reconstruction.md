# Healthcare Phishing Campaign Reconstruction

**Campaign:** MD-PHISH-Q1-2026  
**Incident Link:** Precursor to Module 5 Cobalt Strike response  
**Prepared for:** 6x04 Security Awareness Program Design  
**Classification:** Internal Training

## Summary

The campaign delivered 41 phishing emails to MedDefense users over a 36-hour period. Twenty-three recipients clicked. Six users submitted credentials to the simulated/reconstructed phishing page during the original incident investigation timeline. The earliest click occurred within 9 minutes of delivery, during a shift-start window. The first confirmed malicious beacon followed the credential-harvest phase and subsequent endpoint activity.

## Timeline

| Time | Event | Notes |
|---|---|---|
| 2026-03-25 06:58 | First clinical wave delivered | Nurses and patient care technicians |
| 2026-03-25 07:07 | First click | Clinical recipient before shift handoff |
| 2026-03-25 07:12 | First credential submission | Epic-themed lure |
| 2026-03-25 09:44 | Billing wave delivered | Compliance/MFA-themed lure |
| 2026-03-25 10:02 | Billing user reported message | Report arrived after two coworkers clicked |
| 2026-03-25 13:15 | Finance/executive wave delivered | Document review and payment approval theme |
| 2026-03-25 15:40 | SOC triage began | Reports correlated with SIEM alerts |
| 2026-03-25 19:05 | Evening clinical wave delivered | Secure message theme |
| 2026-03-25 19:21 | Multiple clicks within 16 minutes | Shift transition pressure |
| 2026-03-26 02:14 | Suspicious privileged activity | Service-account misuse pattern observed |
| 2026-03-26 03:18 | IR escalation | Credential exposure playbook activated |

## Outcome Metrics From Incident Review

| Metric | Value |
|---|---:|
| Delivered | 41 |
| Clicked | 23 |
| Click rate | 56% |
| Reported by users | 6 |
| Report rate | 15% |
| Mean time to first click | 11 minutes |
| Mean time to report | 74 minutes |
| Credential submissions | 6 |
| First report before first click | No |
| Departments affected | Clinical, Billing, Finance, IT |

## Role Patterns

### Clinical Staff

Clinical staff clicked most often during shift start or handoff. Lures that threatened EHR access were strongest because blocked access directly affects patient care.

### Administrative and Billing Staff

Administrative staff responded to compliance and benefits language. They were less influenced by patient-care urgency but more influenced by deadlines, policy language and task completion.

### Finance and Executives

Finance and executive users were more cautious with links but more exposed to business email compromise and document-review pressure. The primary risk is not click rate alone but high-impact action.

### IT Staff

IT staff were less likely to click generic lures but more exposed to vendor-support and change-window lures. Their risk is privileged follow-on action, not basic credential entry.

## Design Implications

1. Campaign metrics must track click, report and mean time to report separately.
2. Clinical waves must avoid unsafe timing during real critical events; shift start can be used, but ICU/OR windows require exclusion.
3. Templates must be realistic enough to teach real attack recognition, not obvious enough to produce false confidence.
4. HR privacy constraints are essential because individual shame reduces reporting.
5. Repeated simulation failure should trigger coaching, not discipline, until a formal escalation threshold is met.
