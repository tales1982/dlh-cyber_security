# Insider Threat Case Notes

**Purpose:** Provide realistic case context for `insider_threat_program.md`.  
**Classification:** Confidential training material

## Case A: Dormant Service Account Reactivation

| Field | Detail |
|---|---|
| Account | `svc_helpdesk` |
| Normal function | Ticket routing automation |
| Privilege | Domain Admin |
| Observed anomaly | Interactive logon at 02:13 |
| Follow-on behavior | Accessed two servers outside documented function |
| Observer | SOC and IT operations |
| Lesson | Dormant or role-inconsistent service account activity is reportable without accusing a person |

## Case B: Transferred Employee Retains Access

| Field | Detail |
|---|---|
| Account | `j.yamamoto` |
| Prior role | IT systems support |
| New role | Finance analyst |
| Observed anomaly | Retained Server Admins membership |
| Observer | Manager, HR, IT |
| Lesson | Role transfer must trigger access review |

## Case C: Vendor Support Overreach

| Field | Detail |
|---|---|
| Vendor | Unnamed clinical application vendor |
| Request | Temporary domain admin for troubleshooting |
| Issue | No ticket justification and no expiration |
| Observer | IT helpdesk |
| Lesson | Vendor urgency cannot bypass privilege approval |

## Case D: Unusual Data Access Pattern

| Field | Detail |
|---|---|
| User type | Administrative staff |
| Behavior | Accessed unusually high number of patient records unrelated to role |
| Observer | Audit log review |
| Lesson | Access-based indicators should be triaged carefully and privately |

## Ethical Note

These cases are about observable risk signals. They are not proof of malicious intent by themselves. The program must teach employees to report facts, not labels.
