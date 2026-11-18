# Privileged Account Findings Relevant to Awareness

**Source:** 6x02 Identity at Scale  
**Prepared for:** 6x04 role-based guidance and insider threat design  
**Classification:** Confidential

## Summary

The IAM audit identified several identity risks that should influence awareness content for IT staff, managers and executives. These findings are not only technical control issues; they also define what employees should notice and report.

## Key Findings

| Finding ID | Account | Issue | Awareness Relevance |
|---|---|---|---|
| IAM-001 | `svc_epic_int` | Dormant service account with Domain Admin | IT staff should challenge undocumented service accounts |
| IAM-002 | `svc_helpdesk` | Helpdesk automation with Domain Admin | Helpdesk staff must understand privilege creep and vendor excuses |
| IAM-003 | `t.morrison` | Contractor still enabled with privileged groups | Managers must report contractor status changes quickly |
| IAM-004 | `admin.legacy` | Legacy admin account, no MFA, dormant | IT must remove migration-era accounts after projects end |
| IAM-005 | `j.yamamoto` | Transferred to Finance but kept IT privileges | Managers and HR must coordinate role changes with access review |
| IAM-006 | `svc_backup` | Backup service account overprivileged | Privileged automation should use scoped credentials |
| IAM-007 | `b.carter` | Disabled account still in privileged groups | Offboarding must remove access, not just disable sign-in |

## Failure Modes To Include in Guidance

- Dormant privileged accounts becoming active outside normal hours
- Service accounts used interactively
- Admin actions from personal devices or personal email
- Privilege changes without ticket/change reference
- Vendor requests for broad admin access
- Role transfers that do not trigger access review
- Disabled users retaining privileged group membership

## Insider Threat Program Implication

Not every anomaly is malicious. The program must teach observable reporting without accusation:

- "This account is active outside its documented purpose"
- "This user retained access after transfer"
- "This vendor request exceeds the approved scope"

Avoid language such as "suspicious person" or "bad employee" unless evidence supports escalation.
