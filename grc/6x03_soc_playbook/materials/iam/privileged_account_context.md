# Privileged Account Context

The credential exposure playbook uses this context to interpret account risk.

## Domain Admin Accounts

| Account | Type | Context | Risk |
|---|---|---|---|
| `svc_helpdesk` | service | helpdesk automation | vendor-granted Domain Admin, high risk |
| `svc_epic_int` | service | old Epic integration | dormant, no current function |
| `svc_backup` | service | backup automation | overprivileged |
| `admin.legacy` | user | legacy migration account | dormant and no MFA in 6x02 |
| `t.morrison` | user | former contractor | should be disabled |
| `j.yamamoto` | user | transferred to Finance | retained IT privilege |

Domain Admin account involvement in credential access should escalate even when source IP is internal. Service accounts should not normally be used interactively.
