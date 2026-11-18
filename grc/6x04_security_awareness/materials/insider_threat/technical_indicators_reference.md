# Technical Indicators Reference

Use this file for the technical indicator framework in Task 7.

## Indicator 1: Dormant Privileged Account Activation

| Field | Detail |
|---|---|
| Log source | Windows Security Event 4624, IAM audit export |
| Detection logic | privileged account inactive >90 days logs in |
| 6x02 link | dormant accounts and `svc_helpdesk` risk |
| Triage question | Was this activity tied to approved change or incident response? |

## Indicator 2: Service Account Interactive Logon

| Field | Detail |
|---|---|
| Log source | Windows Security Event 4624 LogonType 2/10 |
| Detection logic | account name starts with `svc_` and interactive logon occurs |
| 6x02 link | service accounts with excessive privileges |
| Triage question | Should this service account ever log in interactively? |

## Indicator 3: Privileged Group Membership Change

| Field | Detail |
|---|---|
| Log source | Windows Security Event 4728/4732/4756 |
| Detection logic | user added to Domain Admins or Server Admins |
| Triage question | Is there an approved ticket and owner? |

## Indicator 4: LSASS Access From Privileged Context

| Field | Detail |
|---|---|
| Log source | Sysmon Event ID 10 |
| Detection logic | suspicious process accesses LSASS |
| Incident link | Cobalt Strike credential access path |
| Triage question | Is this approved security tooling? |

## Indicator 5: Unusual Patient Record Access

| Field | Detail |
|---|---|
| Log source | EHR audit log |
| Detection logic | user accesses records outside assigned unit or role pattern |
| Privacy note | Requires careful review and minimum necessary disclosure |
| Triage question | Is there a treatment, payment or operations reason? |

## Indicator 6: Bulk Download Outside Normal Hours

| Field | Detail |
|---|---|
| Log source | file share audit, EDR telemetry |
| Detection logic | unusual volume, unusual time, sensitive directory |
| Triage question | Does the employee's role justify this access? |
