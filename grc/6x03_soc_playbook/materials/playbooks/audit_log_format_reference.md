# Audit Log Format Reference

All playbooks append to `playbook_audit.log`.

## Phishing

```text
2026-04-28T10:15:48Z | PHISHING_TRIAGE | ALT-20260428-001 | IOCs:3 | BLOCK:2,INVESTIGATE:0,ALLOW:1 | Verdict:ESCALATE | Case:CASE-20260428-001 | Severity:Critical
```

## Credential

```text
2026-04-28T14:33:22Z | CREDENTIAL_EXPOSURE | ALT-20260428-007 | Host:WST-WS-031 | User:svc_helpdesk | IPVerdict:BLOCK | Privilege:Domain Admin | Case:CASE-20260428-003 | Severity:Critical | IsolationQueued:yes
```
