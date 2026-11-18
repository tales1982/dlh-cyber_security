# Sample Stdout Outputs

## Phishing Known Malicious

```text
[2026-04-28T10:15:48Z] PHISHING TRIAGE PLAYBOOK
Alert      : ALT-20260428-001
Rule       : phishing_email_suspicious_sender
IOCs       : 3 extracted, 2 enriched, 1 dedup skipped
  198.51.100.42          ipv4    BLOCK       score=95  (c2, cobalt_strike)
  meddefense-secure.net  domain  BLOCK       score=97  (typosquat, phishing)
Verdict    : ESCALATE
Case       : CASE-20260428-001  Severity: Critical  Status: escalated
Action     : SOC notification queued for on-call analyst
```

## Credential Exposure Critical

```text
[2026-04-28T14:33:22Z] CREDENTIAL EXPOSURE PLAYBOOK
Alert      : ALT-20260428-007
Host       : WST-WS-031
User       : svc_helpdesk  Privilege: Domain Admin
Source IP  : 198.51.100.42  Verdict: BLOCK  Score: 95
MITRE      : T1003.001 OS Credential Dumping: LSASS Memory
Case       : CASE-20260428-004  Severity: Critical  Status: escalated
Action     : Host written to isolation_queue.json for analyst authorization
```
