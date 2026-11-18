# IOC Scoring Reference

**Owner:** SOC Engineering  
**Version:** 1.0  
**Applies to:** `enrich_ioc.py`, phishing triage playbook, credential exposure playbook

## Verdict Model

| Condition | Score | Verdict | Automation Meaning |
|---|---:|---|---|
| Private or loopback IP | 0 | ALLOW | Internal address by itself is not a threat-intel hit |
| Benign IP or domain allowlisted | 0 | ALLOW | Known infrastructure or approved vendor |
| Malicious feed confidence >= 80 | confidence | BLOCK | Strong indicator; playbook can escalate case |
| Malicious feed confidence < 80 | confidence | INVESTIGATE | Suspicious but requires human review |
| Unknown public IP or external domain | 30 | INVESTIGATE | Not known bad, not known good |
| Malformed IOC | 30 | INVESTIGATE | Preserve analyst review rather than fail silently |

## Documentation IP Ranges

The lab uses RFC documentation ranges so no real hostile infrastructure is referenced:

- `192.0.2.0/24`
- `198.51.100.0/24`
- `203.0.113.0/24`

Student scripts must classify these explicitly as `documentation`.

## Required Output Fields

Every enrichment result should include `ioc`, `type`, `ip_class`, `reverse_dns`, `feed_result`, `score`, `verdict`, and `enriched_at`.

Private or loopback IPs should include a note such as `Private address range; internal network traffic`.

## Automation Boundary

`BLOCK` means a strong malicious indicator. It does not mean endpoint isolation or user disablement may happen automatically.
