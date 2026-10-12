# MedDefense Severity Matrix

## Purpose

Common severity language for all MedDefense incidents. Applied from first alert through closure.

## Severity Matrix

| Level | Patient Safety Impact | Data Exposure | Service Availability | Max Response Time | Decision Authority |
|-------|-----------------------|---------------|----------------------|-------------------|--------------------|
| SEV1 | high | confirmed_broad | full_outage | 15 min | CISO |
| SEV2 | moderate | confirmed_limited | partial_outage | 30 min | IR Commander |
| SEV3 | low | suspected | degraded | 60 min | SOC Lead |
| SEV4 | none | none | none | 240 min | SOC Analyst |

## Level Definitions

### SEV1

- Ransomware affecting clinical systems across multiple sites
- Confirmed exfiltration of patient records at scale
- Patient monitoring system offline during active care

### SEV2

- Confirmed compromise of a clinical-access account
- Malware confirmed on a single workstation at a clinical site
- Suspected exfiltration under investigation

### SEV3

- Phishing email clicked by a staff member, no credential entry confirmed
- Slow EHR or imaging access at one site caused by suspicious network activity
- Repeated failed logins against a clinical-access account from an unknown source

### SEV4

- Phishing email reported by staff and blocked before any click
- Malware detected and quarantined automatically by EDR on an administrative workstation
- Port scan from the internet blocked at the perimeter firewall

## Escalation Rule

Severity is reviewed at every status update. It increases when new evidence raises patient safety, data exposure, or service availability to the next tier. It decreases only after confirmed containment and IR Commander approval.
