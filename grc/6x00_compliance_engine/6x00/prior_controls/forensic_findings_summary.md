# Post-Incident Forensic Findings Summary

**Incident:** Nexus update channel compromise leading to Cobalt Strike beacon  
**Incident window:** 2026-03-25 to 2026-03-26  
**Prepared by:** Incident Response Team  
**Classification:** Confidential

## Executive Summary

The attacker gained initial access through a compromised vendor update path. The first confirmed beacon was observed on workstation `WST-WS-031`. The attacker attempted credential access, moved laterally, and used excessive service account privileges to accelerate domain compromise. The incident was contained before confirmed ePHI exfiltration, but forensic evidence shows identity control gaps and vendor trust controls were significant contributors.

## Key Findings

| Finding | Evidence | Risk |
|---|---|---|
| Vendor update channel abused | Proxy and endpoint logs from `WST-WS-031` | Trusted vendor path lacked sufficient validation |
| Cobalt Strike beacon detected | SIEM alert export and Sysmon events | Confirmed post-exploitation tooling |
| Credential access attempted | LSASS access event and memory artifact | Enabled lateral movement path |
| Service account over-privilege | `svc_epic_int` Domain Admin membership | Excessive privilege materially increased blast radius |
| Vendor risk process incomplete | No vendor tiering or security review record | Supply chain risk not governed |
| CloudTrail gaps | No DR region CloudTrail | Limits cloud investigation completeness |

## Risk Register Updates Created

- R-001: Vendor risk management process missing
- R-002: Privileged service account over-permissioned
- R-003: Endpoint logging coverage incomplete
- R-004: Security awareness evidence incomplete
- R-005: Cloud audit logging incomplete in DR region

## Compliance Relevance

This document supports:

- ID.RA-01: vulnerabilities and threats identified
- ID.RA-06: risk responses identified, partially
- DE.AE-02: adverse event analysis
- RS.AN-03: incident analysis
- HIPAA 164.308(a)(6): incident procedures, if paired with playbooks

This document does not by itself prove remediation closure. It is incident evidence, not a completed management program.
