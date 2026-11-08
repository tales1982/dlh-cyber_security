# MedDefense Endpoint Hardening Baseline

**Document owner:** IT Security  
**Baseline version:** 1.4  
**Assessment date:** 2026-04-18  
**Scope:** Windows clinical workstations, Linux clinical support servers, and administrative endpoints  
**Classification:** Confidential

## Executive Summary

The endpoint hardening program was completed after the Cobalt Strike incident to reduce workstation compromise risk and improve auditability of endpoint security controls. The program covered 280 Windows workstations across three MedDefense sites, 3 Linux clinical support servers (`billing-srv-01`, `web-srv-01`, `log-srv-01`), and 26 administrative laptops.

The Linux servers were brought to a CIS-aligned score of 84/100. Windows workstations improved significantly but remain inconsistent across departments because legacy Group Policy Objects still conflict with the new security baseline. This document is strong evidence for technical safeguard implementation, but it is not sufficient by itself to prove governance, policy adoption, workforce accountability, vendor management, or periodic access review.

## Scope Details

| Asset Group | Count | Coverage | Notes |
|---|---:|---:|---|
| Clinical Windows workstations | 280 | 231 hardened | ICU and ED endpoints prioritized first |
| Administrative laptops | 26 | 18 hardened | Finance and executive laptops partially complete |
| Linux support servers | 3 | 3 hardened | CIS-aligned hardening completed |
| Domain controllers | 2 | Not included | Reviewed under IAM project, not endpoint hardening |
| Medical devices | Unknown | Not included | Inventory incomplete |

## Implemented Controls

| Control Area | Status | Evidence |
|---|---|---|
| Local administrator restriction | Partial | Local admin group restricted on hardened Windows endpoints |
| Password policy enforcement | Implemented | Domain GPO enforces minimum length and lockout |
| Windows Defender baseline | Partial | Enabled on managed endpoints; exceptions inconsistent |
| Sysmon deployment | Partial | Deployed to 198 of 280 clinical workstations |
| PowerShell Script Block Logging | Partial | Enabled on IT and Finance endpoints, missing from several clinical OU policies |
| Linux SSH hardening | Implemented | Root login disabled, password auth disabled on support servers |
| Linux auditd | Implemented | auditd rules deployed to support servers |
| Sudo logging | Implemented | Linux sudo logs forwarded to `log-srv-01` |
| Disk encryption | Partial | BitLocker confirmed on 173 Windows endpoints |
| Centralized log forwarding | Partial | Sysmon and auditd forwarding incomplete |

## Known Gaps

1. **Endpoint inventory incomplete:** workstation inventory does not include unmanaged biomedical devices or network-connected medical equipment.
2. **Legacy GPO conflict:** several older GPOs still override Script Block Logging and PowerShell restrictions.
3. **Medical device exclusion:** biomedical systems were not part of the baseline and may handle ePHI or operational telemetry.
4. **Evidence gap:** monthly review sign-off is not documented. Hardening exists technically but review evidence is weak.
5. **Coverage gap:** Sysmon coverage is below 80% of clinical endpoints.

## Audit Mapping Notes

This artifact supports:

- NIST CSF PR.PS-01: configuration management and secure system configuration
- NIST CSF DE.CM-01: endpoint monitoring where Sysmon/auditd is deployed
- HIPAA 164.312(b): audit controls, partially, for systems sending logs
- HIPAA 164.312(c)(1): integrity, partially, for hardened systems

This artifact does **not** prove:

- organization-wide policy adoption
- workforce sanctions or acceptable use enforcement
- vendor management
- complete asset inventory
- periodic access review

## Evidence Quality

**Evidence strength:** Partial  
**Reason:** technical configuration evidence exists, but management approval and recurring review records are incomplete.
