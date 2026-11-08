# MedDefense Sigma Detection Catalog

**Owner:** SOC Engineering  
**Catalog version:** 2.1  
**Last updated:** 2026-04-22  
**Classification:** Confidential

## Overview

The Sigma detection catalog documents analytic rules developed after the Cobalt Strike incident. The rules are mapped to common attack behaviors observed during the incident: credential dumping, encoded PowerShell, suspicious remote access, service account abuse, and destructive ransomware precursors.

## Active Rules

| Rule ID | Filename | ATT&CK Mapping | Status | Data Source | Notes |
|---|---|---|---|---|---|
| SIG-001 | `credential_dumping_lsass.yml` | T1003.001 | Active | Sysmon Event ID 10 | Detects suspicious process access to LSASS |
| SIG-002 | `powershell_encoded_command.yml` | T1059.001 | Active | PowerShell logs | Requires Script Block Logging |
| SIG-003 | `suspicious_rdp_lateral_movement.yml` | T1021.001 | Active | Windows Security | Detects unusual RDP between workstation subnets |
| SIG-004 | `service_account_interactive_logon.yml` | T1078 | Active | Windows Security | Flags service accounts used interactively |
| SIG-005 | `domain_admin_group_change.yml` | T1098 | Active | AD Security | Detects privileged group membership changes |
| SIG-006 | `shadowcopy_deletion.yml` | T1490 | Active | Sysmon / Security | Ransomware precursor detection |
| SIG-007 | `cobalt_strike_named_pipe.yml` | T1105 | Testing | Sysmon Event ID 17/18 | Needs tuning due false positives |
| SIG-008 | `impossible_travel_vpn.yml` | T1078 | Draft | VPN logs | Not production-ready |
| SIG-009 | `s3_public_policy_change.yml` | T1530 | Draft | CloudTrail | CloudTrail region coverage incomplete |

## Coverage Gaps

- Script Block Logging is not enabled on all endpoints, limiting SIG-002.
- CloudTrail is not enabled in the DR region, limiting cloud detections.
- Medical devices and biomedical gateways do not forward logs to the SIEM.
- Current catalog does not include a formal detection engineering change-management record.
- SOC reviews rule performance weekly, but review evidence is informal.

## Audit Mapping Notes

This artifact supports:

- DE.CM-01: networks and endpoints monitored for adverse events
- DE.CM-06: external service provider activity monitored, partially, where cloud logs exist
- DE.AE-02: potentially adverse events analyzed, partially

This artifact does **not** prove:

- formal policy approval
- complete audit control coverage
- workforce training completion
- vendor contractual controls

## Evidence Quality

**Evidence strength:** Partial to Strong depending on subcategory.  
Rules exist and are specific, but operational coverage depends on log source completeness.
