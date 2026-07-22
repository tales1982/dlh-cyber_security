# 3. The Gap-to-Framework Bridge MedDefense Health Systems

**Analyst:** Security Analyst
**Date:** Current

*Selected from the 12 Critical gaps in the 1x01 T15 re-prioritized list, prioritized for having the strongest direct evidence in the 1x02 vulnerability scan alongside their threat correlation.*

## GAP-002 No Functioning Detection or Incident-Response Capability

- **Gap Reference:** GAP-002 (1x00 Task 12, Critical)
- **Description:** Logs exist in isolated pockets, but nothing reviews or alerts on them anywhere in the environment.
- **Vulnerability Evidence:** 1x02 Finding 031 (Ghostcat, CVSS 9.8) was found only through a human manually following up on a "Medium" clue (Finding 017) direct proof that automated detection would not have caught the single most dangerous vulnerability in the entire scan.
- **Threat Context:** All 6 threat actor types (1x01 T6); appears in Kill Chains #1, #2, #3, #5 and all 3 threat scenarios (S1, S2, S3) 7 of 8 possible appearances, the single most universal enabler of undetected dwell time in the entire threat landscape.
- **NIST CSF Function:** Detect (DE.CM, DE.AE)
- **CIS Control:** Control 8 (Audit Log Management) and Control 13 (Network Monitoring and Defense)
- **Recommended Action:** Deploy a SIEM (Wazuh) covering critical servers and the firewall first, with a named owner reviewing alerts on a defined daily cadence.

## GAP-001 EHR Database Reachable Network-Wide

- **Gap Reference:** GAP-001 (1x00 Task 12, upgraded to Critical in 1x01 T15)
- **Description:** `ehr-db-01` accepts connections from the entire internal network with no anomalous-access detection.
- **Vulnerability Evidence:** 1x02 Finding 003 (PostgreSQL unrestricted network access no exploit required, only network reachability and a password).
- **Threat Context:** Ransomware Groups, Insider (Malicious/Negligent), Unskilled/Opportunistic effectively every actor type once any foothold exists; Kill Chains #1, #3, #5; named in all 3 scenarios (S1, S2, S3), the only gap to appear in every one.
- **NIST CSF Function:** Protect (PR.AA Access Control)
- **CIS Control:** Control 3 (Data Protection, Safeguard 3.3) and Control 6 (Access Control Management)
- **Recommended Action:** Restrict `pg_hba.conf` to accept connections only from `ehr-srv-01`, and include database access logs in the SIEM scope from GAP-002.

## GAP-014 No MFA Anywhere in the Environment

- **Gap Reference:** GAP-014 (1x00 Task 13, Critical)
- **Description:** No multi-factor authentication exists on any remote, administrative or externally-exposed access path.
- **Vulnerability Evidence:** 1x02 Finding 009 (SSH password authentication enabled, no second factor) and Finding 019 (RDP enabled on 5 hosts with no additional authentication layer beyond NLA).
- **Threat Context:** Ransomware Groups, the #1-priority actor type (1x01 T6); tied for the most kill-chain appearances of any gap Kill Chains #1, #2, #5; Scenarios S1, S3.
- **NIST CSF Function:** Protect (PR.AA)
- **CIS Control:** Control 6 (Access Control Management, Safeguards 6.3/6.4/6.5)
- **Recommended Action:** Enable MFA on all externally-exposed applications, VPN remote access, and administrative accounts using MedDefense's existing O365 E3 licensing no new procurement required.

## GAP-008 Billing Server Weak Coverage Despite Two Prior Compromises

- **Gap Reference:** GAP-008 (1x00 Task 12, upgraded to Critical in 1x01 T15)
- **Description:** `billing-srv-01` remains under-protected despite being compromised twice already (ransomware, then a cryptominer).
- **Vulnerability Evidence:** 1x02 Findings 001, 002, 006, 009, 011 and 026 six of the report's 31 findings concentrate on this single host, all traceable to the same unpatched, EOL, unhardened base.
- **Threat Context:** Unskilled/Opportunistic Attacker, ranked #2 priority actor (1x01 T6); Kill Chain #4, Step 1 this is not a theoretical path, it is MedDefense's own proven pattern.
- **NIST CSF Function:** Protect (PR.PS Platform Security) / Identify (ID.AM software currently supported)
- **CIS Control:** Control 2 (Software Assets, Safeguard 2.2) and Control 7 (Continuous Vulnerability Management)
- **Recommended Action:** Enroll `billing-srv-01` in Ubuntu Pro/ESM immediately and apply the emergency Apache patch within 7 days.

## GAP-003 Sole Backup Repository (NAS-01) Unprotected

- **Gap Reference:** GAP-003 (1x00 Task 12, Critical)
- **Description:** MedDefense's only backup copy has no protection or redundancy of its own.
- **Vulnerability Evidence:** 1x02 Finding 015 (NAS-01 management interface exposed network-wide, backup data stored unencrypted).
- **Threat Context:** Ransomware Groups specifically backup neutralization is BlackReef's own documented operational playbook step (1x01 T6); Kill Chain #1, Step 6; Scenario S1 ("Operation Flatline"), named explicitly.
- **NIST CSF Function:** Recover (RC.RP)
- **CIS Control:** Control 11 (Data Recovery, Safeguards 11.3/11.4)
- **Recommended Action:** Restrict the DSM interface to an admin-only subnet, enable backup encryption, and implement the cloud replication with immutable storage already approved in the 1x00 Risk Decisions.

## GAP-017 No Privileged Access Tiering for Active Directory

- **Gap Reference:** GAP-017 (1x00 Task 12, Critical)
- **Description:** No separation exists between domain-admin-level credentials and day-to-day administrative accounts.
- **Vulnerability Evidence:** 1x02 Finding 007 (LDAP signing not required, SMBv1 enabled on `ad-dc-01`) a second, independent path to the same domain-compromise outcome this gap describes.
- **Threat Context:** Ransomware Groups, the #1-priority actor type; Kill Chains #1, #2 the specific mechanism converting a single phished or purchased credential into full domain compromise.
- **NIST CSF Function:** Protect (PR.AA)
- **CIS Control:** Control 5 (Account Management, Safeguard 5.4) and Control 6
- **Recommended Action:** Enforce LDAP signing, disable SMBv1, and implement tiered administrative accounts that separate Domain Admin activity from routine account management.

## GAP-007 Medical IoT Devices Share a Flat Network

- **Gap Reference:** GAP-007 (1x00 Task 12, Critical)
- **Description:** The Philips monitor fleet and other medical IoT devices sit on the same flat network as general workstations, with no isolation.
- **Vulnerability Evidence:** 1x02 Finding 016 (13 Philips IntelliVue monitors reachable network-wide with unauthenticated web interfaces and an exposed HL7 data channel).
- **Threat Context:** Unskilled/Opportunistic Attacker; Kill Chain #4, built directly on MedDefense's own proven `billing-srv-01` double-compromise pattern as its entry point.
- **NIST CSF Function:** Protect (PR.IR Technology Infrastructure Resilience)
- **CIS Control:** Control 12 (Network Infrastructure Management, Safeguard 12.2)
- **Recommended Action:** Extend the already-funded medical-device VLAN segmentation (GAP-004's Phase 1) to the Philips monitor fleet as Phase 2.

## GAP-004 Infusion Pump Fleet Has Zero Dedicated Controls

- **Gap Reference:** GAP-004 (1x00 Task 12, Critical)
- **Description:** The BD Alaris infusion pump fleet has no security controls of any kind despite a known, vendor-flagged vulnerability.
- **Vulnerability Evidence:** 1x02 Finding 010 (unchanged default credentials `admin/admin` on 7 of 7 scanned pumps, no network isolation implemented despite a two-year-old vendor advisory).
- **Threat Context:** Unskilled/Opportunistic Attacker directly; Ransomware Groups secondarily as a post-lateral-movement target; Kill Chain #4.
- **NIST CSF Function:** Protect (PR.AA / PR.PS)
- **CIS Control:** Control 4 (Secure Configuration, Safeguard 4.7) and Control 12
- **Recommended Action:** Reset default credentials fleet-wide immediately, and implement the dedicated pump VLAN already funded and phased in the 1x00 Risk Decisions.

## Traceability Summary Table

| Gap     | Vulnerability (1x02)                          | Threat Actor / Kill Chain (1x01)                     | NIST CSF Function  | CIS Control | Recommended Action                                  |
| ------- | --------------------------------------------- | ---------------------------------------------------- | ------------------ | ----------- | --------------------------------------------------- |
| GAP-002 | Finding 031 (found only via manual follow-up) | All 6 actors; KC1/2/3/5; S1/S2/S3                    | Detect             | 8, 13       | Deploy SIEM, assign daily alert review              |
| GAP-001 | Finding 003 (PostgreSQL open)                 | Ransomware/Insider/Opportunistic; KC1/3/5; S1/S2/S3  | Protect            | 3, 6        | Restrict`pg_hba.conf` to `ehr-srv-01`           |
| GAP-014 | Findings 009, 019 (no second factor)          | Ransomware Groups (#1); KC1/2/5; S1/S3               | Protect            | 6           | Enable MFA via existing O365 licensing              |
| GAP-008 | Findings 001, 002, 006, 009, 011, 026         | Unskilled/Opportunistic (#2); KC4                    | Protect / Identify | 2, 7        | ESM enrollment + emergency Apache patch             |
| GAP-003 | Finding 015 (NAS exposed, unencrypted)        | Ransomware Groups; KC1; S1                           | Recover            | 11          | Restrict DSM access, encrypt, cloud replication     |
| GAP-017 | Finding 007 (LDAP/SMBv1 on`ad-dc-01`)       | Ransomware Groups (#1); KC1/2                        | Protect            | 5, 6        | Enforce LDAP signing, disable SMBv1, tier AD access |
| GAP-007 | Finding 016 (Philips monitors exposed)        | Unskilled/Opportunistic; KC4                         | Protect            | 12          | Extend pump VLAN segmentation to monitor fleet      |
| GAP-004 | Finding 010 (Alaris default creds)            | Unskilled/Opportunistic; Ransomware (secondary); KC4 | Protect            | 4, 12       | Reset default creds, implement pump VLAN            |
