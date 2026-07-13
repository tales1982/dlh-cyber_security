# Complete Control Matrix — MedDefense Health Systems

## Part 1: Control Registry (Updated)

| ID    | Control Name                           | Category       | Function     | Asset(s) Protected        | Effectiveness | Evidence/Source                                                       |
| ----- | -------------------------------------- | -------------- | ------------ | ------------------------- | ------------- | --------------------------------------------------------------------- |
| C-001 | Firewall Web Inbound Restriction       | Technical      | Preventive   | `web-srv-01`            | Strong        | Task 4, Artifact 1                                                    |
| C-002 | Firewall VPN-Restricted Server Access | Technical      | Preventive   | Server subnet             | Adequate      | Task 4; Marcus's note: "allows ALL services from VPN too permissive" |
| C-003 | Firewall Default-Deny Rule             | Technical      | Preventive   | Entire internal network   | Strong        | Task 4, Artifact 1                                                    |
| C-004 | SSH Key-Only Auth                      | Technical      | Preventive   | `ehr-srv-01` only       | Adequate      | Task 4; strong on this host, but not rolled out org-wide              |
| C-005 | SSH Verbose Logging                    | Technical      | Detective    | `ehr-srv-01` only       | Weak          | Logs exist, nobody reviews them (Task 5, G-002)                       |
| C-006 | Password Complexity & Rotation Policy  | Administrative | Preventive   | All accounts              | Adequate      | Task 4; no MFA requirement, shared accounts tolerated                 |
| C-007 | Account Lockout                        | Technical      | Preventive   | AD-managed accounts       | Strong        | Task 4, enforced via GPO                                              |
| C-008 | Sophos Endpoint Protection             | Technical      | Preventive   | Windows workstations only | Weak          | Excludes all servers (Task 5, G-004)                                  |
| C-009 | Nightly Backup (Veeam)                 | Technical      | Corrective   | Core servers              | Adequate      | Never DR-tested; same room as production (Task 5, G-003)              |
| C-010 | Security Guard                         | Physical       | Preventive   | Central main entrance     | Weak          | Mon-Fri 7-19h only; no other site or hours                            |
| C-011 | CCTV Coverage                          | Physical       | Detective    | Building entrances        | Weak          | No coverage of server room/closet/admin wing (Task 5, G-006)          |
| C-012 | Annual Security Training               | Administrative | Preventive   | All staff                 | Weak          | 58-71% completion, no phishing simulation                             |
| C-013 | FortiGate Local Logging                | Technical      | Detective    | Network perimeter         | Weak          | Local only, no forwarding, no alerting                                |
| C-014 | MRI Network Segmentation               | Technical      | Compensating | `WS-RAD-01` (MRI)       | Weak          | Task 6 - **proposed, not yet implemented**                     |
| C-015 | MRI Risk Governance Process            | Administrative | Compensating | `WS-RAD-01` (MRI)       | Weak          | Task 6 -**proposed, not yet implemented**                       |
| C-016 | MRI Physical/USB Restriction           | Physical       | Preventive   | `WS-RAD-01` (MRI)       | Weak          | Task 6 -**proposed, not yet implemented**                       |

## Part 2: Updated Control Summary Matrix

|                          | Preventive                                              | Detective            | Corrective          | Compensating               | Deterrent |
| ------------------------ | ------------------------------------------------------- | -------------------- | ------------------- | -------------------------- | --------- |
| **Technical**      | 6 controls Adequate avg (3 Strong, 2 Adequate, 1 Weak) | 2 controls Weak avg | 1 control Adequate | 1 control Weak (proposed) | 0         |
| **Administrative** | 2 controls Weak/Adequate avg                            | 0                    | 0                   | 1 control Weak (proposed)  | 0         |
| **Physical**       | 2 controls Weak avg                                     | 1 control Weak       | 0                   | 0                          | 0         |

## Part 3: Control Coverage Map (Top 5 Critical Assets, Task 8)

| Critical Asset       | Preventive          | Detective    | Corrective | Compensating | Coverage Assessment                                                                                                                                  |
| -------------------- | ------------------- | ------------ | ---------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ehr-db-01`        | C-002, C-006        | —           | C-009      | —           | **Partially Protected** no detective control at all on the single highest-value data store                                                    |
| `ad-dc-01`         | C-002, C-006, C-007 | —           | C-009      | —           | **Partially Protected** same detective blind spot on the domain trust anchor                                                                   |
| `NAS-01`           | C-002               | —           | —         | —           | **Under-Protected** it *is* the corrective control for everything else, but nothing protects it directly and nothing corrects it if it fails |
| FortiGate 100F       | C-003 (self)        | C-013 (self) | —         | —           | **Partially Protected** decent self-coverage, but no redundancy/failover if it is taken down                                                   |
| BD Alaris Pump Fleet | —                  | —           | —         | —           | **Unprotected** no dedicated control of any kind; vendor-recommended isolation never implemented                                              |
