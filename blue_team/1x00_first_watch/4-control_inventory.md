# Security Control Inventory — MedDefense Health Systems

## Controls

### C-001

- **Control Name:** Firewall Rule Web Inbound Restriction
- **Description:** FortiGate policy "Allow-Web-Inbound" permits inbound HTTP/HTTPS traffic from the internet only to `web-srv-01` in the DMZ; all other inbound paths are blocked by default, and matching traffic is logged.
- **Category:** Technical
- **Function:** Preventive
- **Asset(s) Protected:** `web-srv-01` (public website / patient portal)
- **Source:** Artifact 1 Firewall Configuration, rule "Allow-Web-Inbound"

### C-002

- **Control Name:** Firewall Rule — VPN-Restricted Server Access
- **Description:** Policies "Allow-VPN-Westside" and "Allow-VPN-HQ" only let traffic reach the server subnet if it arrives through the site-to-site VPN interfaces, blocking direct internet access to that subnet.
- **Category:** Technical
- **Function:** Preventive
- **Asset(s) Protected:** Server subnet (`ehr-srv-01`, `ehr-db-01`, `billing-srv-01`, `ad-dc-01`, `file-srv-01`)
- **Source:** Artifact 1 Firewall Configuration, rules "Allow-VPN-Westside" / "Allow-VPN-HQ"

### C-003

- **Control Name:** Firewall Default-Deny Rule
- **Description:** The final policy ("Deny-All") blocks and logs any traffic that did not match an earlier explicit allow rule.
- **Category:** Technical
- **Function:** Preventive
- **Asset(s) Protected:** Entire internal network
- **Source:** Artifact 1 Firewall Configuration, rule "Deny-All"

### C-004

- **Control Name:** SSH Key-Only Authentication (ehr-srv-01)
- **Description:** `sshd_config` disables password login and root login, requiring public-key authentication to reach the server over SSH.
- **Category:** Technical
- **Function:** Preventive
- **Asset(s) Protected:** `ehr-srv-01`
- **Source:** Artifact 2 SSH Configuration

### C-005

- **Control Name:** SSH Verbose Authentication Logging (ehr-srv-01)
- **Description:** `sshd_config` sets `LogLevel VERBOSE` and logs to the AUTH facility, recording authentication attempts against the server.
- **Category:** Technical
- **Function:** Detective
- **Asset(s) Protected:** `ehr-srv-01`
- **Source:** Artifact 2 SSH Configuration

### C-006

- **Control Name:** Password Complexity & Rotation Policy
- **Description:** Company policy requires 8+ character passwords with mixed case, numbers and symbols, rotated every 90 days, with 5-password history.
- **Category:** Administrative
- **Function:** Preventive
- **Asset(s) Protected:** All user accounts
- **Source:** Artifact 3 Password Policy

### C-007

- **Control Name:** Account Lockout on Failed Logins
- **Description:** Accounts lock for 30 minutes after 5 failed login attempts, enforced via Active Directory Group Policy on Windows systems.
- **Category:** Technical
- **Function:** Preventive
- **Asset(s) Protected:** AD-managed user accounts (Windows systems)
- **Source:** Artifact 3 Password Policy, Section 5 (Enforcement)

### C-008

- **Control Name:** Sophos Endpoint Protection
- **Description:** Antivirus deployed on 372 Windows 10/11 workstations, actively blocking and quarantining detected threats (e.g. adware, phishing URLs, trojans in the last 30 days).
- **Category:** Technical
- **Function:** Preventive
- **Asset(s) Protected:** Windows workstations (Central, Westside, HQ)
- **Source:** Artifact 4 Sophos Antivirus Status Report

### C-009

- **Control Name:** Nightly Full Backup (Veeam)
- **Description:** Veeam runs a full nightly backup of core VMs to NAS-01, retained for 14 days, enabling restoration after data loss or corruption.
- **Category:** Technical
- **Function:** Corrective
- **Asset(s) Protected:** `ehr-srv-01`, `ehr-db-01`, `billing-srv-01`, `ad-dc-01`, `file-srv-01`, `web-srv-01`
- **Source:** Artifact 5 Backup Configuration

### C-010

- **Control Name:** Uniformed Security Guard (Main Entrance)
- **Description:** A ClearView guard staffs the Central main entrance Mon–Fri, 07:00–19:00, registering visitors and verifying badges before allowing entry.
- **Category:** Physical
- **Function:** Preventive
- **Asset(s) Protected:** Central main entrance / lobby
- **Source:** Artifact 6 Physical Security Contract

### C-011

- **Control Name:** CCTV Camera Coverage
- **Description:** Analog cameras cover the main entrance, ER entrance and parking garage at Central (recorded to a 30-day DVR), plus one camera at Westside's front entrance.
- **Category:** Physical
- **Function:** Detective
- **Asset(s) Protected:** Building entrances, parking garage
- **Source:** Artifact 6  Physical Security Contract, Camera System

### C-012

- **Control Name:** Annual Security Awareness Training
- **Description:** Mandatory "CyberSafe Basics" module covering password hygiene, phishing recognition, and physical security awareness for all staff.
- **Category:** Administrative
- **Function:** Preventive
- **Asset(s) Protected:** All staff / all systems (reduces human error)
- **Source:** Artifact 7  Training Records

### C-013

- **Control Name:** FortiGate Local Traffic Logging
- **Description:** The firewall retains its own traffic logs locally for 30 days, providing a record of network activity for later review.
- **Category:** Technical
- **Function:** Detective
- **Asset(s) Protected:** Network perimeter (visibility)
- **Source:** Artifact 8 Log Management

## Control Summary Matrix

|                          | Preventive                               | Detective    | Corrective | Compensating | Deterrent |
| ------------------------ | ---------------------------------------- | ------------ | ---------- | ------------ | --------- |
| **Technical**      | C-001, C-002, C-003, C-004, C-007, C-008 | C-005, C-013 | C-009      |              |           |
| **Administrative** | C-006, C-012                             |              |            |              |           |
| **Physical**       | C-010                                    | C-011        |            |              |           |
