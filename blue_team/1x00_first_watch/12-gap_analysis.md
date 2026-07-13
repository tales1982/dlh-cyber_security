# Prioritized Gap Analysis MedDefense Health Systems

*Methodology note: "no detective or corrective control" in the Critical/High rules below is read strictly both functions absent, not just one. Where a corrective control (e.g., backup) exists but detective does not, the gap is rated High rather than Critical.*

## Gaps

### GAP-001

- **Title:** EHR database reachable from the entire internal network, with no detection of anomalous access
- **Affected Asset(s):** `ehr-db-01` (Critical, Task 8)
- **Data at Risk:** Patient medical records (Restricted, Task 9)
- **Current Control Status:** C-002 (VPN-restricted subnet access), C-009 (nightly backup) apply
- **What is Missing:** Detective no monitoring of who queries the database beyond its intended app server
- **Risk Level:** High
- **Risk Justification:** Critical asset and Restricted data, but a corrective control (backup) does exist the missing piece is detection, not total absence of coverage.
- **Potential Impact:** An attacker anywhere on the flat network could query or exfiltrate patient records directly, with no alert generated.

### GAP-002

- **Title:** No functioning detection or incident-response capability anywhere in the environment
- **Affected Asset(s):** Network Core, Identity & Directory Services, EHR System (all Critical, Task 8)
- **Data at Risk:** All Restricted and Confidential categories (Task 9) logs themselves are Confidential and unprotected
- **Current Control Status:** C-005, C-013 produce logs, but nothing reviews or alerts on them (Task 10)
- **What is Missing:** Detective (functioning) and Corrective (no incident response plan exists anywhere in the project)
- **Risk Level:** Critical
- **Risk Justification:** Affects Critical assets and Restricted data; detection is void in practice (logs nobody reads) and there is no documented response process both functions genuinely absent.
- **Potential Impact:** Repeat of Task 2 a compromise runs for weeks undetected, discovered only by accident.

### GAP-003

- **Title:** Sole backup repository has no protection or redundancy of its own
- **Affected Asset(s):** `NAS-01` (Critical, Task 8)
- **Data at Risk:** Mirrors Restricted/Confidential data from every backed-up system (Task 9)
- **Current Control Status:** C-002 restricts network path only
- **What is Missing:** Detective and Corrective nothing monitors NAS-01 for tampering, and nothing backs it up
- **Risk Level:** Critical
- **Risk Justification:** Critical asset, no detective or corrective control protects the control itself.
- **Potential Impact:** A single ransomware event with lateral movement destroys production and the last-resort recovery copy simultaneously.

### GAP-004

- **Title:** Infusion pump fleet has zero dedicated security controls
- **Affected Asset(s):** BD Alaris Pump Fleet (Critical, Task 8)
- **Data at Risk:** Real-time clinical/vitals and dosing data (Restricted, Task 9)
- **Current Control Status:** None found in Task 10 coverage map
- **What is Missing:** Preventive, Detective, and Corrective complete absence
- **Risk Level:** Critical
- **Risk Justification:** Critical, patient-safety asset with no control coverage of any kind and a known, vendor-flagged, unmitigated vulnerability.
- **Potential Impact:** Direct patient harm through dosage manipulation, with no way to detect or contain it.

### GAP-005

- **Title:** Endpoint antivirus excludes every server in the environment
- **Affected Asset(s):** `ehr-srv-01`, `billing-srv-01`, `ad-dc-01/02`, `file-srv-01` (Critical, Task 8)
- **Data at Risk:** Patient records, financial data, credentials (Restricted/Confidential, Task 9)
- **Current Control Status:** C-009 backup exists; C-005 covers only `ehr-srv-01`
- **What is Missing:** Preventive/Detective coverage on every server except partial logging on one
- **Risk Level:** High
- **Risk Justification:** Critical assets, but a corrective control (backup) exists org-wide, so coverage is incomplete rather than fully absent.
- **Potential Impact:** Malware on any server (as already happened twice) runs unchecked until it causes a visible symptom.

### GAP-006

- **Title:** Network closet has no lock, exposed credentials, no camera and no breach procedure
- **Affected Asset(s):** Network Core (Critical, Task 8) A-022
- **Data at Risk:** System credentials (Restricted, Task 9)
- **Current Control Status:** None
- **What is Missing:** Preventive, Detective, and Corrective, all absent
- **Risk Level:** Critical
- **Risk Justification:** Critical asset, complete absence of detective and corrective controls, trivial to exploit.
- **Potential Impact:** Anyone can read the switch credentials off the wall and reconfigure or intercept traffic for an entire floor, undetected.

### GAP-007

- **Title:** Medical IoT devices share a flat network with no isolation
- **Affected Asset(s):** Medical IoT category monitors, badge readers, nurse call (Critical, Task 8)
- **Data at Risk:** Real-time clinical data (Restricted, Task 9)
- **Current Control Status:** Perimeter firewall only
- **What is Missing:** Preventive (no segmentation) and Detective (no device-specific monitoring)
- **Risk Level:** Critical
- **Risk Justification:** Critical, patient-safety category with no dedicated detective or corrective control.
- **Potential Impact:** A compromised workstation reaches medical devices directly the same pattern flagged for the MRI in Task 6, but across the entire device fleet.

### GAP-008

- **Title:** Billing server has weak coverage despite two prior compromises
- **Affected Asset(s):** `billing-srv-01` (High, Task 8)
- **Data at Risk:** Financial/billing data (Confidential, Task 9)
- **Current Control Status:** C-002, C-009 apply; no AV, no dedicated detective control
- **What is Missing:** Preventive and Detective are both incomplete
- **Risk Level:** High
- **Risk Justification:** High-rated asset, Confidential data, with incomplete (not absent) coverage corrective control exists.
- **Potential Impact:** A third compromise, following the same pattern as the ransomware and cryptominer incidents.

### GAP-009

- **Title:** HR file share reachable by unmanaged devices
- **Affected Asset(s):** `file-srv-01`
- **Data at Risk:** Employee HR records (Confidential, Task 9)
- **Current Control Status:** Standard file permissions only
- **What is Missing:** Network-level segmentation to prevent unmanaged device reachability
- **Risk Level:** High
- **Risk Justification:** Confidential data with a proven (not theoretical) incomplete-coverage incident Task 1, Incident F.
- **Potential Impact:** An unauthorized device on the network reaches employee PII with no restriction.

### GAP-010

- **Title:** Shared PACS login removes individual accountability for imaging access
- **Affected Asset(s):** `pacs-srv-01` (Critical, Task 8)
- **Data at Risk:** Medical imaging data (Restricted, Task 9)
- **Current Control Status:** None reported to Sarah Park, unresolved
- **What is Missing:** Detective (no way to attribute access) and Corrective (issue known and unaddressed)
- **Risk Level:** Critical
- **Risk Justification:** Critical asset, Restricted data, no detective or corrective control despite the issue being formally known.
- **Potential Impact:** Unauthorized viewing of patient imaging cannot be traced to an individual, undermining any investigation.

### GAP-011

- **Title:** Three confirmed shadow IT systems sit entirely outside governance
- **Affected Asset(s):** A-012, A-023, A-025, A-026, A-027 (Shadow IT category, High, Task 8)
- **Data at Risk:** Research data, HR-adjacent network reachability, unclear scope (Task 9/11)
- **Current Control Status:** None, by definition
- **What is Missing:** Every control category
- **Risk Level:** High
- **Risk Justification:** High-rated category with control coverage entirely absent, though individual device impact is bounded compared to core clinical systems.
- **Potential Impact:** Any of the five becomes an undetected foothold or data-loss point, as detailed in Task 11.

### GAP-012

- **Title:** Flat network turns every endpoint into a potential pivot point
- **Affected Asset(s):** Central Workstation Fleet (Medium, Task 8)
- **Data at Risk:** Varies by what each workstation accesses
- **Current Control Status:** C-006, C-008, C-012 all apply and reduce but do not eliminate the risk
- **What is Missing:** Network segmentation to cap the blast radius of a single endpoint compromise
- **Risk Level:** Medium
- **Risk Justification:** Medium-rated asset with partial controls already reducing risk, per the Medium rule.
- **Potential Impact:** A single phished workstation becomes a launchpad reaching servers and medical devices alike.

### GAP-013

- **Title:** Print server past end-of-life
- **Affected Asset(s):** `print-srv-01`
- **Data at Risk:** Minimal print jobs only
- **Current Control Status:** Internal-network-only exposure acts as a partial compensating factor
- **What is Missing:** OS support/patching
- **Risk Level:** Low
- **Risk Justification:** Low-value target with a partial compensating measure (no external exposure), consistent with Marcus's own M-08 assessment.
- **Potential Impact:** Limited a compromise here is a compliance issue more than an active exploitation risk.

## Gap Distribution Summary

**By risk level:** 6 Critical (GAP-002, 003, 004, 006, 007, 010), 5 High (GAP-001, 005, 008, 009, 011), 1 Medium (GAP-012), 1 Low (GAP-013) 13 gaps total.

**Asset categories with the most gaps:** Medical IoT and File/Backup Infrastructure each appear in 2-3 gaps; Network Core, EHR, and PACS each anchor at least one Critical gap confirming these as the categories needing the most attention.

**Concentration by control function:** Overwhelmingly **Detective and Corrective**. Every single gap in this list traces back to a missing or non-functional Detective or Corrective control, never a total absence of Preventive measures this matches the pattern first identified in Task 5: MedDefense over-invests in prevention and has almost no ability to notice or recover when prevention fails.
