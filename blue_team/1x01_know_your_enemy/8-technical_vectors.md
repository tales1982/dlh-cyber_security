
# 8. Technical Vectors Assessment

**Analyst:** Threat Intelligence Analyst
**Date:** Current

## 1. Vulnerable Software

```
Vector Category: Vulnerable Software
MedDefense Evidence: Apache 2.4.29 on billing-srv-01 (known RCE, standard
  support ended June 2023, ESM available but not activated); Ubuntu 18.04
  LTS underlying it is itself past standard support.
Affected Asset(s): billing-srv-01 (A-004)
Actor Most Likely to Exploit: Unskilled / Opportunistic Attacker — this is
  not hypothetical, the same vulnerability has already been exploited twice
  (ransomware, then a cryptominer) by automated, non-targeted scanning.
Exploitation Scenario: An automated scanner sweeping the internet for the
  known Apache 2.4.29 RCE finds billing-srv-01's exposed port 80, exploits
  it without any human targeting decision, and drops a payload — exactly
  the pattern documented in 1x00 Task 2.
Current Protection: C-009 (nightly backup) applies as a corrective
  measure; no preventive patching has occurred and no dedicated detective
  control monitors this host.
Gap Reference: GAP-008 (billing server has weak coverage despite two prior
  compromises)
```

## 2. Unsupported Systems

```
Vector Category: Unsupported Systems
MedDefense Evidence: Windows XP SP3 on WS-RAD-01 (MRI control workstation,
  cannot be patched, upgraded, replaced or disconnected per 1x00 Task 6);
  Windows Server 2012 R2 on print-srv-01 (EOL October 2023, still in
  production).
Affected Asset(s): WS-RAD-01 (A-014), print-srv-01 (A-008)
Actor Most Likely to Exploit: Ransomware Groups (via lateral movement once
  inside) and Unskilled/Opportunistic Attackers (direct exploitation of
  unpatched, publicly known vulnerabilities in these OS versions).
Exploitation Scenario: Once any actor gains a foothold anywhere on the
  flat network, WS-RAD-01 and print-srv-01 are trivial follow-on targets —
  neither can receive a security patch for known vulnerabilities in their
  respective operating systems, so any compromise here is effectively
  permanent until the hardware itself is replaced or isolated.
Current Protection: C-014/C-015/C-016 (MRI segmentation, risk governance,
  physical/USB restriction) are proposed but not implemented; print-srv-01
  has only its internal-only exposure as a partial compensating factor.
Gap Reference: GAP-013 (print-srv-01 past end-of-life); the MRI situation
  connects to GAP-004/GAP-007 (medical IoT/flat network) since it is the
  clinical-device instance of the same unpatchable-legacy-system pattern.
```

## 3. Open Service Ports

```
Vector Category: Open Service Ports
MedDefense Evidence: MySQL (billing-srv-01:3306) and PostgreSQL
  (ehr-db-01:5432) both reachable from the entire internal network instead
  of being restricted to their respective application servers; RDP (3389)
  enabled on reception and admin workstations with no network-level
  restriction; medical IoT web management interfaces (80/443) reachable
  network-wide.
Affected Asset(s): billing-srv-01 (A-004), ehr-db-01 (A-002), reception/
  admin workstations (A-013), medical IoT fleet (A-015/A-016)
Actor Most Likely to Exploit: Ransomware Groups during the reconnaissance/
  lateral-movement phase, and Insider (Malicious) actors who already sit on
  the internal network.
Exploitation Scenario: Once inside the network by any means, an attacker
  needs no further exploit to reach the patient database or billing data —
  the open ports themselves are the access path, turning a single foothold
  anywhere into direct database access everywhere.
Current Protection: C-002 (VPN-restricted server access) governs the
  perimeter path in, but does not restrict lateral reachability once
  inside; no detective control monitors these ports for anomalous queries.
Gap Reference: GAP-001 (EHR database reachable network-wide, no anomalous-
  access detection)
```

## 4. Default Credentials

```
Vector Category: Default Credentials
MedDefense Evidence: PACS shared account (`raduser/radiology1`) used by
  every radiology technician; BD Alaris infusion pump management interfaces
  running firmware 12.1.2 with a known, vendor-flagged CVE and vendor-
  recommended isolation never implemented.
Affected Asset(s): pacs-srv-01 (A-003), BD Alaris Pump Fleet (A-016)
Actor Most Likely to Exploit: Unskilled/Opportunistic Attackers (default/
  shared credentials require no skill to use) and Insider (Malicious)
  actors already aware of the shared PACS login.
Exploitation Scenario: Anyone — internal or, if the pump management
  interfaces are ever reachable beyond the internal network, external —
  who obtains the shared credential or exploits the known pump CVE gains
  access with no individual attribution possible, directly threatening
  both imaging confidentiality and, for the pumps, patient safety.
Current Protection: None found for either system — reported to Sarah Park
  and unresolved for PACS; no dedicated control of any kind for the pump
  fleet.
Gap Reference: GAP-010 (shared PACS login) and GAP-004/GAP-019 (infusion
  pump fleet has zero dedicated controls; management interfaces never
  verified for default credentials)
```

## 5. Unsecure Networks

```
Vector Category: Unsecure Networks
MedDefense Evidence: The entire environment is a single flat network with
  no VLAN or firewall separation between workstations, servers and medical
  devices (confirmed by the network scan: all subnets reachable from the
  scan host with no restriction); Westside Clinic connects via a consumer-
  grade Netgear router with no firewall, no managed switches and an
  unlocked server closet.
Affected Asset(s): Effectively every asset in the environment — Network
  Core (A-020/021/022) and the Westside Clinic site (A-024) specifically.
Actor Most Likely to Exploit: Ransomware Groups — this is the single
  enabling condition for their entire lateral-movement and privilege-
  escalation phases.
Exploitation Scenario: A compromise anywhere (a phished HQ workstation, a
  Westside device, a single medical monitor) can reach the domain
  controller, the EHR database and the backup NAS with no additional
  segmentation to slow it down — this is the exact pattern that let the
  regional-hospital breach in the Task 0 dossier reach its domain
  controller within 3 hours.
Current Protection: Perimeter firewall (C-001/C-003) only; nothing
  compensates once traffic is already inside.
Gap Reference: GAP-007 (medical IoT flat network), GAP-012 (flat network
  turns every endpoint into a pivot point), GAP-015 (Westside lacks basic
  network and physical security)
```

## 6. Removable Devices / Unmanaged Endpoints

```
Vector Category: Removable Devices / Unmanaged Endpoints
MedDefense Evidence: No Group Policy restricts USB storage devices
  anywhere except the MRI workstation specifically (and even there, C-016
  is only proposed, not implemented); unmanaged iPads and other shadow IT
  devices identified in 1x00 Task 11, plus Dr. Patel's personal NAS
  (T3 Scenario 3) and the IT intern's personal laptop (1x00 Incident F).
Affected Asset(s): Central Workstation Fleet (A-013), and any network
  segment an unmanaged device connects to.
Actor Most Likely to Exploit: Insider (Negligent) — every documented
  instance of this vector at MedDefense originated from well-intentioned
  convenience, not malicious intent, though it creates an opening any
  external actor could subsequently exploit.
Exploitation Scenario: An employee connects an unmanaged device (personal
  NAS, USB drive, personal laptop) to the network for a legitimate-seeming
  reason; because nothing detects or blocks it, that device becomes an
  unmonitored, unencrypted, ungoverned extension of the network — exactly
  how a compromised Raspberry Pi pivoted into a nurse-call system in one of
  the classification-exercise reports (T1, Report F).
Current Protection: None found org-wide; C-016 (MRI Physical/USB
  Restriction) is proposed but not implemented, and even then covers only
  the MRI workstation.
Gap Reference: GAP-011 (three confirmed shadow IT systems sit entirely
  outside governance)
```

---
