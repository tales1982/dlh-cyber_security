
# 5. The Supply Chain Question Third-Party Risk Assessment

**Analyst:** Threat Intelligence Analyst
**Date:** Current

## Instructions Recap

For each of the 5 vendors below, complete the block using the Onboarding Packet (1x00 T0), vendor contracts, and Asset Registry (1x00 T7). Be specific about access scope and the compromise path.

---

## Vendor 1 MedTech Solutions (EHR Maintenance)

```
Vendor: MedTech Solutions
Service: EHR maintenance ($145,000/year contract, 4-hour SLA response)
Access Type: Network + Application direct remote maintenance access to
  ehr-srv-01
Access Scope: Privileged administrative/maintenance access to the EHR
  application server, and by extension the same reach into ehr-db-01 that
  GAP-001 already documents as accessible network-wide effectively
  equivalent to an internal sysadmin's access to MedDefense's single most
  critical data store.
Compromise Scenario: If MedTech Solutions is breached, an attacker inherits
  their remote maintenance credentials into ehr-srv-01, which sits directly
  on the same path to ehr-db-01 (10.10.2.11:5432, reachable from anywhere on
  the internal network per the 1x00 network scan). No further exploit is
  needed the vendor's own legitimate access already reaches patient
  records for 50,000+ patients.
Existing Controls: C-002 (VPN-restricted subnet access) governs the
  connection path; C-004 (SSH key-only auth) protects ehr-srv-01 itself but
  does not limit what a valid MedTech session can reach once connected; no
  MFA exists on this access (GAP-014).
Risk Assessment: Critical direct, privileged, unmultifactored access to
  MedDefense's #1 most critical asset (ehr-db-01, Top 5 Critical Assets,
  1x00 Task 8), with no detective control (GAP-002) to notice anomalous
  vendor session behavior.
```

---

## Vendor 2 Microsoft (O365 E3)

```
Vendor: Microsoft
Service: O365 E3 organization-wide email, SharePoint, OneDrive; identity
  provider if Entra ID is in use
Access Type: Application / Cloud Identity
Access Scope: All organizational email, SharePoint and OneDrive document
  stores, and if Entra ID underlies MedDefense's identity potentially
  federated authentication for any connected cloud application.
Compromise Scenario: The realistic path here is not Microsoft's own
  infrastructure (heavily invested in security) but MedDefense's
  configuration of it: a phished or reused-password O365 Global Admin
  account, with no MFA (GAP-014), would hand an attacker every mailbox,
  every SharePoint/OneDrive file, and a direct platform to launch further
  BEC campaigns identical in style to the CEO wire-transfer scenario (T4).
Existing Controls: C-006 (password complexity/rotation) applies to O365
  accounts; no MFA is enforced on admin or user accounts (GAP-014).
Risk Assessment: High the blast radius is organization-wide (all email,
  all documents, and potentially federated identity), and the specific,
  known gap enabling it (no MFA) is already documented and unresolved.
```

---

## Vendor 3 Sophos (Endpoint Protection)

```
Vendor: Sophos
Service: Endpoint protection agent installed on all managed endpoints,
  with centralized push capability for updates and configuration
Access Type: Application / Technical a management console with
  organization-wide push authority
Access Scope: Every Windows workstation carrying the Sophos agent (per
  GAP-005, this covers workstations but explicitly excludes servers)
  centrally and simultaneously.
Compromise Scenario: If Sophos's cloud management console or update
  distribution infrastructure is compromised, an attacker could push a
  malicious "update" to every managed MedDefense workstation at once
  turning the very tool meant to stop malware into the ransomware delivery
  mechanism, with no phishing, VPN exploit or credential theft required as
  a separate step.
Existing Controls: None found governing update/push integrity
  independently C-008 (Sophos Endpoint Protection) is itself the control,
  meaning if the vendor's own supply chain is the compromise point, the
  control and the risk are the same thing.
Risk Assessment: Critical this single vendor relationship bypasses every
  other perimeter and endpoint control simultaneously, because trusted,
  org-wide push access is already built into the tool by design.
```

---

## Vendor 4  Siemens (MRI Scanner Manufacturer)

```
Vendor: Siemens
Service: MRI scanner manufacturer periodic maintenance of the Windows XP
  control workstation, firmware updates
Access Type: Physical + Technical on-site/remote maintenance access to
  WS-RAD-01
Access Scope: Direct access to the MRI control workstation (A-014, Windows
  XP SP3, cannot be patched, upgraded, replaced or disconnected per 1x00
  Task 6) a single EOL system sitting on the general workstation subnet
  (10.10.1.0/24) with no isolation from anything else on it.
Compromise Scenario: If a Siemens technician's credentials, laptop or
  maintenance tooling is compromised, an attacker gains a foothold on
  WS-RAD-01 that inherits every weakness of the flat network immediately
  no additional exploit is needed once on this system, since it already
  sits unsegmented alongside general clinical and administrative traffic.
Existing Controls: C-014 (MRI Network Segmentation), C-015 (MRI Risk
  Governance Process) and C-016 (MRI Physical/USB Restriction) are all
  explicitly proposed but **not yet implemented** (1x00 Task 10) this
  access path is currently entirely uncontrolled.
Risk Assessment: Critical the most concentrated single risk of the five:
  an EOL, unpatchable, flat-network-connected clinical device with vendor
  access and zero implemented compensating controls today.
```

---

## Vendor 5 Greenfield Building Management (HQ Office Building)

```
Vendor: Greenfield Building Management
Service: Manages the Corporate HQ office building's network infrastructure;
  MedDefense has a VLAN on their network
Access Type: Network + Physical administrative control of the physical
  network fabric beneath MedDefense's own HQ VLAN
Access Scope: As the building network operator, Greenfield sits "below"
  MedDefense's own network layer entirely controlling the switches and
  routing that MedDefense's Corporate HQ traffic (10.10.20.0/24) rides on
  before it ever reaches the site-to-site VPN tunnel to Central.
Compromise Scenario: If Greenfield's network infrastructure is compromised,
  an attacker could intercept or manipulate HQ traffic before it reaches
  MedDefense's own VPN tunnel a man-in-the-middle position on exactly the
  HQ-to-Central path that, per the Task 13 ATT&CK evidence, is the real
  route an attacker used to reach Central from a compromised HQ workstation.
Existing Controls: None found MedDefense has no visibility into or
  control over Greenfield's own network security posture; the VPN tunnel
  protects the traffic in transit but not the shared infrastructure
  carrying it.
Risk Assessment: Medium the VLAN and VPN tunnel provide a meaningful
  logical boundary that reduces direct exposure, but MedDefense has zero
  visibility into a network segment its HQ operations fundamentally depend
  on.
```

---

## Supply Chain Risk Summary

The single vendor compromise that would cause the most damage is **MedTech Solutions**, because its access path is the shortest and most direct route to MedDefense's single highest-value asset: a compromised MedTech credential lands an attacker inside `ehr-srv-01` with a clear path to `ehr-db-01` patient records for 50,000+ people with no additional exploitation, lateral movement or privilege escalation required, and no MFA or detection to slow it down. The one control MedDefense should implement first, across all five vendor relationships at once, is **mandatory MFA on every vendor remote-access path** (closing GAP-014 specifically for third-party connections) it is the single change that raises the cost of exploiting the *shortest and most damaging* of these five paths (MedTech), while also directly hardening the Microsoft and Greenfield-adjacent access routes at the same time.
