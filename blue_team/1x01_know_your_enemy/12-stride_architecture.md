# 12. STRIDE Across the Architecture

**Analyst:** Threat Intelligence Analyst
**Date:** Current

## System 1: PACS / Medical Imaging

```
System: PACS / Medical Imaging (pacs-srv-01 + MRI workstation + radiology network path)
Architecture Notes: pacs-srv-01 (Windows Server 2016, DICOM ports 4242/
  11112) serves medical imaging to radiology workstations over the flat
  network; the MRI control workstation (WS-RAD-01) runs Windows XP SP3 and
  cannot be patched, upgraded or disconnected; pacs-srv-01 is notably not
  covered by the nightly backup job that protects other core servers.
```

| STRIDE | Threat                                                                                                                                                                         | Impact                                                                                                            | Severity |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------- | -------- |
| S      | The shared`raduser/radiology1` login lets anyone using it impersonate any radiology technician when accessing imaging.                                                       | Any unauthorized viewer of patient imaging is indistinguishable from a legitimate technician.                     | Critical |
| T      | An attacker with network access to pacs-srv-01 could alter or replace a medical image before a physician reviews it, with no integrity check to catch the change.              | A misdiagnosis driven by tampered imaging data.                                                                   | Critical |
| R      | The shared login removes any ability to attribute a specific image view or export to an individual.                                                                            | Any investigation into unauthorized imaging access stalls immediately.                                            | High     |
| I      | Imaging data (Restricted, 1x00 Task 9) crosses the flat network with no segmentation, and pacs-srv-01 sits reachable network-wide like every other core server.                | Broad exposure of Restricted medical imaging beyond radiology staff.                                              | High     |
| D      | pacs-srv-01 is explicitly not covered by the nightly backup, and the MRI workstation cannot be patched or replaced if compromised.                                             | A ransomware or destructive event here has**no recovery path at all** — permanent loss, not just downtime. | Critical |
| E      | The unpatchable Windows XP MRI workstation means any local exploit grants an attacker whatever access that workstation already has to radiology systems, with no possible fix. | An attacker who compromises WS-RAD-01 cannot be remediated through patching — only isolation.                    | Critical |

`Top Threat: Denial of Service. pacs-srv-01 is the only Critical asset in the entire environment explicitly excluded from backup coverage — combined with an unpatchable legacy workstation on the same imaging chain, this is the one system where a destructive event is not just disruptive but potentially unrecoverable.`

---

## System 2: Active Directory

```
System: Active Directory (ad-dc-01 + ad-dc-02)
Architecture Notes: Two domain controllers (Windows Server 2019) provide
  authentication for every user and service in the organization; no MFA is
  enforced anywhere, and no privileged access tier separates routine
  sysadmin work from full Domain Admin authority.
```

| STRIDE | Threat                                                                                                                                                                                        | Impact                                                                                          | Severity |
| ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- | -------- |
| S      | Pass-the-hash using a harvested credential lets an attacker authenticate to the domain as any user, including Domain Admin (Kill Chain#1, T10).                                               | Full impersonation of any account in the organization.                                          | Critical |
| T      | An attacker with Domain Admin access modifies a Group Policy Object to push a malicious payload domain-wide, as in the ransomware kill chain.                                                 | Every domain-joined system inherits the same malicious configuration simultaneously.            | Critical |
| R      | With no MFA and thin logging discipline, actions under a compromised admin credential can't be distinguished from the legitimate admin's own actions.                                         | No reliable attribution after any AD-level incident.                                            | High     |
| I      | Authentication traffic (password hashes, Kerberos tickets) crosses the same flat, unsegmented network as everything else.                                                                     | Credential material exposed to a far larger population than intended.                           | High     |
| D      | ad-dc-01/02 provide mutual redundancy, but both sit on the same flat network with no dedicated detective coverage; the same GPO mechanism used to attack can disable authentication org-wide. | Organization-wide lockout — nearly every system depends on AD to function.                     | Critical |
| E      | No privileged access tiering (GAP-017) means any compromised admin-level credential — routine or true Domain Admin — carries equivalent domain-wide authority.                              | Escalation from "one admin account" to "full domain control" is not a technical barrier at all. | Critical |

`Top Threat: Elevation of Privilege. This is the one gap most specific to AD itself — the absence of privilege tiering means AD's entire trust model has no internal boundary, so every other STRIDE threat against it ultimately cashes out at full domain compromise.`

---

## System 3: Network Infrastructure

```
System: Network Infrastructure (FortiGate + core switch + Westside router + VPN tunnels)
Architecture Notes: The FortiGate 100F is MedDefense's sole perimeter
  device and internal routing chokepoint; the Westside Clinic connects via
  a consumer-grade, unfirewalled Netgear router; VPN access rules are
  documented as "too permissive" (Marcus's own annotation on C-002).
```

| STRIDE | Threat                                                                                                                                                                                                | Impact                                                                                                                              | Severity |
| ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | -------- |
| S      | Switch/FortiGate management credentials are physically taped to the wall in the unlocked network closet (GAP-006), letting anyone impersonate an authorized network administrator.                    | Full impersonation of network-management sessions.                                                                                  | Critical |
| T      | Physical access to the unlocked network closet allows direct alteration of switch configuration or patch-panel wiring, no software exploit needed.                                                    | Traffic can be rerouted or intercepted for an entire floor.                                                                         | High     |
| R      | FortiGate logging (C-013) is local-only with no forwarding or alerting, so configuration changes or anomalous traffic can't be reliably attributed after the fact.                                    | No forensic trail following any perimeter-level incident.                                                                           | High     |
| I      | VPN rules allow**all services** from any VPN connection rather than only what's needed, per Marcus's own note.                                                                                  | Any VPN session — legitimate or stolen — reaches far more than it should.                                                         | High     |
| D      | The FortiGate is the single perimeter and routing chokepoint with no redundancy or failover.                                                                                                          | Its failure or compromise doesn't degrade one service — it can take down or expose the entire Central site's connectivity at once. | Critical |
| E      | The Westside consumer-grade router has no firewall or managed switching, so anyone reaching it inherits broad routing capability with none of the restrictions a proper managed device would enforce. | An architectural elevation of network privilege simply by reaching a weaker device.                                                 | High     |

`Top Threat: Denial of Service. The FortiGate's single-point-of-failure role is already flagged as one of MedDefense's Top 5 Critical Assets (1x00 Task 8) for exactly this reason — no other system in the environment has the ability to take down the entire site's connectivity in one event.`

---
