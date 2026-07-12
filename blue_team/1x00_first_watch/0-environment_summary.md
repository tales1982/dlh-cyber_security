# Structured Environment Summary — MedDefense Health Systems

## 1. Organization Overview

### Sites

**MedDefense Central Hospital**
- Location type: Acute care facility, downtown/urban location
- Function: 350-bed hospital; departments include Emergency, Surgery, Cardiology, Radiology, Oncology, Pediatrics, Maternity, Pharmacy, Laboratory, Administration
- Approximate headcount: 1,400 (clinical + support)
- Building: 6 floors + basement (mechanical/server room)

**Westside Clinic**
- Location type: Outpatient facility, suburban location (12 min drive from Central)
- Function: Primary care, diagnostic imaging (X-ray, ultrasound — no MRI), blood work, minor procedures, physical therapy
- Approximate headcount: 180
- Building: 2-story medical office complex, shared parking with adjacent retail plaza
- Note: shares some IT services with Central but has its own local server closet

**Corporate HQ**
- Location type: Leased office space, Greenfield Business Park (15 min from Central)
- Function: Finance, HR, Legal, Marketing, Executive Leadership, IT department (IT staff: 12)
- Approximate headcount: 220
- Building: 3rd floor of a 5-story commercial building

**Organization-wide total:** approximately 2,000 employees

### Reporting Structure Relevant to Security

- CEO: Dr. Patricia Morales
- CISO position: **vacant** — James Chen serves as Deputy CISO (acting), reporting in practice directly to the CEO
- Sarah Park: IT Director — organizationally a peer to James Chen, not his subordinate
- Under Sarah Park: 3x System Administrators, 2x Network Technicians, 1x Database Administrator, 2x Helpdesk Analysts (incl. Mike Torres, lead), 2x Desktop Support Technicians, 1x IT Intern (vacant)
- Under James Chen: 1x Security Analyst (this role, replacing Marcus Webb)
- **Security-relevant friction:** James has authority over security policy but no authority over IT operations, which are controlled by Sarah Park.

## 2. IT Infrastructure Identified

### Servers — MedDefense Central

| Name | OS/Platform | Function |
|---|---|---|
| ehr-srv-01 | Ubuntu 20.04 LTS | EHR Application Server |
| ehr-db-01 | Ubuntu 20.04 LTS | EHR Database (PostgreSQL) |
| pacs-srv-01 | Windows Server 2016 | PACS Imaging Server |
| billing-srv-01 | Ubuntu 18.04 LTS | Billing/Claims Processing |
| ad-dc-01 | Windows Server 2019 | Primary Domain Controller |
| ad-dc-02 | Windows Server 2019 | Secondary Domain Controller |
| file-srv-01 | Windows Server 2016 | Department File Shares |
| print-srv-01 | Windows Server 2012 R2 | Print Server *(unverified in over a year)* |
| backup-srv-01 | Ubuntu 22.04 LTS | Backup Server (Veeam agent) |
| web-srv-01 | Ubuntu 20.04 LTS | Public Website + Patient Portal |

### Servers — Westside Clinic

| Name | OS/Platform | Function |
|---|---|---|
| ws-srv-01 | Windows Server 2016 | Local file server + scheduling |

A possible second server in the Westside closet was mentioned informally but never confirmed (see Known Unknowns).

### Servers — Corporate HQ

No on-premise servers. Staff use cloud services and connect to Central's infrastructure via site-to-site VPN.

### Network Equipment — Central

| Item | Model | Qty |
|---|---|---|
| Core switch | Cisco (model unknown) | 1 |
| Access switch | Cisco | 2 per floor |
| Firewall | Fortinet FortiGate 100F | 1 |
| WiFi Access Point | Ubiquiti UniFi | 12 |

### Network Equipment — Westside

| Item | Model | Qty |
|---|---|---|
| Switch | Unmanaged, brand unknown | 1 |
| Router | Consumer-grade (Netgear Nighthawk) | 1 |

No firewall present — the site-to-site VPN to Central runs directly on the consumer router.

### Network Equipment — Corporate HQ

Managed by the building landlord. MedDefense has its own VLAN on the shared building network.

### Endpoints

| Site | Type | Approx. Count |
|---|---|---|
| Central | Windows 10 workstations | ~320 |
| Central | Thin clients (clinical areas) | ~60 |
| Westside | Windows 10 workstations | ~45 |
| HQ | Windows 10/11 workstations | ~120 |
| HQ | Laptops (remote-capable) | ~30 |
| All sites (physicians) | iPads (rounds) | ~25 — management status unclear |

Note: figures are drawn from the last Active Directory report, which is ~8 months old; no complete current count exists.

### Medical Devices (IoT)

| Device | Details | Location |
|---|---|---|
| Patient monitors | ~80 units, Philips IntelliVue, network-connected | Central |
| Infusion pumps | ~120 units, BD Alaris, network-connected for dosage updates | Central |
| MRI scanner | 1x Siemens MAGNETOM — **runs Windows XP (unsupported OS)** | Radiology, Central |
| CT scanner | 1x GE Revolution — OS unknown | Central |
| Nurse call system | IP-based, integrated with phone system | Central |
| Badge/access system | HID Global, integrated with Active Directory for some doors | Central (primarily) |

**Critical note:** the medical devices above (including infusion pumps and the Windows XP MRI) sit on the same flat, unsegmented network (10.10.0.0/16) as workstations and servers — see Known Unknowns.

## 3. Data and Services

| System | Data Type | Primary Users | Criticality |
|---|---|---|---|
| ehr-srv-01 / ehr-db-01 | Patient health records (PHI) | Physicians, nursing staff | Critical — clinical care depends on availability |
| pacs-srv-01 | Radiology imaging (PHI) | Radiology department | High — diagnostic workflow |
| billing-srv-01 | Financial/claims data | Billing/finance staff | High — revenue cycle |
| file-srv-01 | Departmental documents | All departments | Medium |
| web-srv-01 | Public website + patient portal content (includes PHI via portal) | Patients, public | Medium-High — externally facing |
| Patient monitors / infusion pumps | Real-time clinical/vital data | Clinical staff | Critical — direct patient safety impact |
| Nurse call system | Operational/clinical signaling | Nursing staff | Critical in clinical areas |
| Badge/access system | Physical access/identity data | Facilities, all staff | Medium — physical security |
| O365 (org-wide) | Email, productivity, likely other business data | All employees | High — organization-wide dependency |

MedDefense handles **protected health information (PHI)** (records, imaging, real-time clinical data), **financial/billing data**, and **operational/physical security data** (badge access). Critical services depending on this infrastructure include the EHR system, PACS imaging, billing/claims processing, and life-safety clinical devices (monitors, infusion pumps) — an outage or compromise of any of these has direct clinical or financial impact.

## 4. Known Unknowns

**Network & Segmentation**
- Central network is flat (10.10.0.0/16) — medical devices, workstations, and servers share the same broadcast domain. Segmentation is reportedly "planned for next fiscal year" but was raised 4+ months ago with no confirmed timeline.
- Guest WiFi at Central exists on a separate SSID, but isolation from the main network has not been verified.
- HQ VPN configuration appears sound but its ACLs have never been audited.
- Whether a second server exists in the Westside closet (informally mentioned, never confirmed).

**Servers & Systems**
- `billing-srv-01` has recurring, unexplained performance issues — IT restarts it rather than diagnosing root cause.
- `print-srv-01` has been out of support (Windows Server 2012 R2, EOL Oct 2023) with no remediation plan.
- `ehr-db-01` (PostgreSQL) is reachable from the entire 10.10.0.0/16 range instead of being restricted to `ehr-srv-01` only.
- Backup server and its NAS target sit in the same server room, on the same network and rack — a single ransomware event could destroy both primary and backup data. A request for offsite/cloud backup was denied for budget reasons.
- CT scanner operating system is unknown.

**Authentication & Access**
- No MFA anywhere except one individually configured personal account (James Chen's).
- Radiology department uses a shared PACS login for all staff.
- SSH password authentication remains enabled on nearly all Linux servers; key-only migration was started but only completed on `ehr-srv-01`.
- Whether the ~25 physician iPads are centrally managed is unclear.

**Physical Security**
- Server room uses the same generic badge issued to all staff — no differentiated/tracked access.
- No cameras cover the server room corridor (cameras exist only at the parking garage and ER entrance).
- Westside has essentially no physical security for IT equipment — the "server closet" does not lock.
- Contracted guard service at Central covers Mon–Fri 7AM–7PM only; no coverage nights/weekends, and no guard presence at Westside or HQ at all.

**Compliance & Process**
- HIPAA Security Rule compliance has never been formally assessed; Legal asserts compliance without documented evidence.
- No formal incident response plan exists — the January ransomware incident on `billing-srv-01` was handled ad hoc over 4 days.
- No business continuity or disaster recovery plan; if Central loses power beyond ~20 minutes of UPS runtime, there is no documented procedure for clinical operations to continue.
- No formal vulnerability assessment has been conducted on any servers.
- Endpoint protection is Sophos, but whether it is current across all machines is unverified.
- Cloud service inventory is incomplete — O365 is confirmed, but individual departments are suspected to use additional, unvetted cloud services.
- No documented threat landscape analysis specific to healthcare-sector threats.
- Endpoint counts across all sites are based on an 8-month-old Active Directory report and may not reflect the current environment.

**Medical Devices**
- Patient monitors and infusion pumps are reachable from the general network — no isolation between clinical IoT and the rest of the environment.
- The MRI scanner runs Windows XP, an operating system with no vendor security support, and its exposure/isolation status is not documented beyond this observation.
