# MedDefense Business Impact Analysis

**Version:** 1.0
**Classification:** Confidential
**Prepared by:** Tales Lima, IT Security
**Date:** 2026-11-08
**CISO approval:** _________________________ Date: _________

## Executive Summary

MedDefense runs a 230-bed acute care hospital where the emergency department, ICU, laboratory, pharmacy and radiology operate 24x7. This BIA assesses ten systems and asks one question for each: if it fails at 2 AM on a Tuesday, what breaks, who is harmed, and how long can the hospital run without it before the harm cannot be undone?

Key results:

- **Six systems are Tier 1** (maximum tolerable downtime of 4 hours or less): Network Core, Active Directory, Epic EHR, Laboratory Information System (LIS), Pharmacy Dispensing System and the Medical Device Integration Gateway. Three are Tier 2 and one is Tier 3.
- **Network Core and Active Directory are single points of failure.** Every clinical application depends on them, so they must be restored first, even though nurses never see them.
- **Three recovery objectives cannot be met by the current backup schedule** (`backup_log_review_findings.md`). The worst is the LIS: the hospital needs a recovery point of 1 hour for critical lab values, but the LIS is backed up once a night, so up to 24 hours of results could be lost. The Medical Device Integration Gateway has no off-site copy, and the Active Directory snapshot interval (8 hours) is longer than the 4-hour objective set here. `backup_architecture.md` closes these gaps.
- **The old declared Epic RTO of 4 hours equals its MTD**, which leaves no margin. This BIA sets it at 2 hours.

## Methodology

Each system was scored on four impact criteria using `meddefense_system_inventory.csv`, `downtime_impact_notes.md`, `regulatory_reference_map.md` and `dependency_map_seed.md`:

| Criterion | What was assessed |
| --- | --- |
| Patient safety | Concrete clinical harm at 1 hour, 4 hours and 24 hours of downtime, assuming downtime procedures are used |
| Regulatory | HIPAA Security Rule specifications (45 CFR 164.308(a)(7), 164.312), Joint Commission emergency management expectations, mandatory reporting |
| Revenue | Estimated exposure per hour, from lost or delayed charge capture, ED diversion and cancelled procedures (see Assumptions) |
| Operational dependency | What the system needs to run, and what fails downstream when it stops |

Recovery objectives are business decisions, set in this order:

1. **Maximum Tolerable Downtime (MTD):** the point after which patient harm or regulatory breach becomes likely even with downtime procedures in place.
2. **Recovery Time Objective (RTO):** the target time to restore service. It is always set **below** the MTD, leaving time for validation and clinical reconciliation.
3. **Recovery Point Objective (RPO):** the maximum acceptable data loss, measured in time. It drives backup frequency.

Priority tiers:

| Tier | Definition |
| --- | --- |
| Tier 1 | MTD of 4 hours or less; direct patient safety impact or foundation for Tier 1 systems |
| Tier 2 | MTD between 4 and 24 hours; patient care degrades but safe workarounds exist |
| Tier 3 | MTD between 24 and 72 hours; indirect clinical impact |
| Tier 4 | MTD over 72 hours; business support only |

## System Impact Assessment

### 1. Network Core

- **Owner:** Network Engineering Lead. **Data:** network configuration.

| Window | Patient safety impact |
| --- | --- |
| 1 hour | Every networked system is unreachable at once: Epic, LIS, PACS, pharmacy, device alarms routed to nurses, and secure messaging. All units switch to paper and phones together. Bedside monitors still alarm locally. |
| 4 hours | Lab results go by runner and phone, imaging cannot reach the ED, and medication verification is manual everywhere. The ED likely goes on diversion. |
| 24 hours | Hospital-wide emergency operations. Paper records become hard to reconcile, and delayed results and medication errors become likely. |

- **Regulatory:** 164.308(a)(7)(ii)(B) disaster recovery plan; 164.308(a)(7)(ii)(C) emergency mode operation; Joint Commission emergency management (communication and continuity of care).
- **Revenue exposure:** about $60,000 per hour (all charge capture stops, plus ED diversion and cancelled elective procedures).
- **Dependencies:** none inside the hospital (power and cooling only). Downstream failure sequence: Network Core, then Active Directory authentication, then every clinical application, then device alarm routing, then security monitoring.
- **MTD:** 1 hour. **RTO:** 30 minutes. **RPO:** 6 hours (configuration changes only).
- **Tier:** Tier 1.

### 2. Active Directory

- **Owner:** Systems Administrator. **Data:** identity data. **Current DR status:** secondary DC (DC02) exists; DC01 recovery not recently tested.

| Window | Patient safety impact |
| --- | --- |
| 1 hour | Cached sessions survive briefly, but staff starting a shift cannot log in to Epic, LIS, PACS or pharmacy, and service accounts fail to authenticate. Clinicians on shift change are locked out. |
| 4 hours | Most clinical applications are effectively down for anyone who logged out. The hospital is in full paper downtime, and the security team loses EDR and SIEM access. |
| 24 hours | Same as a multi-system outage: medication and lab errors become likely, and reconciliation backlog grows by thousands of entries. |

- **Regulatory:** 164.312(a)(1) access control (unique user identification, emergency access procedure); 164.308(a)(7)(ii)(B).
- **Revenue exposure:** about $55,000 per hour (blocks every clinical and billing application).
- **Dependencies:** Network Core. Downstream: Epic, LIS, PACS/RIS, Pharmacy, email and secure messaging, Security Operations Platform, and access control for the backup platform.
- **MTD:** 2 hours. **RTO:** 1 hour. **RPO:** 4 hours (with DC02 replication the practical loss for a single DC failure is minutes).
- **Tier:** Tier 1.

### 3. Epic EHR

- **Owner:** Clinical Applications Manager. **Data:** ePHI.

| Window | Patient safety impact |
| --- | --- |
| 1 hour | No electronic orders, medication administration record, allergy list or recent history. Nurses switch to the paper MAR and verbal orders with read-back, and allergy checks are manual. |
| 4 hours | Medication verification delays and duplicate documentation grow. Admitting physicians lack history for deteriorating patients. Risk of giving a drug the patient is allergic to, or a duplicate dose. |
| 24 hours | Patient safety and regulatory event: paper records diverge from the electronic chart, critical results may not reach the right clinician, and leadership must run emergency operations. |

- **Regulatory:** 164.308(a)(7)(ii)(B) and (C); 164.312(c)(1) integrity of ePHI during reconciliation; Joint Commission record of care and medication management continuity.
- **Revenue exposure:** about $40,000 per hour (order entry, charge capture and registration stop).
- **Dependencies:** Network Core, Active Directory; interfaces to LIS, Pharmacy and PACS/RIS; secure messaging. Downstream: LIS result posting, pharmacy verification, PACS ordering and results, billing.
- **MTD:** 4 hours. **RTO:** 2 hours. **RPO:** 15 minutes (vendor replication every 15 minutes).
- **Tier:** Tier 1.

### 4. Laboratory Information System (LIS)

- **Owner:** Laboratory Systems Lead. **Data:** ePHI. **Current DR status:** nightly SQL export; recovery test never executed before this cycle.

| Window | Patient safety impact |
| --- | --- |
| 1 hour | Lab orders, specimen tracking and analyzer results stop linking to patients. STAT labs continue by phone and paper. The main risks are specimen mislabeling and a critical value (for example potassium 6.1 mEq/L) not reaching the nurse. |
| 4 hours | Backlog of unlinked analyzer results, delayed sepsis (lactate), cardiac (troponin) and anticoagulation (PT-INR) decisions, and manual critical value calls overload lab staff. |
| 24 hours | Results posted to the wrong patient or not at all, delayed treatment for critical values, and a large reconciliation risk when results are re-entered. |

- **Regulatory:** 164.308(a)(7)(ii)(A) data backup and (B) disaster recovery; 164.312(c)(1) integrity of results; CLIA and Joint Commission requirements for timely critical value reporting with read-back.
- **Revenue exposure:** about $12,000 per hour (lab charges and delayed discharges).
- **Dependencies:** Network Core, Active Directory, Epic interface engine, lab instrument feeds. Downstream: Epic result posting, critical value notification, clinical decisions in ED and ICU.
- **MTD:** 4 hours. **RTO:** 30 minutes (declared, kept). **RPO:** 1 hour (critical values and STAT orders). The current nightly backup cannot meet this; see `backup_architecture.md`.
- **Tier:** Tier 1.

### 5. Pharmacy Dispensing System

- **Owner:** Pharmacy IT Lead. **Data:** ePHI medication data.

| Window | Patient safety impact |
| --- | --- |
| 1 hour | Dispensing continues manually, but automated allergy and interaction checks stop, barcode administration degrades, and cabinets may need override access. |
| 4 hours | Interaction checks rely on pharmacist memory and paper references. Controlled substance counts become hard to reconcile, and time-critical antibiotics and anticoagulants may be delayed. |
| 24 hours | High risk of medication error and diversion of controlled substances; DEA reconciliation burden. |

- **Regulatory:** 164.308(a)(7)(ii)(B); 164.312(c)(1); DEA controlled substance record-keeping (21 CFR 1304); Joint Commission medication management.
- **Revenue exposure:** about $8,000 per hour.
- **Dependencies:** Active Directory, Epic EHR, Network Core, medication cabinets. Downstream: medication administration on every unit.
- **MTD:** 4 hours. **RTO:** 2 hours. **RPO:** 1 hour.
- **Tier:** Tier 1.

### 6. Medical Device Integration Gateway

- **Owner:** Biomedical IT Lead. **Data:** ePHI device telemetry.

| Window | Patient safety impact |
| --- | --- |
| 1 hour | Bedside monitors keep alarming at the bedside, but alarms no longer reach central stations or nurse phones, and vital signs stop charting into Epic. ICU and telemetry nurses must stay physically closer to patients. |
| 4 hours | A deterioration alarm can be missed in a room the nurse is not in, and manual vital sign charting adds workload and transcription errors. |
| 24 hours | Sustained missed-alarm risk in ICU and telemetry; possible need to restrict admissions to monitored beds. |

- **Regulatory:** 164.308(a)(7)(ii)(B); 164.312(c)(1); Joint Commission National Patient Safety Goal on clinical alarm safety (NPSG.06.01.01).
- **Revenue exposure:** about $3,000 per hour (monitored-bed capacity).
- **Dependencies:** Network Core and VLAN segmentation. Downstream: alarm routing to nurses and vital sign charting in Epic.
- **MTD:** 4 hours. **RTO:** 2 hours. **RPO:** 24 hours (configuration only; telemetry is not stored on the gateway).
- **Tier:** Tier 1.

### 7. PACS/RIS

- **Owner:** Radiology Systems Lead. **Data:** ePHI imaging.

| Window | Patient safety impact |
| --- | --- |
| 1 hour | Urgent images can still be acquired on modalities, but prior studies and reports are not available and images do not reach ED or surgery screens. |
| 4 hours | Stroke, trauma and surgical decisions are delayed while radiologists read at the modality console. The ED may divert stroke and trauma patients. |
| 24 hours | Report backlog, repeat imaging (extra radiation), and delayed diagnoses. |

- **Regulatory:** 164.308(a)(7)(ii)(B); 164.312(c)(1); Joint Commission imaging and diagnostic services.
- **Revenue exposure:** about $15,000 per hour (imaging procedures and reports).
- **Dependencies:** Network Core, Active Directory, modality devices, Epic order interface. Downstream: ED, stroke, trauma and surgical workflows.
- **MTD:** 8 hours. **RTO:** 4 hours. **RPO:** 4 hours.
- **Tier:** Tier 2.

### 8. Email and Secure Messaging

- **Owner:** Collaboration Services Lead. **Data:** ePHI possible.

| Window | Patient safety impact |
| --- | --- |
| 1 hour | Clinical messages and alert notifications move to phones and overhead paging. Little direct harm if phone trees work. |
| 4 hours | Consult requests and critical result notifications sent by message are delayed; outage communication to staff slows. |
| 24 hours | Coordination across units degrades, and regulatory correspondence (for example breach notices) is delayed. |

- **Regulatory:** 164.312(e)(1) transmission security; 164.308(a)(7)(ii)(C); Joint Commission emergency communication.
- **Revenue exposure:** about $2,000 per hour.
- **Dependencies:** identity provider (Active Directory), network egress, mobile device access. Downstream: clinical communication and incident coordination.
- **MTD:** 24 hours. **RTO:** 8 hours. **RPO:** 1 hour.
- **Tier:** Tier 2.

### 9. Backup and DR Infrastructure

- **Owner:** Infrastructure Manager. **Data:** backup copies of ePHI and system data.

| Window | Patient safety impact |
| --- | --- |
| 1 hour | No direct impact while production runs. |
| 4 hours | Backup jobs are missed, so the recovery point of every system slips. |
| 24 hours | If any other system fails now, its data may be permanently lost; recovery of every Tier 1 system depends on this platform. |

- **Regulatory:** 164.308(a)(7)(ii)(A) retrievable exact copies of ePHI; 164.310(d)(2)(iv) data backup and storage.
- **Revenue exposure:** no direct hourly revenue loss; indirect exposure equals the cost of permanent data loss on any system.
- **Dependencies:** Network Core, Active Directory (access control), storage. Downstream: recovery of every other system.
- **MTD:** 24 hours (shorter during any other outage: it becomes a prerequisite for Tier 1 recovery). **RTO:** 8 hours. **RPO:** 4 hours (backup catalog).
- **Tier:** Tier 2.

### 10. Security Operations Platform

- **Owner:** SOC Manager. **Data:** security telemetry.

| Window | Patient safety impact |
| --- | --- |
| 1 hour | No direct clinical impact. SIEM alerts and EDR console access stop. |
| 4 hours | An attacker active during an outage is not detected; ransomware spread could go unnoticed. |
| 24 hours | Loss of detection and response capability; missing logs weaken HIPAA audit controls and any later breach investigation. |

- **Regulatory:** 164.312(b) audit controls; 164.308(a)(6) security incident procedures.
- **Revenue exposure:** no direct hourly revenue loss; indirect exposure is the cost of an undetected breach.
- **Dependencies:** Network Core, log sources, EDR management, Active Directory. Downstream: incident detection and response.
- **MTD:** 72 hours. **RTO:** 24 hours. **RPO:** 4 hours.
- **Tier:** Tier 3.

## Dependency Map

```text
Power and cooling (data center)
└── Network Core ........................ restore 1st (Tier 1)
    ├── Active Directory (DC01, DC02) ... restore 2nd (Tier 1)
    │   ├── Backup and DR Infrastructure access control ... 3rd (needed to restore everything else)
    │   ├── Epic EHR (Tier 1)
    │   │   ├── LIS interface ......... LIS (Tier 1) also needs lab instrument feeds
    │   │   ├── Pharmacy Dispensing System (Tier 1) + medication cabinets
    │   │   └── PACS/RIS ordering and results (Tier 2)
    │   ├── Email and Secure Messaging (Tier 2)
    │   └── Security Operations Platform (Tier 3)
    ├── Medical Device Integration Gateway (Tier 1) ... needs VLAN segmentation, not AD
    ├── PACS/RIS image movement
    └── Backup replication traffic
```

Downstream failure sequence when a foundation fails:

- **Network Core down:** every system below fails within seconds, including device alarm routing.
- **Active Directory down:** new logins fail, cached sessions expire, and service accounts stop. Epic, LIS, PACS, pharmacy, email and security tools fail in turn. The device gateway keeps running.
- **Epic down:** LIS results cannot post, pharmacy cannot verify orders, and PACS orders stop arriving, even though those systems are themselves up.

## RTO / RPO / MTD Summary Table

| System | Tier | MTD | RTO | RPO | RTO below MTD | Current backup can meet RPO |
| --- | --- | --- | --- | --- | --- | --- |
| Network Core | Tier 1 | 1 hour | 30 minutes | 6 hours | Yes | Yes (config every 6 hours) |
| Active Directory | Tier 1 | 2 hours | 1 hour | 4 hours | Yes | **No** (snapshot every 8 hours) |
| Epic EHR | Tier 1 | 4 hours | 2 hours | 15 minutes | Yes | Yes (replication every 15 minutes) |
| Laboratory Information System | Tier 1 | 4 hours | 30 minutes | 1 hour | Yes | **No** (nightly dump only) |
| Pharmacy Dispensing System | Tier 1 | 4 hours | 2 hours | 1 hour | Yes | Yes (hourly database backup) |
| Medical Device Integration Gateway | Tier 1 | 4 hours | 2 hours | 24 hours | Yes | Frequency yes; **no off-site copy** |
| PACS/RIS | Tier 2 | 8 hours | 4 hours | 4 hours | Yes | Yes (snapshot every 4 hours) |
| Email and Secure Messaging | Tier 2 | 24 hours | 8 hours | 1 hour | Yes | Yes (provider continuous) |
| Backup and DR Infrastructure | Tier 2 | 24 hours | 8 hours | 4 hours | Yes | Yes (catalog every 4 hours) |
| Security Operations Platform | Tier 3 | 72 hours | 24 hours | 4 hours | Yes | Yes (index snapshot every 4 hours) |

## Assumptions and Limitations

1. **Revenue figures are planning estimates**, based on a 230-bed acute care hospital with about $1.1 million net patient revenue per day. Finance has not validated them. They rank systems; they are not loss forecasts.
2. Patient safety impacts assume downtime procedures, paper forms and escalation contacts are available (`clinical_downtime_procedures.md`). Without them, every MTD is shorter.
3. Epic's 15-minute RPO relies on vendor replication and a monthly vendor restore certificate. MedDefense has not tested an Epic restore itself.
4. MTDs assume one system fails at a time. In a full data center loss the effective MTD of each system is shorter, because every workaround runs in parallel with the same night-shift staff.
5. Only the LIS recovery has been tested (`recovery_test_record.md`). All other RTOs are targets, not demonstrated values, until tested.
6. Medical device inventory is incomplete. Devices outside the integration gateway are not assessed here.
7. This BIA must be reviewed every year and after any major system change or real outage, and approved by the CISO.
