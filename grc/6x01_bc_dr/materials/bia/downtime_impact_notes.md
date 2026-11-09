# MedDefense Downtime Impact Notes

## Purpose

These notes provide scenario realism for the Business Impact Analysis. They are not final answers. Use them to support defensible RTO, RPO and MTD decisions.

## Environment Assumptions

MedDefense operates a 230-bed acute care hospital with emergency department, ICU, inpatient surgery, radiology, laboratory and pharmacy operations. Night shift staffing is reduced, but ED, ICU, lab, pharmacy and radiology continue 24x7.

## Downtime Threshold Guidance

### 1 Hour

Most departments can continue with downtime procedures if forms and escalation contacts are available. The risk is missed context: allergies, recent medications, pending orders, recent labs, imaging availability and patient movement.

### 4 Hours

Manual workarounds become strained. Duplicate documentation, specimen tracking errors, medication verification delays and delayed diagnostic decisions become more likely.

### 24 Hours

Downtime becomes a patient safety and regulatory event. Paper records become hard to reconcile, delayed critical results affect treatment, and leadership may need emergency operations and reporting processes.

## System Notes

### Active Directory

Identity outage affects login and authorization to Epic, LIS, PACS/RIS, pharmacy, email and security tooling. Cached sessions may survive briefly, but new logins and service-account authentication fail.

### Epic EHR

Epic outage affects order entry, medication documentation, clinical notes, allergy verification, patient history and care coordination.

### Laboratory Information System

LIS outage affects lab order intake, specimen tracking, analyzer result association, critical value notification and result posting to Epic. STAT workflows can continue by phone and paper, but mislabeling and delayed critical value notification are primary risks.

### PACS/RIS

Radiology may acquire urgent images, but prior studies, reports and distribution to clinicians are delayed. ED, stroke, trauma and surgery workflows are most exposed.

### Pharmacy Dispensing System

Medication verification and dispensing continue manually, but allergy and interaction checks may be delayed. Controlled substance tracking and barcode administration degrade.

### Medical Device Integration Gateway

Bedside monitoring continues locally, but automatic charting and alarm routing degrade. ICU and telemetry units are most affected.

### Network Core

Network outage can produce simultaneous failure across applications, monitoring, authentication, communication and security visibility.

### Backup and DR Infrastructure

Backup platform failure creates recovery risk even when production applications still run. Without restore capability, an outage can become permanent data loss.

### Security Operations Platform

Loss of SIEM/EDR management reduces detection and response during a period when opportunistic attack risk can rise.
