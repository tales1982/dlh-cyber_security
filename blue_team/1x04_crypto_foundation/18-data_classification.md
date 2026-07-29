# 18. The Data Classification Matrix MedDefense Health Systems

**Analyst:** Security Analyst
**Date:** Current

## Part 1: Data Type Inventory

| Data Type                       | MedDefense Examples                                                                                                                                                                                                                                                                           |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Regulated (HIPAA/PHI)** | Patient records (`ehr-db-01`), DICOM medical images (`pacs-srv-01`), any patient identifier combined with health information (diagnosis, prescription, treatment) including the `prescription.txt` example built in T5                                                                 |
| **PII**                   | Patient names, SSNs, dates of birth, addresses (overlaps heavily with Regulated data above, but also includes non-health PII such as employee personal records in HR systems)                                                                                                                 |
| **Financial**             | Billing/insurance data on`billing-srv-01` (MySQL), credit card PANs (tokenized per T7, Part 2), payroll data                                                                                                                                                                                |
| **Intellectual Property** | Any internally-developed clinical protocols, proprietary scheduling/operational software configurations, and the security program's own documentation (risk register, this project's crypto architecture decisions) MedDefense's IP footprint is smaller than a tech company's, but not zero |
| **Legal**                 | Vendor contracts (e.g., the MedTech Solutions maintenance agreement, 1x01), the Business Associate Agreements HIPAA requires with processors, incident investigation records, this project's own audit trail                                                                                  |
| **Operational**           | Staff directories, meeting schedules, shift rosters, the hospital's own facilities/visiting-hours information                                                                                                                                                                                 |

**Overlap examples, as the instructions anticipate:** a patient record is simultaneously Regulated and PII. A signed vendor contract covering a Business Associate relationship is simultaneously Legal and (if it references specific data-handling costs) Financial. A specific risk register entry is simultaneously Operational (day-to-day tracking) and Legal (documented evidence of due diligence in the event of a future breach investigation). Classification level (Part 2) is driven by the most sensitive type a given piece of data belongs to, not an average of all applicable types.

## Part 2: Classification Levels

| Level                  | Who Can Access                                                                                                                                                                                             | Encryption Required (At Rest)                                                                                                                | Encryption Required (In Transit)                                                               | If Exposed                                                                                                                                                                                                                      |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Public**       | Anyone, including the general public no access control needed                                                                                                                                             | None required                                                                                                                                | None required (though HTTPS is still reasonable for a professional web presence)               | No meaningful harm this data is intended to be public (e.g., hospital address, visiting hours)                                                                                                                                 |
| **Internal**     | All MedDefense employees, authenticated via standard domain credentials no special approval needed beyond being staff                                                                                     | Recommended but not strictly mandated (e.g., full-disk encryption on the server hosting it, per T13's laptop/general-purpose recommendation) | TLS recommended for any web-based internal tool                                                | Minor reputational/operational friction (e.g., a competitor learning a meeting schedule) embarrassing, not legally consequential                                                                                               |
| **Confidential** | Named roles with a specific business need (e.g., Finance for financial reports, the Deputy CISO and CEO for vendor contracts) access requires explicit role assignment, not just being an employee        | Required database-level or file-level encryption per T13's recommendations, AES-256 per T6                                                  | Required TLS 1.2+ per T11's standard                                                          | Real financial/competitive harm and potential contractual/legal consequences (e.g., a leaked vendor contract exposing negotiated pricing)                                                                                       |
| **Restricted**   | Named individuals only, on a strict need-to-know basis, with access logged and reviewed (e.g., clinicians for the specific patients under their care, the Security Analyst/Sarah Park for encryption keys) | Mandatory database-level plus record-level encryption for the most sensitive fields (T13), keys never co-located with the data (T14)        | Mandatory TLS 1.2+/1.3 exclusively, no exceptions, matching the hardened configuration in T11 | Severe: regulatory penalties (HIPAA fines), patient safety/trust harm, and exactly the kind of incident this entire project's risk register (1x03) quantifies in the hundreds of thousands of dollars (RISK-001's $495,000 ALE) |

## Part 3: The Classification Decision Tree

```
START: Is this a new type of data MedDefense needs to classify?
│
├── Does it identify a specific patient AND relate to their health,
│   treatment, diagnosis, or care in any way?
│   └── YES → RESTRICTED (this is PHI under HIPAA, regardless of
│             which system stores it or how sensitive it "feels")
│   └── NO  → continue below
│
├── Does it contain credentials, encryption keys, or other secrets
│   that grant access to systems or data?
│   └── YES → RESTRICTED (a compromised key/credential is equivalent
│             in consequence to a compromised patient record — see T16)
│   └── NO  → continue below
│
├── Does it contain financial account numbers, payment card data,
│   or legally binding contractual/financial terms?
│   └── YES → CONFIDENTIAL (tokenize card data specifically per T7,
│             Part 2, rather than storing/encrypting it directly)
│   └── NO  → continue below
│
├── Is it internal MedDefense operational information NOT intended
│   for public consumption, but also not tied to a specific patient,
│   financial account, or credential?
│   └── YES → INTERNAL (e.g., staff directory, meeting schedules,
│             shift rosters)
│   └── NO  → continue below
│
├── Is it explicitly intended for public consumption (marketing,
│   facility information, publicly published hours/services)?
│   └── YES → PUBLIC
│   └── NO  → escalate to Sarah Park (Data Custodian) or James Chen
│             (Deputy CISO, Accountable) for a manual classification
│             decision — do not guess; the default when genuinely
│             uncertain is the MORE restrictive of the two candidate
│             levels under consideration, never the less restrictive
```

## Part 4: Sovereignty and Geolocation

Data sovereignty matters for healthcare because different jurisdictions impose different, sometimes conflicting legal requirements on who can access data, under what legal process, and which government's laws ultimately govern it a patient's records physically stored in a jurisdiction with weaker health-privacy protections (or one subject to a foreign government's compelled-disclosure laws) can become accessible in ways HIPAA never contemplated MedDefense agreeing to, even if MedDefense itself never intended to weaken that protection. If AWS stores the backup replica in a region outside the state (or country) MedDefense operates in, the direct HIPAA implication is that MedDefense's Business Associate Agreement with AWS must explicitly cover that specific storage location and its legal exposure HIPAA does not prohibit out-of-state or international storage outright, but MedDefense remains fully accountable for ensuring the BAA's protections travel with the data regardless of where AWS physically places it, and cross-border storage specifically raises the added complexity of a foreign government's legal process potentially reaching data that a U.S.-only BAA was never drafted to anticipate. **Encryption meaningfully reduces, but does not eliminate, the sovereignty concern:** if MedDefense holds the only decryption key (customer-managed keys, per T12, Part 4's recommendation) and AWS never possesses usable plaintext, a foreign legal demand directed at AWS alone cannot compel disclosure of readable PHI but sovereignty concerns extend beyond confidentiality to jurisdiction and legal process itself (e.g., which court has authority to compel MedDefense to produce the data, or to freeze/seize the storage account), which encryption does not resolve; the recommended mitigation is therefore both encryption with customer-held keys **and** contractually restricting AWS to specific, MedDefense-selected regions within the BAA, rather than relying on encryption as a complete substitute for controlling where the data physically resides.
