# MedDefense Health Systems — Acceptable Use Policy

**Effective Date:** [Upon CEO approval]
**Owner:** Deputy CISO (James Chen)
**Review Cycle:** Annually, or upon a material change to systems, threats, or applicable regulation

---

## 1. Purpose and Scope

This policy defines how MedDefense Health Systems' technology systems, network and data may be used, and by whom. It exists so that when a security concern arises, the response is not "please don't do that" but a documented, enforceable standard every person agreed to when they joined.

**This policy applies to:** all MedDefense employees, contractors, physicians with system access, and vendors with remote access to MedDefense systems — at Central, Westside Clinic, and Corporate HQ.

**This policy covers:** all MedDefense-owned devices (workstations, servers, medical device management interfaces), the internal network (`10.10.0.0/16`) and any personal device or removable media connected to it, MedDefense email and O365 accounts, the EHR system, and any system storing or transmitting patient, financial, or employee data.

## 2. Acceptable Use of Systems

You may use MedDefense systems to perform your job duties, including clinical documentation, patient scheduling, billing, and standard business communication. Reasonable, incidental personal use of email or the internet is permitted provided it does not interfere with your duties, consume significant network resources, or violate Section 3.

Every account is individually assigned. You are accountable for actions taken under your credentials — this includes EHR access, PACS imaging access, and administrative systems. Do not share your login with a colleague, regardless of urgency; if a workflow genuinely requires shared access, report it to IT so a proper solution can be evaluated, rather than working around it informally.

## 3. Prohibited Activities

The following are prohibited because each maps to a specific, real risk already identified in MedDefense's own environment — not a generic list copied from elsewhere:

- **Bypassing or disabling security controls**, including antivirus, MFA prompts, or firewall rules, even temporarily "to get something to work." (This is how a negligent insider incident becomes a breach — Risk Register RISK-004.)
- **Exporting patient records in bulk** outside of a documented business need and manager approval. Export activity is logged and monitored (Section 7).
- **Connecting any personally-owned or vendor-owned device to the clinical or server network** without prior IT approval and inventory registration — this includes IoT devices, monitoring tools, or single-board computers (e.g., Raspberry Pi) brought in for "just checking something."
- **Storing patient or financial data on personal cloud storage, personal email, or unencrypted personal devices.**
- **Continuing to access MedDefense systems after employment or contract termination**, including via any credential that has not yet been formally revoked. Report any access you retain past your last working day — do not use it "just to finish something up."

## 4. Personal Devices and Removable Media

MedDefense has previously discovered undocumented personal devices connected to its clinical and server networks, including a personal laptop that bypassed network controls for three weeks and a Raspberry Pi connected to the medical device network "to monitor performance" — neither with malicious intent, both creating real, unmanaged risk. **Any device that is not on the IT asset inventory has no business being on the network, regardless of intent.**

- **Personal phones and laptops** may connect only to the designated guest/visitor network, never to the clinical, server, or medical device networks.
- **USB drives and other removable media** are restricted on clinical workstations. If your role requires removable media for a documented business purpose, request an approved, encrypted device from IT — personal USB drives may not be connected to any MedDefense workstation.
- **Any device you wish to connect for a legitimate operational reason** (a vendor diagnostic tool, a new piece of equipment) must be submitted to IT for approval and inventory *before* connection, not after.

## 5. Password and Authentication Requirements

- Passwords must be at least 8 characters, using a mix of upper/lowercase, numbers and symbols, and must be changed every 90 days (unchanged from existing policy).
- **Multi-factor authentication (MFA) is required** for all VPN remote access, all administrative accounts, and all access to externally-exposed applications, including the Patient Portal admin console and O365. This applies to every employee, contractor and vendor account with remote access — no exceptions, including for physicians and executives.
- Never share a one-time MFA code with anyone, including someone claiming to be IT support. MedDefense IT will never ask for your MFA code over phone or email.

## 6. Data Handling

MedDefense classifies data as **Restricted** (patient health information, authentication credentials) or **Confidential** (financial records, employee HR data), per the organization's data classification standard.

- **Restricted data** may only be accessed on MedDefense-managed devices, must never be emailed externally or copied to removable media without encryption and documented approval, and must only be viewed on-screen in areas where unauthorized individuals cannot casually view it (e.g., lock your workstation before stepping away from a nurse station).
- **Confidential data** (billing, financial, HR records) follows the same handling standard as Restricted data with respect to storage and transmission, but has a narrower internal access list tied to role.
- **Credentials of any kind** (database passwords, service account credentials, API keys) must never be stored in plaintext configuration files, spreadsheets, or shared documents. Use the approved credential management method provided by IT.

## 7. Monitoring and Enforcement

MedDefense monitors network traffic, authentication events, and data export activity on systems containing Restricted or Confidential data, consistent with applicable law and this policy. This monitoring exists to protect patients and the organization — not to surveil routine work.

**Violations are handled proportionally:**
- A first, unintentional violation (e.g., a misplaced USB drive with no data loss) typically results in a documented conversation and refresher training.
- A violation involving actual data exposure, repeated disregard for this policy, or deliberate circumvention of security controls will be escalated to HR and may result in disciplinary action up to and including termination, and, where applicable, legal or regulatory referral.
- Suspected malicious activity (e.g., unauthorized bulk data export before a resignation) will be referred immediately to the Deputy CISO for incident response, independent of any HR process already underway.

## 8. Acknowledgment

I have read and understand this Acceptable Use Policy. I understand that violating this policy may result in disciplinary action, up to and including termination of employment or contract, and that I am responsible for reporting any security concern to IT or the Deputy CISO without fear of retaliation for good-faith reporting.

| Field | |
|---|---|
| Employee/Contractor Name | ______________________________ |
| Department | ______________________________ |
| Signature | ______________________________ |
| Date | ______________________________ |

**Approved by:** Dr. Morales, CEO — MedDefense Health Systems

## Repo

- **GitHub repository:** `dlh-cyber_security`
- **Directory:** `blue_team/1x03_defense_blueprint`
- **File:** `12-acceptable_use_policy.md`
