
# 14. The Three Scenarios

**Analyst:** Threat Intelligence Analyst
**Date:** Current

## Scenario 1 — External: BlackReef Ransomware Campaign

```
Title: Operation Flatline — BlackReef Ransomware Against MedDefense Central
Threat Actor: Organized crime / RaaS affiliate (BlackReef profile, T2/T6)
Motivation: Financial gain (double extortion)
Initial Vector: Spear phishing impersonating Fortinet support (T4 Scenario 1 / T8)
Attack Surface Exploited: Human (T7) — initial entry via a phished IT
  Director — transitioning immediately into the Internal surface once a
  foothold exists.

Attack Sequence:
  Step 1: Spear phishing email delivers a malicious document to Sarah
    Park; a macro drops a reverse-shell payload. — Initial Access
  Step 2: A scheduled task disguised as Windows Update maintains C2 access
    every 30 minutes. — Persistence
  Step 3: Network discovery commands map the entire flat 10.10.0.0/16
    range from a single HQ workstation. — Discovery
  Step 4: Mimikatz dumps a cached Domain Admin hash; pass-the-hash grants
    Domain Admin on ad-dc-01. — Credential Access / Lateral Movement
  Step 5: Patient data (~35GB from ehr-db-01) and HR/financial documents
    (~8GB from file-srv-01) are exfiltrated via Rclone to cloud storage. — Exfiltration
  Step 6: NAS-01 backups and Volume Shadow Copies are deleted; a GPO
    deploys ransomware to every domain-joined system. — Impact

STRIDE Categories Triggered: EHR-S1 (credential-based spoofing via pass-
  the-hash), EHR-D1 (ransomware encryption), EHR-I1 (exfiltration via the
  open database port), plus the AD system's full STRIDE row from T12
  (Spoofing, Tampering via GPO, Denial of Service, Elevation of Privilege).
MedDefense Assets Impacted: ehr-db-01, ehr-srv-01, ad-dc-01/ad-dc-02,
  NAS-01, billing-srv-01, file-srv-01, and effectively every domain-joined
  workstation.
Business Impact: Clinical — EHR offline organization-wide, forcing a
  return to paper records during active patient care. Financial — ransom
  demand in the $1-3M range (T2 profile) plus recovery costs; peer
  incidents in the profile paid $600K-$1.1M. Regulatory — mandatory HHS
  breach notification for 50,000+ patients. Reputational — the profile's
  own Case 3 shows a CEO resignation within 4 months of a comparable
  incident.
Gaps Exploited: GAP-014 (no MFA), GAP-002 (no detection), GAP-017 (no AD
  privilege tiering), GAP-003 (unprotected backup), GAP-001 (EHR reachable
  network-wide), GAP-012 (flat network).
Detection Opportunities: Step 1 (an email security gateway with DMARC
  enforcement blocks the spoofed domain before delivery); Step 3
  (endpoint detection flagging discovery commands and the disguised
  scheduled task); Step 4 (a SIEM alerting on pass-the-hash / abnormal
  authentication patterns); Step 6 (DLP flagging a 43GB outbound transfer,
  and alerting on backup-deletion commands like vssadmin).
```

---

## Scenario 2 — Internal: Insider Data Exfiltration

```
Title: The Quiet Departure — Billing Department Insider Data Theft
Threat Actor: Malicious insider — a billing-department employee facing
  termination (T3 profile)
Motivation: Financial gain (selling patient records)
Initial Vector: Legitimate access abused (T3)
Attack Surface Exploited: Human (T7) — no intrusion occurs; the entire
  scenario runs on pre-existing, authorized access.

Attack Sequence:
  Step 1: The employee assesses what her billing and read-only EHR access
    can reach, noting no volume limit or anomalous-access alerting exists. — Discovery
  Step 2: Over two weeks, ~200 records/day are exported via the EHR's
    built-in CSV function, mixed into normal work. — Collection
  Step 3: CSV files are moved to a personal USB drive; ~2,800 records
    accumulate with no Group Policy restriction to stop it. — Exfiltration
  Step 4: Local files and the recycle bin are cleared to remove local
    evidence. — Defense Evasion
  Step 5: Plaintext database credentials found in a billing config file
    are copied to the same USB drive. — Credential Access
  Step 6: Three days after her last day, she reconnects via VPN using
    still-active credentials and extracts 400 more records directly. — Initial Access (Valid Accounts) / Collection

STRIDE Categories Triggered: EHR-E2 (functional privilege escalation via
  the unrestricted export function), EHR-R1/EHR-R2 (repudiation — no
  reliable attribution of the access), EHR-I1 (information disclosure).
MedDefense Assets Impacted: ehr-db-01 (patient records), billing-srv-01
  (financial data and harvested credentials).
Business Impact: Clinical — negligible direct impact. Financial —
  downstream identity theft and insurance fraud exposure for affected
  patients; investigation and legal costs for MedDefense. Regulatory —
  mandatory breach notification for 3,200+ records. Reputational — this
  class of breach is typically discovered far later than a ransomware
  event, which compounds the trust damage once disclosed.
Gaps Exploited: GAP-001 (no anomalous-access detection), GAP-002 (no
  detection/log review), GAP-018 (no automated deprovisioning — enables
  Step 6 specifically), GAP-016 (no change management/secrets handling,
  enabling the plaintext credential exposure in Step 5).
Detection Opportunities: Step 2 (DLP or export-volume alerting would flag
  200 records/day as anomalous for a billing-verification role); Step 3
  (a USB restriction policy blocks the physical exfiltration outright);
  Step 6 (automated offboarding tied to HR termination prevents this step
  from being possible at all).
```

---

## Scenario 3 — Third Party: Supply Chain Compromise via MedTech Solutions

```
Title: The MedTech Backdoor — Vendor-Mediated EHR Data Theft
Threat Actor: External attacker using a compromised vendor as a stepping
  stone (T5)
Motivation: Financial gain (data theft for resale)
Initial Vector: Vendor access pathway — compromised MedTech Solutions
  remote maintenance credentials (T5)
Attack Surface Exploited: External (T7) — via a trusted third party
  rather than MedDefense's own perimeter.

Attack Sequence:
  Step 1: An attacker breaches MedTech Solutions and obtains their remote
    maintenance credentials for MedDefense's EHR server. — Initial Access
    (Valid Accounts, from MedDefense's perspective)
  Step 2: The attacker authenticates to ehr-srv-01 using MedTech's own
    pre-authorized maintenance session — no MFA required. — Initial
    Access / Lateral Movement (first touch inside MedDefense's environment)
  Step 3: The session reaches ehr-db-01 directly, since the database is
    not restricted to ehr-srv-01 alone. — Lateral Movement
  Step 4: Patient records are queried and exported, blending in with
    legitimate vendor maintenance activity. — Collection / Exfiltration

STRIDE Categories Triggered: EHR-S1 (a variant — identity/authorization
  spoofing via a legitimate but stolen vendor credential rather than a
  phished employee one), EHR-I1 (information disclosure via the same
  reachable-database pattern).
MedDefense Assets Impacted: ehr-srv-01, ehr-db-01.
Business Impact: Clinical — none directly. Financial — breach response
  costs plus contractual/liability disputes with MedTech Solutions.
  Regulatory — mandatory HHS breach notification. Reputational — a harder
  narrative to communicate to the Board and public than a direct attack,
  since MedDefense's own perimeter was never touched.
Gaps Exploited: GAP-014 (no MFA on vendor remote access), GAP-001 (EHR
  database reachable beyond just ehr-srv-01), GAP-002 (no detection of
  anomalous vendor session behavior).
Detection Opportunities: Step 1 (MFA specifically enforced on vendor
  remote-access paths, independent of the vendor's own security, would
  stop a stolen credential from being usable); Step 3 (restricting
  ehr-db-01 access to ehr-srv-01 only, the original 1x00 recommendation,
  would contain even a compromised vendor session); Step 4 (behavioral
  monitoring of vendor sessions — flagging query volume or patterns
  inconsistent with routine maintenance — would catch the exfiltration in
  progress).
```

---
