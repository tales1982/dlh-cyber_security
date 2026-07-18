# 11. STRIDE on the EHR

**Analyst:** Threat Intelligence Analyst
**Date:** Current

## Spoofing

```
Category: S
Threat ID: EHR-S1
Description: An attacker uses a stolen or purchased EHR/VPN credential
  (no MFA, GAP-014) to authenticate to the EHR application as a legitimate
  clinician, with nothing to verify the login is who it claims to be.
Attack Vector: VPN Exploit / purchased valid credentials (T8, T9)
Impact: The system treats fully unauthorized activity as trusted clinical
  access — every downstream control that assumes "logged in = legitimate"
  is defeated in one step.
Existing Control: C-006 (password complexity/rotation) raises the cost of
  guessing a password but does nothing once a valid password is obtained.
Gap: GAP-014 (no MFA anywhere in the environment)
```

```
Category: S
Threat ID: EHR-S2
Description: A phishing email impersonating IT or vendor support (as in
  the FortiGate email to Sarah Park, T4 Scenario 1) tricks a user into
  revealing credentials that are then used to authenticate to systems
  feeding into the EHR environment.
Attack Vector: Phishing / Spear Phishing (T8, T9)
Impact: The attacker's session is indistinguishable from the real
  employee's, letting them act with that person's full EHR-adjacent access.
Existing Control: None found specific to EHR-targeted phishing.
Gap: GAP-002 (no detection to catch anomalous post-phishing authentication)
```

## Tampering

```
Category: T
Threat ID: EHR-T1
Description: An attacker with network access to ehr-db-01 (PostgreSQL port
  5432, reachable from the entire internal network) connects directly to
  the database and modifies a patient record — e.g., a medication dosage
  or allergy entry — bypassing the EHR application's own validation logic
  entirely.
Attack Vector: Open Service Ports / Vulnerable Software Exploit (T8, T9)
Impact: A clinician acting on a tampered record could make a dangerous
  treatment decision with no application-layer warning that the data was
  altered outside the normal workflow.
Existing Control: C-002 (VPN-restricted server access) limits how the
  attacker got onto the network in the first place, but does not restrict
  what a session already inside can reach.
Gap: GAP-001 (EHR database reachable from the entire internal network,
  with no detection of anomalous access)
```

```
Category: T
Threat ID: EHR-T2
Description: A user with direct database access (a compromised admin
  session, or an insider abusing elevated access) alters billing or
  diagnosis codes tied to patient encounters to commit insurance fraud,
  with no integrity check flagging direct writes that bypass the
  application layer.
Attack Vector: Insider (Malicious) / Vulnerable Software Exploit (T9)
Impact: Financial and regulatory exposure, and potential downstream
  clinical confusion if diagnosis codes feed into other care decisions.
Existing Control: None found — no database-level change auditing exists
  independent of the application's own (unreviewed) logs.
Gap: GAP-002 (no functioning detection capability anywhere in the
  environment)
```

## Repudiation

```
Category: R
Threat ID: EHR-R1
Description: A user accesses or modifies a patient record and later denies
  having done so; because verbose logging (C-005) exists only on
  ehr-srv-01 and nobody reviews it, there is no practical way to prove or
  disprove the claim.
Attack Vector: N/A — this is an absence-of-accountability threat rather
  than a delivered attack vector.
Impact: Investigations following any incident (insider theft, tampering)
  stall on "who actually did this," undermining both internal discipline
  and any external regulatory response.
Existing Control: C-005 (SSH verbose logging) exists but is Weak — logs
  exist, nobody reviews them.
Gap: GAP-002 (no functioning detection or incident-response capability)
```

```
Category: R
Threat ID: EHR-R2
Description: If EHR credentials are ever shared informally between staff
  under time pressure (the same cultural pattern already documented for
  PACS, GAP-010), any given login becomes impossible to attribute to a
  specific individual, letting a user plausibly deny an action performed
  under their own account.
Attack Vector: Default / Shared Credentials (T8, T9)
Impact: Accountability for clinical data access collapses exactly where
  it matters most — during an investigation into unauthorized viewing or
  alteration of a specific patient's record.
Existing Control: None found specific to EHR credential-sharing (unlike
  PACS, this has not yet been formally observed, but no control prevents
  it).
Gap: GAP-010 (the same shared-credential pattern already Critical-rated
  for PACS applies structurally to any similarly unmonitored EHR account)
```

## Information Disclosure

```
Category: I
Threat ID: EHR-I1
Description: `ehr-db-01`'s PostgreSQL port (5432) is reachable from the
  entire internal network instead of being restricted to `ehr-srv-01`, so
  any compromised endpoint anywhere can directly query and exfiltrate
  patient records, bypassing the application's own access controls
  entirely.
Attack Vector: Open Service Ports (T8, T9) — the single most direct path
  in the entire Vector-to-Asset Matrix.
Impact: A breach of up to 50,000+ patient records, triggering mandatory
  HHS notification, litigation exposure and reputational damage.
Existing Control: C-002 (VPN-restricted server access) limits the
  perimeter path in but not lateral reachability once inside.
Gap: GAP-001 (EHR database reachable from the entire internal network,
  with no detection of anomalous access)
```

```
Category: I
Threat ID: EHR-I2
Description: Traffic between clinical workstations and the EHR application
  crosses a flat, unsegmented network with no isolation from any other
  device, making interception or passive sniffing by anything else already
  on the network (a compromised workstation, an unmanaged device) feasible.
Attack Vector: Unsecure Networks (T8, T9)
Impact: Patient data in transit is exposed to a far larger population of
  potential observers than the clinical staff who are supposed to see it.
Existing Control: None found at the network-segmentation level; only the
  perimeter firewall (C-003) applies, and it does nothing for internal
  traffic.
Gap: GAP-012 (flat network turns every endpoint into a potential pivot
  point)
```

## Denial of Service

```
Category: D
Threat ID: EHR-D1
Description: A ransomware payload (Kill Chain #1, T10) encrypts
  `ehr-srv-01` and `ehr-db-01` simultaneously, taking the entire EHR
  offline during active patient care.
Attack Vector: Phishing → domain-wide ransomware deployment (T9, T10)
Impact: This is not hypothetical — an EHR outage already forced a return
  to paper records once before (1x00 Task 1, Incident E); a ransomware-
  driven repeat would be far more prolonged and organization-wide.
Existing Control: C-009 (nightly backup) exists as a corrective measure,
  but is undermined by GAP-003 (the backup shares the same network and has
  never been tested for full disaster recovery).
Gap: GAP-002 and GAP-003
```

```
Category: D
Threat ID: EHR-D2
Description: `ehr-srv-01` is explicitly excluded from endpoint antivirus
  coverage (GAP-005), so a resource-exhaustion payload — a cryptominer or
  a simpler DoS tool — could degrade the EHR application's availability
  for an extended period without antivirus ever flagging it, the same
  pattern already proven on `billing-srv-01`.
Attack Vector: Vulnerable Software Exploit (T8, T9)
Impact: Degraded EHR performance or intermittent unavailability during
  clinical use, with no automated alert to explain why.
Existing Control: C-005 (SSH verbose logging, Weak) is the only coverage
  on this host, and it is not reviewed.
Gap: GAP-005 (endpoint antivirus excludes every server in the environment)
```

## Elevation of Privilege

```
Category: E
Threat ID: EHR-E1
Description: A user with only local admin rights on their own workstation
  (as in Kill Chain #1) escalates to Domain Admin via credential
  harvesting; because no privileged access tiering exists, that Domain
  Admin authority extends directly to controlling permissions on
  `ehr-srv-01`/`ehr-db-01`.
Attack Vector: Phishing → Insider (Malicious)-equivalent access level (T9,
  T10)
Impact: An attacker who never had any legitimate EHR access at all ends
  up with full administrative control over the entire EHR environment.
Existing Control: C-007 (account lockout) slows brute-force attempts but
  does not address the underlying lack of privilege separation.
Gap: GAP-017 (no privileged access tiering for Active Directory)
```

```
Category: E
Threat ID: EHR-E2
Description: A user with only legitimate, read-only EHR access (the
  billing-clerk pattern, T3/T10 Kill Chain #3) uses the EHR's own
  unrestricted export function to obtain effective bulk-database-level
  access — a functional privilege escalation within the application layer
  itself, even though no OS-level permission ever changed.
Attack Vector: Insider (Malicious/Negligent) abusing legitimate access
  (T9)
Impact: Read-only access, intended for individual patient lookups during
  billing verification, becomes equivalent to a full data export
  capability with no additional authorization step.
Existing Control: None found — the export function is available to all
  users with read access, with no additional authorization or volume cap.
Gap: GAP-001 (no detection of anomalous access, including anomalous
  export volume)
```

---

## STRIDE Summary for EHR

**Denial of Service** represents the greatest risk to the EHR system specifically. Every other STRIDE category here ultimately produces a data or accountability problem — serious, but resolvable after the fact through investigation, notification and remediation. Denial of Service is different in a clinical setting: when `ehr-srv-01`/`ehr-db-01` go offline, physicians lose real-time access to allergies, medication histories and active orders *during active patient care*, which is precisely why the EHR was rated Critical across all three CIA pillars in 1x00 Task 8 rather than only for confidentiality. This is also the category where MedDefense's own gaps compound most dangerously: GAP-005 leaves the EHR server itself unprotected by antivirus, GAP-002 means an attack in progress goes unnoticed, and GAP-003 removes the one thing (a working backup) that would otherwise cap the damage — turning what could be a contained outage into the kind of prolonged, paper-chart emergency MedDefense has already experienced once before.

---
