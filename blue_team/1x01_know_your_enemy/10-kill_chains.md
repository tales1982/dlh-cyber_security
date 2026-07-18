
# 10. The Kill Chains

**Analyst:** Threat Intelligence Analyst
**Date:** Current

## Kill Chain #1: Phishing to Domain-Wide Ransomware

```
Threat Actor: Ransomware Groups (Organized Crime) — BlackReef-style RaaS affiliate
Target Asset: ehr-db-01 and NAS-01 (Top 5 Critical Assets)
Expected Impact: Full encryption of domain-joined systems plus exfiltration
  of the patient database, with the backup destroyed in the same operation.

Step 1 - Initial Access:
  Vector: Spear phishing email impersonating FortiGate vendor support
  Surface: Human / External
  Detail: A spoofed email from a lookalike domain convinces IT Director
    Sarah Park to open a malicious "firmware patch" document, executing a
    macro that drops a reverse-shell payload on her workstation.

Step 2 - Establish Foothold:
  Action: The reverse shell connects to attacker-controlled infrastructure;
    a scheduled task disguised as Windows Update re-establishes the
    connection every 30 minutes.
  MedDefense Weakness: No endpoint detection catches the persistence
    mechanism — the workstation fleet has no dedicated detective control.

Step 3 - Lateral Movement / Escalation:
  Action: Network discovery commands map the environment; credential
    dumping (Mimikatz) recovers a cached Domain Admin hash, used in a
    pass-the-hash attack against ad-dc-01.
  MedDefense Weakness: The flat network lets the attacker see and reach
    the entire 10.10.0.0/16 range from a single HQ workstation, and no
    privileged access tier separates this credential from full domain
    authority.

Step 4 - Objective Execution:
  Action: Patient data is exported from ehr-db-01 and exfiltrated over
    HTTPS; NAS-01's management interface is used to delete backup jobs
    and stored backups before a GPO pushes the ransomware payload
    domain-wide.
  Data/System Affected: ehr-db-01 (patient records), NAS-01 (backup
    infrastructure), all domain-joined Windows systems.

Step 5 - Impact:
  Business Impact: Clinical operations halted org-wide, regulatory breach
    notification triggered, multi-million-dollar recovery and ransom
    exposure, no viable backup to restore from.
  CIA Pillars: Confidentiality (patient data exfiltrated), Integrity
    (encrypted/altered systems), Availability (all encrypted systems and
    the backup itself unavailable).

Gaps Exploited: GAP-014, GAP-002, GAP-017, GAP-003
Break Points: Step 1 (email security gateway/DMARC could have blocked the
  spoofed domain before delivery) and Step 3 (a functioning detective
  control reviewing the SSH/Windows logs, or AD privilege tiering, would
  have stopped credential escalation before it reached Domain Admin).
```

## Kill Chain #2: VPN Credential Compromise to Domain Takeover

```
Threat Actor: Ransomware Groups (Organized Crime), via an Initial Access
  Broker-purchased credential
Target Asset: ad-dc-01 (Top 5 Critical Asset)
Expected Impact: Domain-wide authentication compromise without any exploit
  being used at all.

Step 1 - Initial Access:
  Vector: Purchased or phished VPN credential (no MFA)
  Surface: External
  Detail: An affiliate buys valid VPN access to MedDefense from an Initial
    Access Broker for $3,000-$8,000 and authenticates directly through the
    FortiGate with no second factor required.

Step 2 - Establish Foothold:
  Action: The affiliate lands directly on the internal network with a
    working, unflagged session.
  MedDefense Weakness: GAP-014 (no MFA anywhere) means a valid password is
    sufficient on its own; nothing distinguishes this login from a
    legitimate remote worker.

Step 3 - Lateral Movement / Escalation:
  Action: The affiliate scans the flat network, identifies ad-dc-01
    directly (no segmentation to slow discovery), and attempts credential
    attacks against it, aided by MedDefense's password policy having no
    MFA backstop.
  MedDefense Weakness: The flat network exposes the domain controller
    directly to any authenticated internal session; GAP-002 means none of
    this reconnaissance activity is reviewed.

Step 4 - Objective Execution:
  Action: Once Domain Admin credentials are obtained, the affiliate
    authenticates to ad-dc-01 with full administrative authority.
  Data/System Affected: ad-dc-01 / ad-dc-02, and by extension every
    domain-joined system and account.

Step 5 - Impact:
  Business Impact: Total loss of identity trust — every login in the
    organization is now suspect, staff locked out or impersonated at will,
    a precondition for any larger ransomware or data-theft operation.
  CIA Pillars: Integrity (domain trust compromised), Availability (staff
    can be locked out org-wide), Confidentiality (every credential in the
    domain is now exposed).

Gaps Exploited: GAP-014, GAP-012, GAP-002, GAP-017
Break Points: Step 1 (MFA on the VPN alone would have stopped this chain
  entirely, regardless of how the credential was obtained) and Step 3
  (network segmentation would prevent a general internal session from
  reaching the domain controller directly).
```

## Kill Chain #3: Insider Data Exfiltration via Legitimate Access

```
Threat Actor: Insider (Malicious) — a departing employee with legitimate
  EHR read access
Target Asset: ehr-db-01 (Top 5 Critical Asset)
Expected Impact: Bulk theft of patient records for resale, with no
  technical exploit involved anywhere in the chain.

Step 1 - Initial Access:
  Vector: Pre-existing, legitimate account access (no intrusion required)
  Surface: Human / Internal
  Detail: A billing-department employee facing termination already holds
    read access to the EHR for normal billing-verification purposes.

Step 2 - Establish Foothold:
  Action: No foothold is needed — access already exists and is fully
    authorized under the employee's current role.
  MedDefense Weakness: GAP-001 means nothing distinguishes routine access
    from access with theft intent; the system has no concept of unusual
    volume for this user.

Step 3 - Lateral Movement / Escalation:
  Action: No lateral movement is required; the employee uses the EHR's
    own built-in export function repeatedly over several weeks, mixed into
    normal daily work.
  MedDefense Weakness: The export function has no per-session or per-day
    volume limit and generates no alert regardless of how much is
    exported.

Step 4 - Objective Execution:
  Action: Exported CSV files are copied to an unmanaged personal USB
    drive (no Group Policy restricts USB storage) and removed from the
    building.
  Data/System Affected: ehr-db-01 (thousands of patient records).

Step 5 - Impact:
  Business Impact: Mandatory HIPAA breach notification, patient trust
    damage, potential regulatory fine, no ransom or encryption — pure
    confidentiality loss discovered only after the fact, if at all.
  CIA Pillars: Confidentiality only — integrity and availability of the
    EHR are never touched, which is exactly why this chain is so hard to
    notice.

Gaps Exploited: GAP-001, GAP-002 (no DLP/export monitoring), and the
  absence of automated offboarding tied to termination timing (GAP-018)
  extends the exposure window even after the employee's last day.
Break Points: Step 3 (a Data Loss Prevention control flagging unusual
  export volume would catch this while it is happening) and Step 4 (a USB
  restriction policy would block the physical exfiltration step entirely).
```

## Kill Chain #4: Unpatched Web Server to Medical Device Exposure

```
Threat Actor: Unskilled / Opportunistic Attacker
Target Asset: Medical IoT fleet (Philips monitors, BD Alaris pumps)
Expected Impact: Patient-safety-relevant device access reached through a
  completely untargeted, automated compromise.

Step 1 - Initial Access:
  Vector: Automated exploitation of the known Apache 2.4.29 RCE
  Surface: External
  Detail: A mass internet scanner finds billing-srv-01's exposed,
    unpatched Apache instance and exploits it automatically — the same
    vulnerability already used twice against MedDefense (1x00 Task 1/2).

Step 2 - Establish Foothold:
  Action: The attacker (or automated toolkit) drops a lightweight payload
    on billing-srv-01 and confirms network reachability.
  MedDefense Weakness: GAP-008 — the billing server still has no dedicated
    detective control despite two prior compromises.

Step 3 - Lateral Movement / Escalation:
  Action: From billing-srv-01, the flat network exposes every subnet,
    including 10.10.3.0/24 where the medical IoT fleet lives with no VLAN
    separation from general server/workstation traffic.
  MedDefense Weakness: GAP-007 — medical IoT devices share a flat network
    with no isolation from anything else, including a compromised
    financial server.

Step 4 - Objective Execution:
  Action: The attacker reaches Philips monitor and BD Alaris pump web
    management interfaces directly (ports 80/443), which run on firmware
    with a known, unmitigated CVE.
  Data/System Affected: Real-time patient vitals monitoring and medication
    dosage delivery systems.

Step 5 - Impact:
  Business Impact: Direct patient-safety risk (manipulated dosing or
    falsified vitals readings), not just a data event — this is the most
    severe possible category of impact in a healthcare environment.
  CIA Pillars: Integrity (falsified readings/dosage) and Availability
    (device disruption) — both are direct clinical-harm vectors, not
    abstract technical failures.

Gaps Exploited: GAP-008, GAP-007, GAP-004, GAP-019
Break Points: Step 1 (patching Apache or isolating billing-srv-01's
  internet exposure stops the chain at the door) and Step 3 (network
  segmentation between servers/workstations and the medical device subnet
  would contain any compromise well short of the pump fleet).
```

## Kill Chain #5: Vendor Compromise to Direct Patient Data Access

```
Threat Actor: External attacker using a compromised vendor as a stepping
  stone (Supply Chain Compromise)
Target Asset: ehr-db-01 (Top 5 Critical Asset)
Expected Impact: Direct access to patient records via a trusted third
  party, bypassing MedDefense's own perimeter entirely.

Step 1 - Initial Access:
  Vector: Compromise of MedTech Solutions (EHR maintenance vendor)
  Surface: External (via a trusted third party, not MedDefense's own
    perimeter)
  Detail: An attacker breaches MedTech Solutions' own environment and
    obtains their remote maintenance credentials/tooling for MedDefense's
    EHR server.

Step 2 - Establish Foothold:
  Action: The attacker authenticates to ehr-srv-01 using MedTech's own
    legitimate, pre-authorized maintenance access.
  MedDefense Weakness: GAP-014 — no MFA on vendor remote access means a
    stolen credential alone is sufficient; the connection looks identical
    to routine maintenance.

Step 3 - Lateral Movement / Escalation:
  Action: No further lateral movement is required — MedTech's contracted
    access already reaches ehr-srv-01 directly, which in turn has an open
    path to ehr-db-01.
  MedDefense Weakness: GAP-001 — ehr-db-01 is reachable network-wide, not
    restricted to ehr-srv-01 alone, so the vendor session reaches the
    database without needing elevated MedDefense-specific privileges.

Step 4 - Objective Execution:
  Action: The attacker queries and exports patient records directly
    through the maintenance session, blending in with legitimate vendor
    activity.
  Data/System Affected: ehr-db-01 (patient records for 50,000+ patients).

Step 5 - Impact:
  Business Impact: A breach MedDefense cannot detect through its own
    controls, since the access appears fully authorized; regulatory and
    reputational damage compounded by the difficulty of even attributing
    the breach to a third party quickly.
  CIA Pillars: Confidentiality (direct patient data exposure) — the chain
    is silent on integrity/availability, since nothing is altered or taken
    offline.

Gaps Exploited: GAP-014, GAP-001, GAP-002
Break Points: Step 1 (MFA specifically on vendor remote-access paths would
  stop a stolen MedTech credential from being usable) and Step 3 (
  restricting ehr-db-01 access to ehr-srv-01 only, per the original 1x00
  recommendation, would mean even a compromised MedTech session couldn't
  reach the database beyond what the application itself exposes).
```

---
