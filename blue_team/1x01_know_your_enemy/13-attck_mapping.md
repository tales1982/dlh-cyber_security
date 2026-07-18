
# 13. The ATT&CK Mapping

**Analyst:** Threat Intelligence Analyst
**Date:** Current

## Scenario Alpha — "Operation Flatline" (Ransomware)

```
Step 1: Affiliate purchases a list of healthcare orgs with Fortinet VPN
  appliances from an Initial Access Broker on a dark web forum.
  Tactic: Resource Development
  Technique: Acquire Access (T1650)
  MedDefense Factor: MedDefense's FortiGate VPN appliance is internet-
    facing and discoverable via mass scanning, matching the healthcare
    profile Initial Access Brokers specifically compile and sell.

Step 2: Spear phishing email impersonating Fortinet support delivers a
  malicious document to Sarah Park; a macro runs PowerShell to download a
  reverse-shell payload.
  Tactic: Initial Access
  Technique: Phishing: Spearphishing Attachment (T1566.001)
    (Alternate: Execution — User Execution: Malicious File, T1204.002, and
    Command and Scripting Interpreter: PowerShell, T1059.001, for the
    macro itself.)
  MedDefense Factor: Sarah Park, as IT Director, owns the FortiGate
    directly, making a firmware-themed lure highly plausible (T4 Scenario 1).

Step 3: The reverse shell connects to C2; a scheduled task disguised as
  Windows Update re-establishes the connection every 30 minutes.
  Tactic: Persistence
  Technique: Scheduled Task/Job: Scheduled Task (T1053.005)
    (Alternate: Command and Control — Application Layer Protocol: Web
    Protocols, T1071.001, for the reverse-shell channel itself.)
  MedDefense Factor: No EDR or endpoint detection on workstations exists
    to flag a disguised scheduled task (GAP-002 — no functioning detection).

Step 4: Network discovery commands (nltest, net group "Domain Admins",
  arp -a) map the environment; the flat network exposes the entire
  10.10.0.0/16 range from a single HQ workstation.
  Tactic: Discovery
  Technique: Account Discovery: Domain Account (T1087.002)
    (Alternate: Remote System Discovery, T1018, for the network mapping.)
  MedDefense Factor: The flat network and site-to-site VPN mean a single
    workstation foothold sees every subnet, with no segmentation to limit
    what discovery reveals (GAP-012).

Step 5: Mimikatz dumps cached credentials from Sarah's workstation memory,
  revealing a Domain Admin service account's (svc_backup) NTLM hash,
  cached from a prior backup-troubleshooting session.
  Tactic: Credential Access
  Technique: OS Credential Dumping: LSASS Memory (T1003.001)
  MedDefense Factor: No privileged access tiering (GAP-017) means a
    Domain Admin service account was used interactively on a regular
    workstation, leaving its hash exposed to any local compromise.

Step 6: A pass-the-hash attack using the svc_backup hash authenticates to
  ad-dc-01, granting Domain Admin access; verified by querying all
  computer objects.
  Tactic: Lateral Movement
  Technique: Use Alternate Authentication Material: Pass the Hash
    (T1550.002)
  MedDefense Factor: No MFA (GAP-014) means possession of the hash alone
    is sufficient — there is no second factor to block authentication.

Step 7: High-value data is located and exfiltrated: ehr-db-01 is queried
  directly via pg_dump (~35GB) and file-srv-01 documents (~8GB) are
  compressed and sent to attacker-controlled cloud storage via Rclone
  over HTTPS, with no alerts generated.
  Tactic: Exfiltration
  Technique: Exfiltration Over Web Service: Exfiltration to Cloud Storage
    (T1567.002)
    (Alternate: Collection — Data from Information Repositories, T1213,
    for the pg_dump step.)
  MedDefense Factor: ehr-db-01 is reachable network-wide with no
    additional authentication beyond OS-level access (GAP-001), and no
    detective/DLP control exists to flag a 43GB outbound transfer (GAP-002).

Step 8: Domain Admin access is used to delete all NAS-01 backup jobs and
  stored backups, and Volume Shadow Copies are deleted on all Windows
  systems via vssadmin.
  Tactic: Impact
  Technique: Inhibit System Recovery (T1490)
  MedDefense Factor: NAS-01 has no protection or redundancy of its own
    (GAP-003) and sits reachable on the same network as everything else
    once Domain Admin access is obtained.

Step 9: A Group Policy Object deploys the BlackReef ransomware payload to
  all domain-joined Windows systems at the next refresh cycle; Linux
  servers are targeted separately via SSH using credentials found in a
  plaintext config file on file-srv-01.
  Tactic: Impact
  Technique: Data Encrypted for Impact (T1486)
    (Alternate: Defense Evasion/Privilege Escalation — Domain Policy
    Modification: Group Policy Modification, T1484.001, for the GPO
    deployment mechanism; Lateral Movement — Remote Services, T1021, for
    reaching the Linux servers via SSH.)
  MedDefense Factor: No privileged access tiering (GAP-017) lets Domain
    Admin push a GPO to every system at once, and plaintext credentials
    left in a config file (the same negligent pattern as T3 Scenario 5)
    extend the blast radius to the Linux servers too.
```

## Scenario Beta — "The Quiet Departure" (Insider Data Theft)

```
Step 1: Maria, facing termination in 3 weeks, already holds legitimate
  billing and EHR read-only access and decides to steal patient records.
  Tactic: N/A — pre-existing legitimate access; ATT&CK models an
    attacker's actions, not the decision point of an insider who already
    holds authorized access. No technique applies to this step.
  MedDefense Factor: Broad clinical/billing access is a genuine job
    requirement (T3 context), which is exactly what makes insider risk
    structurally different from external intrusion.

Step 2: Maria assesses what data her billing and read-only EHR access can
  reach, noting the EHR imposes no per-session record limit and no
  unusual-volume alerting.
  Tactic: Discovery
  Technique: File and Directory Discovery (T1083) — the closest available
    fit; ATT&CK's Discovery techniques are built around an intruder
    mapping an unfamiliar environment, an imperfect model for an insider
    exploring access she already legitimately holds.
  MedDefense Factor: The EHR enforces no volume cap and generates no
    alert on unusual access patterns (GAP-001), so this step itself
    produces no detectable signal.

Step 3: Over two weeks, Maria accesses ~200 records/day during normal
  hours, using the EHR's built-in export function to download CSVs; the
  audit log records the access but nobody reviews it.
  Tactic: Collection
  Technique: Data from Information Repositories (T1213)
  MedDefense Factor: The export function is available to any user with
    read access, with no additional authorization step (GAP-001), and
    audit logs exist but are never reviewed (GAP-002).

Step 4: Maria transfers the CSV files to a personal USB drive; no Group
  Policy restricts USB storage, accumulating ~2,800 records over 2 weeks.
  Tactic: Exfiltration
  Technique: Exfiltration Over Physical Medium: Exfiltration over USB
    (T1052.001)
  MedDefense Factor: No Group Policy restricts USB storage devices
    anywhere in the environment (the same gap category flagged, but never
    formally closed org-wide, in 1x00 Task 15).

Step 5: Maria deletes the CSV files and empties the recycle bin to cover
  her tracks; she is unaware the EHR maintains its own server-side audit
  log, which requires a 48-hour vendor export request and is never
  reviewed proactively.
  Tactic: Defense Evasion
  Technique: Indicator Removal: File Deletion (T1070.004)
  MedDefense Factor: Even though the surviving server-side log is
    technically intact, the 48-hour export requirement and total absence
    of proactive review (GAP-002) make it functionally useless for early
    detection.

Step 6: Maria copies the billing application's plaintext database
  connection credentials from a config file on her workstation to her
  USB drive.
  Tactic: Credential Access
  Technique: Unsecured Credentials: Credentials In Files (T1552.001)
  MedDefense Factor: The billing application stores DB credentials in
    plaintext on the workstation — the same negligent-credential-handling
    pattern documented in T3 Scenario 5, with no secrets management in
    place anywhere.

Step 7: On departure, her manager's deactivation ticket sits unprocessed
  for 5 business days (no SLA, no automated deactivation tied to HR
  termination); her VPN credentials remain active throughout.
  Tactic: N/A — this step describes an organizational process failure
    (the absence of a control), not a technique performed by the actor.
  MedDefense Factor: No automated account deprovisioning tied to HR/
    contract termination (GAP-018) is the entire enabling condition for
    Step 8.

Step 8: Three days after her last day, Maria connects to the VPN from
  home using her still-active credentials, accesses billing-srv-01 with
  the saved database credentials, and extracts 400 more records directly.
  Tactic: Initial Access
  Technique: Valid Accounts (T1078)
    (Secondary — Collection: Data from Information Repositories, T1213,
    for the direct database extraction itself.)
  MedDefense Factor: No MFA (GAP-014) means the still-active password
    alone was sufficient from an entirely new location, and GAP-018 is
    the reason the account was still usable at all.
```

---

## ATT&CK Coverage Assessment

Despite representing two structurally opposite threat types — an external RaaS affiliate and a departing insider — both scenarios converge on the same three tactics: **Discovery, Credential Access, and Exfiltration**. In Alpha, Discovery maps the network and Credential Access harvests a Domain Admin hash; in Beta, Discovery is the insider learning the limits of her own access and Credential Access is lifting plaintext database credentials from a config file. Both scenarios also end in Exfiltration, whether via Rclone to cloud storage or a USB drive walked out the door. This overlap tells MedDefense exactly where to invest first: detection capability at Discovery and Credential Access would catch an attack in progress regardless of whether the actor arrived through a phished VPN credential or already sat inside as an employee, and monitoring for unusual data movement at the Exfiltration stage is the last common checkpoint before either scenario becomes an irreversible breach — making it the single highest-leverage gap to close across both very different actor types.

---
