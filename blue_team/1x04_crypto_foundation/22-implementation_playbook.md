# 20. The Implementation Playbook MedDefense Health Systems

**Analyst:** Security Analyst
**Date:** Current
**Audience:** Sarah Park and the IT team this is an execution document, not a strategy document. The 5 actions below are the "Immediate" priority findings from T15's Crypto Posture Audit, selected to cover the five highest-impact systems rather than clustering on one.

```
Action #1: Disable DES and RC4 Kerberos Encryption Types
Priority: Immediate (T15 — CRYPTO-011; tied to RISK-002, $300,000 ALE domain-wide ransomware risk)
System Affected: ad-dc-01, ad-dc-02
Prerequisites:
  - Inventory of all service accounts and their current supported encryption
    types (query msDS-SupportedEncryptionTypes for every account) — completed
    BEFORE this change, so any account relying solely on DES/RC4 is identified
    and remediated first, rather than discovered by an outage afterward.
  - Confirmation that no legacy system requiring DES/RC4 exists undocumented
    (T6 Gap Analysis flagged this as unverified — this prerequisite closes
    that gap before proceeding).
  - Change window approved by James Chen (Deputy CISO, Accountable per 1x03
    governance).

Steps:
  1. On each domain controller, open Group Policy Management and edit the
     Default Domain Controllers Policy (or a dedicated new GPO scoped to
     domain controllers).
  2. Navigate to Computer Configuration > Policies > Windows Settings >
     Security Settings > Local Policies > Security Options > "Network
     security: Configure encryption types allowed for Kerberos".
  3. Enable only: AES128_HMAC_SHA1, AES256_HMAC_SHA1, and Future encryption
     types. Explicitly leave DES_CBC_CRC, DES_CBC_MD5, and RC4_HMAC_MD5
     unchecked.
  4. Run `gpupdate /force` on ad-dc-01 and ad-dc-02 to apply immediately
     rather than waiting for the normal refresh interval.
  5. For any service account identified in the Prerequisites inventory,
     explicitly set msDS-SupportedEncryptionTypes to 24 (AES128 + AES256
     only, decimal) via PowerShell:
     `Set-ADAccountControl` / `Set-ADObject -Replace
     @{'msDS-SupportedEncryptionTypes'=24}`

Validation:
  - Run `klist` on a test client after re-authenticating, and confirm the
    Kerberos ticket's encryption type shows AES256-CTS-HMAC-SHA1-96, never
    RC4-HMAC or DES-CBC.
  - Attempt a Kerberoasting-style service ticket request (`Get-ADUser
    -Filter {ServicePrincipalName -ne "$null"}` + a ticket request) in a
    controlled test and confirm only AES-encrypted tickets are issuable.
  - Confirm no authentication failures appear in the Security event log
    (Event ID 4768/4769 failures) for legitimate users/services in the
    hour following the change.

Rollback:
  - Re-enable RC4_HMAC_MD5 in the same GPO setting and run `gpupdate
    /force` again — this is a fast, single-setting reversal.
  - Maximum acceptable downtime before rollback is triggered: 30 minutes
    of authentication failures affecting any production clinical system
    (EHR access, PACS login) — patient care systems take priority over
    completing this change on the original schedule.

Maintenance Window: Overnight (low-traffic hours) — authentication changes
  on domain controllers affect every system MedDefense runs, so this must
  not be attempted during clinical operating hours.
Communication: Notify all department heads 48 hours in advance (per 1x03
  RACI, department heads own getting their staff through operational
  changes); notify Sarah Park and James Chen immediately before and after
  execution; on-call IT staff should be aware in case of an authentication
  disruption requiring rapid rollback.
```

```
Action #2: Enforce TLS-Only PostgreSQL Connections for the EHR Database
Priority: Immediate (T15 — CRYPTO-002; tied to RISK-001, $495,000 ALE — the highest quantified risk in the register)
System Affected: ehr-db-01 (with ehr-srv-01 as the connecting application)
Prerequisites:
  - Confirm the PostgreSQL server certificate is valid and not near expiry
    (apply the same certificate hygiene established in T17).
  - Confirm ehr-srv-01's connection string/driver supports SSL mode
    "require" or stronger (most modern PostgreSQL drivers do by default).

Steps:
  1. On ehr-db-01, edit `pg_hba.conf` and remove every `hostnossl` line
     currently permitting unencrypted connections from the 10.10.0.0/16
     range (T0 audit notes documented this exact gap).
  2. Replace with `hostssl` entries only, for the same address range and
     database/user scope.
  3. Confirm `postgresql.conf` still has `ssl = on` (already set per T0) and
     additionally set `ssl_min_protocol_version = 'TLSv1.2'` to match T11's
     hardened standard.
  4. Reload the PostgreSQL configuration: `sudo systemctl reload
     postgresql` (a reload, not a full restart, to avoid an unnecessary
     connection drop for unrelated sessions).
  5. Update ehr-srv-01's database connection string to `sslmode=require` (or
     `verify-full` if the internal CA from T17 is in place) if not already
     configured this way.

Validation:
  - From ehr-srv-01, run `psql "sslmode=require host=ehr-db-01"` and confirm
    a successful connection; then attempt `psql "sslmode=disable
    host=ehr-db-01"` and confirm it is REJECTED — proving hostnossl is
    truly gone, not just deprioritized.
  - Confirm the EHR application itself loads and displays a test patient
    record successfully post-change (functional check, not just a raw
    `psql` test).
  - Check PostgreSQL logs for any connection refusals from legitimate
    application IPs in the 30 minutes following the change.

Rollback:
  - Restore the previous `pg_hba.conf` from backup (taken before Step 1)
    and reload PostgreSQL again.
  - Maximum acceptable downtime before rollback is triggered: 15 minutes of
    the EHR application being unable to reach the database — this is a
    clinical-care-critical system, tolerance for downtime is lower here
    than for Action #1's domain-wide change.

Maintenance Window: Overnight, coordinated with clinical operations to
  confirm no active shift depends on continuous EHR access during the
  window (unlike Action #1, this affects one specific application, so the
  window can be shorter).
Communication: Notify clinical department heads and on-call nursing
  supervisors 48 hours in advance; Sarah Park executes, Security Analyst
  validates, James Chen notified of completion.
```

```
Action #3: Enforce Encrypted Transport for Billing Database Connections
Priority: Immediate (T15 — CRYPTO-005; tied to RISK-003, $189,200 ALE, a server with a documented repeat-compromise history)
System Affected: billing-srv-01
Prerequisites:
  - Issue or confirm a valid TLS certificate for the MySQL server (internal
    CA per T17).
  - Confirm the billing application's MySQL client library supports
    `require_secure_transport` (standard in modern MySQL/MariaDB clients).

Steps:
  1. On billing-srv-01, configure MySQL with `ssl_cert`, `ssl_key`, and
     `ssl_ca` pointing to the issued certificate and internal CA chain.
  2. Set `require_secure_transport = ON` in the MySQL configuration file
     (`my.cnf`).
  3. Restart the MySQL service: `sudo systemctl restart mysql` (a restart is
     required here, unlike PostgreSQL's reload, since this setting is not
     dynamically reloadable in most MySQL versions).
  4. Update the billing application's connection configuration to require
     SSL (`useSSL=true&requireSSL=true` or equivalent, depending on the
     client library in use).

Validation:
  - Attempt `mysql -h billing-srv-01 --ssl-mode=DISABLED` and confirm the
    connection is REJECTED with an explicit secure-transport error.
  - Attempt `mysql -h billing-srv-01 --ssl-mode=REQUIRED` and confirm
    success, then run `SHOW STATUS LIKE 'Ssl_cipher';` and confirm a modern
    AEAD cipher (not a legacy CBC/RC4 suite) is in use.
  - Confirm the billing application can process a test transaction
    end-to-end post-change.

Rollback:
  - Set `require_secure_transport = OFF`, restart MySQL, and revert the
    application's connection string — a fast, fully reversible change.
  - Maximum acceptable downtime before rollback is triggered: 30 minutes of
    billing application connectivity failure — billing is important but not
    immediately patient-safety-critical the way EHR access is, allowing a
    slightly longer tolerance than Action #2.

Maintenance Window: Overnight or a low-billing-volume period (e.g., a
  weekend), since this requires a full MySQL restart rather than a reload.
Communication: Notify the billing department head 48 hours in advance;
  Sarah Park executes; James Chen notified given this server's repeat-
  compromise history makes this a closely-watched change.
```

```
Action #4: Enable DICOM TLS for PACS Imaging Traffic
Priority: Immediate (T15 — CRYPTO-008; closes active cleartext exposure of patient identifiers embedded in DICOM headers, Finding 024)
System Affected: pacs-srv-01, plus the MRI workstation and radiology workstations that connect to it
Prerequisites:
  - Confirm the PACS software version in use actually supports DICOM TLS
    (DICOM PS3.15) — this must be verified against the specific vendor
    product in use before scheduling the change, since not all legacy PACS
    versions support it (the MRI workstation is noted elsewhere in this
    project as running Windows XP, which may itself be a constraint here).
  - Issue certificates for pacs-srv-01 and each connecting workstation via
    the internal CA (T17).

Steps:
  1. Configure pacs-srv-01's DICOM service to require TLS on its DICOM
     listener ports (4242, 11112), presenting the issued certificate.
  2. Configure each radiology workstation's DICOM sender/receiver
     application to connect using DICOM TLS rather than plaintext DICOM.
  3. If the Windows XP MRI workstation cannot support DICOM TLS (likely,
     given its age), implement a compensating control instead: route its
     traffic through an isolated network segment with no other systems
     reachable, until the workstation itself can be replaced or upgraded —
     this is a documented, deliberate exception, not a silent gap.
  4. Test connectivity from one modern radiology workstation before
     rolling out to all of them.

Validation:
  - Capture network traffic between a test workstation and pacs-srv-01
    (e.g., with `tcpdump`) and confirm the DICOM payload, including patient
    identifier fields, is no longer visible in cleartext.
  - Confirm a test image transfer completes successfully and is viewable in
    the PACS viewer with no corruption.
  - Confirm the MRI workstation's compensating network isolation (if
    applicable) does not block its legitimate, intended traffic path.

Rollback:
  - Revert the DICOM listener configuration to allow plaintext connections
    temporarily if TLS causes transfer failures blocking active imaging
    work — imaging availability for active patient care takes priority
    over completing this change on schedule.
  - Maximum acceptable downtime before rollback is triggered: 20 minutes of
    any radiology workstation being unable to transfer images — imaging
    delays directly affect clinical diagnosis turnaround time.

Maintenance Window: Overnight, with a radiology technologist available
  on-call to confirm real-world transfer functionality immediately after
  the change (not just a synthetic test).
Communication: Notify the radiology department head and on-call
  technologist 48 hours in advance; Sarah Park executes; Security Analyst
  validates the network capture confirming cleartext exposure is closed.
```

```
Action #5: Deploy LUKS Volume Encryption for NAS-01 Backup Storage
Priority: Immediate (T15 — CRYPTO-013; an explicit Phase 1 roadmap priority independent of this audit, per T12's context)
System Affected: NAS-01
Prerequisites:
  - A verified, tested full backup exists BEFORE this change begins (this
    change involves reformatting storage — an unverified backup here would
    be catastrophic, not just risky).
  - The encryption key management system (HSM/KMS per T14) is provisioned
    and ready to hold the LUKS key — the key must never be stored on
    NAS-01 itself (T12, Part 4).
  - Sufficient temporary storage capacity exists to hold a full copy of
    current backup data during the migration window.

Steps:
  1. Copy all existing backup data from NAS-01's current unencrypted RAID-5
     array to temporary secure storage.
  2. Format the RAID-5 array's underlying volume with LUKS
     (`cryptsetup luksFormat`), following the exact procedure demonstrated
     in T12.
  3. Open the LUKS volume (`cryptsetup luksOpen`) and create the filesystem
     on it.
  4. Store the LUKS key/passphrase in the HSM/KMS provisioned in the
     Prerequisites — never on NAS-01's own configuration or DSM interface.
  5. Copy backup data back onto the newly encrypted volume.
  6. Configure NAS-01 to automatically unlock the LUKS volume at boot using
     a call to the HSM/KMS (rather than a manually-entered passphrase each
     time, which is operationally unsustainable for a server).

Validation:
  - Confirm a test backup job completes successfully to the new encrypted
    volume.
  - Confirm a test restore from the encrypted volume produces byte-for-byte
    identical data to the pre-migration copy (matching the verification
    method demonstrated in T12, Part 2).
  - Confirm the raw underlying storage is unreadable without the key
    (`strings` against the raw block device shows no recognizable backup
    content), exactly as demonstrated in T12.

Rollback:
  - Restore from the temporary secure copy taken in Step 1 onto an
    unencrypted volume if the encrypted configuration proves unworkable —
    this is the one action in this playbook where rollback means reverting
    to the LESS secure prior state temporarily, which must be explicitly
    approved by James Chen given what that implies, not executed
    unilaterally.
  - Maximum acceptable downtime before rollback is triggered: 4 hours of
    backup capability being unavailable — longer tolerance than the other
    four actions, since a temporary backup gap (with production systems
    otherwise unaffected) is less immediately disruptive than an EHU/
    billing/imaging outage, provided it is resolved before the next
    scheduled backup window.

Maintenance Window: A full weekend maintenance window — this is the most
  operationally involved change in this playbook (data migration, not just
  a configuration flag) and should not be attempted during a single
  overnight window.
Communication: Notify Sarah Park and James Chen at the start and
  completion of each major step (data copy, LUKS format, restore, key
  provisioning) given the higher-stakes nature of this specific change;
  no clinical department notification is required since NAS-01 is not
  patient-facing, but IT staff on call throughout the window should be
  aware given the extended timeline.
```
