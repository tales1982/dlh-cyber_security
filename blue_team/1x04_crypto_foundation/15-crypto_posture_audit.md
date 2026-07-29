# 15. The Crypto Posture Audit  MedDefense Health Systems

**Analyst:** Security Analyst
**Date:** Current

This audit revisits every "Weak" or "Absent" cell from the Task 0 Data Protection Map (16 of the map's 18 applicable cells) and produces a Crypto Finding for each, connecting it to the relevant 1x02 vulnerability finding, 1x03 risk register entry, Task 6's algorithm assessment, Task 13's encryption-level recommendation, and Task 14's key management plan.

## Crypto Findings

```
Finding ID: CRYPTO-001
Data Category: Patient medical records (EHR)
Data State: At rest
Current Protection: None (PostgreSQL data directory on unencrypted ext4)
Vulnerability Reference: None specifically cited in 1x02; documented directly in T0 audit notes
Risk Reference: RISK-001 (Ghostcat exposes EHR DB credentials; ALE $495,000, residual $24,750)
Algorithm Assessment: No algorithm currently in use — inadequate by default
Recommended Protection: AES-256 (T6), database-level encryption of the PostgreSQL data files
Encryption Level: Database-level (T13)
Key Management: HSM-managed key (T14); Sarah Park (Custodian) operational access, James Chen (Deputy CISO) Accountable
Implementation Priority: Immediate — highest quantified ALE in the entire register
```

```
Finding ID: CRYPTO-002
Data Category: Patient medical records (EHR)
Data State: In transit
Current Protection: Partial — PostgreSQL ssl=on, but pg_hba.conf permits both hostssl and hostnossl
Vulnerability Reference: None specifically cited in 1x02; documented directly in T0 audit notes
Risk Reference: RISK-001
Algorithm Assessment: TLS is available but not enforced — the gap is enforcement, not algorithm choice; once enforced, should follow T11's TLS 1.2/1.3-only, AEAD-only standard
Recommended Protection: Remove all hostnossl entries from pg_hba.conf; enforce hostssl exclusively with TLS 1.2+ (T11 cipher configuration)
Encryption Level: Transport-level (not one of T13's six storage levels — a network-layer control)
Key Management: Certificate-based, same CA/renewal process built out in T10
Implementation Priority: Immediate — a configuration-only fix with no new infrastructure required
```

```
Finding ID: CRYPTO-003
Data Category: Patient medical records (EHR)
Data State: In use
Current Protection: None (decrypted in memory for display; nurse station screensaver timeout set to "Never")
Vulnerability Reference: None specifically cited in 1x02; documented directly in T0 audit notes
Risk Reference: RISK-002 (domain-wide ransomware/Kill Chain #1; ALE $300,000) — thematic, via workstation access as an entry point
Algorithm Assessment: Not applicable — this gap is an access-control/endpoint policy failure, not a cryptographic algorithm failure; no encryption scheme by itself secures an unlocked, unattended screen
Recommended Protection: Not a cryptographic control — enforce a short automatic screen-lock timeout via Group Policy and endpoint session management
Encryption Level: Not applicable
Key Management: Not applicable
Implementation Priority: Phase 1 — a Group Policy change, low cost, no new technology
```

```
Finding ID: CRYPTO-004
Data Category: Financial/billing data (MySQL)
Data State: At rest
Current Protection: None (unencrypted ext4; forensic finding from the 1x00 crypto-miner incident confirmed files readable without MySQL credentials)
Vulnerability Reference: 1x00 crypto-miner forensic finding (billing-srv-01)
Risk Reference: RISK-003 (billing server repeat RCE-to-root; ALE $189,200, residual $23,650)
Algorithm Assessment: No algorithm currently in use — inadequate by default
Recommended Protection: AES-256 (T6), database-level encryption; credit card PAN data specifically should be tokenized instead of encrypted (T7, Part 2), removing it from this database's compliance scope entirely
Encryption Level: Database-level, with tokenization as a targeted exception for card data (T13)
Key Management: HSM-managed key (T14)
Implementation Priority: Immediate — second-highest quantified ALE in the register
```

```
Finding ID: CRYPTO-005
Data Category: Financial/billing data (MySQL)
Data State: In transit
Current Protection: None (MySQL bound to 0.0.0.0, no SSL enforced, plaintext protocol)
Vulnerability Reference: Finding 006
Risk Reference: RISK-003
Algorithm Assessment: No algorithm currently in use
Recommended Protection: Enforce MySQL's require_secure_transport with TLS 1.2+ (T11 cipher standard)
Encryption Level: Transport-level
Key Management: Certificate-based (T10 process)
Implementation Priority: Immediate — configuration-only fix
```

```
Finding ID: CRYPTO-006
Data Category: Financial/billing data (MySQL)
Data State: In use
Current Protection: None (inferred consistent with the EHR pattern; not separately audited)
Vulnerability Reference: None specifically cited; inferred pattern
Risk Reference: RISK-003
Algorithm Assessment: Not applicable — an access-control/display gap
Recommended Protection: Role-based data masking for billing clerk views (T7, Part 3), plus endpoint screen-lock policy matching CRYPTO-003
Encryption Level: Not applicable (masking, not encryption)
Key Management: Not applicable
Implementation Priority: Phase 1
```

```
Finding ID: CRYPTO-007
Data Category: Medical images (DICOM/PACS)
Data State: At rest
Current Protection: None (unencrypted local disk; patient identifiers readable in plaintext DICOM headers)
Vulnerability Reference: None specifically cited in 1x02; documented directly in T0 audit notes
Risk Reference: RISK-006 (Shared PACS login; ALE not separately quantified) — same asset, thematic tie
Algorithm Assessment: No algorithm currently in use
Recommended Protection: AES-256 (T6)
Encryption Level: Volume-level for the PACS storage array, matching the NAS-01 design pattern (T13)
Key Management: HSM/KMS-managed key (T14)
Implementation Priority: Phase 1
```

```
Finding ID: CRYPTO-008
Data Category: Medical images (DICOM/PACS)
Data State: In transit
Current Protection: None (DICOM TLS/PS3.15 exists as a standard but is not configured anywhere at MedDefense)
Vulnerability Reference: Finding 024
Risk Reference: RISK-006
Algorithm Assessment: No algorithm currently in use — patient identifiers embedded in DICOM headers traverse the network in cleartext
Recommended Protection: Enable DICOM TLS with the same TLS 1.2/1.3, AEAD-only cipher standard as T11
Encryption Level: Transport-level
Key Management: Certificate-based (T10 process)
Implementation Priority: Immediate — patient identifiers are actively exposed on the wire today
```

```
Finding ID: CRYPTO-009
Data Category: Medical images (DICOM/PACS)
Data State: In use
Current Protection: None (inferred; not separately audited)
Vulnerability Reference: None specifically cited; inferred pattern
Risk Reference: RISK-006
Algorithm Assessment: Not applicable
Recommended Protection: Workstation session controls and PACS viewer access logging (also relevant to detecting the steganographic exfiltration risk identified in T7, Part 4)
Encryption Level: Not applicable
Key Management: Not applicable
Implementation Priority: Phase 2
```

```
Finding ID: CRYPTO-010
Data Category: Credentials (Active Directory)
Data State: At rest
Current Protection: NTHash (MD4) for NTLM compatibility
Vulnerability Reference: None specifically cited in 1x02; documented directly in T0 audit notes
Risk Reference: RISK-002 (domain-wide ransomware/Kill Chain #1; ALE $300,000, residual ~$96,000 after MFA)
Algorithm Assessment: MD4-family hashing is rated "Broken" in T6 — inadequate; cannot be fully eliminated without breaking NTLM compatibility (T6 Gap Analysis, case 4)
Recommended Protection: Cannot be replaced outright — audit and eliminate remaining NTLM dependencies so NTLM/NTHash can be disabled wherever legacy compatibility does not genuinely require it; treat NTDS.dit as a maximum-sensitivity asset in the interim
Encryption Level: Not applicable (credential hashing, not disk/file encryption)
Key Management: Not applicable
Implementation Priority: Phase 1 — requires a legacy-system dependency audit before NTLM can be safely disabled
```

```
Finding ID: CRYPTO-011
Data Category: Credentials (Active Directory)
Data State: In transit
Current Protection: Kerberos permits AES, RC4, and DES encryption types; LDAP is unsigned
Vulnerability Reference: Finding 018 (DES/RC4 Kerberos), Finding 007 (LDAP signing not required)
Risk Reference: RISK-002
Algorithm Assessment: DES and RC4 are both rated "Broken" in T6 — actively enabling Kerberoasting (T3, Part 2) — inadequate
Recommended Protection: Disable DES and RC4 Kerberos encryption types domain-wide (AES128/256-only), enforce LDAP signing on all domain controllers (T6 Gap Analysis, cases 1-2)
Encryption Level: Not applicable (protocol/authentication configuration)
Key Management: Not applicable
Implementation Priority: Immediate — a Group Policy/domain configuration change, no new infrastructure required
```

```
Finding ID: CRYPTO-012
Data Category: Credentials (Active Directory)
Data State: In use
Current Protection: None
Vulnerability Reference: 1x01 Kill Chain #1, Step 4 (Mimikatz dumping a cached Domain Admin hash from memory) — a kill-chain reference, not a 1x02 Finding ID
Risk Reference: RISK-002
Algorithm Assessment: Not applicable — this is a credential-exposure-in-memory gap, not an encryption algorithm gap
Recommended Protection: Deploy Credential Guard/LSASS protection and EDR tooling to detect credential-dumping behavior; restrict cached credential retention where operationally feasible
Encryption Level: Not applicable
Key Management: Not applicable
Implementation Priority: Phase 1
```

```
Finding ID: CRYPTO-013
Data Category: Backup data (NAS-01)
Data State: At rest
Current Protection: None (RAID-5 array, no encryption layer; Synology's built-in AES-256-CBC feature exists but is not enabled)
Vulnerability Reference: Finding 015
Risk Reference: RISK-002 — backups are the last line of recovery from the exact ransomware scenario this risk quantifies
Algorithm Assessment: No algorithm currently in use, despite one being natively available and unused
Recommended Protection: AES-256-XTS via LUKS, demonstrated directly in T12
Encryption Level: Volume-level (T12/T13) — matches NAS-01's RAID array as the natural logical boundary
Key Management: HSM/KMS-managed key, explicitly never stored on NAS-01 itself (T12, Part 4; T14)
Implementation Priority: Immediate — already an explicit Phase 1 roadmap priority independent of this audit
```

```
Finding ID: CRYPTO-014
Data Category: Backup data (NAS-01)
Data State: In transit
Current Protection: None (inferred; backup job traffic travels the same flat internal network as everything else)
Vulnerability Reference: None specifically cited; inferred from the network context in Finding 015
Risk Reference: RISK-002
Algorithm Assessment: No algorithm currently in use
Recommended Protection: Enable encrypted transport for backup jobs (Veeam and equivalent tooling support TLS-protected backup traffic) using the same TLS 1.2+ standard as T11
Encryption Level: Transport-level
Key Management: Certificate-based
Implementation Priority: Phase 1
```

```
Finding ID: CRYPTO-015
Data Category: Email (O365)
Data State: In use
Current Protection: None (S/MIME/OME not configured; PHI sometimes emailed in plaintext content despite policy)
Vulnerability Reference: None specifically cited; documented directly in T0 audit notes (Sarah's note)
Risk Reference: Not directly quantified in the risk register; a compliance/PHI-exposure exposure rather than a modeled financial risk
Algorithm Assessment: Not applicable — the platform-level protections (BitLocker, TLS 1.2) are already Adequate per T0; the gap is message-content protection specifically
Recommended Protection: Enable Microsoft Office Message Encryption (OME) or S/MIME for any message containing PHI, paired with a DLP rule flagging/blocking plaintext PHI patterns in outbound email body content
Encryption Level: Message-level (T13)
Key Management: Microsoft-managed (OME) or per-user certificate-based (S/MIME)
Implementation Priority: Phase 2
```

```
Finding ID: CRYPTO-016
Data Category: VPN traffic (site-to-site tunnels)
Data State: In transit
Current Protection: AES-256/SHA-256, IKEv2 with DH Group 14 — strong algorithm choice, undermined by the Westside endpoint
Vulnerability Reference: Finding 014
Risk Reference: RISK-007 (Westside consumer router; ALE $15,000, residual $3,000)
Algorithm Assessment: Adequate per T6 — this is the one finding in this audit where the algorithm itself is not the problem; the weakness is entirely the unmanaged consumer-grade endpoint terminating one side of the tunnel
Recommended Protection: No algorithm change needed; replace the Westside consumer router with a managed, business-grade VPN endpoint, and consider certificate-based IKE authentication (T4, Part 3) rather than a static pre-shared key
Encryption Level: Not applicable (network layer, not storage)
Key Management: FortiGate-managed; Westside endpoint key material should be reviewed and reissued once the hardware is replaced
Implementation Priority: Phase 1 — low ALE, already an active treatment item in the risk register
```

## Posture Score

Of the Data Protection Map's 21 total cells, 3 are Not Applicable (Task 0) and 18 are applicable. Of those 18, 2 were already Adequate (both Microsoft-managed O365 protections) and the remaining **16 were Weak or Absent every one of those 16 now has a documented Crypto Finding above with a specific recommended protection, encryption level, and key management plan.**

**Posture Score: 18/18 applicable data flows (100%) now have either adequate protection already in place or a clear, specific remediation path documented in this audit.** This is a measurable improvement from Task 0's baseline, where only 2/18 (11.1%) had adequate protection and the remaining 88.9% had no documented path forward at all the gap has not yet been *closed* (these are recommendations, not completed remediations), but it has been fully *mapped*, which was this task's explicit goal.

## Top 3 Crypto Risks (ranked by combined impact)

**1. CRYPTO-001 / CRYPTO-002 Patient medical records (EHR), at rest and in transit.** Tied to RISK-001's $495,000 ALE the single highest quantified financial risk anywhere in the 1x03 risk register and protecting the organization's largest, most sensitive dataset (every patient's full medical record). No other finding in this audit carries a comparably large, already-quantified dollar figure.

**2. CRYPTO-010 / CRYPTO-011 / CRYPTO-012 Credentials (Active Directory), across all three data states.** Tied to RISK-002's $300,000 ALE and the domain-wide ransomware Kill Chain #1 scenario weak credential protection (MD4 NTHash, DES/RC4 Kerberos, in-memory exposure via Mimikatz) is not just one risk among many, it is the specific mechanism that turns a single compromised workstation into the organization-wide compromise RISK-002 quantifies, making it a force-multiplier risk rather than an isolated one.

**3. CRYPTO-004 / CRYPTO-005 Financial/billing data (MySQL), at rest and in transit.** Tied to RISK-003's $189,200 ALE, the register's third-highest quantified figure, compounded by the fact that this same server has already suffered two real incidents (the RCE-to-root pattern the risk description itself references) meaning this is not a theoretical exposure but a data store with a demonstrated, repeated history of compromise.
