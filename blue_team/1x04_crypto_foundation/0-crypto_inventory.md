
# 0. The Crypto Inventory MedDefense Health Systems

**Analyst:** Security Analyst
**Date:** Current

*Three cells below are marked **N/A (Not Applicable)** rather than forced into Adequate/Weak/Absent a data-at-rest state does not meaningfully exist for live VPN tunnel traffic, and an "in-use" state does not meaningfully exist for dormant backup data or for a VPN tunnel. Marking these honestly as out-of-scope is more accurate than checking a box that doesn't describe anything real.*

## Data Protection Map

### 1. Patient Medical Records (EHR: `ehr-srv-01` / `ehr-db-01`)

| State      | Protection               | Evidence                                                                                                                                                                                                       | Status |
| ---------- | ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| At Rest    | None                     | Audit notes: PostgreSQL data directory on unencrypted ext4; readable in full if root/disk is obtained.                                                                                                         | Absent |
| In Transit | PostgreSQL SSL (partial) | Audit notes:`ssl=on`, but `pg_hba.conf` allows both `hostssl` and `hostnossl` from the whole `/16` encryption is possible but not enforced, and no one can currently confirm which sessions use it. | Weak   |
| In Use     | None                     | Audit notes: decrypted in memory on`ehr-srv-01` for display; nurse station screensaver timeout set to "Never" (no session protection either).                                                                | Absent |

### 2. Financial/Billing Data (MySQL on `billing-srv-01`)

| State      | Protection      | Evidence                                                                                                                                                                                                                                                                                                                                                                                                          | Status |
| ---------- | --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| At Rest    | None            | Audit notes + 1x00 cryptominer forensic finding: database files readable directly from the filesystem with no MySQL credentials needed at all.                                                                                                                                                                                                                                                                    | Absent |
| In Transit | None            | Audit notes: MySQL bound to`0.0.0.0`, no SSL enforced, "connects via plaintext MySQL protocol." Sarah's own notes label this "WEAK," but the description is of literal plaintext with zero encrypted-session evidence — reclassified here as **Absent**, not Weak, since nothing partial is actually happening (unlike the EHR's `ssl=on`-but-inconsistent case above). Also ties to 1x02 Finding 006. | Absent |
| In Use     | None (inferred) | Not explicitly audited by Sarah for billing specifically; inferred consistent with the identical pattern documented for the EHR system, since both applications share the same operational environment.                                                                                                                                                                                                           | Absent |

### 3. Medical Images (DICOM on `pacs-srv-01`)

| State      | Protection      | Evidence                                                                                                                                                                                                                           | Status |
| ---------- | --------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| At Rest    | None            | Audit notes: images stored unencrypted on local disk; DICOM headers with patient identifiers readable "with any DICOM viewer or even a text editor."                                                                               | Absent |
| In Transit | None            | Audit notes: DICOM TLS (PS3.15) exists as a standard but is not configured anywhere at MedDefense; imaging traffic (including embedded patient identifiers) traverses the network in cleartext. Ties directly to 1x02 Finding 024. | Absent |
| In Use     | None (inferred) | Not explicitly audited; inferred from the same pattern as EHR/billing no evidence of any session or display-level protection anywhere in the audit notes.                                                                         | Absent |

### 4. Credentials (Active Directory: `ad-dc-01`/`02`, application passwords)

| State      | Protection                                                      | Evidence                                                                                                                                                                                                                              | Status |
| ---------- | --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| At Rest    | NTHash (MD4) for NTLM compatibility                             | Audit notes: AD stores NTLM-compatible hashes using MD4, a cryptographically broken algorithm by modern standards, purely for legacy compatibility no one has documented the need for.                                                | Weak   |
| In Transit | Kerberos (AES available, RC4/DES also permitted); LDAP unsigned | Audit notes + 1x02 Finding 018 (DES/RC4 Kerberos encryption types enabled) + Finding 007 (LDAP signing not required). Strong options exist but are not enforced to the exclusion of broken ones.                                      | Weak   |
| In Use     | None                                                            | Not directly documented in the audit notes, but 1x01 Kill Chain#1 Step 4 explicitly describes Mimikatz dumping a cached Domain Admin hash from memory direct evidence that credentials-in-use have zero additional protection today. | Absent |

### 5. Backup Data (`NAS-01`)

| State      | Protection      | Evidence                                                                                                                                                                                            | Status |
| ---------- | --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| At Rest    | None            | Audit notes: RAID-5 array with no encryption layer; Synology's built-in AES-256-CBC shared folder encryption exists but is not enabled. Ties to 1x02 Finding 015.                                   | Absent |
| In Transit | None (inferred) | Not explicitly audited; no mention anywhere of Veeam backup-job traffic being encrypted between production servers and`NAS-01`, and it travels the same flat internal network as everything else. | Absent |
| In Use     | N/A             | Backup data does not have a meaningful "in use" state it is dormant until a restore operation is initiated, which is itself covered by the At Rest / In Transit protections above.                 | N/A    |

### 6. Email (O365)

| State      | Protection                                                | Evidence                                                                                                                                                                                                            | Status   |
| ---------- | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| At Rest    | BitLocker (Microsoft datacenter) + per-mailbox encryption | Audit notes: Microsoft-managed, enforced platform-wide.                                                                                                                                                             | Adequate |
| In Transit | TLS 1.2 (Exchange Online, Microsoft-enforced since 2023)  | Audit notes: confirmed, enforced by Microsoft, not MedDefense-configured.                                                                                                                                           | Adequate |
| In Use     | None                                                      | Audit notes: S/MIME/OME not configured; Sarah's own note confirms physicians email PHI in plaintext content despite being told not to the platform protects the pipe, nothing protects the message content itself. | Absent   |

### 7. VPN Traffic (Site-to-Site Tunnels)

| State      | Protection                              | Evidence                                                                                                                                                                                                                                                                                                                               | Status |
| ---------- | --------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| At Rest    | N/A                                     | VPN tunnel traffic has no "at rest" state by definition it exists only while in transit.                                                                                                                                                                                                                                              | N/A    |
| In Transit | AES-256/SHA-256, IKEv2 with DH Group 14 | Audit notes describe strong algorithm choices on the FortiGate side, but the Westside tunnel terminates on a consumer-grade Netgear router (1x02 Finding 014) with unknown firmware/patch history the algorithm is adequate, but the endpoint it runs on is not. Downgraded from Sarah's own "appears adequate" note for this reason. | Weak   |
| In Use     | N/A                                     | No meaningful "in use" state distinct from in-transit for tunnel traffic.                                                                                                                                                                                                                                                              | N/A    |

## Gap Summary

| Status               | Count (of 21 cells) |
| -------------------- | ------------------- |
| Adequate             | 2                   |
| Weak                 | 4                   |
| Absent               | 12                  |
| N/A (not applicable) | 3                   |

**Overall crypto coverage:** Excluding the 3 cells that are not applicable by definition, **2 of the 18 applicable cells (11.1%) have adequate cryptographic protection.** The remaining 88.9% is either weak (4 cells, 22.2%) or fully absent (12 cells, 66.7%). The two Adequate cells both belong to Email, and both are protections **Microsoft provides, not MedDefense** meaning of the cryptographic protection MedDefense itself is responsible for configuring and maintaining, **effectively none of it is currently adequate.** This confirms Sarah's own blunt summary with a number: "we encrypt almost nothing that we control" is not an exaggeration, it is 11.1%, and all of that 11.1% belongs to a vendor.
