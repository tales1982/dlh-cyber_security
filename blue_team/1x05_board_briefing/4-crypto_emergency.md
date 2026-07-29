# 4. The Crypto Emergency MedDefense Health Systems

**Analyst:** Security Analyst
**Date:** Current

## Part 1 Crypto Attack Surface Mapping

Three of the seven Crimson Tide phases exploit a cryptographic weakness directly; the advisory's own Phase 4 target list ("patient databases... financial and billing records... insurance claim data") maps to both the EHR and billing crypto findings, not just one.

```
Phase: 3 — Lateral Movement
Crypto Weakness: CRYPTO-011 (1x04 Task 15) — Active Directory Kerberos permits AES, RC4, and DES encryption types; RC4/DES rated "Broken" (1x04 Task 6)
What Crimson Tide Exploits: RC4-encrypted service tickets can be requested for any account with a registered SPN and cracked offline (Kerberoasting) — confirmed in 3 of 5 real incidents — turning a single low-privilege foothold into a path toward Domain Admin without needing to touch the domain controller directly
Recommended Crypto Fix: Implementation Playbook Action #1 — disable DES/RC4 domain-wide, AES128/256-only
Emergency Timeline: Yes — a Group Policy change, no new infrastructure. Feasible inside 72 hours (Task 3, Tier 2), though it requires an overnight maintenance window given the risk of breaking legacy authentication
```

```
Phase: 4 — Data Exfiltration
Crypto Weakness: CRYPTO-001/CRYPTO-002 (patient records: no at-rest encryption, inconsistently-enforced in-transit TLS) and CRYPTO-004/CRYPTO-005 (financial/billing: identical pattern — MySQL bound to 0.0.0.0, plaintext protocol)
What Crimson Tide Exploits: In 4 of 5 real incidents, databases were not encrypted at rest, letting the attacker copy raw database files directly from the filesystem with no database credentials required at all — exactly the condition documented for both ehr-db-01 and billing-srv-01 in the 1x04 Data Protection Map
Recommended Crypto Fix: Implementation Playbook Action #2 (enforce TLS-only PostgreSQL for ehr-db-01) and Action #3 (enforce encrypted MySQL transport for billing-srv-01) as the fast, in-transit fix; full AES-256 database-level at-rest encryption (CRYPTO-001/004) as the larger fix behind it
Emergency Timeline: Partial — TLS enforcement on both databases is achievable inside 72 hours (configuration-only). Full at-rest encryption requires HSM/KMS key provisioning (Playbook prerequisite) and realistically cannot fully complete in 72 hours, but should begin immediately rather than wait for its originally-scheduled Month 3+ slot
```

```
Phase: 5 — Backup Destruction
Crypto Weakness: CRYPTO-013 (NAS-01 RAID-5 array unencrypted; Synology's built-in AES-256-CBC feature exists natively but is not enabled)
What Crimson Tide Exploits: Unencrypted backups let the attacker verify they contain valuable data before destroying them, confirmed in 3 of 5 real incidents — the lack of encryption doesn't just fail to protect the backup, it actively helps the attacker decide it's worth destroying
Recommended Crypto Fix: Implementation Playbook Action #5 — LUKS (AES-256-XTS) volume encryption for NAS-01
Emergency Timeline: No. Action #5's own prerequisites (a verified full backup taken first, HSM/KMS key provisioning ready, sufficient temporary storage, a full weekend maintenance window for the data migration) make this the one crypto fix that cannot be safely compressed into 72 hours without real data-loss risk. This is precisely why Task 3's Tier 1 response substitutes **network isolation** for NAS-01 tonight — isolation is not encryption, but it is the achievable substitute given the timeline, and it directly buys the time LUKS migration needs to be done safely rather than rushed
```

## Part 2 Encryption Priority Re-ranking

Original Implementation Playbook order (1x04 Task 20): (1) Disable DES/RC4 Kerberos, (2) TLS-only PostgreSQL, (3) Encrypted MySQL transport, (4) DICOM TLS for PACS, (5) LUKS encryption for NAS-01.

**Updated Crypto Priority List:**

1. **Disable DES/RC4 Kerberos (unchanged, #1).** Still first it directly closes the advisory's confirmed Phase 3 TTP and remains the fastest, cheapest change on the list.
2. **NAS-01 backup protection moved from #5 to #2.** Backup destruction (Phase 5) is the *only* Crimson Tide phase confirmed in 100% of real incidents (5 of 5), and NAS-01 is the last line of recovery for every other risk in the register. Because full LUKS migration cannot safely finish in 72 hours, priority #2 is executed in two parts: physical/network isolation now (Task 3, Tier 1), full encryption immediately following (this week, Tier 3) not deferred back to its original position.
3. **TLS-only PostgreSQL for ehr-db-01 stays roughly #2/#3.** Still immediate and configuration-only; the difference now is that at-rest encryption for the EHR is explicitly queued right behind Kerberos and NAS-01, not behind DICOM.
4. **Encrypted MySQL transport for billing-srv-01 moved up in practical urgency (was #3, effectively unchanged in position but now justified differently).** The advisory names "financial and billing records" as a direct Crimson Tide exfiltration target previously this action's priority rode mostly on billing-srv-01's repeat-compromise history (1x03 RISK-003); now it also rides on being a named target of this specific active campaign.
5. **DICOM TLS for PACS moved down from #4 to #5.** This is the one re-ranking that goes the other direction: medical imaging is **not** named among Crimson Tide's observed exfiltration targets in any of the 5 real incidents. Still a real, worthwhile fix just not one the current threat intelligence gives any reason to accelerate ahead of the other four this week.

## Part 3 The "What If" Calculation

If `ehr-db-01` had been encrypted at rest as recommended (1x04 Task 13, database-level AES-256), would Phase 4 data still be exfiltrable, given the attacker already has domain admin and the encryption key is stored on the same server?

**Yes under exactly that condition, the data would very likely still be exfiltrable, through either of two paths:**

1. **Live query extraction.** A database engine must be able to decrypt its own data to serve normal application queries. At-rest (database-level/TDE-style) encryption protects a *stolen disk or raw file copy* it does nothing to stop a principal with sufficient privilege on the host itself from simply running `pg_dump` or an equivalent live export, which returns plaintext regardless of what sits on disk underneath it. Domain admin access, combined with lateral movement onto `ehr-srv-01`/`ehr-db-01` itself (Phase 3), is more than sufficient privilege to do exactly this.
2. **Key extraction.** If the encryption key genuinely sits on the same server as the encrypted data the specific failure mode this question describes an attacker with root/domain-admin-equivalent access to that host can locate and extract the key directly, then decrypt any stolen files offline at leisure. This is exactly the scenario 1x04 Task 14's own key management plan explicitly warns against ("the key must never be stored on NAS-01 itself"); the same principle applies with equal force to `ehr-db-01`.

**Where encryption still matters, even in this worst case:**

- It eliminates the "trivial raw file copy without needing any credentials" pattern the advisory documents in 4 of 5 real incidents Crimson Tide's own standard playbook assumes an unencrypted target and would need to adapt, costing the attacker time and increasing the chance of detection.
- If the key is properly isolated in a separate HSM/KMS (as 1x04 Task 14 and this task's own recommendation specify, rather than co-located as the question's hypothetical describes), compromising the database server alone does **not** yield the key the attacker would need to separately compromise the HSM/KMS, a materially harder target.
- The "live query" path still requires the attacker to have already escalated to domain admin **and** pivoted onto the specific database host a later, harder-to-reach stage than "flat network, no segmentation" currently allows on day one.

**Conclusion:** at-rest encryption is necessary but not sufficient against an adversary who has already reached domain admin. It reliably defeats the cheap, no-skill raw-file-theft path that accounts for the majority of real-world Crimson Tide incidents; it does not substitute for the access-control layers proper key isolation, network segmentation, and AD tiering that keep an attacker from reaching domain admin in the first place. Encryption and segmentation are not alternatives to each other; this module's emergency plan funds both because neither one alone closes Phase 4.
