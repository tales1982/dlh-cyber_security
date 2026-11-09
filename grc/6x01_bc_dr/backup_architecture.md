# MedDefense Backup Architecture

**Version:** 1.0
**Prepared by:** Tales Lima, IT Security
**Date:** 2026-11-08
**Inputs:** `business_impact_analysis.md` (RTO, RPO, tiers), `current_backup_schedule.csv`, `backup_log_review_findings.md`, `dependency_map_seed.md`
**Scope:** all Tier 1 and Tier 2 systems in the BIA (six Tier 1, three Tier 2). The Tier 3 Security Operations Platform keeps its current schedule, which already meets its 4-hour RPO.

## Strategy Overview

1. **The schedule follows the RPO.** For every system, the interval between verified recovery points is equal to or shorter than the BIA RPO. Where it was not (`backup_log_review_findings.md` findings 1 and 3), the schedule changes.
2. **3-2-1-1 rule for Tier 1.** Three copies, on two media types, one in a geographically separate region, and one immutable (object lock) so that ransomware with administrator rights cannot delete it. Every Tier 1 system has a secondary copy in a different region from the data center.
3. **Encryption everywhere for ePHI.** AES-256 at rest with keys in a MedDefense-controlled key management service (AWS KMS customer-managed keys for cloud copies, the backup platform key vault on-site). Keys are never stored with the backups they protect. TLS 1.2 or later in transit.
4. **A completed job is not a verified backup** (finding 4). Each backup is verified by a SHA-256 manifest, and each system has a scheduled test restore with a record count or application-level check, a named tester and a date.
5. **Restoration follows dependencies, not alphabetical order.** Network, then identity, then the backup platform, then clinical systems by patient safety.
6. **Vendor storage needs a BAA first.** CloudVault Medical, the LIS secondary destination listed in `current_backup_schedule.csv`, holds no executed Business Associate Agreement. Until it does, the LIS off-site copy goes to MedDefense's own isolated backup account.

Common storage:

| Name | Type | Location |
| --- | --- | --- |
| Backup NAS rack A | On-site disk NAS, encrypted volumes | Primary data center |
| Isolated backup account | AWS S3 with Object Lock (compliance mode), separate AWS account and credentials | `us-east-2`, geographically separate from the primary site |
| Vendor DR site | Epic vendor-hosted DR | Vendor region, covered by Epic BAA |

## RPO Compliance Verification

| System | Tier | BIA RPO | Current recovery point frequency | Current compliant | New recovery point frequency | New compliant | Change |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Network Core | 1 | 6 hours | Config backup every 6 hours | Yes | Every 6 hours + on every change | Yes | Add change-triggered backup |
| Active Directory | 1 | 4 hours | System state daily; snapshot every 8 hours | **No** (8 h > 4 h) | System state every 4 hours; DC02 continuous replication | Yes | Finding 3 closed |
| Epic EHR | 1 | 15 minutes | Vendor replication every 15 minutes | Yes | Same, plus nightly export | Yes | Add MedDefense-witnessed restore test |
| Laboratory Information System | 1 | 1 hour | Nightly SQL dump at 23:30 (up to 24 h loss) | **No** (24 h > 1 h) | Nightly full dump + hourly incremental (transaction log) | Yes | Finding 1 closed |
| Pharmacy Dispensing System | 1 | 1 hour | Database hourly | Yes | Hourly | Yes | Add restore test |
| Medical Device Integration Gateway | 1 | 24 hours | Configuration daily, no off-site copy | Frequency yes; **no geographic copy** | Daily + after each change, off-site copy | Yes | Finding 2 closed |
| PACS/RIS | 2 | 4 hours | Storage snapshot every 4 hours | Yes | Every 4 hours | Yes | Document restore sequence |
| Email and Secure Messaging | 2 | 1 hour | Provider continuous; export daily | Yes | Same | Yes | None |
| Backup and DR Infrastructure | 2 | 4 hours | Catalog every 4 hours | Yes | Every 4 hours, catalog copy off-site | Yes | Add timed platform recovery |

The arithmetic rule: worst-case data loss equals the interval between two verified recovery points. A system is compliant only if that interval is less than or equal to its RPO. Under the new schedule, no Tier 1 backup interval is longer than the system's RPO.

## Per-System Backup Specifications

### Network Core (Tier 1, RTO 30 minutes, RPO 6 hours)

| Field | Specification |
| --- | --- |
| Backup type | Configuration export of every router, core switch, firewall and wireless controller |
| Schedule | Every 6 hours (00:00, 06:00, 12:00, 18:00) and automatically after every committed change |
| Retention | 90 days recent; monthly copy kept 1 year; annual copy kept 7 years |
| Primary destination | Network management server, encrypted local disk, primary data center |
| Secondary destination | Encrypted Git repository mirrored to the isolated backup account (`us-east-2`) |
| Encryption at rest | AES-256; repository encryption key in AWS KMS (customer-managed key), local disk key in the backup platform key vault |
| Encryption in transit | SSH / TLS 1.2+ (SCP or HTTPS pull from devices, Git over SSH) |
| Integrity verification | SHA-256 per config file; automatic diff against previous version; quarterly restore of one core switch config to a lab switch |
| Restoration sequence | 1. Replace or power on core hardware. 2. Load firmware version recorded in the backup. 3. Push last verified config. 4. Verify routing tables, VLANs and WAN links. 5. Confirm reachability of DC01/DC02 and the backup NAS |
| Responsible role | Executes: Network Engineering Lead. Verifies: Infrastructure Manager |

### Active Directory (Tier 1, RTO 1 hour, RPO 4 hours)

| Field | Specification |
| --- | --- |
| Backup type | Windows system state backup of DC01 and DC02 + VM snapshot; continuous multi-master replication between DC01 and DC02 |
| Schedule | System state every 4 hours (01:00, 05:00, 09:00, 13:00, 17:00, 21:00); VM snapshot every 8 hours; replication continuous |
| Retention | 30 days recent; monthly copy kept 1 year for audit. Backups older than the 180-day tombstone lifetime cannot be used for a DC restore |
| Primary destination | Backup NAS rack A (`\\backup-srv\ad-backups\DC01\` and `\DC02\`) |
| Secondary destination | Isolated backup account (`us-east-2`), Object Lock 30 days |
| Encryption at rest | AES-256 (NAS volume encryption and S3 SSE-KMS); keys in backup platform key vault and AWS KMS; DSRM password in the privileged access vault, not with the backups |
| Encryption in transit | SMB 3.1.1 encryption to the NAS; TLS 1.2+ to S3 |
| Integrity verification | SHA-256 manifest per backup set; quarterly system state restore of DC01 into an isolated recovery network, validated with `dcdiag` and `repadmin /showrepl` |
| Restoration sequence | Single DC loss: seize FSMO roles on DC02 if needed, rebuild DC01, promote it and let it replicate (non-authoritative). Full loss: restore DC01 system state from the newest verified set, then restore DC02 non-authoritatively. See `recovery_runbooks.md` Runbook 2 |
| Responsible role | Executes: Systems Administrator. Verifies: Infrastructure Manager |

### Epic EHR (Tier 1, RTO 2 hours, RPO 15 minutes)

| Field | Specification |
| --- | --- |
| Backup type | Vendor database replication + nightly full export |
| Schedule | Replication every 15 minutes; full export nightly 00:30 |
| Retention | 35 days at the vendor; monthly export 1 year; archive 7 years (medical record retention) |
| Primary destination | Vendor-hosted production with replicated standby |
| Secondary destination | Vendor-hosted DR site in a separate region; nightly export copy to the isolated backup account (`us-east-2`) |
| Encryption at rest | AES-256, vendor-managed keys under the Epic BAA; MedDefense copy encrypted with an AWS KMS customer-managed key |
| Encryption in transit | TLS 1.2+ for replication and export transfer |
| Integrity verification | Vendor monthly restore certificate; plus a semi-annual restore witnessed by MedDefense with record counts of patients, encounters and active orders checked against production |
| Restoration sequence | 1. Confirm Network Core and AD are up. 2. Vendor fails over to the DR site. 3. Restore interface engine connections to LIS, Pharmacy and PACS. 4. Validate login, a test patient chart and an order round-trip. 5. Start downtime reconciliation |
| Responsible role | Executes: Clinical Applications Manager with the Epic vendor. Verifies: Clinical Applications Lead |

### Laboratory Information System (Tier 1, RTO 30 minutes, RPO 1 hour)

| Field | Specification |
| --- | --- |
| Backup type | Nightly full compressed SQL dump (gzip) + hourly incremental (transaction log backup) |
| Schedule | Full nightly 23:30; incremental every hour on the hour |
| Retention | 30 days recent; monthly full 1 year; archive 7 years for result records |
| Primary destination | Backup NAS `/backup/lis/YYYY-MM-DD/` |
| Secondary destination | Isolated backup account (`us-east-2`), Object Lock 30 days. CloudVault Medical only after the BAA is executed and the vendor risk assessment conditions are met |
| Encryption at rest | AES-256 (NAS volume and S3 SSE-KMS customer-managed key) |
| Encryption in transit | TLS 1.2+ |
| Integrity verification | SHA-256 manifest generated **without a BOM** (`sha256sum lis_backup.sql.gz > backup_manifest.sha256`) and checked with `sha256sum -c` after every job; monthly test restore with row count of `patient_orders` and the latest critical values checked |
| Restoration sequence | 1. Verify manifest. 2. Restore last full dump. 3. Apply hourly incrementals in order up to the failure time. 4. Row count and critical value check. 5. Point the application at the restored database. 6. Notify the laboratory. See `recovery_runbooks.md` Runbook 1 |
| Responsible role | Executes: Laboratory Systems Lead (database) with Systems Administrator. Verifies: Chemistry lead (critical values) |

Note from the 2026-11-08 recovery test: the backup dump does not include the `ordered_at` column, so restored orders take the restore time. The dump job must export all columns.

### Pharmacy Dispensing System (Tier 1, RTO 2 hours, RPO 1 hour)

| Field | Specification |
| --- | --- |
| Backup type | Full database nightly + hourly incremental; daily cabinet configuration export |
| Schedule | Incremental hourly; full nightly 01:30; cabinet config daily 03:00 |
| Retention | 30 days recent; monthly 1 year; archive 2 years for controlled substance records (DEA) |
| Primary destination | Pharmacy backup share on the backup NAS |
| Secondary destination | Isolated backup account (`us-east-2`), Object Lock 30 days |
| Encryption at rest | AES-256, SSE-KMS customer-managed key |
| Encryption in transit | TLS 1.2+ |
| Integrity verification | SHA-256 manifest daily (replaces weekly); quarterly test restore with count of active medication orders and controlled substance balances checked against the cabinets |
| Restoration sequence | 1. Confirm AD and Epic interface. 2. Restore full + incrementals. 3. Re-sync cabinets from config export. 4. Controlled substance count reconciliation with pharmacy. 5. Re-enable barcode administration |
| Responsible role | Executes: Pharmacy IT Lead. Verifies: pharmacist on duty |

### Medical Device Integration Gateway (Tier 1, RTO 2 hours, RPO 24 hours)

| Field | Specification |
| --- | --- |
| Backup type | Full configuration export (device mappings, alarm routing rules, interface settings) + VM image monthly |
| Schedule | Configuration daily 02:30 and after every change; VM image monthly |
| Retention | 30 days recent; monthly 1 year |
| Primary destination | Biomed file share on the backup NAS |
| Secondary destination | **New:** isolated backup account (`us-east-2`), Object Lock 30 days (closes finding 2) |
| Encryption at rest | AES-256, SSE-KMS customer-managed key |
| Encryption in transit | TLS 1.2+ |
| Integrity verification | SHA-256 manifest; quarterly restore to a spare gateway with an end-to-end alarm test from one monitor per ICU pod to the central station |
| Restoration sequence | 1. Confirm Network Core and clinical VLANs. 2. Rebuild gateway from VM image. 3. Apply latest config. 4. Alarm routing test per unit. 5. Confirm vital signs posting to Epic |
| Responsible role | Executes: Biomedical IT Lead. Verifies: ICU charge nurse (alarm test) |

### PACS/RIS (Tier 2, RTO 4 hours, RPO 4 hours)

| Field | Specification |
| --- | --- |
| Backup type | Storage snapshot + nightly metadata (RIS database) export |
| Schedule | Snapshot every 4 hours; metadata export nightly 01:00 |
| Retention | 30 days hot; images 7 years archive (adults; longer for minors per state law) |
| Primary destination | PACS storage cluster |
| Secondary destination | Cloud object archive (separate region), Object Lock |
| Encryption at rest | AES-256, SSE-KMS customer-managed key |
| Encryption in transit | TLS 1.2+ (DICOM over TLS for image movement) |
| Integrity verification | SHA-256 on archive objects; quarterly restore of a sample of studies (the last test was missed and must be run) |
| Restoration sequence | 1. Network and AD. 2. Restore RIS metadata database. 3. Mount latest snapshot. 4. Re-link Epic order interface. 5. Open three recent studies from ED |
| Responsible role | Executes: Radiology Systems Lead. Verifies: radiologist on duty |

### Email and Secure Messaging (Tier 2, RTO 8 hours, RPO 1 hour)

| Field | Specification |
| --- | --- |
| Backup type | Cloud provider continuous retention + daily export |
| Schedule | Continuous; export daily 04:00 |
| Retention | Provider policy; export 1 year |
| Primary destination | Cloud provider |
| Secondary destination | Provider paired region; export to isolated backup account |
| Encryption at rest | AES-256 (provider); export SSE-KMS customer-managed key |
| Encryption in transit | TLS 1.2+ |
| Integrity verification | Quarterly restore of a test mailbox and message thread |
| Restoration sequence | 1. Identity provider up. 2. Provider region failover if needed. 3. Restore affected mailboxes from export. 4. Test clinical message delivery to a unit |
| Responsible role | Executes: Collaboration Services Lead. Verifies: Nursing Supervisor (test message received) |

### Backup and DR Infrastructure (Tier 2, RTO 8 hours, RPO 4 hours)

| Field | Specification |
| --- | --- |
| Backup type | Backup catalog backup + platform configuration export |
| Schedule | Catalog every 4 hours; config daily |
| Retention | 30 days local; 1 year off-site |
| Primary destination | DR platform storage |
| Secondary destination | Isolated backup account (`us-east-2`), separate credentials not joined to the domain |
| Encryption at rest | AES-256; platform key vault backed up to an offline, sealed key escrow |
| Encryption in transit | TLS 1.2+ |
| Integrity verification | Monthly catalog restore; **new:** semi-annual timed rebuild of the backup platform from bare hardware (finding 5) |
| Restoration sequence | 1. Network. 2. Rebuild backup server from the off-site config. 3. Restore the catalog. 4. Re-attach NAS and cloud targets. 5. Run a test restore |
| Responsible role | Executes: Infrastructure Manager. Verifies: IT Security |

## Full Data Center Loss: Restoration Sequence

Scenario: the primary data center is lost (power, cooling or fire). Recovery runs in the secondary environment from the isolated backup account and vendor DR sites. The order is set by dependencies first and patient safety second.

| Order | System | Why at this position | Target time from declaration |
| --- | --- | --- | --- |
| 1 | Network Core (DR site routing, VPN, clinical VLANs) | Nothing else can be reached without it | 0:30 |
| 2 | Active Directory (DC02 or restored DC01) | Every login and service account needs it | 1:00 |
| 3 | Backup and DR Infrastructure (catalog, access to backups) | Needed to restore every remaining system | 1:30 (restore access only; full platform within RTO 8 h) |
| 4 | Medical Device Integration Gateway | Alarm routing for ICU and telemetry patients; needs only network | 2:00 |
| 5 | Epic EHR (vendor DR failover) | Core record; LIS, pharmacy and PACS interfaces depend on it | 2:00 |
| 6 | Laboratory Information System | Critical values; posts results into Epic | 2:30 (30 minutes after Epic interface is up) |
| 7 | Pharmacy Dispensing System | Needs AD and Epic orders | 3:00 |
| 8 | PACS/RIS | Needs AD and Epic order interface; modalities can buffer images | 5:00 |
| 9 | Email and Secure Messaging | Phones and paging cover the gap | 8:00 |
| 10 | Security Operations Platform | Restored in reduced mode first (EDR console), full SIEM later | 24:00 |

Steps 4 and 5 run in parallel because they share no dependency. Every Tier 1 system is back before its MTD (4 hours), and Network Core and Active Directory are back before theirs (1 and 2 hours).

## Dependency Restore Constraints

1. **No application restore before Active Directory answers authentication.** A restored Epic or LIS whose service accounts cannot authenticate counts as down.
2. **LIS must not accept results before the Epic interface is confirmed.** Otherwise results post nowhere or to the wrong encounter. Until then, critical values go by phone using the Critical Value Call Log.
3. **The restored LIS must point to the recovery database, never to the production host** (`DB_HOST=lis-db-prod.meddefense.internal` in `app_config.env`). Configuration is checked before the application starts.
4. **Active Directory restores are non-authoritative by default.** An authoritative restore is used only to recover deleted objects, and is never applied to a DC that has been offline longer than the tombstone lifetime (USN rollback risk).
5. **Backup platform credentials are not domain-joined.** If Active Directory is compromised (for example by ransomware), backups must still be reachable.
6. **Incrementals are applied in order** after their full backup. A missing incremental stops the chain at the last good point, and the actual RPO achieved is recorded.
7. **Pharmacy restore requires a controlled substance count** before cabinets return to automatic dispensing.
8. **Medical device alarm routing is tested at the bedside** before the unit is told the system is back.
