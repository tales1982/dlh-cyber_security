# MedDefense Recovery Runbooks

**Version:** 1.1 (updated after the 2026-11-08 LIS recovery test)
**Prepared by:** Tales Lima, IT Security
**Replaces:** `old_lis_recovery_runbook.md` (v0.7) and `old_ad_recovery_notes.md` (v0.5)
**Paths and values:** taken from `lab_config.env` and `app_config.env`; Active Directory values from `old_ad_recovery_notes.md` and `command_output_examples.md`

Rules for both runbooks:

- Start the timer before step 1 and record every step: `./recovery_timer.sh "<step name>" START`, then `PASS` or `FAIL`.
- Record every deviation when it happens, with the time, in the test or incident record. Do not wait until the end.
- Do not skip a verification check. If a check fails, follow the deviation handling for that step; do not move on.

## Runbook 1: Laboratory Information System Recovery

**System:** Laboratory Information System (Tier 1). **RTO:** 30 minutes. **RPO:** 1 hour (target; the current backup is nightly).
**Executed by:** Systems Administrator with the Laboratory Systems Lead. **Clinical verification:** chemistry lead.
**Environment (lab):**

| Item | Path or value |
| --- | --- |
| Backup file | `/tmp/meddefense-dr-test/backup/lis/2026-04-21/lis_backup.sql.gz` |
| Manifest | `/tmp/meddefense-dr-test/backup/lis/2026-04-21/backup_manifest.sha256` |
| Recovery workspace | `/tmp/meddefense-dr-test/recovery/` |
| Staged SQL | `/tmp/meddefense-dr-test/recovery/lis_dump.sql` |
| Recovery database | `/tmp/meddefense-dr-test/recovery/lis_recovered.db` |
| Application config | `/tmp/meddefense-dr-test/config/app_config.env` |
| Validation workspace | `/tmp/meddefense-dr-test/validation/` |
| Expected row count | 5 (`EXPECTED_ROW_COUNT` in `lab_config.env`) |

**Precondition:** Network Core and Active Directory are available. The incident commander (extension 7200) has declared the LIS outage, and the laboratory is working from the LIS downtime procedure.

### Step 1: Identify the latest recovery target

- **Command:**

  ```bash
  ls -1d /tmp/meddefense-dr-test/backup/lis/*/ | sort | tail -n 1
  ls -l /tmp/meddefense-dr-test/backup/lis/2026-04-21/
  ```

- **Expected output:** `/tmp/meddefense-dr-test/backup/lis/2026-04-21/`, containing `lis_backup.sql.gz` and `backup_manifest.sha256`.
- **Verification check:** both files exist and are not empty. Record the backup date: the data loss for this recovery is everything entered after that backup (nightly 23:30).
- **Deviation handling:** if the newest folder is missing or empty, take the previous date and record the extra data loss. If no backup is found, escalate to the Infrastructure Manager and confirm the lab stays on downtime procedures.

### Step 2: Verify backup integrity

- **Command:**

  ```bash
  sha256sum -c /tmp/meddefense-dr-test/backup/lis/2026-04-21/backup_manifest.sha256
  ```

- **Expected output:** `/tmp/meddefense-dr-test/backup/lis/2026-04-21/lis_backup.sql.gz: OK`
- **Verification check:** exit code 0 and the word `OK`.
- **Deviation handling:**
  - `no properly formatted checksum lines found` (seen in the 2026-11-08 test): the manifest starts with a UTF-8 byte order mark (BOM). Confirm with `head -c 3 <manifest> | od -An -c` (shows `357 273 277`). Do **not** edit the original manifest; check a clean copy:

    ```bash
    sed '1s/^\xEF\xBB\xBF//' /tmp/meddefense-dr-test/backup/lis/2026-04-21/backup_manifest.sha256 \
      > /tmp/meddefense-dr-test/validation/backup_manifest.nobom.sha256
    sha256sum -c /tmp/meddefense-dr-test/validation/backup_manifest.nobom.sha256
    ```

  - `FAILED` (hash mismatch): the backup is corrupt or altered. Stop. Do not restore it. Go back to Step 1 with the previous backup and notify IT Security, since tampering is possible.

### Step 3: Create the recovery workspace

- **Command:**

  ```bash
  mkdir -p /tmp/meddefense-dr-test/recovery
  ls -ld /tmp/meddefense-dr-test/recovery
  ```

- **Expected output:** a directory listing for `/tmp/meddefense-dr-test/recovery`.
- **Verification check:** the directory exists and is writable, and `df -h /tmp` shows free space greater than 10 times the backup size.
- **Deviation handling:** if there is not enough space, use another local disk and record the new path in the incident record. Every later command must then use that path.

### Step 4: Decompress the backup to the correct staging path

- **Known failure mode (old runbook v0.7):** the old procedure decompresses to `/recovery/lis_dump.sql`. That path does not exist in the current environment. The command fails with `/recovery/lis_dump.sql: No such file or directory`, as it did in the 2026-11-08 test. Do not create `/recovery` to make the old path work; it is outside the recovery workspace.
- **Corrected command:**

  ```bash
  gzip -dc /tmp/meddefense-dr-test/backup/lis/2026-04-21/lis_backup.sql.gz \
    > /tmp/meddefense-dr-test/recovery/lis_dump.sql
  ```

- **Expected output:** no output, exit code 0.
- **Verification check:** `ls -l /tmp/meddefense-dr-test/recovery/lis_dump.sql` shows a non-empty file (668 bytes for the 2026-04-21 backup); `head -n 1` shows `DROP TABLE IF EXISTS patient_orders;`.
- **Deviation handling:** `gzip: unexpected end of file` means the archive is truncated. Go back to Step 2, since the manifest check should have caught this, and then to the previous backup.

### Step 5: Restore the SQL dump into SQLite

- **Command:**

  ```bash
  sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db \
    < /tmp/meddefense-dr-test/recovery/lis_dump.sql
  sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db "PRAGMA integrity_check;"
  ```

- **Expected output:** no output from the restore; `ok` from the integrity check.
- **Verification check:** `sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db ".tables"` lists `patient_orders`.
- **Deviation handling:** any SQL error message means the restore is incomplete. Delete only `lis_recovered.db` (never the dump or the backup), then re-run the step once. If it fails again, escalate to the Laboratory Systems Lead.

### Step 6: Check the row count in `patient_orders`

- **Command:**

  ```bash
  sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db "SELECT COUNT(*) FROM patient_orders;"
  ```

- **Expected output:** `5`
- **Verification check:** the result equals `EXPECTED_ROW_COUNT` in `lab_config.env`.
- **Deviation handling:** a lower count means data loss. Record the missing number of rows, compare the restored rows against `expected_lis_records.txt`, and do not declare recovery. Escalate to the Laboratory Systems Lead.

### Step 7: Confirm the critical results for MRN-10043 and MRN-10045

- **Command:**

  ```bash
  sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db \
    "SELECT patient_mrn, test_code, result_value, critical_flag FROM patient_orders WHERE patient_mrn IN ('MRN-10043','MRN-10045');"
  ```

- **Expected output:**

  ```text
  MRN-10043|BMP|K+: 6.1 mEq/L|1
  MRN-10045|TROPONIN|0.08 ng/mL|1
  ```

- **Verification check:** both rows are present, the values are exact, and `critical_flag` is 1. The chemistry lead confirms both values against the Critical Value Call Log.
- **Deviation handling:** if a critical value is missing or different, recovery is **not** declared. The lab keeps phoning critical values and the discrepancy is escalated to the laboratory medical director (extension 7520).
- **Known limitation (2026-11-08 test):** the `ordered_at` column is not in the backup, so it shows the restore time. Do not use restored order times clinically. Take order times from paper requisitions until the dump job is fixed.

### Step 8: Inspect `app_config.env` for configuration artifacts

- **Command:**

  ```bash
  cat /tmp/meddefense-dr-test/config/app_config.env
  grep -nE 'DB_HOST|RECOVERY_DB_PATH|DB_ENGINE' /tmp/meddefense-dr-test/config/app_config.env
  head -c 3 /tmp/meddefense-dr-test/config/app_config.env | od -An -c
  ```

- **Expected output:** includes `DB_HOST=lis-db-prod.meddefense.internal` and `RECOVERY_DB_PATH=/tmp/meddefense-dr-test/recovery/lis_recovered.db`.
- **Verification check:** identify `DB_HOST=lis-db-prod.meddefense.internal` as a **configuration artifact**. It points at the production database server, which is the failed system in a real outage and unreachable from the recovery host. An application started with this file would either fail or, worse, write into production during a test.
- **Deviation handling:** if `od` shows `357 273 277`, the file starts with a BOM, and `source app_config.env` fails on line 1 (`APP_ENV=recovery-test: command not found`). Never `source` the original file; use the override from Step 9.

### Step 9: Apply the local recovery override and validate

- **Command:** build a recovery-only copy of the config with the BOM removed, `DB_HOST` disabled and a trailing newline guaranteed. Then run the health check against the local SQLite path.

  ```bash
  O=/tmp/meddefense-dr-test/validation/app_config.recovery_override.env
  sed -e '1s/^\xEF\xBB\xBF//' -e 's/^DB_HOST=.*/DB_HOST=/' \
    /tmp/meddefense-dr-test/config/app_config.env > "$O"
  printf '\n' >> "$O"          # the source file has no final newline
  (set -a; . "$O"; sqlite3 "$RECOVERY_DB_PATH" "SELECT COUNT(*) FROM patient_orders;")
  ```

- **Expected output:** `5`
- **Verification check:** `grep '^DB_HOST=' "$O"` shows an empty value, `grep '^RECOVERY_DB_PATH=' "$O"` shows the local path, and the original `app_config.env` is unchanged (`sha256sum` before and after).
- **Deviation handling:** in the 2026-11-08 test the override file was created without the `printf '\n'` line. The appended line merged with the last line (`BACKUP_DATE=2026-04-21DB_PATH_OVERRIDE=...`). Validation was not affected because it used `RECOVERY_DB_PATH`, but the command above now guarantees a trailing newline. If the health check returns anything other than `5`, go back to Step 6.

### Step 10: Notify the clinical team

- **Action:** the IT Incident Commander (extension 7200) sends the notification below to Laboratory accessioning (7500), the Nursing Supervisor (7100) and the Clinical Applications Lead (7300), and records it in `/tmp/meddefense-dr-test/validation/clinical_notification.txt`.
- **Notification content:**
  1. The LIS is restored from the backup of `<backup date and time>`.
  2. Results entered after that time are **not** in the restored system and must be re-entered from the paper logs.
  3. Critical values from the downtime period are taken from the Critical Value Call Log, not from the restored system.
  4. Order times in restored records show the restore time (known limitation).
  5. The laboratory may return to the LIS once the chemistry lead confirms the critical values. Downtime reconciliation then starts.
- **Expected output:** a written notification with sender, recipients and time.
- **Verification check:** the Nursing Supervisor and the lab accessioning desk acknowledge receipt by phone, and the time is recorded.
- **Deviation handling:** if there is no acknowledgment within 10 minutes, the Incident Commander calls the Nursing Supervisor directly.

### Recovery declaration (LIS)

Declare the LIS recovered only when all of these are true: Step 2 integrity is `OK`; Step 6 count equals the expected value; Step 7 critical values are confirmed by the chemistry lead; Step 9 runs with the local recovery path and no production host; Step 10 is acknowledged. Record the total time with `./recovery_timer.sh SUMMARY`.

## Runbook 2: Active Directory Recovery (DC01 lost, DC02 healthy)

**System:** Active Directory, domain `meddefense.local` (Tier 1). **RTO:** 1 hour. **RPO:** 4 hours.
**Executed by:** Systems Administrator. **Verified by:** Infrastructure Manager.
**Starting point:** DC01 is confirmed unrecoverable (hardware or OS loss), and DC02 responds normally to logons and DNS.
**Backup path:** `\\backup-srv\ad-backups\DC01\`
**Note:** documentation-only runbook. The lab container is Linux, so expected outputs come from `command_output_examples.md`.

### Step 1: Document current FSMO role holders

- **Command (on DC02, elevated prompt):**

  ```text
  netdom query fsmo
  ```

- **Expected output (normal state, from `command_output_examples.md`):**

  ```text
  Schema master               DC01.meddefense.local
  Domain naming master        DC01.meddefense.local
  PDC                         DC01.meddefense.local
  RID pool manager            DC01.meddefense.local
  Infrastructure master       DC01.meddefense.local
  The command completed successfully.
  ```

- **Verification check:** save the output to the incident record. All five roles are on the lost DC01, so DC02 can authenticate users but cannot issue new RIDs, act as PDC (time source, password changes, lockouts) or make schema changes.
- **Deviation handling:** if DC01 will be back within the RTO from a system state restore, the roles can stay on it. If not, seize the roles on DC02 before restoring (`ntdsutil` → `roles` → `connections` → `connect to server DC02` → `seize pdc`, `seize rid master`, `seize infrastructure master`, `seize naming master`, `seize schema master`). **A DC whose roles were seized must never return with the old roles:** in that case DC01 is rebuilt as a new DC (Step 3, option B), not restored.

### Step 2: Decide authoritative or non-authoritative restore

| Criterion | Non-authoritative restore (default) | Authoritative restore |
| --- | --- | --- |
| Situation | DC01 lost; directory data on DC02 is correct | Objects were deleted or corrupted, and the deletion has replicated to DC02 |
| Effect | Restored DC01 receives all newer changes from DC02 | Marked objects on restored DC01 overwrite the copies on DC02 |
| Use in this scenario | **Yes**: DC02 is healthy and holds the current directory | No, unless an accidental OU or user deletion is part of the incident |
| Risk | Low | Overwrites newer legitimate changes to the marked objects |

- **Decision rule:** use non-authoritative restore unless the IR or Infrastructure Manager confirms that deleted or corrupted objects must be recovered.
- **Hard stops:** never restore a backup older than the tombstone lifetime (180 days). Never restore DC01 from a VM snapshot by just reverting it; this causes USN rollback and silent replication failure. Only a system state restore or a rebuild is supported.

### Step 3: Restore DC01 system state

- **Option A, system state restore (DC01 hardware replaced, same OS reinstalled):**
  1. Boot the new DC01 into Directory Services Restore Mode (DSRM). Log on with the DSRM password from the privileged access vault.
  2. List the available backups:

     ```text
     wbadmin get versions -backuptarget:\\backup-srv\ad-backups\DC01
     ```

  3. Restore the most recent verified version within the RPO (example from `command_output_examples.md`):

     ```text
     wbadmin start systemstaterecovery -version:04/21/2026-01:00 -backuptarget:\\backup-srv\ad-backups\DC01 -quiet
     ```

  4. For an authoritative restore only: before rebooting, run `ntdsutil` → `activate instance ntds` → `authoritative restore` → `restore subtree "OU=...,DC=meddefense,DC=local"`.
  5. Reboot normally.

- **Option B, rebuild (roles seized, or no usable backup):** run metadata cleanup for DC01 on DC02 (`ntdsutil` → `metadata cleanup`), install a new server named DC01, and promote it as an additional DC (`Install-ADDSDomainController -DomainName meddefense.local`) so that it replicates from DC02.
- **Expected output:** `The operation to recover the system state completed successfully.` and a normal reboot.
- **Verification check:** the event log shows Directory Service event 1109 or 1004 (restore and invocation ID change) after the reboot.
- **Deviation handling:** if wbadmin reports the version is missing or corrupt, use the previous version and record the extra data loss. If no version is usable, switch to Option B.

### Step 4: Check replication health

- **Command:**

  ```text
  repadmin /showrepl DC01
  repadmin /replsummary
  ```

- **Expected output (from `command_output_examples.md`):**

  ```text
  Default-First-Site-Name\DC01
  ==== INBOUND NEIGHBORS ======================================
  DC=meddefense,DC=local
      Default-First-Site-Name\DC02 via RPC
          Last attempt @ 2026-04-21 09:42:13 was successful.
  ```

- **Verification check:** every naming context shows `was successful`; `repadmin /replsummary` shows 0 fails.
- **Deviation handling:** error 8456/8457 (replication disabled) or event 2095 (USN rollback) means DC01 is not usable. Isolate it and switch to Option B. DNS errors: check that DC01 points to DC02 as its primary DNS server.

### Step 5: Validate with dcdiag

- **Command sequence:**

  ```text
  dcdiag /s:DC01 /test:Connectivity
  dcdiag /s:DC01 /test:SysVolCheck
  dcdiag /s:DC01 /test:NetLogons
  dcdiag /s:DC01 /test:Replications
  dcdiag /s:DC01 /test:KnowsOfRoleHolders
  dcdiag /s:DC01 /test:DNS /DnsBasic
  ```

- **Expected output (from `command_output_examples.md`):**

  ```text
  Testing server: Default-First-Site-Name\DC01
  Starting test: Connectivity
  ......................... DC01 passed test Connectivity
  Starting test: SysVolCheck
  ......................... DC01 passed test SysVolCheck
  Starting test: NetLogons
  ......................... DC01 passed test NetLogons
  ```

- **Verification check:** every test reports `passed`; `netdom query fsmo` returns a consistent role holder from both DCs.
- **Deviation handling:** a SysVolCheck failure means SYSVOL is not shared. Check DFSR replication from DC02 before allowing logons against DC01. Any other failed test blocks the recovery declaration until it is fixed.

### Step 6: Recovery declaration criteria

Declare Active Directory recovered only when all of these are true:

1. `netdom query fsmo` shows all five roles on a healthy DC, and both DCs agree.
2. `repadmin /showrepl` shows successful inbound replication on DC01 and DC02, and `repadmin /replsummary` shows 0 fails.
3. All `dcdiag` tests in Step 5 pass.
4. A test user and one service account (for example the LIS service account) authenticate against DC01, and a clinical user can log in to Epic.
5. DNS resolves `meddefense.local` records from both DCs.
6. Total time and deviations are recorded, and the Infrastructure Manager signs off.

Until all six are true, DC02 remains the only trusted DC and the incident stays open.
