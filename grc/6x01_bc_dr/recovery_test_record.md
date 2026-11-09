# LIS Recovery Test Record

**Test date:** 2026-11-08 (18:43:56 to 18:45:20 CET, UTC+1)
**Test conductor:** Tales Lima, IT Security
**Declared RTO:** 30 minutes
**Test environment:** /tmp/meddefense-dr-test/
**Runbook followed:** `recovery_runbooks.md` Runbook 1 (written from `old_lis_recovery_runbook.md` v0.7 before the test)
**Backup restored:** `lis_backup.sql.gz` of 2026-04-21 (nightly 23:30 dump), SHA-256 `ac918cf7ffd5c5cad3fdec178207c684a00bcb02a19fdcf994b22314fdacf0e1`
**Host:** Ubuntu 24.04.5 LTS, Linux 6.8.0, sqlite3 3.45.3. The workspace was staged at the exact lab paths from the provided `meddefense-dr-test` archive. The test ran on the analyst workstation, not inside the `6x01-when-everything-fails` container, which was not available. Paths, files and commands are identical to the lab specification.
**Raw evidence:** every command and its full output was saved during the test in `evidence/step01_*.txt` to `evidence/step11_*.txt`, plus `evidence/timer_summary.txt`.

## Step Timing Log

`recovery_test_log.txt`, as written by `recovery_timer.sh` while the test ran:

```text
[STEP 01] Identify recovery target | Start: 18:43:56 | End: 18:43:56 | Duration: 0m 0s | PASS
[STEP 02] Verify backup integrity | Start: 18:44:01 | End: 18:44:10 | Duration: 0m 9s | PASS
[STEP 03] Create recovery workspace | Start: 18:44:15 | End: 18:44:15 | Duration: 0m 0s | PASS
[STEP 04] Decompress backup (old runbook path) | Start: 18:44:23 | End: 18:44:23 | Duration: 0m 0s | FAIL
[STEP 05] Decompress backup (corrected path) | Start: 18:44:30 | End: 18:44:30 | Duration: 0m 0s | PASS
[STEP 06] Restore SQL dump into SQLite | Start: 18:44:39 | End: 18:44:39 | Duration: 0m 0s | PASS
[STEP 07] Check row count in patient_orders | Start: 18:44:39 | End: 18:44:39 | Duration: 0m 0s | PASS
[STEP 08] Confirm critical results MRN-10043 and MRN-10045 | Start: 18:44:45 | End: 18:44:45 | Duration: 0m 0s | PASS
[STEP 09] Inspect app_config.env | Start: 18:44:54 | End: 18:44:54 | Duration: 0m 0s | PASS
[STEP 10] Apply local recovery override and validate | Start: 18:45:07 | End: 18:45:07 | Duration: 0m 0s | PASS
[STEP 11] Record clinical notification | Start: 18:45:20 | End: 18:45:20 | Duration: 0m 0s | PASS
```

`./recovery_timer.sh SUMMARY`:

```text
----------------------------------------------------------------
Test start: 18:43:56 | Test end: 18:45:20 | Steps: 11 | Failed steps: 1
Total elapsed: 1m 24s | Declared RTO: 30m 0s
RTO RESULT: PASS (1m 24s <= 30m 0s)
```

How to read the timings: most steps show `0m 0s` because the command itself finished in under a second on a 5-row database. The 1 minute 24 seconds of total time is mostly the gaps between steps, where the output was read, the next check was decided and deviations were diagnosed. Mapping to the runbook: timer steps 04 and 05 are runbook Step 4 (failed old path, then corrected path); timer steps 06 to 11 are runbook Steps 5 to 10.

## Conditions Encountered

### Condition 1: Path mismatch

**Discovered at:** 18:44:23 (timer step 04)
**Runbook specified:** /recovery/lis_dump.sql
**Actual path:** /tmp/meddefense-dr-test/recovery/lis_dump.sql
**Resolution:** the old runbook command failed:

```text
$ gzip -dc /tmp/meddefense-dr-test/backup/lis/2026-04-21/lis_backup.sql.gz > /recovery/lis_dump.sql
bash: line 1: /recovery/lis_dump.sql: No such file or directory
exit=1
$ ls -ld /recovery
ls: cannot access '/recovery': No such file or directory
```

The step was logged as FAIL. I did not create `/recovery` to force the old path; the staging path must stay inside the recovery workspace. The corrected command was run as timer step 05:

```text
$ gzip -dc /tmp/meddefense-dr-test/backup/lis/2026-04-21/lis_backup.sql.gz > /tmp/meddefense-dr-test/recovery/lis_dump.sql
exit=0
$ ls -l /tmp/meddefense-dr-test/recovery/lis_dump.sql
-rw-rw-r-- 1 tales tales 668 nov  8 18:44 /tmp/meddefense-dr-test/recovery/lis_dump.sql
```

Category: runbook error / environment assumption. Runbook Step 4 now documents the failure mode and the corrected command.
**Time added:** 0.1 minutes (7 seconds, from the failed attempt at 18:44:23 to the corrected start at 18:44:30)

### Condition 2: Configuration artifact

**Discovered at:** 18:44:54 (timer step 09)
**Expected:** Local recovery database path for validation
**Actual:** DB_HOST=lis-db-prod.meddefense.internal
**Resolution:** the production host is configured for an application that, in a real outage, runs against a restored copy. The name does not even resolve from the recovery host (`getent hosts lis-db-prod.meddefense.internal` returned nothing). The file also starts with a UTF-8 BOM, so it cannot be sourced: `source` fails on line 1 with `APP_ENV=recovery-test: command not found`. I left the original file untouched and built a recovery-only override, then validated against the local SQLite path:

```text
$ sed -e '1s/^\xEF\xBB\xBF//' -e 's/^DB_HOST=.*/DB_HOST=/' app_config.env > /tmp/meddefense-dr-test/validation/app_config.recovery_override.env
$ set -a; . app_config.recovery_override.env; sqlite3 "$RECOVERY_DB_PATH" "SELECT COUNT(*) FROM patient_orders;"
DB_HOST='' RECOVERY_DB_PATH=/tmp/meddefense-dr-test/recovery/lis_recovered.db
5
```

Category: configuration drift / documentation gap.
**Time added:** 0.2 minutes (13 seconds, from 18:44:54 to the end of the validated override at 18:45:07)

### Condition 3: Row count check

**Query:** SELECT COUNT(*) FROM patient_orders;
**Expected:** 5
**Actual:** 5
**Outcome:** PASS

```text
$ sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db "SELECT COUNT(*) FROM patient_orders;"
5
```

### Additional deviations found during the test

These were not on the condition cards. They are recorded because the purpose of the test is to find what the plan gets wrong.

| # | Discovered at | Deviation | Impact | Resolution during test | Permanent fix |
| --- | --- | --- | --- | --- | --- |
| D-1 | 18:44:01 (step 02) | `sha256sum -c backup_manifest.sha256` failed with `no properly formatted checksum lines found`. The manifest starts with a UTF-8 BOM (`od` shows `357 273 277`) and has no line terminator. | Integrity cannot be verified with the documented command. An operator under pressure might skip verification. | Removed the BOM in a working copy (`validation/backup_manifest.nobom.sha256`): `lis_backup.sql.gz: OK`, confirmed by an independent `sha256sum`. Original manifest left untouched. 9 seconds added. | Generate manifests with `sha256sum` on Linux (no BOM); added to `backup_architecture.md` and runbook Step 2 |
| D-2 | 18:44:45 (step 08) | The `ordered_at` column is not in the backup dump, so all restored rows show the restore time (`2026-11-08 17:44:39` UTC) instead of the original order time. | Order times in the restored LIS are wrong. A clinician could misjudge how old a pending order is. | Recorded; clinical notification states that restored order times must not be used. | Fix the dump job to export every column; noted in `backup_architecture.md` and runbook Step 7 |
| D-3 | 18:45:07 (step 10) | Operator error. `app_config.env` has no final newline, so the line I appended to the override merged with the last line (`BACKUP_DATE=2026-04-21DB_PATH_OVERRIDE=...`). | The override copy has a corrupted `BACKUP_DATE`. Validation was not affected because it used `RECOVERY_DB_PATH`, which was intact. | Found while reviewing the evidence after the step. | Runbook Step 9 now adds `printf '\n'` before any append |
| D-4 | 18:44:15 (step 03) | The backup is the 2026-04-21 23:30 nightly dump. | In a real outage everything entered after the last nightly dump is lost: up to 24 hours against a BIA RPO of 1 hour. | Not fixable during a test; stated in the clinical notification. | Hourly incremental backup (`backup_architecture.md`, RPO compliance table) |

## Recovery Validation

**Recovered database file:**

```text
$ ls -l /tmp/meddefense-dr-test/recovery/lis_recovered.db
-rw-r--r-- 1 tales tales 12288 nov  8 18:44 /tmp/meddefense-dr-test/recovery/lis_recovered.db
$ sha256sum lis_recovered.db
bb6ee809ba9fdd959f5d604ede231c38d966effa6d8e1aabe20dc4474d3ef511  /tmp/meddefense-dr-test/recovery/lis_recovered.db
$ sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db "PRAGMA integrity_check;"
ok
```

**Critical values accessible:**

```text
$ sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db "SELECT patient_mrn, test_code, result_value, critical_flag FROM patient_orders WHERE patient_mrn IN ('MRN-10043','MRN-10045');"
MRN-10043|BMP|K+: 6.1 mEq/L|1
MRN-10045|TROPONIN|0.08 ng/mL|1
```

Both critical values from `expected_lis_records.txt` are present with `critical_flag=1`: MRN-10043 K+ 6.1 mEq/L and MRN-10045 Troponin 0.08 ng/mL. Full table after restore:

```text
order_id  patient_mrn  test_code  ordered_at           status    result_value   critical_flag
--------  -----------  ---------  -------------------  --------  -------------  -------------
1         MRN-10042    CBC        2026-11-08 17:44:39  RESULTED  9.2/13.4/412   0
2         MRN-10043    BMP        2026-11-08 17:44:39  RESULTED  K+: 6.1 mEq/L  1
3         MRN-10044    PT-INR     2026-11-08 17:44:39  PENDING                  0
4         MRN-10045    TROPONIN   2026-11-08 17:44:39  RESULTED  0.08 ng/mL     1
5         MRN-10046    LACTATE    2026-11-08 17:44:39  PENDING                  0
```

## Test Result

**Actual recovery time:** 1 minute 24 seconds (18:43:56 to 18:45:20, from `recovery_timer.sh SUMMARY`)
**RTO met:** YES
**Test outcome:** CONDITIONAL PASS

Why CONDITIONAL PASS and not PASS:

1. **The documented procedure did not work as written.** The old runbook path failed (Condition 1), the documented integrity command failed (D-1), and the documented configuration pointed at production (Condition 2). Recovery succeeded only because the operator diagnosed each problem on the spot. The corrected runbook (v1.1) must be retested end to end without deviations before the result can be called PASS.
2. **The restored data is not fully correct.** Original order times are lost (D-2), and the nightly backup cannot meet the 1-hour RPO (D-4).
3. **The measured time is not a realistic RTO estimate.** It covers only the technical restore of a 5-row database by an operator who had already studied the runbook. It does not include outage detection, paging the on-call team, approvals, starting the LIS application, reconnecting the Epic interface and analyzers, or the chemistry lead's clinical check. A production-sized database also takes far longer to decompress and restore. The 30-minute RTO should be retested with a production-sized backup and the full call-out chain.

Follow-up actions (owners as in the BIA):

| Action | Owner role | Due |
| --- | --- | --- |
| Regenerate backup manifests without BOM and verify with `sha256sum -c` after every job | Laboratory Systems Lead | 2026-11-20 |
| Fix the dump job to export all columns, including `ordered_at` | Laboratory Systems Lead | 2026-11-20 |
| Remove the production `DB_HOST` from the recovery configuration; keep a separate recovery config under change control | Clinical Applications Lead | 2026-11-20 |
| Implement hourly incremental LIS backups (RPO 1 hour) | Infrastructure Manager | 2026-12-15 |
| Retest with runbook v1.1, a production-sized backup, the full call-out chain and the chemistry lead validation | IT Incident Commander | 2026-12-31 |
