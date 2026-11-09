# Old LIS Recovery Runbook

Version: 0.7  
Status: Outdated; retained for comparison

## Old Procedure

1. Identify latest backup in `/backup/lis/YYYY-MM-DD/`.
2. Verify the backup manifest.
3. Copy backup file to recovery server.
4. Decompress the SQL dump to `/recovery/lis_dump.sql`.
5. Restore the database.
6. Start application service.
7. Confirm user login.
8. Notify clinical users.

## Known Problems

- Assumes `/recovery/lis_dump.sql`, but current lab uses `/tmp/meddefense-dr-test/recovery/`.
- Does not specify exact integrity command.
- Says "restore the database" without exact command.
- Does not include row count validation.
- Does not validate critical values.
- Does not mention `DB_HOST=lis-db-prod.meddefense.internal`.
- Does not require deviations to be documented while the clock runs.

## Historical Note

The old environment used MariaDB. The rebuilt student lab uses SQLite-compatible SQL to avoid Docker-in-Docker.
