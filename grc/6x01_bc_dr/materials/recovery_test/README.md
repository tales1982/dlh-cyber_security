# LIS Recovery Test Lab Notes

This lab uses SQLite-compatible SQL so the exercise can run fully inside one Docker lab container.

Important files:

```text
/tmp/meddefense-dr-test/backup/lis/2026-04-21/lis_backup.sql.gz
/tmp/meddefense-dr-test/backup/lis/2026-04-21/backup_manifest.sha256
/tmp/meddefense-dr-test/config/app_config.env
/tmp/meddefense-dr-test/recovery/
```

Expected recovered database:

```text
/tmp/meddefense-dr-test/recovery/lis_recovered.db
```

Expected row count: `5`

Do not run Docker commands inside the lab.
