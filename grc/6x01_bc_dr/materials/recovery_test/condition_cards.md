# Recovery Test Condition Cards

## Condition 1: Path Mismatch

Old runbook path: `/recovery/lis_dump.sql`  
Actual lab path: `/tmp/meddefense-dr-test/recovery/lis_dump.sql`

Expected category: Runbook Error or Environment Assumption.

## Condition 2: Configuration Artifact

Config file: `/tmp/meddefense-dr-test/config/app_config.env`  
Problem line: `DB_HOST=lis-db-prod.meddefense.internal`

Expected category: Configuration Drift or Documentation Gap.

## Condition 3: Row Count Check

Query: `SELECT COUNT(*) FROM patient_orders;`  
Expected result: `5`

Expected category: Recovery Validation.
