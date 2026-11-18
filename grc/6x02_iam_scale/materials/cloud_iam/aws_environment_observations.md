# MedDefense AWS Environment Observations

| # | Observation |
|---|---|
| 1 | AWS root account has no MFA configured; root access keys were created on 2022-03-15 and have never been deleted |
| 2 | Seven IAM users have AWS console access; four have MFA enrolled; three do not |
| 3 | Four IAM users have long-lived programmatic access keys; two were created more than 22 months ago and have no documented rotation schedule |
| 4 | IAM password policy: minimum 8 characters; no complexity requirement; no expiration; no MFA requirement for console login |
| 5 | CloudTrail is enabled in `us-east-1`; not enabled in `us-east-2`, the DR region where clinical backup S3 buckets reside |
| 6 | S3 bucket `meddefense-clinical-backup-2022`: Block Public Access is disabled; bucket policy contains `Principal: "*"` for `s3:GetObject`; bucket contains ePHI backup archives |
| 7 | Three IAM roles carry AWS-managed `AdministratorAccess`: `MedDefenseDevRole`, `MedDefenseLegacyRole`, `MedDefenseVendorAccess` |
| 8 | VPC Flow Logs are not enabled on any VPC |
| 9 | IAM role `MedDefenseEHRBackupRole` uses pre-correction `s3:*` on `Resource: *` |
| 10 | AWS Organizations is not configured; no Service Control Policies exist |
