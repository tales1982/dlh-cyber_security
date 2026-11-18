# MedDefense IAM Policy Analysis

**Classification:** Confidential
**Prepared by:** Tales Lima, IT Security
**Date:** 2026-11-18
**Account:** `123456789012`, region `us-east-1`
**Sources:** `materials/cloud_iam/original_siem_reader_policy.json`, `original_ehr_backup_policy.json`, `original_break_glass_policy.json`
**Corrected policies:** `iam_policies/siem_reader_policy.json`, `iam_policies/ehr_backup_policy.json`, `iam_policies/break_glass_policy.json`

All three original policies follow the same pattern: a wildcard action (`s3:*`, `kms:*`, `logs:*`, `*`) on a wildcard resource (`*`) with no conditions. Each role can therefore do far more than its job, on every resource in the account. If an attacker steals the role's credentials (from a Lambda environment, a backup server or a phished administrator), the damage is limited only by what the policy allows, which today is almost everything. The corrections below keep each role's real function and remove the rest.

## Policy 1: MedDefenseSIEMLogReader Violations

**Function:** a Lambda function (`siem-log-reader`) reads log files from the `meddefense-siemlog-prod` bucket and writes its own execution logs to CloudWatch Logs.

| # | Original statement | Violation | Attack surface created | Correction | How it closes the gap |
| --- | --- | --- | --- | --- | --- |
| 1.1 | `S3Access`: `s3:*` | A reader needs two actions; `s3:*` grants over 100, including `PutObject`, `DeleteObject`, `PutBucketPolicy`, `PutBucketPublicAccessBlock` | A stolen Lambda credential can delete or overwrite SIEM logs (destroying incident evidence), or make any bucket public | Allow only `s3:ListBucket` and `s3:GetObject` | The role can read logs and nothing else; it cannot change, delete or expose them |
| 1.2 | `S3Access`: `Resource: *` | Applies to every bucket in the account, including `meddefense-ehr-backup-prod` and `meddefense-clinical-backup-2022` | The log reader can read and download ePHI backup archives | `ListBucket` on `arn:aws:s3:::meddefense-siemlog-prod`; `GetObject` on `arn:aws:s3:::meddefense-siemlog-prod/*` | Read access exists for the SIEM bucket only; clinical buckets are out of reach |
| 1.3 | `CloudWatchAccess`: `logs:*` | Grants read, delete and retention changes on every log group | An attacker can delete or shorten retention of CloudTrail and application log groups to hide activity, or read logs that contain PHI | Allow `logs:CreateLogGroup` on `log-group:/aws/lambda/siem-log-reader` and `logs:CreateLogStream`, `logs:PutLogEvents` on its log streams | The function can write only its own logs; it cannot read or delete any log group |
| 1.4 | `CloudWatchAccess`: `cloudwatch:*` | The function has no need for metrics or alarms | An attacker can delete or disable security alarms (`DeleteAlarms`, `DisableAlarmActions`) so detections never fire | Removed | No alarm or dashboard can be changed by this role |
| 1.5 | `CloudWatchAccess`: `Resource: *` | Same as 1.2 for logs | Covers every log group in every region | Scoped to the one log group ARN in `us-east-1` | Blast radius is one log group |

## Policy 2: MedDefenseEHRBackupRole Violations

**Function:** nightly automation writes encrypted EHR backup archives to `meddefense-ehr-backup-prod`, using KMS key `arn:aws:kms:us-east-1:123456789012:key/mrk-abc123def456`, and reads them back to verify integrity.

| # | Original statement | Violation | Attack surface created | Correction | How it closes the gap |
| --- | --- | --- | --- | --- | --- |
| 2.1 | `S3FullAccess`: `s3:*` | Includes delete, policy, ACL, public access and versioning actions | Ransomware running with this role can delete every backup, suspend versioning and remove the last recovery copy; it can also make a bucket public | Allow only `ListBucket`, `GetBucketLocation`, `ListBucketMultipartUploads`, `PutObject`, `GetObject`, `AbortMultipartUpload`, `ListMultipartUploadParts` | The role can write and verify backups, which is all the job does |
| 2.2 | `S3FullAccess`: `Resource: *` | Applies to every bucket | The backup role can read the SIEM logs and the 2022 clinical backup bucket, and write to any bucket | Scoped to `arn:aws:s3:::meddefense-ehr-backup-prod` and `/*` | Other buckets are out of reach |
| 2.3 | `KMSFullAccess`: `kms:*` | Includes `ScheduleKeyDeletion`, `DisableKey`, `PutKeyPolicy`, `CreateGrant` | An attacker can schedule deletion of the key (making every encrypted backup unreadable, a ransomware outcome without touching the data) or grant the key to an outside account | Allow only `kms:GenerateDataKey` and `kms:Decrypt` | These are the only actions S3 needs for SSE-KMS upload and download; key management is removed |
| 2.4 | `KMSFullAccess`: `Resource: *` | Every key in the account | The role can decrypt data protected by any other key | Scoped to `key/mrk-abc123def456` | Only the EHR backup key is usable |
| 2.5 | No condition on KMS use | The key can be called directly | A stolen credential can call `Decrypt` outside S3 on any ciphertext under this key | `kms:ViaService = s3.us-east-1.amazonaws.com` | The key works only through S3 in the home region |
| 2.6 | No explicit deny | Nothing stops a later broad policy from re-adding destructive actions | Policy drift silently restores delete rights | Explicit `Deny` on `DeleteObject`, `DeleteObjectVersion`, `DeleteBucket`, bucket policy, ACL, public access block, versioning and lifecycle changes | Explicit deny wins over any allow attached later |
| 2.7 | No encryption or transport requirement | Unencrypted or non-TLS uploads were possible | ePHI backups could be stored unencrypted or sent in clear | Deny `PutObject` unless `s3:x-amz-server-side-encryption = aws:kms`; deny all S3 actions when `aws:SecureTransport = false` | Every backup is KMS-encrypted at rest and TLS-protected in transit (HIPAA 164.312(a)(2)(iv) and (e)(1)) |

## Policy 3: MedDefenseBreakGlassAdmin Violations

**Function:** emergency administrator access when normal administration is unavailable (for example during an incident). Full admin capability must be kept.

| # | Original statement | Violation | Attack surface created | Correction | How it closes the gap |
| --- | --- | --- | --- | --- | --- |
| 3.1 | `Action: *`, `Resource: *` with no condition | Full account control from any credential that can assume the role | One phished password is a full account takeover from anywhere in the world | Keep `Action: *`, `Resource: *` but only when `aws:MultiFactorAuthPresent = true`, `aws:MultiFactorAuthAge <= 3600` and `aws:SourceIp` in `198.51.100.0/24` | Emergency capability is unchanged, but it needs a recent MFA and the SOC network |
| 3.2 | No MFA requirement | Password or access key alone is enough | Credential theft (phishing, NTLM-style reuse, leaked keys) gives admin directly | Explicit `Deny *` with `BoolIfExists aws:MultiFactorAuthPresent = false` | Access keys without MFA and sessions without MFA are blocked even if another policy allows them |
| 3.3 | No network restriction | Usable from any IP | Attacker infrastructure can use stolen credentials | Explicit `Deny *` with `NotIpAddress 198.51.100.0/24`, `aws:ViaAWSService = false` | Calls from outside the approved range fail; AWS services acting on the admin's behalf still work |
| 3.4 | No protection of audit trail | Admin can stop CloudTrail, delete log groups, stop AWS Config and GuardDuty | A misused break-glass session can erase evidence of what it did | Explicit deny on `cloudtrail:StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors`, `logs:DeleteLogGroup`, `logs:DeleteLogStream`, Config and GuardDuty disable actions | Every break-glass action stays logged |
| 3.5 | No protection against persistence | Admin can create IAM users, access keys and console passwords | An attacker turns a short emergency session into permanent access | Explicit deny on `iam:CreateUser`, `CreateAccessKey`, `CreateLoginProfile`, `UpdateLoginProfile` | Break-glass access ends when the session ends |
| 3.6 | No protection of the role itself | Admin can edit its own policy or trust policy | The conditions above can be removed by the session they restrict | Explicit deny on attach, detach, put, delete, trust and version changes against the `MedDefenseBreakGlassAdmin` role and policy ARNs | The MFA and IP controls cannot be removed from inside a break-glass session |

## Least Privilege Summary

| Policy | Before | After | Main risk removed |
| --- | --- | --- | --- |
| MedDefenseSIEMLogReader | `s3:*`, `logs:*`, `cloudwatch:*` on `*` | 2 S3 read actions on 1 bucket; 3 log write actions on 1 log group | Evidence deletion, alarm tampering, read of ePHI backups |
| MedDefenseEHRBackupRole | `s3:*`, `kms:*` on `*` | 7 S3 actions on 1 bucket; 2 KMS actions on 1 key via S3; 3 explicit deny statements | Backup deletion, key destruction, public exposure, unencrypted ePHI |
| MedDefenseBreakGlassAdmin | `*` on `*`, no conditions | `*` on `*` with MFA (1 hour) and source IP `198.51.100.0/24`; 5 explicit deny statements | Admin takeover from a single stolen credential; erasing the audit trail; persistence |

Principles applied: name the exact actions the job needs; name the exact resource ARNs; add conditions (MFA, source IP, `kms:ViaService`, TLS, encryption) where an allow alone is too broad; add explicit denies for the actions that would cause the most harm, because an explicit deny overrides any allow added later.

## Residual Risk and Operational Notes

- **Test before production.** Each policy was written from the role's stated function. Before attaching, run the job (Lambda, nightly backup, break-glass drill) in a test window and check CloudTrail for `AccessDenied`. Use IAM Access Analyzer policy validation and "Generate policy from CloudTrail activity" to confirm no needed action is missing.
- **SIEM reader region and account.** The log group ARN assumes `us-east-1` and account `123456789012`. If the Lambda runs in another region, the ARN must change. If the SIEM bucket uses SSE-KMS, add `kms:Decrypt` on that bucket's key only.
- **Backup uploads must send the encryption header.** `DenyUnencryptedUploads` denies a `PutObject` that does not send `x-amz-server-side-encryption: aws:kms`, even if the bucket has default encryption. The backup job must set it (`aws s3 cp --sse aws:kms --sse-kms-key-id <key ARN>`).
- **Backup retention and deletion.** The backup role can no longer delete old archives. Expiry must be handled by a lifecycle rule managed by a separate administrator role. Enable S3 Versioning and Object Lock on `meddefense-ehr-backup-prod` so even an administrator cannot delete backups inside the retention period.
- **Break-glass source IP.** The allowed range `198.51.100.0/24` must be the SOC or a jump host network. If the emergency happens when that network is down (for example during the incident that needs break-glass), access fails. Keep a documented, tested fallback (a second approved range or the root account in a sealed envelope with hardware MFA) and test it twice a year.
- **Break-glass is still admin.** Inside the allowed conditions the role can read every ePHI bucket. Alert on every `AssumeRole` of `MedDefenseBreakGlassAdmin` (CloudTrail to SIEM, page the SOC lead) and review every session afterwards.
- **IAM policies do not fix bucket policies.** Observation 6 (`meddefense-clinical-backup-2022` public through `Principal: "*"`) is a resource policy problem and is handled in `cloud_security_assessment.md`. These corrected identity policies do not close it.
- **Guardrails.** Without AWS Organizations and Service Control Policies, a future administrator can re-attach `AdministratorAccess` or a wildcard policy. The explicit denies reduce this risk only for the roles that carry these policies.
