# MedDefense Cloud Security Assessment

**Classification:** Confidential
**Prepared by:** Tales Lima, IT Security
**Date:** 2026-11-18
**Benchmark:** CIS Amazon Web Services Foundations Benchmark v3.0.0
**Sources:** `materials/cloud_iam/aws_environment_observations.md` (Helena Reyes, post-incident walk-through), `materials/cloud_iam/cis_aws_control_map.md`, corrected policies in `iam_policies/` and `iam_policy_analysis.md`

## Assessment Scope

- **Environment:** MedDefense AWS account `123456789012`; primary region `us-east-1`, DR region `us-east-2` (clinical backup S3 buckets).
- **Input:** the ten configuration states recorded by Helena Reyes during the manual walk-through. Each is assessed as observed; no live API calls were made for this assessment. Every finding must be confirmed with the verification command in the remediation before it is closed.
- **Method:** each observation is mapped to the CIS AWS Foundations Benchmark v3.0 recommendation that covers it, rated with the MedDefense severity model (`materials/iam_audit/severity_model.md` and the suggested severity in `cis_aws_control_map.md`), and given a status:
  - **Non-compliant:** the control is not met.
  - **Remediated (pending deployment):** a corrected configuration has been written but is not yet confirmed in the account.
- **Out of scope:** workloads inside EC2 and RDS, application security, Azure and on-premises systems. Directory accounts are covered in `iam_audit_report.md`.
- **Result:** 10 findings: **2 Critical, 4 High, 4 Medium**. Observations 1, 6 and 7 create direct ePHI exposure or unrestricted administrative access.

## Findings Table

| # | Observation | CIS v3.0 control | Severity | Status | Remediation (console or CLI) |
| --- | --- | --- | --- | --- | --- |
| CLD-01 | Root account has no MFA; root access keys created 2022-03-15 still exist | 1.4 Ensure no root user account access key exists; 1.5 Ensure MFA is enabled for the root user account; 1.6 Ensure hardware MFA for the root user account | **Critical** | Non-compliant | Sign in as root → Security credentials → Access keys → **Deactivate** then **Delete**. Same page → **Assign MFA device** (hardware key). Verify: `aws iam get-account-summary --query 'SummaryMap.[AccountMFAEnabled,AccountAccessKeysPresent]'` returns `[1, 0]` |
| CLD-02 | 7 IAM users have console access; 3 have no MFA | 1.10 Ensure MFA is enabled for all IAM users that have a console password | High | Non-compliant | `aws iam generate-credential-report` then `aws iam get-credential-report` and list `password_enabled=true` with `mfa_active=false`. Enroll MFA for each, or disable their console password with `aws iam delete-login-profile --user-name <user>`. Attach a deny-without-MFA policy until enrolled |
| CLD-03 | 4 users have long-lived access keys; 2 are older than 22 months, no rotation | 1.14 Ensure access keys are rotated every 90 days or less; 1.12 Ensure credentials unused for 45 days or greater are disabled | Medium | Non-compliant | `aws iam list-access-keys --user-name <user>` and `aws iam get-access-key-last-used --access-key-id <id>`. Create a new key, update the application, then `aws iam update-access-key --access-key-id <old> --status Inactive` and after 7 days `aws iam delete-access-key`. Prefer IAM roles or Identity Center over keys |
| CLD-04 | Password policy: 8 characters minimum, no complexity, no expiry, no MFA requirement | 1.8 Ensure IAM password policy requires minimum length of 14 or greater; 1.9 Ensure IAM password policy prevents password reuse | Medium | Non-compliant | `aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters --password-reuse-prevention 24 --max-password-age 365`. MFA for console is enforced by CLD-02, not by the password policy |
| CLD-05 | CloudTrail enabled in `us-east-1` only; not in `us-east-2` (DR region with clinical backups) | 3.1 Ensure CloudTrail is enabled in all regions; 3.2 Ensure CloudTrail log file validation is enabled; 3.5 Ensure CloudTrail logs are encrypted at rest using KMS CMKs | High | Non-compliant | `aws cloudtrail update-trail --name <trail> --is-multi-region-trail --enable-log-file-validation --kms-key-id <key-arn>` (or create a new multi-region trail), then `aws cloudtrail start-logging --name <trail>`. Add S3 data events for the backup buckets: `aws cloudtrail put-event-selectors`. Verify: `aws cloudtrail describe-trails --region us-east-2` shows `IsMultiRegionTrail: true` |
| CLD-06 | Bucket `meddefense-clinical-backup-2022`: Block Public Access disabled; bucket policy `Principal: "*"` for `s3:GetObject`; holds ePHI backup archives | 2.1.4 Ensure that S3 is configured with Block Public Access enabled (bucket and account level) | **Critical** | Non-compliant | `aws s3api put-public-access-block --bucket meddefense-clinical-backup-2022 --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`; `aws s3api delete-bucket-policy --bucket meddefense-clinical-backup-2022`; `aws s3control put-public-access-block --account-id 123456789012 --public-access-block-configuration <same four = true>`. Then breach risk assessment (see Critical Findings) |
| CLD-07 | `AdministratorAccess` attached to `MedDefenseDevRole`, `MedDefenseLegacyRole`, `MedDefenseVendorAccess` | 1.16 Ensure IAM policies that allow full `*:*` administrative privileges are not attached | High | Non-compliant | `aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess`. For each role: review last use with `aws iam get-role --role-name <role>` (`RoleLastUsed`), then `aws iam detach-role-policy --role-name <role> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess`. Delete `MedDefenseLegacyRole` if unused for 90 days; give Dev and Vendor scoped policies; vendor access time-bound and with `sts:ExternalId` |
| CLD-08 | VPC Flow Logs not enabled on any VPC | 3.7 Ensure VPC flow logging is enabled in all VPCs | Medium | Non-compliant | `aws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc-id> --traffic-type ALL --log-destination-type cloud-watch-logs --log-group-name /meddefense/vpc-flow --deliver-logs-permission-arn <role-arn>` for every VPC in both regions. Verify: `aws ec2 describe-flow-logs` |
| CLD-09 | `MedDefenseEHRBackupRole` had `s3:*` and `kms:*` on `Resource: *` | 1.16 Ensure IAM policies that allow full `*:*` administrative privileges are not attached (least privilege; `s3:*` and `kms:*` on `*` is the service-level form of the same violation) | High | Remediated (pending deployment) | Corrected policy written: `iam_policies/ehr_backup_policy.json`. Deploy: `aws iam put-role-policy --role-name MedDefenseEHRBackupRole --policy-name MedDefenseEHRBackupPolicy --policy-document file://iam_policies/ehr_backup_policy.json`, then detach the old policy and run one backup and one restore test |
| CLD-10 | AWS Organizations not configured; no Service Control Policies | 1.21 Ensure IAM users are managed centrally via identity federation or AWS Organizations for multi-account environments; 1.20 Ensure IAM Access Analyzer is enabled for all regions. SCPs themselves are guidance from AWS Well-Architected, not a scored CIS item | Medium | Non-compliant | Console → AWS Organizations → **Create organization** (all features). `aws organizations enable-policy-type --root-id <r-xxxx> --policy-type SERVICE_CONTROL_POLICY`. Attach SCPs that deny `cloudtrail:StopLogging`/`DeleteTrail`, deny `s3:PutBucketPublicAccessBlock` changes, deny root user actions, and restrict regions to `us-east-1` and `us-east-2`. Enable Access Analyzer: `aws accessanalyzer create-analyzer --analyzer-name meddefense --type ORGANIZATION` |

## Critical Findings

### CLD-06: Public ePHI backup bucket

**What the configuration means.** A bucket policy is a list of rules attached to the bucket. In this one, `"Principal": "*"` means "anyone": any AWS account and any anonymous user on the internet, with no login. The action is `s3:GetObject`, which is the permission to download an object. Together they say: anyone in the world who knows or guesses an object's address can download it. Block Public Access is the account and bucket switch that would override such a policy, and it is turned off. The bucket `meddefense-clinical-backup-2022` holds ePHI backup archives, so every patient record in those archives is downloadable by anyone. Attackers scan S3 for public buckets automatically; a bucket with a predictable name such as this one is found quickly.

**Logging gap.** The bucket is in the DR region `us-east-2`, where CloudTrail is not enabled (CLD-05), and S3 server access logging is not reported as enabled. MedDefense therefore may not be able to prove whether anyone downloaded the archives.

**HIPAA breach analysis.** Under the Breach Notification Rule, **45 CFR 164.402** defines a *breach* as the acquisition, access, use or disclosure of protected health information in a manner not permitted by the Privacy Rule which compromises the security or privacy of the PHI. Two terms in the same section decide the outcome here:

- **Unsecured protected health information:** PHI that is not rendered unusable, unreadable or indecipherable to unauthorized persons (for example by encryption that meets HHS guidance). If the archives are not encrypted with a key that the public cannot use, they are unsecured PHI. S3 server-side encryption does not help: S3 decrypts the object for any principal the policy allows, including `*`.
- **Presumption of breach:** an impermissible disclosure is presumed to be a breach unless MedDefense shows, through a documented risk assessment, a **low probability that the PHI has been compromised**, based on four factors: (1) the nature and extent of the PHI, (2) the unauthorized person who used it or to whom it was disclosed, (3) whether the PHI was actually acquired or viewed, and (4) the extent to which the risk has been mitigated.

Making ePHI publicly readable is a disclosure not permitted by the Privacy Rule. Without access logs MedDefense cannot show factor 3 (that no one acquired it), so it is unlikely to rebut the presumption. If it is a breach, notification is due to affected individuals without unreasonable delay and no later than 60 days after discovery (164.404), to HHS (164.408; immediately if 500 or more individuals) and to prominent media if more than 500 residents of a state are affected (164.406). The discovery date is the date Helena Reyes recorded the observation.

**Actions in order:**

1. Block public access on the bucket and the account, and delete the public bucket policy (commands in the table). This is a containment step; do it the same day.
2. Preserve evidence: copy the current bucket policy, ACLs and object list with dates before changing anything else; pull any S3 server access logs and CloudTrail data events that exist.
3. Open a HIPAA breach risk assessment with the Privacy Officer and legal counsel, using the four factors, and record the discovery date.
4. Decide notification within the 60-day limit.
5. Prevent recurrence: account-level Block Public Access, an SCP that denies turning it off (CLD-10), and AWS Config rule `s3-bucket-public-read-prohibited` with an alert.

### CLD-01: Root account without MFA and with access keys

The root user can do anything in the account, including actions IAM policies cannot restrict: close the account, change billing and support, and remove every other user's access. Its access keys, created on 2022-03-15 and never deleted, give that power to any program that holds them, with no MFA at all. If the keys are in a script, a laptop or a code repository, whoever finds them owns the account and every ePHI bucket in it. Delete the keys, enable a hardware MFA device, store the root credentials in a sealed process with two-person access, and alert on every root login (CloudTrail `userIdentity.type = Root`).

### CLD-07: Three roles with `AdministratorAccess` (unrestricted administrative access)

`MedDefenseDevRole`, `MedDefenseLegacyRole` and `MedDefenseVendorAccess` can each do anything in the account, including reading every ePHI bucket and turning off CloudTrail. The vendor role is the most exposed: its security depends on a third party's credentials and controls. The legacy role has the same profile as `svc_epic_int` in the directory audit (IAM-001): broad privilege, no clear owner, nobody watching. Each role must be reviewed for last use, detached from `AdministratorAccess` and given a scoped policy. The only role that keeps full admin should be `MedDefenseBreakGlassAdmin`, restricted by MFA and source IP (`iam_policies/break_glass_policy.json`).

## Remediation Priority Order

| Order | Finding | Action | Reason for order | Owner | Target |
| --- | --- | --- | --- | --- | --- |
| 1 | CLD-06 | Block public access and remove `Principal: "*"`; preserve evidence; start breach assessment | Active ePHI exposure to the internet; the 60-day notification clock is already running | Cloud Administrator, Privacy Officer | Same day |
| 2 | CLD-01 | Delete root access keys; enable hardware MFA on root | Full, unrestricted account takeover with one leaked key | Cloud Administrator | Same day |
| 3 | CLD-05 | Multi-region CloudTrail with log validation and S3 data events | Needed to see what happens next, including in the DR region | Cloud Administrator | 48 hours |
| 4 | CLD-07 | Detach `AdministratorAccess` from the three roles | Unrestricted admin through vendor and legacy paths | Cloud Administrator, IT Director (vendor) | 7 days |
| 5 | CLD-09 | Deploy corrected EHR backup policy and test | Fix is written; deployment closes backup deletion and cross-bucket access | Cloud Administrator | 7 days |
| 6 | CLD-02 | MFA for the three console users | Phishing path to the console | Cloud Administrator | 7 days |
| 7 | CLD-03 | Rotate or remove the four access keys, oldest first | Persistent credentials that never expire | Cloud Administrator, application owners | 30 days |
| 8 | CLD-04 | Strong password policy | Reduces guessing and reuse | Cloud Administrator | 30 days |
| 9 | CLD-08 | VPC Flow Logs on all VPCs | Detection and investigation | Cloud Administrator, SOC Lead | 30 days |
| 10 | CLD-10 | AWS Organizations, SCP guardrails, Access Analyzer | Prevents the same problems from coming back | IT Director, Cloud Administrator | 90 days |

## Estimated Effort

| Finding | Technical effort | Notes |
| --- | --- | --- |
| CLD-06 | 1 hour containment; 2 to 4 weeks breach assessment | The technical fix is minutes; the legal and notification work is the large part |
| CLD-01 | 1 hour | Needs the hardware MFA key and access to root email; check that no script uses the root keys before deletion |
| CLD-05 | 2 to 4 hours | Plus S3 cost for logs; data events on backup buckets add cost proportional to object access |
| CLD-07 | 2 to 3 days | Reviewing what each role really uses (Access Analyzer policy generation from CloudTrail) takes most of the time |
| CLD-09 | 4 hours | Includes one backup and one restore test |
| CLD-02 | 1 day | Coordinating three users |
| CLD-03 | 2 to 5 days | Each key needs its application owner to deploy the new key or move to a role |
| CLD-04 | 30 minutes | Users change passwords at next rotation |
| CLD-08 | 4 hours | Plus CloudWatch Logs storage cost |
| CLD-10 | 2 to 3 weeks | Organization setup, SCP design and testing in a non-production OU before applying to the production account |

Total: about 4 to 6 weeks of part-time work for one cloud administrator, with the two Critical containment steps done on day one. The breach risk assessment for CLD-06 runs in parallel and is led by the Privacy Officer.
