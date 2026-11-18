# CIS AWS Foundations Benchmark v3.0 Control Map

| Observation | CIS control area | Suggested severity | Notes |
|---|---|---|---|
| 1 | Root account MFA and access key restrictions | Critical | Root without MFA and root keys creates full takeover risk |
| 2 | IAM user MFA | High | Console users without MFA are phishing risk |
| 3 | Access key rotation | Medium | Long-lived keys increase persistence |
| 4 | IAM password policy | Medium | Weak password policy increases reuse/brute force risk |
| 5 | CloudTrail in all regions | High | DR region contains clinical backups |
| 6 | S3 public access restrictions | Critical | Public ePHI backup object access can trigger breach analysis |
| 7 | Least privilege/admin policy use | High | Broad admin roles create blast radius |
| 8 | VPC Flow Logs | Medium | Missing network telemetry limits investigation |
| 9 | Least privilege for backup role | High | `s3:*` can expose or destroy unrelated buckets |
| 10 | AWS Organizations and SCPs | Medium | No guardrails against account-level drift |
