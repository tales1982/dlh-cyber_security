# CloudVault Medical Contract Summary

**Vendor:** CloudVault Medical  
**Service type:** Clinical backup archive and disaster recovery storage  
**Proposed contract term:** 3 years  
**Business owner:** Infrastructure Manager  
**Data owner:** Clinical Applications Manager  
**Security reviewer:** Helena Reyes

## Data Handled

CloudVault would store encrypted backup archives containing:

- Epic EHR database exports
- Laboratory Information System backups
- PACS/RIS metadata exports
- pharmacy dispensing system backups
- operational recovery logs that may contain patient identifiers

This means CloudVault is a Tier A vendor under the policy if ePHI access or storage is possible.

## Access Model

CloudVault will receive backup archives through an encrypted transfer pipeline. CloudVault support staff may access the backup management console for support purposes. MedDefense administrators retain encryption key ownership in the proposed design, but CloudVault metadata may include patient identifiers.

## Contract Issues Requiring Security Review

1. BAA is not executed.
2. DR site location is not disclosed.
3. Vendor incident notification is 72 hours, while MedDefense target is 24 hours.
4. Data deletion period is 90 days, while MedDefense target is 30 days.
5. Penetration test is 22 months old.
6. Subprocessor jurisdiction review is incomplete.

## Initial Recommendation

Do not allow ePHI transfer until BAA execution and security conditions are resolved.
