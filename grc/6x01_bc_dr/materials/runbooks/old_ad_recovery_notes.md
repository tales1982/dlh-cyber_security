# Old Active Directory Recovery Notes

Version: 0.5  
Status: Incomplete notes, not executable

## Environment

- Domain: meddefense.local
- Primary DC: DC01
- Secondary DC: DC02
- DC01 normally holds FSMO roles
- Backup path: `\\backup-srv\ad-backups\DC01\`

## Original Notes

- Check DC02 is healthy.
- Restore DC01 from backup.
- Check replication.
- Confirm users can log in.

## Problems

- No `netdom query fsmo` pre-check.
- No authoritative vs non-authoritative decision.
- No USN rollback warning.
- No exact `wbadmin` command.
- No `repadmin /showrepl` expected output.
- No `dcdiag` validation sequence.
