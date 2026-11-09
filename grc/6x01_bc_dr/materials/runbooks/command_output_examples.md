# Command Output Examples

## netdom query fsmo

```text
Schema master               DC01.meddefense.local
Domain naming master        DC01.meddefense.local
PDC                         DC01.meddefense.local
RID pool manager            DC01.meddefense.local
Infrastructure master       DC01.meddefense.local
The command completed successfully.
```

## repadmin /showrepl healthy example

```text
Default-First-Site-Name\DC01
==== INBOUND NEIGHBORS ======================================
DC=meddefense,DC=local
    Default-First-Site-Name\DC02 via RPC
        Last attempt @ 2026-04-21 09:42:13 was successful.
```

## dcdiag healthy summary

```text
Testing server: Default-First-Site-Name\DC01
Starting test: Connectivity
......................... DC01 passed test Connectivity
Starting test: SysVolCheck
......................... DC01 passed test SysVolCheck
Starting test: NetLogons
......................... DC01 passed test NetLogons
```

## wbadmin command pattern

```text
wbadmin start systemstaterecovery -version:04/21/2026-01:00 -backuptarget:\\backup-srv\ad-backups\DC01 -quiet
```

## SQLite LIS validation

```bash
sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db "SELECT COUNT(*) FROM patient_orders;"
```

Expected:

```text
5
```

```text
MRN-10043|BMP|K+: 6.1 mEq/L|1
MRN-10045|TROPONIN|0.08 ng/mL|1
```
