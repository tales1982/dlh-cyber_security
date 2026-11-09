# 6x01: When Everything Fails

Disaster recovery program package for MedDefense, built after the HHS OCR audit preparation found that the disaster recovery plan had never been tested. It covers the Business Impact Analysis, backup architecture, recovery runbooks, clinical downtime procedures and a real, timed recovery test of the Laboratory Information System (LIS). It supports HIPAA 45 CFR 164.308(a)(7).

- **Organization:** MedDefense (fictional training scenario, DLH Academy)
- **Author:** Tales Lima
- **Date:** 2026-11-08

## Deliverables

| Task | File | Content |
| --- | --- | --- |
| 1 | [business_impact_analysis.md](business_impact_analysis.md) | Ten systems scored on patient safety (1 h / 4 h / 24 h), regulation, revenue and dependencies; MTD, RTO, RPO and tier for each |
| 2 | [backup_architecture.md](backup_architecture.md) | RPO compliance verification, per-system backup specifications for Tier 1 and 2, full data center loss restore sequence, dependency constraints |
| 3 | [recovery_runbooks.md](recovery_runbooks.md) | Command-level runbooks: LIS recovery (tested) and Active Directory DC01 loss with DC02 healthy |
| 4 | [clinical_downtime_procedures.md](clinical_downtime_procedures.md) | One-page quick references for Epic EHR and LIS downtime, written for clinical staff |
| 5 | [recovery_timer.sh](recovery_timer.sh) | Step timer: logs each step as it completes and reports total time against the 30-minute RTO |
| 5 | [recovery_test_log.txt](recovery_test_log.txt) | Step log written by the timer during the real test |
| 5 | [recovery_test_record.md](recovery_test_record.md) | Test record: timing, the three required conditions, four extra deviations, validation output and result |

Supporting files:

- [evidence/](evidence/): raw command output captured during the recovery test, one file per step.
- [materials/](materials/): the provided lab materials, unchanged.

## Key Results

- **BIA:** six Tier 1 systems (Network Core, Active Directory, Epic EHR, LIS, Pharmacy, Medical Device Integration Gateway). Every RTO is below its MTD.
- **Backup gaps closed on paper:** the LIS (nightly backup against a 1-hour RPO), Active Directory (8-hour snapshot against a 4-hour RPO) and the device gateway (no off-site copy) all get new schedules and destinations.
- **Recovery test:** 1 minute 24 seconds against a 30-minute RTO, outcome **CONDITIONAL PASS**. The three planned conditions occurred, and the test also found four extra deviations: BOM in the checksum manifest, order times lost in the backup, an operator error in the override file, and a 24-hour data loss window.

## Running the Timer

```bash
chmod +x recovery_timer.sh
./recovery_timer.sh "Verify backup integrity" START
./recovery_timer.sh "Verify backup integrity" PASS
./recovery_timer.sh SUMMARY
./recovery_timer.sh RESET    # archives the previous log and state, never deletes them
```

State is kept in `/tmp/rtest_state` and steps are appended to `recovery_test_log.txt` as they finish. `SUMMARY` exits 0 if the total time is within the RTO and 1 if not.

## Test Environment Note

The recovery test was executed on the analyst workstation (Ubuntu 24.04) using the exact lab paths under `/tmp/meddefense-dr-test/`, staged from the provided `meddefense-dr-test` archive, because the lab container was not available. Commands and paths match the lab specification. The recovered database is `/tmp/meddefense-dr-test/recovery/lis_recovered.db` on that host.
