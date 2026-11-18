# Case ID Generation Notes

Case IDs use `CASE-YYYYMMDD-NNN`, for example `CASE-20260428-001`.

The sequence is daily and zero-padded. It is derived from cases already created for that date in `cases.db`.

A simple query:

```sql
SELECT COUNT(*) FROM cases WHERE case_id LIKE 'CASE-20260428-%';
```

Production systems would need concurrency-safe IDs; this lab does not test concurrent writers.
