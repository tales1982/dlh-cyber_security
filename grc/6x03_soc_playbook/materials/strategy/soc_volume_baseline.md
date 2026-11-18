# SOC Volume Baseline

MedDefense processes 120 to 180 SIEM alerts per day. For planning, use the midpoint: `150 alerts/day`.

Average analyst effort: `8 minutes/alert`.

Daily manual effort:

```text
150 alerts/day * 8 minutes = 1,200 minutes/day = 20 analyst-hours/day
```

March review found 67 percent of triage time was enrichment activity:

```text
20 analyst-hours/day * 67% = 13.4 hours/day spent on lookup/enrichment
```

During the Cobalt Strike incident, one IP enrichment took approximately `45 minutes`.

Automate lookup-heavy tasks first: IOC reputation lookup, classification, deduplication, case creation, audit logging, and routing recommendations. Do not immediately automate endpoint isolation, mailbox quarantine, user disablement, or firewall blocks.
