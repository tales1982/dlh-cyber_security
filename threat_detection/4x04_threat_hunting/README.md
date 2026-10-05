# 4x04 — Threat Hunting: HEALTHBANE Stage 4 (LOLBin Lateral Movement)

Hypothesis-driven threat hunt for HEALTHBANE Stage 4 — living-off-the-land
lateral movement (PsExec, WMI, PowerShell Remoting, LSASS credential
access, service account abuse) — across 14 days of MedDefense SIEM data,
scoped from the HC3-2026-HEALTHBANE-004 advisory and the post-4x03 ATT&CK
coverage gap.

## Deliverables (this batch)

| # | File | Summary |
|---|---|---|
| 0 | [0-hunt_brief.sh](0-hunt_brief.sh) | Extracts the Stage 4 TTP summary from the advisory and the live NOT-COVERED status of its 5 corresponding ATT&CK techniques from `reference/4x03_attack_mapping.json`; produces the scoped hunt brief and P1-P5 priority ranking |
| 2 | [2-baseline_profile.sh](2-baseline_profile.sh) | Profiles all 93 events in `baseline/robert_kim_activity.json`: 100% from WS-ADMIN-01, 100% within 08:00-18:00 CDT, 100% the named `robert.kim` account, 0 service-account use — the false-positive filter for every later hunt |
| 3 | [3-data_recon.sh](3-data_recon.sh) | Profiles the full 9,800-event, 14-day SIEM export (6,544 alerts + 3,256 raw Sysmon events, deduplication-verified: every raw-Sysmon event ID is a subset of the alerts export); confirms all 5 hunt hypotheses (H1-H5) have testable data present |
| 4 | [4-hunt_psexec.sh](4-hunt_psexec.sh) | Executes hypothesis H1: of 50 PsExec-matching events, 44 match Robert Kim's baseline exactly and **6 are anomalous** — PsExec from WS-RECV-03 (a Records-department workstation, not the admin workstation) using the `svc_healthsync` service account interactively, off-hours, against both production databases and the domain controller. **Finding: POSITIVE — HIGH CONFIDENCE — ESCALATE.** |

## Scope note

This batch covers Tasks 0, 2, 3 and 4 of the project's task list; Task 1 and
Tasks 5 onward (additional hunt hypotheses for LSASS, WMI, PSRemoting and
service-account abuse; temporal analysis; correlated timeline; updated
ATT&CK layer; detection-gap analysis; hunt-derived detection rules; final
report) were not part of this batch.

## Materials

`reference/`, `baseline/` and `siem_export/` are the unmodified lab
materials, copied here from `materials/759fbf7bf2971b5fb8aef293dc6375b3af12eff4/4x04/`
per the project's "do not modify provided files in place" requirement.

Both SIEM export files are JSON Lines (one JSON object per line), confirmed
by direct inspection, not assumed. Many (but not all) records carry a
`hunt_meta` field describing ground-truth category/authorization — this was
used to independently verify computed findings against the dataset's own
labels, not as a shortcut in place of the actual baseline-comparison logic
(source host / time of day / day of week / user account), which is what
every script here actually computes.

## Requirements checklist

- All Bash scripts start with `#!/bin/bash` and pass `shellcheck` — verified
  for all four scripts in this batch.
- All scripts read only from `reference/`, `baseline/` and `siem_export/`
  and produce deterministic output (no live SIEM, Wazuh, EDR or Windows
  host dependency).
- All files end with a trailing newline.
- Two real bugs were found and fixed during development, not shipped
  silently: a `sort | head` SIGPIPE-under-`pipefail` failure in Task 3
  (fixed via bash parameter-expansion first/last-line extraction instead of
  piping a large sorted stream into `head`/`tail`), and a `jq @tsv` filter
  in Task 4 that escapes backslashes — which corrupted every Windows file
  path and command line when read back — fixed by switching to
  `join("\t")`, which does not escape field contents.
