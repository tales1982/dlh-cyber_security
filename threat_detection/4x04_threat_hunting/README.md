# 4x04 — Threat Hunting: HEALTHBANE Stage 4 (LOLBin Lateral Movement)

Hypothesis-driven threat hunt for HEALTHBANE Stage 4 — living-off-the-land
lateral movement (PsExec, WMI, PowerShell Remoting, LSASS credential
access, service account abuse) — across 14 days of MedDefense SIEM data,
scoped from the HC3-2026-HEALTHBANE-004 advisory and the post-4x03 ATT&CK
coverage gap.

**Bottom line: the hunt found direct, multi-source evidence that Stage 4
happened.** See [14-hunting_report.md](14-hunting_report.md) for the full
synthesis.

## Deliverables

| # | File | Summary |
|---|---|---|
| 0 | [0-hunt_brief.sh](0-hunt_brief.sh) | Extracts the Stage 4 TTP summary from the advisory and the live NOT-COVERED status of its 5 corresponding ATT&CK techniques from `reference/4x03_attack_mapping.json`; produces the scoped hunt brief and P1-P5 priority ranking |
| 2 | [2-baseline_profile.sh](2-baseline_profile.sh) | Profiles all 93 events in `baseline/robert_kim_activity.json`: 100% from WS-ADMIN-01, 100% within 08:00-18:00 CDT, 100% the named `robert.kim` account, 0 service-account use — the false-positive filter for every later hunt |
| 3 | [3-data_recon.sh](3-data_recon.sh) | Profiles the full 9,800-event, 14-day SIEM export; confirms all 5 hunt hypotheses (H1-H5) have testable data present |
| 4 | [4-hunt_psexec.sh](4-hunt_psexec.sh) | H1: 6 of 50 PsExec events anomalous — WS-RECV-03, `svc_healthsync`, off-hours, against 3 production servers. **POSITIVE — HIGH CONFIDENCE.** |
| 5 | [5-hunt_wmi.sh](5-hunt_wmi.sh) | H3: 5 of 36 WMI events anomalous — WmiPrvSE.exe spawned a shell on every target within ~30 min of each PsExec session. **POSITIVE — HIGH CONFIDENCE.** |
| 6 | [6-hunt_credentials.sh](6-hunt_credentials.sh) | H2: 2 of 12 LSASS-access events anomalous — `debug_tool.exe` (matches HC3's IOC) dumped LSASS twice, ~1 week apart, each followed within 24h by `svc_healthsync` authentication. **POSITIVE — HIGH CONFIDENCE.** |
| 7 | [7-hunt_psremoting.sh](7-hunt_psremoting.sh) | H4: 4 of 22 PSRemoting events anomalous — interactive sessions staged the 4x03-confirmed exfiltrator (`sync_healthdata.ps1`) onto 2 production databases. **POSITIVE — HIGH CONFIDENCE.** |
| 8 | [8-temporal_analysis.sh](8-temporal_analysis.sh) | Aggregates Tasks 4-7's anomalous events: 100% fall within 01:00-04:59 CDT, across 5 nights with dormant-period clustering matching HC3's described operational pattern exactly |
| 9 | [9-hunt_svcaccount.sh](9-hunt_svcaccount.sh) | H5: 6 of 846 `svc_healthsync` auth events unauthorized (workstation-sourced, NTLM); **0 of 1,442** events across the other 5 service accounts show any deviation. **POSITIVE — CRITICAL CONFIDENCE.** |
| 10 | [10-evidence_correlation.sh](10-evidence_correlation.sh) | Merges Tasks 4-9 into one phase-tagged timeline; pivot host WS-RECV-03, stolen account `svc_healthsync`, targets SRV-HEALTH-DB/SRV-INS-DB/SRV-DC-01, 7d22h observed dwell time, HIGH confidence |
| 11 | [11-attack_update.sh](11-attack_update.sh) / [attack_layer_post_hunt.json](attack_layer_post_hunt.json) | Upgrades exactly the 5 techniques this hunt directly confirmed (T1021.002, T1047, T1021.006, T1003.001, T1078.002) from NOT COVERED to OBSERVED; coverage 48%→65% observed (65%→82% incl. inferred) — recomputed from each file's own technique array after finding the source file's stored summary didn't match it |
| 12 | [12-gap_analysis.sh](12-gap_analysis.sh) | For each newly-discovered technique: why detection missed it, required data source, detection logic, priority — all P1 except NTLM/pass-the-hash (P2, deliberately not overclaimed) |
| 13 | [13-detection_rules.sh](13-detection_rules.sh) / [detection_rules/](detection_rules/) | 6 draft rules (5 Wazuh-style host rules, 1 Suricata-style network rule) closing every Task 12 gap, with FP-rate estimates and baseline logic |
| 14 | [14-hunting_report.md](14-hunting_report.md) | Final synthesis report for SOC + board: executive summary, methodology, H1-H5 findings, attack timeline, ATT&CK update, detection improvements, remaining gaps, lessons learned |

## Scope note

Task 1 was not part of any pasted batch. Tasks 5, 7, 8 and 11 were not
pasted either, but downstream tasks (10, 12, 13, 14) explicitly cite them
by number as dependencies (e.g. Task 10's own instructions say "Merges
anomalous findings from Tasks 4-9," and Task 14 cites "ATT&CK Update (from
T11)") — these four were built from context (the project's "Expected
Outcome" list, the HC3 advisory's own TTP numbering, and the template
established by the pasted Task 4/6/9 scripts) rather than verbatim task
prompts; each file's own header comment says so explicitly.

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
  for all fourteen scripts (0, 2-13).
- All scripts read only from `reference/`, `baseline/` and `siem_export/`
  and produce deterministic output (no live SIEM, Wazuh, EDR or Windows
  host dependency).
- All files end with a trailing newline, including the generated
  `attack_layer_post_hunt.json` and `detection_rules/*.rules` outputs.
- Output filenames are stated in each script's own output (Task 11's
  `attack_layer_post_hunt.json`, Task 13's two rule files).

## Bugs found and fixed during development (not shipped silently)

- **Task 3**: `sort | head` under `pipefail` caused SIGPIPE in `sort` when
  piping ~9,800 sorted lines into `head -1`/`tail -1` (the pipe buffer
  filled before `head` finished reading). Fixed via bash parameter
  expansion (`${VAR%%$'\n'*}` / `${VAR##*$'\n'}`) instead of piping a large
  stream into `head`/`tail`.
- **Task 4**: `jq`'s `@tsv` filter escapes backslashes, which corrupted
  every Windows file path and command line when read back by `read -r`.
  Fixed by switching to `join("\t")`, which does not escape field content.
- **Task 8**: an early version's broad event-matching query picked up one
  *legitimate* LSASS-access event (WmiPrvSE.exe, in the advisory's own
  standard-process allowlist) because it didn't apply the same
  sourceImage-allowlist filter Task 6 uses — it was also off by a UTC/CDT
  day-rollover artifact this exposed. Fixed by applying the identical
  allowlist filter used in Task 6.
- **Task 10**: `paste -sd ', ' -` was used expecting a literal ", "
  separator; `paste -sd` actually *cycles* through each character of a
  multi-character delimiter string per line transition, producing
  "a,b c" instead of "a, b, c". Fixed with `paste -sd, - | sed 's/,/, /g'`.
- **Task 11**: the provided `reference/4x03_attack_mapping.json`'s own
  stored `technique_count_summary` (16 observed / 3 inferred) does not
  match a direct recount of its own `techniques[].score` array (14
  observed / 5 inferred) — a genuine inconsistency in the source file, not
  introduced here. Both before/after coverage figures in Tasks 11, 13 and
  14 are recomputed directly from each file's technique array, never from
  stored summary metadata, so the comparison is apples-to-apples.
- **Task 13**: an XML rule-file comment used `--` (double hyphen), which
  is invalid inside an XML comment per spec. Fixed by rewording to avoid it.
