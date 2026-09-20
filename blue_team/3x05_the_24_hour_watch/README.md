# 3x05 – The 24-Hour Watch

MedDefense Health Systems capstone. Runs the full detection chain (pipeline,
baseline, catalog, triage) built across 3x00-3x03 against a fresh, unseen
24-hour evidence pack, investigates the incidents that surface using both
CLI tools and Wazuh exports, and assembles a shift handoff package.

## Environment Contract

```
export CAPSTONE_PACK=$HOME/evidence_pack_secondary
export ASSETS_DIR=$HOME/3x05_assets/capstone_pack/meta
export WAZUH_EXPORTS=$HOME/3x05_assets/wazuh_exports
export SHIFT_WORKSPACE=$HOME/bt/3x05/shift_pack
export HANDOFF_DIR=$HOME/3x00_handoff/evidence_handoff
export PIPELINE_BIN=$HOME/bt/3x00/pipeline/run_pipeline.sh
export BASELINE_BIN=$HOME/bt/3x01/baseline/build_baseline.sh
export CATALOG_DIR=$HOME/bt/3x02/catalog
export TRIAGE_BIN=$HOME/bt/3x03/triage/triage.sh
```

## Lab setup

The lab sandbox starts empty except for the raw evidence packs and 3x05
assets. `$PIPELINE_BIN`, `$BASELINE_BIN`, `$CATALOG_DIR` and `$TRIAGE_BIN`
are not pre-populated — they are this student's own scripts from 3x00-3x03,
redeployed into the `bt/` layout the environment contract expects. See
`lab_setup/` for the wrapper scripts (`run_pipeline.sh`, `build_baseline.sh`,
`triage.sh`) that chain the individual numbered task scripts from each prior
project into the single entry points this project's tasks call.

## Shift outcome (read before trusting any incident file in this repo)

This shift's catalog produced 1,014 alerts from a single rule, and **zero**
of them survived triage as a true positive. Task 6 (correlation) therefore
found 0 incidents against a required minimum of 3, which is the honest,
mechanically-verified result — not a bug in `6-correlate_alerts.sh`.

Two independent root causes were confirmed by direct investigation of the
raw evidence pack (`evidence_pack_secondary`), not assumed:

1. **Catalog coverage gap.** The 4-rule catalog inherited from 3x02 has no
   rule for T1543.003 (service persistence) or T1071.001 (C2 beaconing) —
   the two TTPs the HC-RED7 advisory actually describes. A targeted search
   (SSH/RDP brute-force burst detection, firewall.csv beacon-interval sweep)
   found no matching pattern in the raw data either.
2. **Context/export content mismatch.** `hc_red7_advisory.md`,
   `change_tickets.json`, `prior_shift_notes.md`, and every file under
   `wazuh_exports/` reference hosts (`rad-srv-02`, `bill-ws-09`,
   `db-patient-01`, `clin-ws-12`, `clin-ws-07`, `med-mri-02`) and IOCs
   (`198.51.100.73`, `198.51.100.82`, `MedSyncHelper`) that appear **zero**
   times anywhere in `evidence_pack_secondary`. The `wazuh_exports/*_search_results.json`
   files all show `hits_total: 0` and query index `meddefense-evidence-2026-03`
   — the 3x04 primary-pack index, not this capstone's data.

Given this, `investigations/`, `reports/`, `campaign/`, and `response/`
contain honestly-documented null findings (what was searched, what was
ruled out) rather than fabricated incident data. Tasks 7, 8, 10, 11, and 13
— which all require a real incident to investigate — were not implemented
against invented data; see `response/tuning_recommendations.json` for what
would need to change (catalog rules, pipeline field preservation, and
capstone content regeneration) before those tasks could produce real
findings. See `handoff/shift_handoff.md` for the full shift narrative.

## Task - 0-shift_intake.sh
Verifies the full toolchain (`jq`, `python3`, `yq`, `sigma-cli`, `sha256sum`),
the four prior-project binaries/directories, the capstone pack, the 5
required asset files, and the 4 required Wazuh export files. Creates the
locked `$SHIFT_WORKSPACE/` layout with stub files, and writes
`runtime/shift_start.json`.

## Task - 1-run_pipeline.sh
Invokes `$PIPELINE_BIN` against the capstone pack, capturing progress and
stdout/stderr into `runtime/pipeline_run.log`. Verifies `enriched_events.jsonl`,
`timeline.jsonl`, and `source_stats.json` all exist and are non-empty, checks
at least 4 source types have non-zero counts, and writes `runtime/pipeline_run.json`
with duration, event counts, and dirty-data detected (12 duplicate events).

## Task - 2-run_baselines.sh
Invokes `$BASELINE_BIN` (which now also runs the 3x01 anomaly-detection
stages 10-13, not just baseline-building 3-9) via a symlinked `HANDOFF_DIR`
pointing at the capstone's enriched events. Normalizes the anomaly output
into the locked `deviation_markers` schema. Result this shift: 16 hosts
processed, 0 deviation markers — genuine, confirmed across two full reruns,
not a fluke.

## Task - 3-run_detections.sh
Runs each catalog rule via `3-sigma_runner.sh` against the evaluation-day
window, with `BASELINE_PKG` symlinked to the 3x01 outputs so canonical-label
enrichment works. Rule 002 (off-hours privileged logon) required a fix: its
original `LogonType` selection field is dropped by the 3x00 pipeline's
normalization and always evaluated to zero matches. Result: 1 rule fires,
1,014 medium-severity alerts.

## Task - 4-shift_briefing.sh
Assembles the IOC feed, advisory, change tickets, and prior-shift open items
into `alerts/shift_briefing.json`, cross-checking the advisory's cluster ID
against `shift_start.json`.

## Task - 5-triage_queue.sh
Classifies every alert using the 3x03 methodology's rules (change-ticket
window match → FP, baseline deviation → TP, otherwise → NOISE), implemented
directly rather than through the original 3x03 scripts (which assume the
richer 3x02 alert schema this capstone's simpler alerts don't carry). Result:
TP=0, FP=0, NOISE=1014.

## Task - 6-correlate_alerts.sh
Union-find clustering of TP alerts by host+15min proximity, shared user,
then shared IOC. Exits non-zero when `incident_count < 3`, which is exactly
what happened this shift (0 TP alerts to cluster) — confirmed on two
independent full reruns against a fresh sandbox.

## Task - 14-shift_handoff.sh
Verifies the full workspace layout, writes `handoff/shift_handoff.md` (6
required sections, 466 words), and generates `MANIFEST.json` with sha256
hashes for all 36 shift artifacts.
