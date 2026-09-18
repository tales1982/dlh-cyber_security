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

## Task - 0-shift_intake.sh
Verifies the full toolchain (`jq`, `python3`, `yq`, `sigma-cli`, `sha256sum`),
the four prior-project binaries/directories, the capstone pack, the 5
required asset files, and the 4 required Wazuh export files. Creates the
locked `$SHIFT_WORKSPACE/` layout with stub files, and writes
`runtime/shift_start.json`.
