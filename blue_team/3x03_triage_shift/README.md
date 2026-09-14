# 3x03 Triage Shift

MedDefense Health Systems — Module 3 capstone bridge project. Works the alert
queue produced by the 3x02 detection catalog: classifies every alert as
true positive, false positive, or benign, escalates true positives into
incident records, and rolls false-positive patterns into rule tuning
recommendations for the detection engineer.

## Environment variables

| Variable       | Default                                  | Points at                          |
|----------------|-------------------------------------------|-------------------------------------|
| `CATALOG_DIR`  | `~/3x02_package/detection_catalog`         | 3x02 detection catalog output       |
| `HANDOFF_DIR`  | `~/3x00_handoff/evidence_handoff`          | 3x00 evidence pipeline output       |
| `BASELINE_PKG` | `~/3x01_package/baseline_package`          | 3x01 baseline package output        |
| `ASSETS_DIR`   | `~/3x03_assets` (must be set manually)     | `ioc_context.json` for this project |
| `TRIAGE_PKG`   | `~/3x03_package/triage_package`            | this project's output directory     |

On the lab sandbox:

```
source ~/m3_env.sh
export ASSETS_DIR=$HOME/3x03_assets
```

## Local testing

This repository's copies of the upstream 3x00/3x01/3x02 outputs live flat at
the root of their own project directories rather than under the nested
`data/`, `context/`, `baselines/`, `alerts/` layout the lab sandbox provides.
`local_catalog/` mirrors that lab layout with symlinks back into
`../3x02_the_alert_factory/`, so scripts here can be exercised locally by
pointing `CATALOG_DIR` at it:

```
CATALOG_DIR="$(pwd)/local_catalog" ./0-queue_assessment.sh
```

Real grading/production runs use the lab-provided environment variables
(no override needed once `~/m3_env.sh` is sourced).

## Tasks

### 0. Queue Assessment — `0-queue_assessment.sh`

Reads `$CATALOG_DIR/alerts/alert_queue.json` and
`$CATALOG_DIR/alerts/alert_queue_schema.json`, validates every alert against
the schema, and writes `queue_assessment.json`:

- `queue_size`, `validation_errors`
- `by_priority_band` (critical >= 20, high 10-19, medium 5-9, low 1-4)
- `by_rule`, `by_hostname` (sorted descending by count)
- `by_attack_tactic` — derived from each source rule's Sigma `tags:` block
  (`$CATALOG_DIR/rules/sigma`, tuned variants override base rules); alerts
  whose rule cannot be located are counted under `unmapped`
- `time_span` (first/last `event_summary.timestamp`)
- `top_targets` — top 3 hosts by cumulative `priority_score`

Also prints a human-readable shift briefing to stdout. The queue's own
`generated_at` values (not wall-clock "today") anchor the briefing date, so
both the JSON output and the printed briefing are deterministic for a given
input queue.
