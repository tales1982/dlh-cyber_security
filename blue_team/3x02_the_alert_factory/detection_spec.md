# MedDefense Detection Engineering Specification

## Purpose
This document is the contract for MedDefense's Sigma-based detection layer: how rules are written, executed, scored, prioritized, and shipped. It is the reference a new SOC detection engineer reads before touching the catalog, not a tutorial.

## Inputs
- `HANDOFF_DIR` (default `~/3x00_handoff/evidence_handoff`): `data/enriched_events.json`, `data/normalized_events.json`, `schema/event_schema.json`, `context/asset_inventory.json`.
- `BASELINE_PKG` (default `~/3x01_package/baseline_package`): `baselines/baseline_summary.json`, `baselines/baseline_process.json`, `baselines/event_taxonomy.json`, `taxonomy/labeled_events.json`, `anomalies/ranked_anomalies.json`.
- `ASSETS_DIR` (default `~/3x02_assets`): `risk_register.json`, `attack_taxonomy.json`.

## Rule Authoring Standard
Every rule is a Sigma YAML file at `rules/sigma/NNN_short_name.yml`, `NNN` a three-digit incrementing id. Required top-level fields: `title`, `id` (UUID v4), `status`, `description`, `logsource`, `detection` (with `condition`), `falsepositives`, `level` (`informational`|`low`|`medium`|`high`|`critical`), `tags`. At least one `attack.tXXXX` tag is mandatory and must name a technique present in `attack_taxonomy.json` - the mapping is how the catalog's ATT&CK coverage and risk ranking are computed, not decoration.

## Execution Model
`3-sigma_runner.sh` loads a rule and evaluates its `detection` block against an NDJSON evidence file (default `normalized_events.json`). Because the normalized schema doesn't carry every field a rule needs, the runner computes documented derived fields at execution time: `canonical_label` (taxonomy match), `hour_of_day` (from `timestamp`), `event_id` (inverse of the Windows category/action mapping), `baseline_seen` (membership in `baseline_process.json`), and `parent_process_name`/`src_ip` (parsed from `raw_message` when the structured field is absent). Selections support `contains`/`startswith`/`endswith` modifiers; conditions support `and`/`or`/`not`; a `count() by <field> > N` condition with a `timeframe` runs as a sliding-window aggregation. `--window <start,end>` scopes evaluation to either the 7-day baseline window (false-positive measurement) or the evaluation window (true-positive measurement), both read from `baseline_summary.json` at runtime - never hardcoded.

## Quality Thresholds
Every shipped rule carries three measured numbers: `fp_count` (T10, baseline window), and `precision`/`recall`/`f1` (T13, against the labeled ground truth). A rule with `fp_count > 10` on the clean baseline is marked `[TUNE]` and does not ship regardless of F1. A rule with `f1 < 0.3` is `[WEAK]`; `f1 >= 0.7` is `[STRONG]`. Rules without both measurements are rejected from the catalog outright.

## Tuning Protocol
A flagged rule is not edited in place. A narrowed copy is written to `rules/sigma/tuned/<same filename>`; every downstream script (T13, T15) prefers the tuned variant automatically when one exists, so the original stays in the catalog as an audit trail. A tuning pass is only accepted if re-running T10 drops `fp_count` at or under the threshold *and* re-running T13 shows `f1` did not regress against the same ground truth.

## Risk Ranking Model
For each rule, `risk_score` sums `likelihood * impact` (qualitative `low..critical` mapped to `1..4`) over every `risk_register.json` scenario whose `mitre_techniques` intersect the rule's `attack.tXXXX` tags (a parent technique tag counts as covering its sub-techniques and vice versa). `priority_score = risk_score * f1`, floored at `risk_score * 0.1` when `f1 = 0` so an untested-but-high-risk rule isn't buried under measured noise. A rule with `risk_score = 0` is an orphan: detection effort not mapped to any tracked MedDefense scenario, flagged separately rather than silently ranked last.

## Outputs
`alert_queue.json` is a JSON array, one object per deduplicated match: `alert_id` (deterministic `uuid5` of rule id + event reference), `generated_at`, `rule_id`/`rule_title`/`rule_level`, `priority_score`, `event_ref`, `event_summary` (timestamp, hostname, user, IPs, process, canonical_label, category), `asset_context`, `attack_techniques`, `status`, `evidence_hash` (sha256 of the raw matched record). Alerts within 60 seconds on the same `(rule_id, hostname, user)` collapse to one. Sort is `priority_score` descending, then timestamp ascending. `alert_queue_schema.json` is the explicit field contract; 3x03 Tier 1 reads `alert_queue.json` directly, so a schema or ranking change here is a breaking change there.

## Failure Modes
1. **Silent blind spot**: a rule depends on a field the evidence never populates (e.g. Windows `LogonType`). Symptom: `fp_count = 0` *and* `tp_count = 0` - it looks clean because it never fires at all.
2. **Ground-truth drift**: `ranked_anomalies.json`/`labeled_events.json` were built from a different evidence drop than the one being scored. Symptom: every rule in the catalog reports `tp_count = 0` even though matches are clearly correct on inspection.
3. **Threshold miscalibration on aggregation rules**: a distributed, low-and-slow attack never crosses a single-key `count()` threshold. Symptom: baseline `fp_count = 0` (looks excellent) paired with near-zero recall.
4. **Hostname drift across sources**: the same host appears as `srv-web-01` in one feed and `srvweb01` in another. Symptom: `asset_context` is `null` on an alert for a host that is clearly in the inventory.

## Reviewer Checklist
- [ ] YAML parses (`python3 -c "import yaml"`) and every required field from the Authoring Standard is present.
- [ ] `--dry-run` returns `VALID`.
- [ ] At least one `attack.tXXXX` tag, and the technique exists in `attack_taxonomy.json`.
- [ ] `fp_count <= 10` on the 7-day baseline, or a documented tuning plan.
- [ ] Every field the rule selects on is either native to the schema or a documented runner-derived field.
- [ ] Rule maps to a `risk_register.json` scenario, or is explicitly accepted as an orphan.
- [ ] Filename follows `NNN_short_name.yml` with the next unused number.
