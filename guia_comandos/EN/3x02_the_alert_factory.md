# 3x02 – The Alert Factory

## Task - 0-detection_matrix.sh

What it does: Analyzes every `source_type` in `enriched_events.json` against `event_schema.json`'s field list and `baseline_summary.json`'s baseline window, computing which of the 4 detection types (signature, anomaly, behavioral, correlation) each source can realistically support — based on field stability (≥95% presence), cardinality (distinct values / record count), and event-volume density inside the baseline window — with a rationale string per type and a recommended set of ATT&CK tactics derived from a documented `event_category` → tactic default table (cross-checked, when present, against `ASSETS_DIR/attack_taxonomy.json`).
How to use it: `HANDOFF_DIR=<dir> BASELINE_PKG=<dir> ./0-detection_matrix.sh` (writes `detection_matrix.json`)
Commands:

- `flatten(record)` — turns nested objects like `asset: {criticality: ...}` into dotted keys (`asset.criticality`) so field-presence/cardinality stats can be computed uniformly across flat and nested fields.
- A fail-fast assertion that every hardcoded candidate field (the signature/behavioral/correlation lists) is actually declared in `event_schema.json` — catches schema drift immediately instead of silently under-detecting.
- `count / record_count >= STABLE_THRESHOLD` (0.95) and `len(values) > HIGH_CARDINALITY_RATIO * record_count` (0.5) — two independent per-field statistics computed in the same streaming pass, used together to decide if a field is good "signature" material (stable AND low-cardinality) versus good "correlation" material (just stable).
- `category_tactics & valid_tactic_ids` — an optional cross-check against a real ATT&CK snapshot that drops (and warns about) any tactic ID the hand-written default table might have gotten wrong, without making the taxonomy file a hard requirement.

## Task - 3-sigma_runner.sh

What it does: The detection engine at the center of the whole module — parses and validates a Sigma YAML rule (required top-level fields, UUID v4 `id`, a valid `level`, at least one `attack.tXXXX` tag), then evaluates its `detection` block against an NDJSON evidence file, computing several fields the normalized schema doesn't carry (`canonical_label` via the 3x01 taxonomy, `hour_of_day`, the Windows numeric `event_id` inverted from category+action, `baseline_seen` membership, and `parent_process_name`/`src_ip` parsed out of `raw_message` when the structured field is null) before testing each event against the rule's selections. Supports `contains`/`startswith`/`endswith` field modifiers, boolean `and`/`or`/`not` conditions, and a `count() by <field> > N` sliding-window aggregation condition; `--window start,end` scopes evaluation to either the baseline or evaluation window.
How to use it: `./3-sigma_runner.sh <rule.yml> [evidence.json] [--dry-run] [--count-only] [--window <start_iso,end_iso>]`
Commands:

- `re.compile(r"^[0-9a-f]{8}-...-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-...$")` — validates the rule's `id` is specifically a UUID *version 4* (checks the version nibble and the variant bits), not just any UUID-shaped string.
- The `WIN_SECURITY_EVENT_ID` lookup table — documents that inverting `(event_category, action) -> event_id` is *safe* here because the forward mapping in 3x00's normalizer is provably one-to-one for this dataset, not a guess dressed up as a fact.
- `CONDITION_TOKEN_RE.sub(replace, condition)` then `eval(expr, {"__builtins__": {}}, {})` — turns a Sigma condition string like `selection and not filter` into a Python boolean expression by substituting each selection name with `True`/`False`, sandboxing `eval` to ever see only those two literals plus `and`/`or`/`not`/parentheses.
- `aggregate_matches` — a two-pointer sliding window over events already sorted by timestamp, expanding the right edge and shrinking the left edge to keep only events within `window_seconds`, the exact same pattern this project's own 3x01 `13-correlate_anomalies.sh` (and the study-guide's 3x01 exercise 3) use for time-window grouping.

## Task - 10-fp_baseline.sh

What it does: Runs `3-sigma_runner.sh --count-only` for every rule under `rules/sigma/` against the 7-day baseline window (read from `baseline_summary.json`), on the theory that anything a rule matches during a window Infrastructure has confirmed clean is, by definition, a false positive; records `fp_count` and `fp_rate_per_day` per rule to `fp_baseline.json` and flags anything over 10 FPs as `[TUNE]` in the printed summary.
How to use it: `HANDOFF_DIR=<dir> BASELINE_PKG=<dir> ./10-fp_baseline.sh` (run from the project root, needs `rules/sigma/`)
Commands:

- `mapfile -t RULE_FILES < <(find "$RULES_DIR" -maxdepth 1 -name '*.yml' | sort)` — loads the rule list into a bash array in one shot, sorted, so results are always processed and printed in a deterministic order.
- `"$RUNNER" "$rule_file" --window "$WINDOW_START,$WINDOW_END" --count-only` — reuses Task 3 unmodified as a subprocess per rule instead of reimplementing rule evaluation, so a change to the runner's matching logic automatically applies here too.
- `read -r WINDOW_START WINDOW_END DURATION_DAYS <<< "$(python3 -c ...)"` — a one-line Python-to-bash handoff that reads three values out of `baseline_summary.json` in a single call instead of three separate `jq` invocations.
- `{k: v for k, v in entry.items() if k != 'rule_file'}` before writing the JSON file — keeps the internal, environment-specific `rule_file` path out of the persisted `fp_baseline.json`, while still using it for the human-readable stdout summary.

## Task - 12-attack_coverage.sh

What it does: Cross-references every technique listed in `ASSETS_DIR/attack_taxonomy.json` against the `attack.tXXXX` tags actually present across `rules/sigma/*.yml`, producing a coverage map (per technique: covered true/false, which rule filenames cover it) so downstream prioritization has a real measurement of catalog coverage instead of a guess.
How to use it: `ASSETS_DIR=<dir> ./12-attack_coverage.sh` (run from the project root)
Commands:

- A comment block at the top of the script explaining it exists specifically because Task 14 needs `attack_coverage.json` as an input but no upstream task in the numbered sequence produces it — a small bit of documentation-as-code explaining why this script exists at all.
- `tag.split('.', 1)[1].upper()` on every `attack.tXXXX` tag — extracts just the technique-ID portion and normalizes case, so `attack.t1110.001` and `ATTACK.T1110.001` compare equal.
- `{name for name, techs in rule_tags.items() if tid.upper() in techs}` — for every technique in the taxonomy, computes the *set* of rule filenames covering it (not just a boolean), so the output can answer both "is this covered" and "by what."

## Task - 13-rule_quality.sh

What it does: Measures precision/recall/F1 per rule against a genuine labeled ground truth (every anomaly this project already found, via `ranked_anomalies.json`, resolved back to its `canonical_label` in `labeled_events.json`), running the *tuned* variant of a rule automatically when one exists under `rules/sigma/tuned/`. True positives are rule matches that land on a ground-truth event; false positives are rule matches that don't, plus the rule's own measured baseline FP count from Task 10; false negatives are ground-truth events of the rule's target category that the rule never matched.
How to use it: `HANDOFF_DIR=<dir> BASELINE_PKG=<dir> ./13-rule_quality.sh` (needs `fp_baseline.json` already written by Task 10, and `rules/sigma/`)
Commands:

- `ACTIVE_RULE_FILES` built by preferring `rules/sigma/tuned/<name>` over `rules/sigma/<name>` whenever a tuned copy exists — the same "prefer tuned" resolution logic reused across every script that runs rules against evidence.
- A three-tier fallback for deciding which `canonical_label`s count as a rule's ground truth: first, values literally referenced in the rule's own `canonical_label` selection field; failing that, a small `logsource -> category` lookup table; failing that, every category present in the ground truth at all — documented in-line as a deliberate ordering, not an accident.
- `fp_count = non_intersecting + fp_baseline.get(rule['id'], 0)` — combines two different kinds of false positive (matches outside the ground truth during the evaluation window, plus the rule's own measured noise rate on the known-clean baseline window) into one number.
- `.ground_truth.json` as a dotfile scratch artifact, written once per script run and `rm -f`'d at the end — computed once outside the per-rule loop since every rule is scored against the exact same ground-truth set.

## Task - 14-rule_prioritization.sh

What it does: Turns rule quality (F1) plus organizational risk (MedDefense's own `risk_register.json` scenarios, each with a qualitative likelihood/impact and a list of MITRE techniques) into one `priority_score` per rule — summing `likelihood * impact` over every risk scenario a rule's ATT&CK tags cover (hierarchical: a parent-technique tag counts as covering a scenario naming a sub-technique), multiplied by the rule's F1, with a floor of `risk_score * 0.1` for a high-risk rule that hasn't been measured yet (F1=0) so it isn't buried under measured noise. Rules covering zero risk scenarios are flagged separately as orphans.
How to use it: `ASSETS_DIR=<dir> ./14-rule_prioritization.sh` (run from the project root; needs `rule_quality.json` and `attack_coverage.json` already written)
Commands:

- `technique_covers(a, b)`: `a == b or a.startswith(b + '.') or b.startswith(a + '.')` — implements MITRE ATT&CK's parent/sub-technique hierarchy (`T1078` vs `T1078.002`) with plain string comparison instead of needing a full technique tree.
- Re-reading every `.yml` under `rules/sigma/` and `rules/sigma/tuned/` to rebuild `rule_tags_by_id`/`rule_shortname_by_id` — `rule_quality.json` deliberately doesn't carry ATT&CK tags or filenames, so this script goes back to the source files and joins by the one thing it does carry, `rule_id`.
- `priority_score = risk_score * f1 if f1 > 0 else risk_score * 0.1` — a single line encoding the whole scoring philosophy: untested-but-relevant beats measured-and-weak, but neither beats a rule that's both relevant and proven.
- Splitting the output into `prioritized` (sorted by score) followed by `orphans` (sorted alphabetically) in the same array — orphan rules are never silently dropped, just demoted to the bottom in a stable, inspectable order.

## Task - 15-generate_alerts.sh

What it does: Runs every active (tuned-preferred) rule against the evaluation window, resolves each match back to its full event record in `normalized_events.json` (a single pass over the whole file, since it can be 100MB+), attaches `priority_score` from Task 14 and asset context by hostname, computes a deterministic `alert_id` (uuid5 of rule_id + event_ref) and a sha256 `evidence_hash` of the raw matched line, deduplicates alerts on the same `(rule_id, hostname, user)` that fire within 60 seconds of each other, sorts by `priority_score` descending, and writes both `alert_queue.json` and an explicit `alert_queue_schema.json` field contract for 3x03 to consume.
How to use it: `HANDOFF_DIR=<dir> BASELINE_PKG=<dir> ./15-generate_alerts.sh` (run from the project root; needs `rule_prioritization.json` already written)
Commands:

- `needed_lines = {int(...) for m in raw_matches if ...}` then a single pass over `normalized_events.json` collecting only those line indices — avoids re-opening a 100MB+ file once per alert, the same "collect the keys you need before the one pass" pattern used by 3x03's `2-context_assembly.sh`.
- `uuid.uuid5(ALERT_NAMESPACE, f"{rule_id}:{event_ref}")` — a fixed namespace UUID plus a deterministic string means re-running the whole pipeline on the same evidence produces the exact same `alert_id`s, so alerts can be safely deduplicated across pipeline runs, not just within one.
- Grouping by `(rule_id, hostname, user)`, sorting each group by timestamp, then keeping an alert only if it's more than `DEDUP_WINDOW_SECONDS` (60) after the last *kept* one — collapses a burst of matches into one alert timestamped at the burst's start, instead of one alert per matching event.
- A hand-written JSON-Schema-shaped dict (`alert_queue_schema.json`) written by the same script that produces the data it describes — keeps the contract and the producer physically next to each other so they can't silently drift apart.
