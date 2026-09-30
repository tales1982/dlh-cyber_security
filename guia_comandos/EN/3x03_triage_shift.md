# 3x03 – Triage Shift

## Task - 0-queue_assessment.sh

What it does: Reads `alert_queue.json` and `alert_queue_schema.json`, validates every alert against the schema with a hand-rolled validator (no `jsonschema` dependency), and writes `queue_assessment.json` with counts by priority band, rule, hostname, ATT&CK tactic (derived from the source rule's Sigma tags), and the 3 hosts with the highest cumulative `priority_score`. Also prints a human-readable shift briefing to stdout.
How to use it: `CATALOG_DIR=<dir> ./0-queue_assessment.sh` (defaults to `~/3x02_package/detection_catalog`)
Commands:

- `re.compile` + `UUID_RE.match`/`is_datetime()` — format validation (`uuid`, `date-time`) reimplemented by hand instead of importing a JSON Schema library, recursively checking every field against `properties`/`required`/`enum`/`items` from the schema (including the nested `event_summary` object).
- `os.path.isdir(rules_dir)` as a guard — if the Sigma rules directory doesn't exist, tactic derivation degrades gracefully (`unmapped` bucket) instead of crashing the script.
- A line-by-line text parser (not a full YAML parse) over each Sigma rule's `tags:` block — recognizes `attack.<tactic>` and resolves it to a fixed MITRE tactic ID (14 stable Enterprise tactics, a small table unlike the hundreds of technique IDs).
- Tuned-rule resolution — for every base file under `rules/sigma/`, prefers the matching file in `rules/sigma/tuned/` when it exists, the same selection logic the 3x02 alert generator already uses.
- `max(generated_ats)[:10]` — anchors the briefing's date on the alerts' own `generated_at` field (not wall-clock "today"), keeping the output deterministic across reruns.

## Task - 2-context_assembly.sh

What it does: Joins `alert_queue.json` with `asset_inventory.json`, `enriched_events.json`, `baseline_summary.json` and `ioc_context.json` in a single pass, producing `enriched_queue.json` where every alert already carries the full asset record, the host's baseline profile, the fully dereferenced event, and any IOC hits.
How to use it: `CATALOG_DIR=<dir> HANDOFF_DIR=<dir> BASELINE_PKG=<dir> ASSETS_DIR=<dir> ./2-context_assembly.sh`
Commands:

- A "needed keys" set (`needed_keys`) built from `event_summary` before opening `enriched_events.json` — allows a single streaming pass over the ~200MB file while only keeping the records some alert actually references in memory, not the whole file.
- Matching by a composite key (`timestamp`, `hostname`, `user`, `process_name`, `src_ip`, `dst_ip`, `event_category`) instead of reopening the raw line at the `event_ref` offset — fixes a real misalignment found between `normalized_events.json` (where the offset was recorded) and `enriched_events.json` (where intermediate cleaning dropped ~134 lines).
- `dict(alert)` as the base of the enriched record — copies every original alert field before adding `asset`/`baseline_host_profile`/`event_record`/`ioc_hits`/`priority_band`, without listing each field by hand.
- Inventory shape detection (bare list vs. `{"assets": [...]}`) with a stderr warning when `service_account_prefix`/`management_subnets` are absent — degrades gracefully instead of assuming a schema that might not be present.

## Task - 3-triage_clearcut_tp.sh

What it does: Reads `enriched_queue.json` and auto-escalates every `priority_band == critical` alert with at least one `malicious` IOC hit and a baseline violation in the rule's category, writing `tickets/batch1_clearcut_tp.json`.
How to use it: `./3-triage_clearcut_tp.sh` (run from the directory where `enriched_queue.json` was already generated)
Commands:

- `datetime.fromisoformat(...replace("Z", "+00:00"))` — converts an ISO-8601 timestamp with a `Z` suffix (not natively accepted by `fromisoformat` on older versions) into the accepted form.
- A per-category dispatch dict (`auth`/`process`/`network`/`file`) inside `baseline_violation()` — each category checks a different `baseline_host_profile` field (a `canonical_label` count, the expected-process set, known ports), reusing the same "never seen before" threshold already described in `baseline_summary.json`.
- `abs((other_ts - alert_ts).total_seconds()) <= CORRELATION_WINDOW_SECONDS` — folds any other alert on the same host within a 1h window into `evidence_refs`, excluding by `event_ref` value (not just object identity) so two alerts pointing at the same event don't produce a duplicate reference.
- `uuid.uuid5(TICKET_NAMESPACE, alert_id)` — generates a deterministic `ticket_id` from a fixed namespace, so running the script twice produces the same ID.

## Task - 4-triage_clearcut_fp.sh

What it does: Reads `enriched_queue.json` and `asset_inventory.json`, and closes every alert matching any of the methodology's 4 false-positive signatures (service account, management subnet, process already seen in baseline, clean IOC with no deviation), writing `tickets/batch2_clearcut_fp.json`.
How to use it: `HANDOFF_DIR=<dir> ./4-triage_clearcut_fp.sh`
Commands:

- `ipaddress.ip_network(cidr)` / `address in network` — tests whether the alert's `src_ip` falls inside any management subnet without hand-rolling CIDR arithmetic.
- `user.startswith(service_account_prefix)` — recognizes service accounts by username prefix (`svc_` by default, or whatever the inventory declares), the simplest and most direct check for that signal.
- An `if`/`elif` chain in the exact order of the task's 4 signatures — each branch is only evaluated if the previous one didn't match, so the recorded `fp_reason` is always the first satisfied signature.

## Task - 6-triage_ambiguous_auth.sh

What it does: Reads `enriched_queue.json` and processes every authentication alert not already classified in earlier batches, fetching the user's login history from `baseline_summary.json` and the raw events from `enriched_events.json` to apply the 4-branch decision tree (unknown IP + critical/high asset + never logged into the host → escalate; unknown IP + medium/low asset + no IOC → close; known IP + failure burst inside the threshold → close; otherwise → monitor).
How to use it: `BASELINE_PKG=<dir> HANDOFF_DIR=<dir> ./6-triage_ambiguous_auth.sh`
Commands:

- `glob.glob("tickets/batch*.json")` + `os.path.abspath` to exclude its own output file — builds the set of alerts already classified in any earlier batch without hardcoding filenames (works even with a not-yet-implemented intermediate task).
- A single pass over `enriched_events.json` filtered to only the users appearing in the candidate alerts — builds each user's historical host/IP set and event list without loading the whole file into memory.
- The walrus operator (`:=`) inside a `sum()` generator expression — computes the 1h failure burst by counting events whose timestamp falls inside the window, all in one expression.
- `timedelta(seconds=FAILURE_BURST_WINDOW_SECONDS)` — defines the 1-hour sliding window used both to count the burst and to compare against the baseline's `max_failures_1h_window`.

## Task - 7-triage_ambiguous_proc_net.sh

What it does: Reads `enriched_queue.json` and `baseline_summary.json`, and processes every process or network alert not already classified, applying the 5-branch decision tree that decides based on the IOC reputation T2 already computed and on whether the process/destination is already known in *another* host's baseline.
How to use it: `BASELINE_PKG=<dir> ./7-triage_ambiguous_proc_net.sh`
Commands:

- `re.compile(r"\bby\s+(\S.*)$")` over `raw_message` — extracts the parent process (`parent_process`) from the event's free-text message (e.g. "Process Create: X by Y"), the same convention `003_interpreter_abuse.yml` already documents for when no literal parent-process field exists.
- `min(flagged, key=lambda h: SEVERITY_ORDER.index(...))` — picks the "worst" IOC hit among several present on the same alert, using its position in an ordered list (`malicious` < `suspicious` < `unknown`) as the criterion.
- Cross-host baseline checks (`process_per_host`, excluding the alert's own host) and against `network.top_destinations` (a global list) — recognizes when a "suspicious" IOC is already established activity elsewhere in the environment.

## Task - 8-triage_correlation.sh

What it does: Reads `enriched_queue.json`, groups same-hostname alerts whose timestamps fall within 600 seconds of each other into a chain (transitively merging them), classifies every group of 2+ alerts as an incident, and **updates the tickets already written**, marking `grouped: true` on the alerts that got grouped.
How to use it: `./8-triage_correlation.sh`
Commands:

- Sort-by-timestamp followed by gap-based grouping (`(ts - current_group[-1][0]).total_seconds() <= 600`) — a sliding-window technique that correctly merges transitive chains (A-B ≤600s, B-C ≤600s) even when A and C alone are further apart.
- `glob.glob` + an `alert_id → (file, index)` dict — locates which ticket file (and which position in its list) each contributing alert was already classified in, so that specific ticket can be edited without rewriting the others.
- In-place mutation of the ticket dict (`ticket_files[path][index]["grouped"] = True`) followed by `json.dump` back to the same file — only the files actually touched get rewritten, leaving the rest byte-for-byte untouched.
- `max(entries, key=lambda e: e[1].get("priority_score", 0))` — when no alert in the group is already `true_positive` in another ticket, uses the one with the highest `priority_score` to decide the incident's classification "from scratch".

## Task - 11-incident_assembly.sh

What it does: Reads every `tickets/batch*.json` and `enriched_queue.json`, selects every `true_positive` ticket recommended for escalation or monitoring (skipping any already marked `grouped: true`, which become part of a T8 incident instead), and assembles `incidents.json` with a timeline, affected assets, IOCs, ATT&CK techniques, and a recommended containment action.
How to use it: `./11-incident_assembly.sh`
Commands:

- `"contributing_alerts" in ticket` vs. `"alert_id" in ticket` — tells apart the two ticket shapes the glob finds (an individual ticket from batches 1-7 vs. a T8 incident ticket) without needing to know the source filename.
- A sort key function (`source_sort_key`) on the earliest timestamp, then the sorted `alert_id`s — guarantees the sequential numbering (`INC-...-0001`, `0002`...) comes out in the same order on every rerun, without relying on a clock.
- A list of `(lambda, action)` predicates evaluated in order (`CONTAINMENT_TABLE`) — implements the task's requested "fixed table" for containment as a plain list walked top to bottom, stopping at the first satisfied condition.
- Underscore-prefixed internal fields (`_hostnames`, `_ioc_values`) kept on the incident dict just to power the second `related_incidents` pass (set intersection between incidents) and stripped (`.pop(..., None)`) before the final JSON is written.

## Task - 1-triage_methodology.md

Concept: A written triage methodology defines, before any alert is processed, the objective criteria separating `true_positive` from `false_positive`, when to escalate to Tier 2, and what every ticket must document — without it, two analysts can classify the same alert differently with no objective way to resolve the disagreement. The correlation escalation criterion ("two or more alerts on the same host/user") is what lets a group of individually-ambiguous alerts escalate once correlated.

## Task - 15-classification_under_ambiguity.md

Concept: A correlation scenario where no single alert crosses the escalation bar, but the group together describes a credible post-compromise pattern, exposes the difference between applying a criterion "strictly" alert-by-alert and applying the methodology as a whole — the correlation criterion exists specifically to cover that case. Tracing the scenario through the actual scripts (instead of just arguing in the abstract) confirms the pipeline already escalates it correctly, and surfaces an honest limitation in the process baseline check (it doesn't look at the parent-child relationship), which correlation compensates for anyway.
