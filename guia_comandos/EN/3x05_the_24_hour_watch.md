# 3x05 – The 24-Hour Watch

MedDefense capstone: chains the whole detection stack built across 3x00-3x03 (pipeline → baseline/anomalies → Sigma catalog → triage) against a fresh, unseen 24-hour evidence pack, investigates whatever surfaces, and assembles a shift handoff package. This particular shift's honest result was **zero** true-positive incidents — two confirmed root causes (a catalog coverage gap, and the shift's context/Wazuh-export files referencing a different evidence pack entirely) — so several of the tasks below are read against real, working code that produced a documented null finding, not a bug.

## Task - 0-shift_intake.sh

What it does: Verifies the full toolchain (`jq`, `python3`, `yq`, `sigma-cli`, `sha256sum`) is on PATH with version probes, confirms the four prior-project binaries/directories (pipeline, baseline, catalog, triage) exist and are executable/readable, confirms the capstone evidence pack and the 5 required asset files and 4 required Wazuh export files all exist, creates the locked `$SHIFT_WORKSPACE/` directory layout with empty stub files for every artifact the rest of the shift will produce, and writes `runtime/shift_start.json` recording the toolchain versions and a shift ID.
How to use it: `CAPSTONE_PACK=<dir> ASSETS_DIR=<dir> WAZUH_EXPORTS=<dir> SHIFT_WORKSPACE=<dir> ./0-shift_intake.sh`
Commands:

- `JQ_V="$(jq --version)"; JQ_V="${JQ_V#jq-}"` — strips a tool's fixed prefix off its version string with bash parameter expansion instead of `sed`/`cut`, repeated once per tool since each tool's `--version` output has a different shape.
- `mkdir -p ... && touch ...` — a fixed list of every artifact the fourteen tasks of the shift will eventually write, created empty up front, so a later stage's `[ -s FILE ]` guard can distinguish "never run yet" from "ran and failed" (both would otherwise look like "file missing").
- Requiring `SIGMA_RULE_COUNT -ge 1` on `$CATALOG_DIR` plus 5 named `ASSETS_DIR` files and 4 named `WAZUH_EXPORTS` files, each checked individually with a named failure message — front-loads every environment problem into one script that fails fast and specifically, instead of letting task 4 or 7 fail confusingly nine steps later.

## Task - 1-run_pipeline.sh

What it does: Invokes `$PIPELINE_BIN` (the student's own 3x00 evidence pipeline, redeployed) against the capstone pack, capturing stdout/stderr to `runtime/pipeline_run.log`; verifies `enriched_events.jsonl`, a timeline file, and `source_stats.json` all exist and are non-empty and that at least 4 source types produced a non-zero count; and writes `runtime/pipeline_run.json` with duration, event counts in/out, and any dirty-data findings (duplicates removed, malformed timestamps repaired) read from the pipeline's own `cleaning_log.json`.
How to use it: `CAPSTONE_PACK=<dir> SHIFT_WORKSPACE=<dir> PIPELINE_BIN=<path> ./1-run_pipeline.sh`
Commands:

- `set +e; "$PIPELINE_BIN" ... ; PIPELINE_EXIT=$?; set -e` — temporarily suspends `set -e` around a subprocess call whose exit code needs to be inspected and handled explicitly, rather than letting a non-zero exit kill the whole script before the log file can even be referenced in the error message.
- `grep -E '^\[pipeline\] stage' ... | sed 's/\.\.\.$/... ok/'` — re-prints only the pipeline's own stage-progress lines from its captured log, appending "ok" to each, giving a compact summary without dumping the whole log to stdout.
- `EVENTS_IN="$(jq '.total_records // .total_events // empty' ... 2>/dev/null || true)"` — tries two possible field names the upstream pipeline's own inventory file might use, falling back to `events_out` (the actual line count) if neither is present, rather than hard-requiring one exact schema.

## Task - 2-run_baselines.sh

What it does: Symlinks the pipeline's enriched-events file into a scratch `HANDOFF_DIR` and invokes `$BASELINE_BIN` (which, in this redeployed layout, also runs the 3x01 anomaly-detection stages, not just baseline-building), then reads the three `anomalies_*.json` files it produces and normalizes every entry into a single locked `deviation_markers` schema (host, marker, field, observed_value, baseline_reference, deviation_score), ranks the top 5 "hot hosts" by summed deviation score, and writes both `runtime/baseline_run.json` and a trimmed `enriched/baseline.json` for later tasks to read.
How to use it: `SHIFT_WORKSPACE=<dir> BASELINE_BIN=<path> ./2-run_baselines.sh` (needs Task 1's output)
Commands:

- `ln -sf "$ENRICHED_FILE" "$BASELINE_HANDOFF/data/enriched_events.json"` — satisfies the baseline binary's expected `HANDOFF_DIR` layout with a symlink instead of copying a potentially large file.
- A jq object mapping specific `anomaly_type` values (`offhours_login`, `unknown_parent_child`, ...) to a smaller, fixed set of `marker` names, with `// .anomaly_type` as the fallback for anything not in the table — normalizes three differently-shaped anomaly files into one vocabulary without needing every possible anomaly type enumerated up front.
- `{critical: 3.0, high: 2.0, medium: 1.0, low: 0.5}[.severity] // 1.0` — converts severity to a numeric weight for ranking "hot hosts," the same severity-to-score idiom used by 3x01's `16-rank_anomalies.sh`.
- `group_by(.host) | map({host, total: (map(.deviation_score) | add)}) | sort_by(-.total) | .[0:5]` — a textbook jq aggregate-then-top-N pipeline, reused here to answer "which hosts deserve attention first" from a flat list of markers.

## Task - 3-run_detections.sh

What it does: Symlinks the 3x01 baseline artifacts the sigma runner needs, resolves the evaluation window from `baseline_summary.json`, runs every catalog rule via 3x02's `3-sigma_runner.sh` against that window, and assembles every rule's raw matches into `alert_queue.json` (a simpler shape than 3x02's own alert schema — id, rule metadata, host, timestamp, event_ref — deliberately, since this capstone doesn't run the full 3x02 prioritization chain). Also records per-severity and per-rule alert counts to `runtime/catalog_run.json`. Documents a real fix made this shift: rule 002's original `LogonType` selection field is silently dropped by the 3x00 normalizer, so the rule always matched zero events until that was corrected.
How to use it: `SHIFT_WORKSPACE=<dir> CATALOG_DIR=<dir> ./3-run_detections.sh` (needs Tasks 1 and 2's output)
Commands:

- `ln -sf "$BASELINE_SRC_DIR/event_taxonomy.json" ...` / `ln -sf ".../baseline_process.json" ...` — builds a minimal fake `BASELINE_PKG` directory out of symlinks to exactly the two files the runner's `canonical_label` and `baseline_seen` enrichment actually read, instead of standing up a full baseline package.
- `RUNNER_ARGS+=(--window "${EVAL_START},${EVAL_END}")` only appended when `EVAL_START` is non-empty and non-`"null"` — lets the script run correctly (unwindowed) even if the baseline stage's summary file is missing, instead of passing a broken `--window ,` argument.
- `alert_id: ($r.rule_id + "-" + (.event_ref | gsub("[^0-9]"; "")))` — builds a cheap deterministic alert ID by stripping everything but digits out of the `line:<N>` event reference and appending it to the rule ID, a simpler stand-in for the uuid5 scheme 3x02's real alert generator uses.
- `[ "$ALERTS_TOTAL" -gt 0 ] || fail ...` — a hard requirement that *something* fired; a catalog producing zero alerts against a real 24-hour hospital evidence pack is treated as a broken pipeline or catalog, not a quiet day.

## Task - 4-shift_briefing.sh

What it does: Reads the H-ISAC advisory (extracting the cluster ID and every `TXXXX(.XXX)` technique mentioned via regex), the IOC feed, active change tickets, and the prior shift's "Open Items" section (parsed out of its Markdown with a small state-machine regex), cross-references the advisory's cluster ID against what `0-shift_intake.sh` recorded, pulls the baseline's hot-hosts list from Task 2's output, and assembles everything into one `alerts/shift_briefing.json` a Tier 1 analyst reads before touching the queue.
How to use it: `ASSETS_DIR=<dir> SHIFT_WORKSPACE=<dir> ./4-shift_briefing.sh` (needs Task 2's output)
Commands:

- `grep -oE 'T[0-9]{4}(\.[0-9]{3})?' "$ADVISORY_FILE" | sort -u` — pulls every MITRE technique ID mentioned anywhere in free-text advisory prose without needing to parse the document's structure.
- A Python one-liner using `re.search(r"^## Open Items.*?\n(.*?)(?=\n## |\Z)", text, re.S | re.M)` then `re.split(r"\n(?=\d+\.\s)", body)` — extracts one Markdown section by heading, then splits it into individual numbered list items using a lookahead on the next number, a small but real Markdown-section-parser built from two regexes instead of a Markdown library.
- `[ "$RECORDED_CLUSTER" = "$CLUSTER_ID" ] || fail ...` — cross-checks the cluster ID this script just parsed from the advisory against the one `0-shift_intake.sh` recorded hours earlier, catching a mismatched or swapped asset file before it silently poisons the rest of the shift.

## Task - 5-triage_queue.sh

What it does: Classifies every alert in `alert_queue.json` using the 3x03 triage methodology's rules — a host+time match inside an approved change-ticket window closes it as FP, a host with a corroborating baseline deviation marker escalates it to TP, everything else is batch-closed as NOISE — implemented directly against this capstone's simpler alert shape rather than by invoking the original 3x03 scripts, which assume the richer 3x02 `alert_queue.json` fields (`priority_score`, full `event_summary`) this shift's alerts don't carry. Writes `alerts/triage_log.jsonl`, one line per classified alert.
How to use it: `SHIFT_WORKSPACE=<dir> ASSETS_DIR=<dir> ./5-triage_queue.sh` (needs Tasks 3 and 4's output)
Commands:

- A documented comment explaining exactly why the real 3x03 triage binary isn't invoked here — a schema mismatch between what this capstone's simpler pipeline produces and what 3x03 expects — instead of silently reimplementing the same logic and leaving the reader to wonder why.
- One `jq -s` pass taking all three input files as separate positional arguments (`.[0]`/`.[1]`/`.[2]`) — classifies every alert in a single filter instead of a per-alert shell loop, each alert checked against the tickets list and the deviated-hosts set built once up front.
- `UNCLASSIFIED=$((ALERT_COUNT - LOGGED_COUNT)); [ "$UNCLASSIFIED" -eq 0 ] || fail ...` — a completeness check that every alert that went in got a classification out, catching a silent jq filter bug (e.g. a null field short-circuiting a `map`) instead of quietly shipping a partial triage log.

## Task - 6-correlate_alerts.sh

What it does: Takes every alert classified TP in the triage log and groups them into incidents using a union-find (disjoint-set) over three linking rules — same host within 15 minutes, shared non-null user, or shared IOC match — then labels each resulting group with a tentative category guessed from keywords in its rule titles and a confidence level, and writes `alerts/incidents.json`. Exits non-zero if the resulting `incident_count` is below 3, treating too few incidents as a signal to go back and check Task 3's catalog coverage or Task 5's triage rules — which is exactly what happened the shift this module documents: 0 TP alerts in, 0 incidents out, a real and reproducible negative result, not a bug in this script.
How to use it: `SHIFT_WORKSPACE=<dir> ./6-correlate_alerts.sh` (needs Task 5's output)
Commands:

- A textbook union-find (`parent` array, path-halving `find`, `union`) implemented in ~15 lines of Python — the standard data structure for "merge things into groups based on several independent pairwise relationships," applied here to alerts instead of graph nodes.
- Three separate grouping passes (`by_host`, `by_user`, `by_ioc`), each just calling `union(a, b)` on adjacent items sharing a key — lets three unrelated linking criteria compose naturally: two alerts get merged into the same incident if *any* rule connects them, transitively.
- `letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"` then `f"INC-{today}-{letters[gi]}"` — human-readable, alphabetically-ordered incident IDs (`INC-20260408-A`, `-B`, ...) instead of opaque UUIDs, matching how the rest of the module's tasks (7, 8, 11) refer to incidents by letter.
- `[ "$INCIDENT_COUNT" -ge 3 ] || fail "..."` — the module's central honesty mechanism: a hard failure (not a warning) when correlation can't produce the minimum incident count the shift narrative requires, forcing the root cause to be investigated rather than papered over.

## Task - 7-investigate_A.sh / 8-investigate_B.sh

What it does: Two parallel, independent investigation scripts, each looking up one lettered incident from `incidents.json` (the `-A`/`-B` suffix) and — if it exists — pulling every enriched event on its hosts within a 15-minute-padded window, cross-referencing IOC feed values and Task 2's baseline deviation markers, guessing likely ATT&CK techniques from the incident's tentative category, and writing a structured finding (`hypothesis`, `confidence`, `event_refs`, `attack_techniques`, `ambiguity_notes`) to `investigations/incident_A.json` / `incident_B.json`. Task 8 additionally cross-references an approved change ticket (host, time window, and owner must all match for a full-covering FP verdict; any partial mismatch is treated as TP regardless). Critically, both scripts have a complete, working branch for the case where the lettered incident *doesn't exist* (as happened this shift, since Task 6 produced 0 incidents): they log the absence honestly, write a finding documenting exactly why there was nothing to investigate, and exit non-zero — rather than fabricating a plausible-looking incident to satisfy the schema.
How to use it: `SHIFT_WORKSPACE=<dir> ASSETS_DIR=<dir> ./7-investigate_A.sh` and `./8-investigate_B.sh` (needs Task 6's output)
Commands:

- `jq -c '[.incidents[] | select(.incident_id | test("-A$"))][0] // null'` — the letter-suffix lookup pattern shared by both scripts; `// null` turns "no match" into an explicit, testable value instead of an empty string that would silently pass later checks.
- The `if [ "$INCIDENT_JSON" = "null" ]; then ... fail ...` branch in both scripts — a genuinely complete alternate code path (not a stub) that still writes a schema-valid finding file and prints a clear reason, then exits non-zero so the calling shift knows this incident slot produced nothing rather than silently succeeding.
- `ACTIONS+=(...)` accumulated as a bash array across the whole script, then folded into the output JSON's `actions` field at the end — every jq/lookup command actually run during the investigation is logged verbatim into the finding itself, so a reader can audit exactly how the hypothesis was derived.
- (Task 8 only) `[[ "$FIRST_SEEN" > "$TWIN_START" || "$FIRST_SEEN" == "$TWIN_START" ]] && [[ "$LAST_SEEN" < "$TWIN_END" ... ]]` — bash's lexicographic string comparison operators used directly on ISO-8601 timestamps, which works correctly here specifically because that format sorts the same lexicographically as chronologically.

## Task - 10-campaign_correlation.sh

What it does: Reads the three incident findings (A, B, and `incident_C_cli.json`) and, for every pair, computes IOC overlap, ATT&CK technique overlap, and temporal distance between the incidents, linking a pair when they share an IOC backed by a feed match, share 2+ techniques within 6 hours of each other, or share a user/host — then declares `campaign_linked` true only if at least one pair links, further tagging the campaign as the advisory's own `HC-RED7` cluster ID only if a linked pair also has IOC feed matches. Separately quotes the Wazuh dashboard export's own `campaign_linked`/`cluster_id` claim, but explicitly annotates it as `"not corroborating"` for this shift since every export search result has `hits_total: 0` against a different evidence pack's index entirely.
How to use it: `SHIFT_WORKSPACE=<dir> ASSETS_DIR=<dir> WAZUH_EXPORTS=<dir> ./10-campaign_correlation.sh` (needs the three investigation findings)
Commands:

- A Python heredoc computing three independent pairwise metrics (`ioc_overlap`, `tactic_overlap`, `temporal_distance`) over all 3 combinations of `{A,B,C}` — small enough (3 pairs) that a full n² comparison is simpler and more transparent than a smarter clustering algorithm.
- Three-tier linking logic (`ioc_overlap>=1 and feed_match`, `tactic_overlap>=2 and temporal_dist<=360`, `shared_user or shared_host`) evaluated in that specific order with the reason recorded — so `linked_pairs` always carries *why* two incidents were judged related, not just that they were.
- A comment directly above the Wazuh cross-check explaining that every `incident_*_search_results.json` this shift queries the wrong index (`meddefense-evidence-2026-03`, the 3x04 primary pack) — the export data is quoted in the output for transparency but explicitly never allowed to influence `campaign_linked` or `confidence`.

## Task - 11-incident_reports.sh

What it does: For each of the three investigation findings, renders a capped, analyst-readable Markdown report (`reports/incident_A.md` etc.) with fixed section limits (timeline ≤15 events, affected-assets table ≤10 rows, IOC table ≤15 rows, ATT&CK table ≤8 rows, evidence references ≤12), re-verifying that every `event_refs` timestamp cited actually exists in the enriched-events file before including it, and defanging any IPv4 address in the IOC table (`1.2.3.4` → `1[.]2[.]3[.]4`) so the report is safe to paste into email or a ticket without a scanner potentially treating it as a link.
How to use it: `SHIFT_WORKSPACE=<dir> ASSETS_DIR=<dir> ./11-incident_reports.sh` (needs the three investigation findings)
Commands:

- `defang() { sed -E 's/([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/\1[.]\2[.]\3[.]\4/g'; }` — a one-line `sed` function reused across every IOC table cell, the standard technique for making an indicator safe to paste into chat or email without it auto-linking or getting flagged as live traffic.
- A verification loop that looks up every cited `event_refs` timestamp in the enriched-events file and calls `fail` if even one isn't found — a report is not allowed to cite evidence that doesn't actually exist, checked mechanically rather than trusted from the investigation script's own output.
- `[ "$TIMELINE_COUNT" -le 15 ] || fail ...` repeated per section with a different cap — treats "too much detail" as a defect the same way "too little" would be: a report with a 40-row IOC table isn't more thorough, it's unreadable, so the script enforces the same discipline a human editor would.
- A single shared `generate_report()` bash function parameterized by letter and finding-file path, called three times — the same report-shape logic runs identically whether the incident is real or a documented null result, so a null finding still produces a complete, correctly-capped report rather than a special-cased blank page.

## Task - 13-containment_package.sh

What it does: Derives up to 12 concrete containment actions from `incidents.json` (block a matched IOC at the firewall as `immediate`, isolate the incident's first host as `immediate`, reset credentials for its users as `short_term`, tighten firewall rules for the affected zone as `medium_term`), each action required to cite a real `incident_id`; and separately assembles an `ioc_package.json` (TLP:AMBER) of every IOC observed across the three investigation findings, each one required to trace back to a `first_seen`/`last_seen` event reference in its own finding (an IOC with no evidence backing it fails the build), IPv4/domain values defanged the same way as Task 11's reports.
How to use it: `SHIFT_WORKSPACE=<dir> ASSETS_DIR=<dir> ./13-containment_package.sh` (needs Task 10's output)
Commands:

- A single jq filter iterating `$incidents[]` and conditionally emitting 0-3 action objects per incident (IOC block only if an IOC exists, host isolation only if a host exists, credential reset only if users exist) via `if ... then [...] else [] end` chains concatenated together — builds a variable-length, situation-appropriate action list per incident instead of a fixed template.
- `("0" * (3 - length)) + .` inside a `to_entries | map(...)` — jq's only string-repetition idiom, used here to zero-pad an incrementing counter into `ACT-001`, `ACT-002`, etc. without a dedicated `printf`-style formatter.
- `[ "$UNTRACEABLE" -eq 0 ] || fail "..."` on the IOC package — the same "every claim must trace to evidence" discipline as Task 11's report generator, applied to the containment package instead: no IOC gets shipped to responders without a `first_seen`/`last_seen` pointing at a real investigated event.
- `source: (if ([.] | inside($feed)) then "ioc_feed" else "shift_discovered" end)` — labels each IOC by whether it was already in the known threat-intel feed or newly found during this shift's own investigation, information a responder needs to judge how much to trust it.

## Task - 14-shift_handoff.sh

What it does: Verifies every artifact the prior 13 tasks were supposed to produce actually exists and is non-empty, computes shift duration, and renders `handoff/shift_handoff.md` — a fixed 6-section, ≤900-word narrative (Shift Identifier, Situation, Incidents, Campaign Assessment, Open Items for Next Shift, Artifact Index) written to honestly describe a shift with zero confirmed incidents and explain, specifically, why (catalog coverage gaps, a context/evidence mismatch) rather than padding the narrative — then builds `MANIFEST.json`, a sha256 hash and byte size for every one of the shift's ~36 artifacts, as the integrity record the next shift (or an auditor) can check against.
How to use it: `SHIFT_WORKSPACE=<dir> ./14-shift_handoff.sh` (needs every prior task's output; run last)
Commands:

- A `REQUIRED_FILES` bash array of every path the whole shift should have produced, checked with `[ -s ... ]` in one loop, except `MANIFEST.json` and `handoff/shift_handoff.md` themselves — deliberately excluded from the pre-check since this same script is what generates them.
- `grep -oE 'INC-[0-9]{8}-[A-Z]' "$HANDOFF_MD" | sort -u` then checking each against `incidents.json` — verifies the handoff narrative never cites an incident ID that doesn't actually exist, a factual consistency check on prose, not just on structured JSON.
- `find "$SHIFT_WORKSPACE" -maxdepth 1 -type d ! -path "$SHIFT_WORKSPACE" -exec find {} -type f -print0 \;` combined with `sha256sum`/`stat -c%s` per file — walks every artifact directory once, hashing and sizing every file, to build a tamper-evident manifest the same way a forensic evidence package would be sealed.
- `[ "$WORD_COUNT" -le 900 ] || fail ...` plus a `REQUIRED_HEADINGS` loop — enforces both a length ceiling and section completeness on a document meant to be read start-to-finish in a few minutes at shift-change, not skimmed or skipped.
