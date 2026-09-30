# 3x01 – Reading the Noise

## Task - 2-query_toolkit.sh

What it does: Dispatches five sub-commands (`filter`, `top`, `distinct`, `count`, `window`) against `$HANDOFF_DIR/data/enriched_events.json`, using one shared jq `select` expression built from whichever `--source`/`--host`/`--category`/`--from`/`--to` filters were passed, plus a generic field accessor that also resolves dotted paths into nested objects like `asset.criticality`.
How to use it: `./2-query_toolkit.sh <verb> [options]` (defaults `HANDOFF_DIR` to `~/3x00_handoff/evidence_handoff` if unset)
Commands:

- `jq -c --arg src ... "select($SELECT_JQ)" file` — builds one shared jq filter expression from all five optional flags, so an unset flag (`$src==""`) short-circuits instead of narrowing the match.
- `getpath($field | split("."))` — resolves both a flat field name and a dotted path like `asset.criticality` with the same code, instead of writing two separate lookup mechanisms.
- `sort | uniq -c | sort -k1,1rn | head -n N` wrapped in `set +o pipefail ... set -o pipefail` — the `top` verb's ranking pipeline; the pipefail toggle exists because `head` closing early after N lines sends `sort` a SIGPIPE that `pipefail` would otherwise treat as a script failure.
- `awk '{c=$1; $1=""; sub(/^ /,""); printf "%s\t%s\n", $0, c}'` — flips `uniq -c`'s "count value" output into "value\tcount", handling multi-word values correctly.

## Task - 3-event_taxonomy.sh

What it does: Ships a hand-built, ordered list of ~49 rules (each a `{source_type, match, label}` record derived from actually inspecting the dataset's `raw_message`/`action`/`process_name` patterns per source), matches every event against the first rule that fits, and writes both the rule list (`event_taxonomy.json`) and the full dataset relabeled with a new `canonical_label` field (`labeled_events.json`), defaulting unmatched events to `"unlabeled"`.
How to use it: `./3-event_taxonomy.sh`
Commands:

- A JSON array written via `cat > file <<'EOF' ... EOF` — keeps the taxonomy human-editable and machine-readable at the same time, instead of building it programmatically.
- `to_entries | all(...)` inside a jq inline predicate — checks that every key/value pair declared in a rule's `match` object holds against the event, so a rule can test one field or five without changing the matching code.
- A trailing `*` convention on a match value, checked with `endswith("*")` then `startswith(value[0:-1])` — lets a handful of rules match message prefixes (like `"An account was logged off.*"`) without needing full regex support in the rule schema.
- `map(select(...)) | .[0].label // "unlabeled"` — picks the first matching rule in declaration order (first-match-wins), falling back to `"unlabeled"` when nothing matches.

## Task - 4-baseline_auth.sh

What it does: Finds the dataset's own earliest timestamp, adds `$BASELINE_DAYS` (default 7) to it to derive the baseline window at runtime, then does a single `reduce` pass over that window's labeled events to build per-host/per-user login counts, the known-accounts list, business-hours vs off-hours average success/failure rates, and the largest 1-hour failure burst from a single `src_ip`.
How to use it: `./4-baseline_auth.sh` (env: `BASELINE_DAYS`)
Commands:

- `sort | head -n 1` wrapped in `set +o pipefail` — finds the earliest timestamp; the SIGPIPE-vs-`head` fix, same idiom as Task 2's `top` verb.
- `date -u -d "$WSTART + N days" +"%Y-%m-%dT%H:%M:%SZ"` — GNU `date` arithmetic derives the window's end from the window's start instead of hard-coding a calendar date.
- `reduce (inputs | select(...)) as $e (...; ...)` — a single streaming pass over the NDJSON file builds every aggregate (per-host counts, per-user counts, hour buckets, IP+hour failure counts) at once, instead of re-reading the file per metric.
- Counting *distinct calendar-hour buckets* actually present in the window (not `days*12`) — makes the hourly average exact even at the window's partial-day edges.

## Task - 5-baseline_process.sh

What it does: Restricts to the same baseline window, then for every host builds the list of processes that ran there (with count, first/last seen, and distinct users), the global top 50 processes, the processes rare enough to be worth watching (single-host or under 5 total runs), and every parent→child relationship it can extract from `"Process Create: <child> by <parent>"` messages.
How to use it: `./5-baseline_process.sh` (env: `BASELINE_DAYS`)
Commands:

- `capture("^Process Create: (?<child>.+) by (?<parent>.+)$")` guarded by a `test(...)` check first — extracts the parent process name embedded in free text; the guard exists because `capture` produces *no output at all* (not `null`) on a non-match, which would otherwise silently break the surrounding `reduce`.
- `map_values(to_entries | map({...}) | sort_by(-.count, .process_name))` — turns the internal per-host accumulator object into the final sorted array, count descending with name as a deterministic tiebreaker.
- `$r.host_sets | to_entries | map(select(.host_count == 1 or .total_count < 5))` — the exact "rare process" rule from the task spec, computed straight from the two sets already built during the reduce.
- `keys` on a `{"<user>": true}` accumulator object — the standard jq idiom for building a deduplicated, pre-sorted set without a second pass.

## Task - 6-baseline_network.sh

What it does: Because firewall/pcap events carry no hostname (only IP addresses), builds the network baseline keyed by `src_ip` instead of by host — known destination ports per source IP, connection-type counts (outbound/inbound/blocked), the top 20 destination IPs overall, and the total count of IDS alerts.
How to use it: `./6-baseline_network.sh` (env: `BASELINE_DAYS`)
Commands:

- `.canonical_label | test("^network_")` — a single filter that catches all four network-related labels at once instead of an `or` chain.
- `.per_src_ip[$ip].known_dst_ports[($e.dst_port|tostring)] = true` — builds a per-IP port set as object keys for fast membership testing, converting the port to a string since jq object keys must be strings.
- `map_values(...) | keys | map(tonumber) | sort` — turns each port set back into a sorted array of numbers for the final JSON, undoing the string conversion used internally.

## Task - 7-baseline_file.sh

What it does: Restricts to `file_read_sensitive`/`file_write_sensitive`/`file_permission_change` events in the baseline window and produces a simple per-host and global count for each of the three.
How to use it: `./7-baseline_file.sh` (env: `BASELINE_DAYS`)
Commands:

- `def is_file_label: . == "a" or . == "b" or . == "c";` — a small named predicate reused in both the `select` filter and the grouping step, kept in one place instead of repeated inline.
- `.totals[$lbl] = ((.totals[$lbl] // 0) + 1)` alongside the equivalent per-host update — the same running-counter pattern used in every baseline script, applied once for the global figure and once for the per-host breakdown in the same reduce step.

## Task - 8-baseline_temporal.sh

What it does: Buckets every baseline-window event by hour-of-day (`"00"`–`"23"`) and by calendar day, then reports the average event count per hour-of-day (raw count divided by `$BASELINE_DAYS`) plus which hour is busiest/quietest.
How to use it: `./8-baseline_temporal.sh` (env: `BASELINE_DAYS`)
Commands:

- `$e.timestamp[11:13]` / `$e.timestamp[0:10]` — jq's string-slicing syntax pulls the hour-of-day and the calendar date straight out of the ISO-8601 timestamp without parsing it.
- A literal `["00","01",...,"23"]` array piped through `max_by`/`min_by` — guarantees all 24 hours are considered for busiest/quietest even if one of them had zero events (and therefore no key in the accumulator).

## Task - 9-baseline_summary.sh

What it does: Loads all five prior baseline files with `--slurpfile`, computes the baseline window's duration in days and derives a 24-hour evaluation window immediately after it, unions every `per_host` key across auth/process/file into one host inventory, and nests everything (plus a documented `thresholds` block) into one `baseline_summary.json`.
How to use it: `./9-baseline_summary.sh`
Commands:

- `strptime("%Y-%m-%dT%H:%M:%SZ") | mktime` — converts an ISO-8601 timestamp to Unix epoch seconds so window durations can be computed by subtraction.
- `mktime | (. + 86400) | strftime(...)` — adds exactly one day in epoch-seconds space, simpler and less error-prone than string-based date arithmetic for a fixed 24h window.
- `[($auth.per_host // {} | keys[]), ...] | flatten | unique | sort` — merges host lists from three independently-shaped documents into one deduplicated, sorted inventory.
- Each threshold stored as `{value, comment}` instead of a bare number — makes the "why" of every threshold machine-readable and auditable, not just a comment in a script.

## Task - 10-anomalies_auth.sh

What it does: Reads the evaluation window out of `baseline_summary.json`, and for each of the four required checks (unknown account, failure burst, off-hours login, privilege-escalation surge) groups matching events by the right key (user, `src_ip`+hour, user, host respectively), keeping every matching event's timestamp as `event_refs` so each anomaly stays traceable back to its evidence.
How to use it: `./10-anomalies_auth.sh` (env overrides: `SUMMARY_FILE`, `OUT_FILE`, used by Task 15)
Commands:

- A second, separate `jq -n` pass over the baseline window (not the evaluation window) — computes which users only ever logged in during business hours in the *clean* period, since that per-user granularity doesn't exist in `baseline_auth.json` and has to be derived on demand.
- `.unknown[$user].events = ((.unknown[$user].events // []) + [$e.timestamp])` — the "append or initialize" idiom used throughout, since jq has no bare `+=` that tolerates a missing path.
- `def sevrank: {critical:3, high:2, medium:1, low:0}[.];` then `sort_by([-(.severity|sevrank), .timestamp])` — ranks the worst anomalies first without hand-writing a comparator.
- `SUMMARY_FILE`/`OUT_FILE` read via `${VAR:-default}` — lets Task 15 re-point this same script at a different summary file and a different output path without touching its code.

## Task - 11-anomalies_process.sh

What it does: Compares every evaluation-window process event against that specific host's baseline process list and parent→child set (both pulled straight from `baseline_summary.json`), flagging processes/pairs never seen on that host, processes that were rare in the baseline but spike past 10 runs, and any watchlist tool (`powershell.exe`, `nc`, `python3`, etc.) appearing on a host where it never ran before.
How to use it: `./11-anomalies_process.sh` (env overrides: `SUMMARY_FILE`, `OUT_FILE`)
Commands:

- A severity rubric declared as four `SEV_*` shell variables at the top of the script, passed into jq with `--arg` — keeps the severity policy in one visible place instead of buried inside the jq filter.
- `if (raw_message|test(pattern)) then capture(pattern) else null end` — guarantees exactly one output (a capture object or `null`) per event so the surrounding `reduce` never silently collapses on a non-matching `raw_message`.
- `def basename: (split("\\")|last) | (split("/")|last) | ascii_downcase;` — normalizes a Windows path, a Unix path, or a bare binary name to the same lowercase basename before checking it against the watchlist.
- `host_processes($host) | index($pname) | not` — the "is this new for this host" test, reused for both the plain unknown-process check and the watchlist check.

## Task - 12-anomalies_network.sh

What it does: Since only one message format (`"Network connection: <proc> -> <ip>:<port>"`) carries both a hostname and a destination, scans the baseline window for each host's known destination IPs/ports using that exact pattern, then flags any evaluation-window connection to a new IP or a new port for that host.
How to use it: `./12-anomalies_network.sh` (env overrides: `SUMMARY_FILE`, `OUT_FILE`)
Commands:

- `capture("^Network connection: .+ -> (?<ip>[0-9.]+):(?<port>[0-9]+)$")` — pulls the destination IP and port out of free text, since the structured `dst_ip`/`dst_port` fields are null for this particular message format.
- Two full passes over `labeled_events.json` in the same script (one for the baseline window, one for the evaluation window) — simpler and easier to verify than folding both computations into a single reduce.
- `$known[$h].ports // {} | keys` — the same known-set-as-object-keys idiom from Task 6, reused here per host instead of per `src_ip`.

## Task - 13-correlate_anomalies.sh

What it does: Tags every entry from the three anomaly files with its source, groups them by host, and inside each host group does single-linkage time clustering (sort by timestamp, start a new cluster whenever the gap to the previous event exceeds `$CORR_WINDOW_SECONDS`), keeping only clusters of 2 or more as correlated findings, each scored by source count plus a type-count bonus, scaled by the host's asset criticality.
How to use it: `./13-correlate_anomalies.sh` (env: `CORR_WINDOW_SECONDS`, default 300)
Commands:

- `reduce events[] as $e ([]; if length==0 then [[$e]] else ... end)` — the gap-based clustering fold: compares each event only to the last event of the last open cluster, enough to implement single-linkage clustering without a graph library.
- A one-pass `reduce` over `labeled_events.json` building `{hostname: first-seen-criticality}` — looks up each host's `asset.criticality` once, from the same raw dataset the anomaly scripts already consume, instead of re-parsing `asset_inventory.json` separately.
- `("corr-" + (epoch|tostring) + "-" + (host|@base64|.[0:8]))` — a short, fully deterministic ID built from data already in hand, avoiding any dependency on an external hashing tool.
- `{LOW:1, MEDIUM:2, HIGH:3, CRITICAL:4}[.] // 1` — turns the asset's criticality label into the score multiplier the task spec calls for, defaulting to 1 for any host with no recorded criticality.

## Task - 15-baseline_validation.sh

What it does: Runs Tasks 10/11/12 twice — once against a copy of `baseline_summary.json` whose `evaluation_window` has been overwritten to equal the `baseline_window` itself (`self_check_*.json`), and once normally against the real evaluation window (`live_check_*.json`) — then computes the self-check total, the live-check total, their ratio, and a pass/fail verdict against two configurable thresholds.
How to use it: `./15-baseline_validation.sh` (env: `SELF_CHECK_THRESHOLD`, `MIN_SIGNAL_TO_NOISE`); exits 0 on pass, 1 on fail
Commands:

- `jq '.evaluation_window = {start: .baseline_window.start, ...}'` — builds the self-check summary file by overwriting just one field of the real summary, so the self-check run reuses the exact same thresholds and per-host baselines as the real run.
- `mktemp -d` paired with `trap 'rm -rf "$WORKDIR"' EXIT` — creates a scratch directory for the temporary summary file and guarantees its cleanup even if the script exits early on an error.
- `SUMMARY_FILE="$SELF_SUMMARY" OUT_FILE="..." ./10-anomalies_auth.sh` — reuses Tasks 10–12 unmodified in behavior, just re-pointed via the environment-variable overrides added for this exact purpose.
- `([$self_total, 1] | max)` as the ratio's denominator — avoids a division-by-zero crash on the (expected, good) case where the self-check finds nothing at all.

## Task - 16-rank_anomalies.sh

What it does: Not one of the numbered 3x01 tasks — a small synthesis step built while working on 3x02's per-rule quality metrics, which needed a single ranked ground-truth file combining every anomaly type this project already detects. It slurps `anomalies_auth.json`, `anomalies_process.json`, `anomalies_network.json`, and `correlated_anomalies.json` (each tolerated as missing), tags every entry with its `source`, converts severity to a numeric score (or reuses a correlated finding's own composite `score`), sorts everything descending, and writes `ranked_anomalies.json` with a 1-based `rank` on each entry. It adds no new detection logic of its own — it only re-packages what Tasks 10–13 already produced.
How to use it: `./16-rank_anomalies.sh` (run after Tasks 10, 11, 12, and 13 have produced their output files)
Commands:

- `python3 -c "..."` with a `$SEVERITY_SCORE` bash variable spliced into the heredoc — keeps the severity-to-number mapping declared once, visibly, at the top of the shell script, even though the transformation logic itself is easier to express in Python than in jq.
- A small `load(name)` helper wrapped in `try/except FileNotFoundError: return []` — lets the script run cleanly even if, say, `anomalies_network.json` was never generated, instead of requiring every upstream task to have run first.
- `[{'host': ..., 'timestamp': ts} for ts in item.get('event_refs', [])]` — normalizes each source's differently-shaped reference list into one common `refs` structure of `{host, timestamp}` pairs, so downstream consumers don't need to know which detector originally produced a given entry.
- `entries.sort(key=lambda e: e['score'], reverse=True)` then `enumerate(entries, start=1)` — a single sort assigns the final `rank`, so ties break by original insertion order (auth, then process, then network, then correlated) rather than arbitrarily.
