# 3x04 – Cross-Platform Detection Analysis

## Task - 0-tool_check.sh
What it does: Verifies `jq`, `yq`, `python3`, `sigma-cli`, `xmllint` and `curl` are on PATH and prints each version; checks that the 5 handoff directories exist; confirms `enriched_events.json` is present and non-empty; counts the Sigma rules in the catalog; verifies the Wazuh export files; and confirms the anchor event matches against `enriched_events.json`. Exits non-zero if any check fails.
How to use it: `./0-tool_check.sh` (uses the `HANDOFF_DIR`/`BASELINE_PKG`/`CATALOG_DIR`/`TRIAGE_PKG`/`ASSETS_DIR`/`WAZUH_EXPORTS` defaults)
Commands:
- `${VAR:-default}` combined with `$HOME` instead of `~` — `~` does not expand inside double quotes in bash, so every directory default uses `$HOME` explicitly.
- `command -v <bin> >/dev/null 2>&1` inside an `if` — shields each binary check from `set -e`, letting the script keep going and accumulate failures in `FAILED` instead of aborting on the first missing tool.
- `${VERSION#prefix}` (parameter-expansion prefix stripping) — used with different prefixes (`jq-`, `Python `, `version v`) because each tool formats its own `--version` output differently.
- `sigma version | cut -d' ' -f1` instead of `sigma --version` — the binary installed by the `sigma-cli` pip package is actually named `sigma`, and it does not accept a `--version` flag; the version only comes out through a dedicated subcommand.
- `jq -c 'select(...)' file | wc -l` over a ~200MB NDJSON file — counts matching events without loading the whole file into memory with `-s`.

## Task - 1-wazuh_workspace.sh
What it does: Reads `index_metadata.json` (index, total documents, time range), `field_mapping.json` (the first 10 field mappings) and `dashboard_credentials.json` (username only); verifies every required file exists under `wazuh_exports/` and `query_results/`; and writes `workspace/workspace_init.json`.
How to use it: `ASSETS_DIR=<dir> ./1-wazuh_workspace.sh`
Commands:
- `python3 -c "print(f'{$N:,}')"` — formats an integer with a thousands separator (`339882` → `339,882`), something plain bash can't do portably.
- `awk -F'\t' '{printf "  %-12s -> %s\n", $1, $2}'` — a literal space before `->`, because `%-12s` alone doesn't guarantee separation once the field is already exactly 12+ characters (printf's padding vanishes in that case).
- `jq -n --argjson total_documents "$N" ...` — injects an already-validated number as JSON (not a string), avoiding stray quotes around a numeric field.
- A fixed list of "required files" walked in a loop, each path tested with `[ -f ... ]` — the final count reflects exactly what was checked, not a generic `ls | wc -l` that would count anything extra sitting in the folder.

## Task - 2-cli_anchor.sh
What it does: Reads the anchor event manifest (host, time window, attacker IPs), filters `enriched_events.json` against those criteria, extracts the first/last matching event, reads the `001_ssh_brute_force.yml` Sigma rule with `yq`, and writes `findings/anchor_cli.json` against the locked schema.
How to use it: `HANDOFF_DIR=<dir> CATALOG_DIR=<dir> ASSETS_DIR=<dir> ./2-cli_anchor.sh`
Commands:
- `test($ips)` with a regex pattern built via `map(gsub("\\."; "\\."))|join("|")` — escapes each IP's dots before joining into an alternation, since `.` in regex matches any character.
- Filtering on `.raw_message | test(...)` instead of `.src_ip == ...` — `src_ip` came back `null` on every `linux_text` record; the attacker's IP only exists inside the raw log line (`Failed password for root from IP ...`).
- `date -u +%Y-%m-%dT%H:%M:%SZ` at the start and end of the script — used both for the schema's ISO 8601 fields and, via `date +%s`, to measure actual execution time in seconds.
- A bash array (`ACTIONS+=(...)`) turned into JSON with `printf '%s\n' "${ACTIONS[@]}" | jq -R . | jq -s .` — converts a shell string list into a JSON array without hand-writing the serialization.

## Task - 3-export_anchor.sh
What it does: Reads `anchor_search_results.json` (hits, query, first/last event) and `anchor_dashboard_trace.json` (click path, estimated time), builds a 5-field comparison from `field_mapping.json`, and writes `findings/anchor_export.json` with the click path as `actions`.
How to use it: `ASSETS_DIR=<dir> ./3-export_anchor.sh`
Commands:
- `jq -r '[.events[]."@timestamp"] | sort | first/last'` — uses `."@timestamp"` (quotes inside the path) because the field name starts with `@`, which is not a valid bare identifier in `jq`.
- `.mappings[] | select(.normalized == $n) | .wazuh` inside a bash loop — looks up 5 specific fields in the 23-entry mapping table, because only those 5 actually appear in the anchor document.
- `jq '.click_path'` used directly as the finding's `actions` array — the task asks that the dashboard investigation's click path substitute the command list as evidence of actions taken.
- `if [ "$DIFF" -ge 0 ]` to decide "faster via export" vs. "slower" — reads `time_to_first_answer_seconds` from the already-written CLI finding (Task 2) to compute the delta without reprocessing anything.

## Task - 4-cli_scenario_a.sh
What it does: Reads the scenario A manifest (host, window, ATT&CK techniques), scopes `enriched_events.json` by host+window, identifies the 3 chain events (LSASS access, dump file creation, SMB connection) by text pattern, and writes `findings/scenario_a_cli.json`.
How to use it: `HANDOFF_DIR=<dir> ASSETS_DIR=<dir> ./4-cli_scenario_a.sh`
Commands:
- Three distinct `contains()` calls (`"lsass.exe accessed by rundll32.exe"`, `"debug.dmp"`, `"10.1.1.10:445"`) instead of filtering on an `event_id` field — the normalized schema has no such field, and the manifest's own `jq` example (which assumes `event_id`) does not work against the real data.
- Filtering on the IOC-specific substring (`10.1.1.10:445`), not "any network connection" — the host has another decoy connection (DNS) in the same window that a generic EID3 filter would also catch.
- `cut -dT -f2 | tr -d Z` — pulls just the time-of-day out of an ISO 8601 timestamp to match the expected output format (`14:22:00Z`), without needing a full date tool for that simple trim.

## Task - 5-cli_scenario_b.sh
What it does: Reads the scenario B manifest, joins host criticality/data classification via `asset_inventory.json`, identifies `p.morales`'s logon, the special-privilege assignment, and the PowerShell bypass execution, and writes `findings/scenario_b_cli.json` with a 2-sentence hypothesis on the TP/FP ambiguity.
How to use it: `HANDOFF_DIR=<dir> ASSETS_DIR=<dir> ./5-cli_scenario_b.sh`
Commands:
- Filter `.user == "p.morales"` combined with `contains("logged on")` — the host has 3 decoy logons in the same minute (other users), so a content-only filter would not be enough.
- `.assets[] | select(.hostname == $h)` over `asset_inventory.json` — the file has a nested structure (`metadata`/`sites`/`assets`), the host record is not at the document root.
- A "2 sentences max" limit on `hypothesis` — a real bug fixed here: concatenating the script's own sentence with the manifest's full `ambiguity_note` (already 2 sentences) produced 3, violating the schema.

## Task - 6-cli_scenario_c.sh
What it does: Filters `network_events.json` for scenario C's src_ip/dst_ip pair, resolves the source IP's network zone by CIDR containment against `network_zones.json`, checks the destination IP's reputation in `ioc_context.json`, orders the beacons and computes the interval between them, and writes `findings/scenario_c_cli.json`.
How to use it: `HANDOFF_DIR=<dir> ASSETS_DIR=<dir> ./6-cli_scenario_c.sh`
Commands:
- `ipaddress.ip_network(cidr)` / `ip in net` in Python, picking the **most specific** (largest prefix) CIDR among all that contain the IP — the `INTERNET` zone (`0.0.0.0/0`) contains every IP, so taking the first match without comparing `prefixlen` would classify everything as `INTERNET`.
- `ioc_context.json` path with a fallback (`$ASSETS_DIR/3x03_assets/...` then `$HOME/3x03_assets/...`) — the literal path from the task text doesn't exist on this sandbox; the real file sits one directory up from what the text describes.
- `.indicators["$ip"]` — the indicators object is a table keyed by the IP itself (not an array), so lookup is direct indexing, not `select()`.
- `while IFS= read -r TS; do ...; done <<< "$LIST"` combined with `date -u -d "$TS" +%s` — converts each timestamp to epoch just to compute the minute gap between consecutive beacons.

## Task - 7-export_scenario_a.sh
What it does: Reads `scenario_a_search_results.json`, filters down to the events that actually form the chain out of the 10 returned by the broad query, reads the dashboard trace and Markdown summary, and writes `findings/scenario_a_export.json` with the time delta against Task 4.
How to use it: `ASSETS_DIR=<dir> ./7-export_scenario_a.sh`
Commands:
- `select(.winlog.event_id==10 or (...==11 and .process.name!=null) or (...==3 and .process.name=="cmd.exe"))` — the broad KQL query returns 10 events, but 2 of them (a decoy EID 11 and a decoy EID 3) share the same `event_id` as the real chain events; the final distinction is by `process.name`, not `event_id`.
- `tr -d '\r' | awk '...'` before extracting a section from the `.md` file — the `dashboard_exports/` files use CRLF line endings, and a lone `\r` on an otherwise "blank" line has non-zero `NF` in awk, so the blank-line filter silently fails without this cleanup.
- `awk '/^## SECTION/{flag=1;next} /^## /{if(flag)exit} flag && NF'` — extracts the content between one Markdown heading and the next, without needing to know how many lines the section has.

## Task - 8-export_scenario_b.sh
What it does: Reads `scenario_b_search_results.json`, extracts host/user/events, checks whether `agent.labels` carries `data_classification` (falling back to `asset_inventory.json` if not), and writes `findings/scenario_b_export.json` noting in `actions` whether the fallback was needed.
How to use it: `HANDOFF_DIR=<dir> ASSETS_DIR=<dir> ./8-export_scenario_b.sh`
Commands:
- `jq '... | has("data_classification")'` — tests for a key's presence (not its value) before deciding whether to use the indexed data or fall back; on this real sandbox the key genuinely wasn't there, so the fallback actually ran.
- `event_refs` filtered by `user.name`/`process.name` — the same gotcha from Task 7 repeats here (multiple logons and multiple EID1s in the raw results), so `event_refs` only includes the 3 relevant events.

## Task - 9-export_scenario_c.sh
What it does: Reads `scenario_c_search_results.json`, confirms `source.zone` is already populated in the document (no fallback needed, unlike Task 8), orders the 5 firewall beacons (excluding the Suricata alert) and computes the interval between them, and writes `findings/scenario_c_export.json`.
How to use it: `ASSETS_DIR=<dir> ./9-export_scenario_c.sh`
Commands:
- `select(._source.full_log | startswith("{") | not)` — splits the 5 firewall flows (CSV-style log) from the 1 Suricata alert (JSON-style log) inside the same events array, using only the first character of `full_log` as the discriminator.
- Reuses the same beacon/interval loop from Task 6, but without the Python CIDR lookup — `source.zone` already comes pre-computed in the indexed document, a real execution-cost difference between the two interfaces for this specific scenario.

## Task - 12-tradeoff_analysis.sh
What it does: Loads the 8 findings, pairs CLI/export by `scenario_id`, computes the time and action-count delta, attributes a cause (from a fixed list of 7 categories) to each advantage, and writes `comparison/tradeoff_table.json` and `.md`.
How to use it: `./12-tradeoff_analysis.sh` (run from the directory containing `findings/`)
Commands:
- `declare -A CAUSES=(...)` — a fixed bash associative array, since cause attribution is analyst judgment about what actually happened in each investigation, not something derivable from the timing numbers alone.
- Incrementally building a JSON array via `jq --argjson row "$ROW_JSON" '. + [$row]'` inside a bash loop — avoids assembling the whole list at once with a single complex `jq` command.

## Task - 13-workflow_comparison.sh
What it does: Aggregates the 8 findings by interface (total/average/median time, actions, fields, event references), computes the confidence distribution, works out the per-scenario delta, and writes `comparison/workflow_comparison.json`.
How to use it: `./13-workflow_comparison.sh`
Commands:
- `def median(arr): ...` — a `jq` function defined right inside the filter expression to compute a median with explicit handling of even vs. odd array length.
- `group_by(.interface) | map(...) | map({(.interface): .}) | add` — turns a grouped array into an object keyed by interface name.
- **Multiplying a string by zero in `jq` returns `null`, not an empty string** — `" " * 0` broke the padding for "wazuh_export" (whose length exactly matched the computed padding); the fix uses `[N, 1] | max` to guarantee at least one space always.
- Replacing `column -t` with plain `printf`/`jq` — the `column` binary doesn't exist on the sandbox's minimized Ubuntu image.

## Task - 15-tool_evaluation_package.sh
What it does: Assembles `tool_evaluation/` with the locked layout (`findings/`, `comparison/`, `playbook/`, `brief/`, `workspace/`, `runtime/`), copying every required file (failing loudly if any is missing or empty), and generates `MANIFEST.json` with path/size/sha256 for each entry.
How to use it: `./15-tool_evaluation_package.sh` (run from the directory holding the subdirectories already produced by earlier tasks)
Commands:
- Fixed bash lists walked in a loop, each file tested with `[ -f ... ] && [ -s ... ]` before copying — guarantees a loud failure on any specific missing file, instead of a generic `cp` that would fail silently or copy extras.
- `find "$DIR" -type f -print0 | sort -z` — null-terminated file listing (safe against spaces in filenames), sorted deterministically before the manifest is built.
- `sha256sum file | cut -d' ' -f1` — pulls just the hash out of `sha256sum`'s default output ("hash  path").
- The original layout also required files from tasks removed from the grading grid (`rules/wazuh/*.xml`, `comparison/questions/*.yml`) — the final package was adjusted to not depend on them, since those tasks no longer exist for this student.

## Task - playbook/tool_agnostic_playbook.md
Concept: A vendor-neutral playbook survives a SIEM swap because it documents the cognitive workflow (filter → aggregation → time window) separately from each interface's execution cost — the same investigative question decomposes the same way in `jq`, Sigma, KQL and Lucene; only "how expensive" each step is changes. The documented "Known Pitfalls" came from real bugs hit during the week (null `src_ip`, missing `event_id`, CRLF in Markdown, `jq` reserving `end` as a keyword), not from theoretical guesswork.

## Task - vendor_brief.md
Concept: A vendor recommendation defended by counted evidence, not opinion, has to admit the limits of its own measurement — in this case, that `time_to_first_answer_seconds` measures script execution time, not a real analyst's dashboard click-through time, and that the two interfaces' `actions` list granularity differs by task design, not by real effort difference.
