#!/bin/bash

set -euo pipefail

BASELINE_DAYS="${BASELINE_DAYS:-7}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LABELED_FILE="$SCRIPT_DIR/labeled_events.json"
OUT_FILE="$SCRIPT_DIR/baseline_process.json"

set +o pipefail
WSTART=$(jq -r '.timestamp' "$LABELED_FILE" | sort | head -n 1)
set -o pipefail
WEND=$(date -u -d "$WSTART + ${BASELINE_DAYS} days" +"%Y-%m-%dT%H:%M:%SZ")

jq -n --arg wstart "$WSTART" --arg wend "$WEND" '
  def is_process_label: . == "process_start" or . == "process_stop" or . == "child_process_spawn";

  reduce (inputs | select(.timestamp >= $wstart and .timestamp < $wend)) as $e
    (
      {per_host: {}, global: {}, host_sets: {}, pairs: {}};
      ($e.hostname) as $host
      | ($e.process_name) as $pname
      | ($e.user) as $user
      | ($e.timestamp) as $ts
      | (if $host != null and $pname != null and ($e.canonical_label | is_process_label) then
           .per_host[$host][$pname].count = ((.per_host[$host][$pname].count // 0) + 1)
           | .per_host[$host][$pname].first_seen = (
               if .per_host[$host][$pname].first_seen == null then $ts
               elif $ts < .per_host[$host][$pname].first_seen then $ts
               else .per_host[$host][$pname].first_seen end)
           | .per_host[$host][$pname].last_seen = (
               if .per_host[$host][$pname].last_seen == null then $ts
               elif $ts > .per_host[$host][$pname].last_seen then $ts
               else .per_host[$host][$pname].last_seen end)
           | (if $user != null then .per_host[$host][$pname].users[$user] = true else . end)
           | .global[$pname] = ((.global[$pname] // 0) + 1)
           | .host_sets[$pname][$host] = true
         else . end)
      | (if $host != null and ($e.raw_message // "" | test("^Process Create: .+ by .+$")) then
           ($e.raw_message | capture("^Process Create: (?<child>.+) by (?<parent>.+)$")) as $cap
           | .pairs[$host][($cap.parent + "||" + $cap.child)] = {parent: $cap.parent, child: $cap.child}
         else . end)
    )
  | . as $r
  | {
      window: {start: $wstart, end: $wend},
      per_host: (
        $r.per_host | map_values(
          to_entries
          | map({
              process_name: .key,
              count: .value.count,
              first_seen: .value.first_seen,
              last_seen: .value.last_seen,
              users: (.value.users // {} | keys)
            })
          | sort_by(-.count, .process_name)
        )
      ),
      global_top: (
        $r.global | to_entries | sort_by(-.value) | .[0:50]
        | map({process_name: .key, count: .value})
      ),
      rare_processes: (
        $r.host_sets | to_entries
        | map({process_name: .key, host_count: (.value | length), total_count: $r.global[.key]})
        | map(select(.host_count == 1 or .total_count < 5))
        | sort_by(.process_name)
      ),
      parent_child_pairs: (
        $r.pairs | map_values(to_entries | map(.value) | sort_by(.parent, .child))
      )
    }
' "$LABELED_FILE" > "$OUT_FILE"

host_count=$(jq '.per_host | length' "$OUT_FILE")
top_name=$(jq -r '.global_top[0].process_name // "none"' "$OUT_FILE")
top_count=$(jq -r '.global_top[0].count // 0' "$OUT_FILE")
rare_count=$(jq '.rare_processes | length' "$OUT_FILE")
pair_count=$(jq '[.parent_child_pairs[][]] | length' "$OUT_FILE")

printf 'baseline window : %s -> %s\n' "$WSTART" "$WEND"
printf 'processes indexed by host: %s hosts\n' "$host_count"
printf 'global top process    : %s (%s executions)\n' "$top_name" "$top_count"
printf 'rare processes        : %s\n' "$rare_count"
printf 'parent->child pairs   : %s\n' "$pair_count"
echo "baseline_process.json written"
