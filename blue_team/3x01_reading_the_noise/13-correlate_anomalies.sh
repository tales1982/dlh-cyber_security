#!/bin/bash

set -euo pipefail

# score = (distinct sources involved) + (distinct anomaly_types * 2 bonus)
#         then multiplied by the host's asset criticality (LOW=1, MEDIUM=2, HIGH=3, CRITICAL=4, unknown=1)
CORR_WINDOW_SECONDS="${CORR_WINDOW_SECONDS:-300}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUTH_FILE="$SCRIPT_DIR/anomalies_auth.json"
PROCESS_FILE="$SCRIPT_DIR/anomalies_process.json"
NETWORK_FILE="$SCRIPT_DIR/anomalies_network.json"
LABELED_FILE="$SCRIPT_DIR/labeled_events.json"
OUT_FILE="$SCRIPT_DIR/correlated_anomalies.json"

for f in "$AUTH_FILE" "$PROCESS_FILE" "$NETWORK_FILE"; do
  if [[ ! -f "$f" ]]; then
    echo "missing required input: $f" >&2
    exit 1
  fi
done

HOST_CRITICALITY=$(jq -c '
  reduce (inputs | select(.hostname != null and .asset.criticality != null)) as $e
    ({}; .[$e.hostname] = (.[$e.hostname] // $e.asset.criticality))
' "$LABELED_FILE")

jq -n \
  --argjson window "$CORR_WINDOW_SECONDS" \
  --argjson crit "$HOST_CRITICALITY" \
  --slurpfile auth "$AUTH_FILE" \
  --slurpfile process "$PROCESS_FILE" \
  --slurpfile network "$NETWORK_FILE" '
  def crit_multiplier: {LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4}[.] // 1;
  def to_epoch: strptime("%Y-%m-%dT%H:%M:%SZ") | mktime;

  def cluster(events):
    reduce events[] as $e (
      [];
      if length == 0 then [[$e]]
      else
        (.[-1][-1].epoch) as $last_epoch
        | if ($e.epoch - $last_epoch) <= $window then (.[0:-1] + [(.[-1] + [$e])])
          else . + [[$e]]
          end
      end
    );

  (
    [($auth[0][] | . + {source: "auth"})]
    + [($process[0][] | . + {source: "process"})]
    + [($network[0][] | . + {source: "network"})]
  ) as $all
  | ($all | map(. + {epoch: (.timestamp | to_epoch)})) as $tagged
  | ($tagged | group_by(.host) | map(select(.[0].host != null))) as $by_host
  | (
      [
        $by_host[] as $group
        | (cluster($group | sort_by(.epoch))[] | select(length >= 2)) as $c
        | ($c[0].host) as $host
        | ($c | map(.timestamp) | sort) as $ts
        | ($c | map(.source) | unique) as $sources
        | ($c | map(.anomaly_type) | unique) as $types
        | (($crit[$host] // "LOW") | crit_multiplier) as $mult
        | (($sources | length) + (($types | length) * 2)) as $base_score
        | {
            correlation_id: ("corr-" + (($ts[0] | to_epoch) | tostring) + "-" + ($host | @base64 | .[0:8])),
            host: $host,
            window_start: $ts[0],
            window_end: $ts[-1],
            sources_involved: $sources,
            anomaly_types: $types,
            member_refs: ($c | map({source: .source, anomaly_type: .anomaly_type, timestamp: .timestamp, host: .host})),
            score: ($base_score * $mult)
          }
      ]
    )
  | sort_by(-.score)
' > "$OUT_FILE"

single_source=$(jq --slurpfile a "$AUTH_FILE" --slurpfile p "$PROCESS_FILE" --slurpfile n "$NETWORK_FILE" -n '($a[0]|length) + ($p[0]|length) + ($n[0]|length)')
correlated=$(jq 'length' "$OUT_FILE")
multi_host=$(jq '[.[].host] | unique | length' "$OUT_FILE")
max_score=$(jq '[.[].score] | if length > 0 then max else 0 end' "$OUT_FILE")

printf 'single-source anomalies  : %s\n' "$single_source"
printf 'correlated findings      : %s\n' "$correlated"
printf 'multi-host findings      : %s\n' "$multi_host"
printf 'max score                : %s\n' "$max_score"
echo "correlated_anomalies.json written"
