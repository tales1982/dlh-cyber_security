#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUTH_FILE="$SCRIPT_DIR/baseline_auth.json"
PROCESS_FILE="$SCRIPT_DIR/baseline_process.json"
NETWORK_FILE="$SCRIPT_DIR/baseline_network.json"
FILE_FILE="$SCRIPT_DIR/baseline_file.json"
TEMPORAL_FILE="$SCRIPT_DIR/temporal_profile.json"
OUT_FILE="$SCRIPT_DIR/baseline_summary.json"

for f in "$AUTH_FILE" "$PROCESS_FILE" "$NETWORK_FILE" "$FILE_FILE" "$TEMPORAL_FILE"; do
  if [[ ! -f "$f" ]]; then
    echo "missing required input: $f" >&2
    exit 1
  fi
done

GENERATED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

jq -n \
  --arg version "1.0" \
  --arg generated_at "$GENERATED_AT" \
  --slurpfile auth "$AUTH_FILE" \
  --slurpfile process "$PROCESS_FILE" \
  --slurpfile network "$NETWORK_FILE" \
  --slurpfile file "$FILE_FILE" \
  --slurpfile temporal "$TEMPORAL_FILE" '
  ($auth[0]) as $auth
  | ($process[0]) as $process
  | ($network[0]) as $network
  | ($file[0]) as $file
  | ($temporal[0]) as $temporal
  | ($auth.window.start) as $bstart
  | ($auth.window.end) as $bend
  | (($bend | strptime("%Y-%m-%dT%H:%M:%SZ") | mktime) - ($bstart | strptime("%Y-%m-%dT%H:%M:%SZ") | mktime)) as $bsecs
  | ($bend) as $estart
  | ($bend | strptime("%Y-%m-%dT%H:%M:%SZ") | mktime | (. + 86400) | strftime("%Y-%m-%dT%H:%M:%SZ")) as $eend
  | (
      [($auth.per_host // {} | keys[]), ($process.per_host // {} | keys[]), ($file.per_host // {} | keys[])]
      | flatten | unique | sort
    ) as $hosts
  | {
      version: $version,
      generated_at: $generated_at,
      baseline_window: {
        start: $bstart,
        end: $bend,
        duration_days: ($bsecs / 86400)
      },
      evaluation_window: {
        start: $estart,
        end: $eend,
        duration_hours: 24
      },
      host_inventory: $hosts,
      auth: $auth,
      process: $process,
      network: $network,
      file: $file,
      temporal: $temporal,
      thresholds: {
        failure_rate_multiplier: {
          value: 3,
          comment: "baseline max_failures_1h_window from a single src_ip, multiplied by 3, marks a burst as anomalous; chosen so normal variance (up to ~3x the worst clean-window hour) does not alert"
        },
        privilege_escalation_surge_threshold: {
          value: 2,
          comment: "hosts with zero privilege_escalation events in the baseline are expected to have none; more than 2 in a single evaluation day is treated as a surge rather than isolated noise"
        },
        unknown_process_penalty: {
          value: 5,
          comment: "score weight added per process seen on a host that never appeared in that host per_host baseline; placeholder for the composite ranking used by later process anomaly scripts"
        },
        unknown_port_penalty: {
          value: 4,
          comment: "score weight added per destination port not present in known_dst_ports; placeholder for the composite ranking used by later network anomaly scripts"
        }
      }
    }
' > "$OUT_FILE"

version=$(jq -r '.version' "$OUT_FILE")
bstart=$(jq -r '.baseline_window.start' "$OUT_FILE")
bend=$(jq -r '.baseline_window.end' "$OUT_FILE")
bdays=$(jq -r '.baseline_window.duration_days' "$OUT_FILE")
estart=$(jq -r '.evaluation_window.start' "$OUT_FILE")
eend=$(jq -r '.evaluation_window.end' "$OUT_FILE")
hosts=$(jq '.host_inventory | length' "$OUT_FILE")

printf 'version           : %s\n' "$version"
printf 'baseline window   : %s -> %s  (%s days)\n' "$bstart" "$bend" "$bdays"
printf 'evaluation window : %s -> %s  (24h)\n' "$estart" "$eend"
printf 'hosts             : %s\n' "$hosts"
printf 'sections included : auth, process, network, file, temporal, thresholds\n'
echo "baseline_summary.json written"
