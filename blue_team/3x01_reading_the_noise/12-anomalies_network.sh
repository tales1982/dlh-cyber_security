#!/bin/bash

set -euo pipefail

# --- severity rubric ---
SEV_UNKNOWN_DEST="medium"
SEV_UNKNOWN_PORT="low"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUMMARY_FILE="${SUMMARY_FILE:-$SCRIPT_DIR/baseline_summary.json}"
LABELED_FILE="$SCRIPT_DIR/labeled_events.json"
OUT_FILE="${OUT_FILE:-$SCRIPT_DIR/anomalies_network.json}"

BSTART=$(jq -r '.baseline_window.start' "$SUMMARY_FILE")
BEND=$(jq -r '.baseline_window.end' "$SUMMARY_FILE")
ESTART=$(jq -r '.evaluation_window.start' "$SUMMARY_FILE")
EEND=$(jq -r '.evaluation_window.end' "$SUMMARY_FILE")

# Only windows_json "Network connection: <proc> -> <ip>:<port>" events carry a
# hostname, so host-scoped network baselining/detection is limited to those.
NET_REGEX='^Network connection: .+ -> (?<ip>[0-9.]+):(?<port>[0-9]+)$'

BASELINE_KNOWN=$(jq -n --arg bstart "$BSTART" --arg bend "$BEND" --arg re "$NET_REGEX" '
  reduce (inputs | select(.timestamp >= $bstart and .timestamp < $bend and .hostname != null and (.raw_message // "" | test($re)))) as $e
    (
      {};
      ($e.raw_message | capture($re)) as $cap
      | .[$e.hostname].ips[$cap.ip] = true
      | .[$e.hostname].ports[$cap.port] = true
    )
' "$LABELED_FILE")

jq -n \
  --arg estart "$ESTART" --arg eend "$EEND" --arg re "$NET_REGEX" \
  --arg sev_dest "$SEV_UNKNOWN_DEST" --arg sev_port "$SEV_UNKNOWN_PORT" \
  --argjson known "$BASELINE_KNOWN" '
  def host_ips($h): ($known[$h].ips // {} | keys);
  def host_ports($h): ($known[$h].ports // {} | keys);

  reduce (inputs | select(.timestamp >= $estart and .timestamp < $eend and .hostname != null and (.raw_message // "" | test($re)))) as $e
    (
      {dest: {}, port: {}};
      ($e.raw_message | capture($re)) as $cap
      | ($e.hostname) as $host
      | (if (host_ips($host) | index($cap.ip) | not) then
           .dest[$host + "||" + $cap.ip].events = ((.dest[$host + "||" + $cap.ip].events // []) + [$e.timestamp])
           | .dest[$host + "||" + $cap.ip].port = $cap.port
         else . end)
      | (if (host_ports($host) | index($cap.port) | not) then
           .port[$host + "||" + $cap.port].events = ((.port[$host + "||" + $cap.port].events // []) + [$e.timestamp])
           | .port[$host + "||" + $cap.port].ip = $cap.ip
         else . end)
    )
  | . as $r
  | (
      [
        ($r.dest | to_entries | map(
           (.key | split("||")) as $hk
           | {
               timestamp: (.value.events | sort | .[0]),
               host: $hk[0],
               dst_ip: $hk[1],
               dst_port: (.value.port | tonumber),
               anomaly_type: "unknown_destination_for_host",
               severity: $sev_dest,
               event_refs: (.value.events | sort)
             }
        )),
        ($r.port | to_entries | map(
           (.key | split("||")) as $hk
           | {
               timestamp: (.value.events | sort | .[0]),
               host: $hk[0],
               dst_ip: .value.ip,
               dst_port: ($hk[1] | tonumber),
               anomaly_type: "unknown_port_for_host",
               severity: $sev_port,
               event_refs: (.value.events | sort)
             }
        ))
      ] | flatten
    )
  | sort_by(.timestamp)
' "$LABELED_FILE" > "$OUT_FILE"

total=$(jq 'length' "$OUT_FILE")
c_dest=$(jq '[.[] | select(.anomaly_type=="unknown_destination_for_host")] | length' "$OUT_FILE")
c_port=$(jq '[.[] | select(.anomaly_type=="unknown_port_for_host")] | length' "$OUT_FILE")

printf 'evaluation window : %s -> %s\n' "$ESTART" "$EEND"
printf 'unknown_destination_for_host : %s\n' "$c_dest"
printf 'unknown_port_for_host        : %s\n' "$c_port"
printf 'total anomalies              : %s\n' "$total"
echo "anomalies_network.json written"
