#!/bin/bash

set -euo pipefail

BASELINE_DAYS="${BASELINE_DAYS:-7}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LABELED_FILE="$SCRIPT_DIR/labeled_events.json"
OUT_FILE="$SCRIPT_DIR/baseline_network.json"

set +o pipefail
WSTART=$(jq -r '.timestamp' "$LABELED_FILE" | sort | head -n 1)
set -o pipefail
WEND=$(date -u -d "$WSTART + ${BASELINE_DAYS} days" +"%Y-%m-%dT%H:%M:%SZ")

# firewall/pcap events carry no hostname, only src_ip, so network baselining
# here is keyed by src_ip rather than by host.
jq -n --arg wstart "$WSTART" --arg wend "$WEND" '
  reduce (inputs | select(.timestamp >= $wstart and .timestamp < $wend and (.canonical_label | test("^network_")))) as $e
    (
      {per_src_ip: {}, ports: {}, destinations: {}, alert_count: 0};
      ($e.src_ip) as $ip
      | ($e.canonical_label) as $label
      | (if $label == "network_alert" then .alert_count += 1 else . end)
      | (if $ip != null then
           .per_src_ip[$ip][$label] = ((.per_src_ip[$ip][$label] // 0) + 1)
           | (if $e.dst_port != null then
                .per_src_ip[$ip].known_dst_ports[($e.dst_port | tostring)] = true
                | .ports[($e.dst_port | tostring)] = ((.ports[($e.dst_port | tostring)] // 0) + 1)
              else . end)
         else . end)
      | (if $e.dst_ip != null then
           .destinations[$e.dst_ip] = ((.destinations[$e.dst_ip] // 0) + 1)
         else . end)
    )
  | . as $r
  | {
      window: {start: $wstart, end: $wend},
      per_src_ip: (
        $r.per_src_ip | map_values(
          . as $v
          | {
              network_connection_outbound: (.network_connection_outbound // 0),
              network_connection_inbound: (.network_connection_inbound // 0),
              network_blocked: (.network_blocked // 0),
              known_dst_ports: (.known_dst_ports // {} | keys | map(tonumber) | sort)
            }
        )
      ),
      known_dst_ports: ($r.ports | keys | map(tonumber) | sort),
      top_destinations: ($r.destinations | to_entries | sort_by(-.value) | .[0:20] | map({dst_ip: .key, count: .value})),
      alert_count: $r.alert_count
    }
' "$LABELED_FILE" > "$OUT_FILE"

ips=$(jq '.per_src_ip | length' "$OUT_FILE")
ports=$(jq '.known_dst_ports | length' "$OUT_FILE")
alerts=$(jq '.alert_count' "$OUT_FILE")

printf 'baseline window : %s -> %s\n' "$WSTART" "$WEND"
printf 'src_ips indexed : %s\n' "$ips"
printf 'known dst ports : %s\n' "$ports"
printf 'network alerts  : %s\n' "$alerts"
echo "baseline_network.json written"
