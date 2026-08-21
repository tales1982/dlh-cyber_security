#!/bin/bash
#
# 9-suricata_analysis.sh
#
# MedDefense Health Systems - Perimeter and Network Defense (2x04)
#
# Replays a PCAP through Suricata and turns eve.json into something a Tier
# 1 analyst can triage in a minute instead of reading dozens of alerts one
# by one: grouped by signature, ranked by source/destination, classified
# by kind. The ruleset decides what fires; this script only reads it.
#
# Usage: sudo ./9-suricata_analysis.sh [pcap]

set -uo pipefail

PCAP="${1:-/home/analyst/MedDefense_Lab/PCAPs/mixed_traffic.pcap}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
OUT_JSON="suricata_alerts.json"

resolve_input() {
    local name="$1" candidate
    for candidate in "./${name}" "${SCRIPT_DIR}/${name}" "${SCRIPT_DIR}/../${name}"; do
        [ -f "$candidate" ] && { echo "$candidate"; return 0; }
    done
    echo "$name"
}
YAML="$(resolve_input suricata.yaml)"
CATEGORIES_JSON="$(resolve_input signature_categories.json)"

if [ ! -f "$PCAP" ]; then
    echo "error: pcap not found: $PCAP" >&2
    exit 1
fi
if [ ! -f "$YAML" ]; then
    echo "error: cannot find suricata.yaml (run 8-suricata_setup.sh first)" >&2
    exit 1
fi

STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
RUN_DIR="$(mktemp -d)"
trap 'rm -rf "$RUN_DIR"' EXIT

# Run suricata -c ./suricata.yaml -r <pcap> -l <tmpdir> and wait for
# completion ($YAML resolves to ./suricata.yaml when run from this
# directory, same as 8-suricata_setup.sh, but also falls back to the
# script's own directory so this still works when invoked from elsewhere).
suricata -c "$YAML" -r "$PCAP" -l "$RUN_DIR" >/dev/null 2>&1
FINISHED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if [ ! -f "$RUN_DIR/eve.json" ]; then
    echo "error: suricata produced no eve.json - check suricata.yaml / pcap path" >&2
    exit 1
fi

ALERTS_JSON="$(jq -nc '[inputs | select(.event_type=="alert")]' "$RUN_DIR/eve.json" 2>/dev/null)"
[ -z "$ALERTS_JSON" ] && ALERTS_JSON="[]"

CATEGORIES="{}"
[ -f "$CATEGORIES_JSON" ] && CATEGORIES="$(cat "$CATEGORIES_JSON")"

jq -n \
    --arg pcap "$PCAP" --arg started "$STARTED_AT" --arg finished "$FINISHED_AT" \
    --argjson alerts_raw "$ALERTS_JSON" --argjson categories "$CATEGORIES" \
    '
    ($alerts_raw | map({
        timestamp: .timestamp,
        src_ip: .src_ip, src_port: .src_port,
        dst_ip: .dest_ip, dst_port: .dest_port,
        proto: .proto,
        signature: .alert.signature,
        signature_id: .alert.signature_id,
        category: .alert.category,
        severity: .alert.severity,
        classification: ($categories[.alert.signature] // "other")
    })) as $alerts
    |
    {
      pcap: $pcap,
      started_at: $started,
      finished_at: $finished,
      total_alerts: ($alerts | length),
      unique_signatures: ([$alerts[].signature] | unique | length),
      severity_distribution: ($alerts | group_by(.severity) | map({key: (.[0].severity | tostring), value: length}) | from_entries),
      by_category: ($alerts | group_by(.classification) | map({key: .[0].classification, value: length}) | from_entries),
      by_signature: ($alerts | group_by(.signature) | map({signature: .[0].signature, signature_id: .[0].signature_id, count: length}) | sort_by(-.count)),
      top_sources: ($alerts | group_by(.src_ip) | map({ip: .[0].src_ip, count: length}) | sort_by(-.count) | .[0:10]),
      top_destinations: ($alerts | group_by(.dst_ip) | map({ip: .[0].dst_ip, count: length}) | sort_by(-.count) | .[0:10]),
      alerts: $alerts
    }
    ' > "$OUT_JSON"

echo "PCAP: $PCAP"
echo "Total alerts: $(jq '.total_alerts' "$OUT_JSON")   Unique signatures: $(jq '.unique_signatures' "$OUT_JSON")"
echo "By category: $(jq -c '.by_category' "$OUT_JSON")"
echo "Report saved to: $OUT_JSON"
