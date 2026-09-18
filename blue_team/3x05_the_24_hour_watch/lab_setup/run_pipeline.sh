#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACK_ROOT="${1:-${CAPSTONE_PACK:-$HOME/evidence_pack_primary}}"
OUTPUT_DIR="${2:-$SCRIPT_DIR}"

mkdir -p "$OUTPUT_DIR"
cp "$SCRIPT_DIR/event_schema.json" "$OUTPUT_DIR/event_schema.json"
cd "$OUTPUT_DIR"

echo "[pipeline] stage 0 source_inventory  ..."
"$SCRIPT_DIR/0-source_inventory.sh" "$PACK_ROOT"
echo "[pipeline] stage 2 windows_parse     ..."
"$SCRIPT_DIR/2-windows_parse.sh" "$PACK_ROOT"
echo "[pipeline] stage 3 linux_parse       ..."
"$SCRIPT_DIR/3-linux_parse.sh" "$PACK_ROOT"
echo "[pipeline] stage 5 normalize         ..."
"$SCRIPT_DIR/5-normalize.sh"
echo "[pipeline] stage 6 network_normalize ..."
"$SCRIPT_DIR/6-network_normalize.sh" "$PACK_ROOT"
echo "[pipeline] stage 8 data_quality      ..."
"$SCRIPT_DIR/8-data_quality.sh"
echo "[pipeline] stage 9 enrich            ..."
"$SCRIPT_DIR/9-enrich.sh" "$PACK_ROOT"

echo "[pipeline] stage 10 timeline         ..."
mv enriched_events.json enriched_events.jsonl
paste -d'\t' <(jq -r '.timestamp' enriched_events.jsonl) enriched_events.jsonl \
	| sort -t$'\t' -k1,1 -S 256M \
	| cut -f2- > timeline.jsonl

echo "[pipeline] stage 11 source_stats     ..."
jq -r '.source_type // "unknown"' enriched_events.jsonl | sort | uniq -c \
	| awk '{print $2, $1}' \
	| jq -R -s 'split("\n") | map(select(length > 0) | split(" ") | {(.[0]): (.[1] | tonumber)}) | add' \
	> source_stats.json

echo "[pipeline] done: $OUTPUT_DIR"
