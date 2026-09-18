#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACK_ROOT="${1:-${CAPSTONE_PACK:-$HOME/evidence_pack_primary}}"

cd "$SCRIPT_DIR"

echo "[pipeline] running against $PACK_ROOT"
./0-source_inventory.sh "$PACK_ROOT"
./2-windows_parse.sh "$PACK_ROOT"
./3-linux_parse.sh "$PACK_ROOT"
./5-normalize.sh
./6-network_normalize.sh "$PACK_ROOT"
./8-data_quality.sh
./9-enrich.sh "$PACK_ROOT"
echo "[pipeline] done: $SCRIPT_DIR/enriched_events.json"
