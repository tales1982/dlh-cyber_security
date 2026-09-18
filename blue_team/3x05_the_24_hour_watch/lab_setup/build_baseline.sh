#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "[baseline] building against \$HANDOFF_DIR=${HANDOFF_DIR:-unset}"
./2-query_toolkit.sh
./3-event_taxonomy.sh
./4-baseline_auth.sh
./5-baseline_process.sh
./6-baseline_network.sh
./7-baseline_file.sh
./8-baseline_temporal.sh
./9-baseline_summary.sh
echo "[baseline] done: $SCRIPT_DIR/baseline_summary.json"
