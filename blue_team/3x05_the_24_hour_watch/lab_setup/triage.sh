#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "[triage] running against \$CATALOG_DIR=${CATALOG_DIR:-unset}"
./0-queue_assessment.sh
./2-context_assembly.sh
./3-triage_clearcut_tp.sh
./4-triage_clearcut_fp.sh
./6-triage_ambiguous_auth.sh
./7-triage_ambiguous_proc_net.sh
./8-triage_correlation.sh
./11-incident_assembly.sh
echo "[triage] done: $SCRIPT_DIR/incidents.json"
