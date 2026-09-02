#!/bin/bash

set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
DATA_FILE=$HANDOFF_DIR/data/enriched_events.json

verb="${1:-help}"
shift || true

case "$verb" in
    help)
        cat <<'EOF'
query_toolkit.sh <verb> [options]
  filter   emit matching records as ndjson
  top      top N values of a field
  distinct distinct values of a field
  count    number of matching records
  window   bucketed counts by time window
  help     this message
EOF
        ;;
    filter)
        opt_source=""
        opt_host=""
        opt_category=""
        opt_from=""
        opt_to=""
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --source)
                    opt_source="$2"
                    shift 2
                    ;;
                --host)
                    opt_host="$2"
                    shift 2
                    ;;
                --category)
                    opt_category="$2"
                    shift 2
                    ;;
                --from)
                    opt_from="$2"
                    shift 2
                    ;;
                --to)
                    opt_to="$2"
                    shift 2
                    ;;
                *)
                    echo "opcao desconhecida: $1" >&2
                    exit 1
                    ;;
            esac
        done
        echo "source=$opt_source host=$opt_host category=$opt_category from=$opt_from to=$opt_to" >&2
        ;;
    *)
        echo "comando desconhecido: $verb" >&2
        exit 1
        ;;
esac