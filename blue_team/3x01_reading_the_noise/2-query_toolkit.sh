#!/bin/bash

set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
DATA_FILE="$HANDOFF_DIR/data/enriched_events.json"

opt_source=""
opt_host=""
opt_category=""
opt_from=""
opt_to=""
opt_field=""
opt_limit="10"
opt_bucket=""

# shellcheck disable=SC2016
SELECT_JQ='($src == "" or .source_type == $src)
  and ($host == "" or .hostname == $host)
  and ($cat == "" or .event_category == $cat)
  and ($from == "" or .timestamp >= $from)
  and ($to == "" or .timestamp <= $to)'

parse_opts() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --source)   opt_source="$2";   shift 2 ;;
            --host)     opt_host="$2";     shift 2 ;;
            --category) opt_category="$2"; shift 2 ;;
            --from)     opt_from="$2";     shift 2 ;;
            --to)       opt_to="$2";       shift 2 ;;
            --field)    opt_field="$2";    shift 2 ;;
            --limit)    opt_limit="$2";    shift 2 ;;
            --bucket)   opt_bucket="$2";   shift 2 ;;
            *)
                echo "unknown option: $1" >&2
                exit 1
                ;;
        esac
    done
}

select_records() {
    jq -c --arg src "$opt_source" --arg host "$opt_host" --arg cat "$opt_category" \
          --arg from "$opt_from" --arg to "$opt_to" \
          "select($SELECT_JQ)" "$DATA_FILE"
}

field_stream() {
    jq -r --arg src "$opt_source" --arg host "$opt_host" --arg cat "$opt_category" \
          --arg from "$opt_from" --arg to "$opt_to" --arg field "$1" \
          "select($SELECT_JQ)
           | getpath(\$field | split(\".\"))
           | select(. != null)
           | tostring" \
          "$DATA_FILE"
}

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
        parse_opts "$@"
        select_records
        ;;
    top)
        parse_opts "$@"
        if [[ -z "$opt_field" ]]; then
            echo "top: --field is required" >&2
            exit 1
        fi
        set +o pipefail
        field_stream "$opt_field" \
            | sort \
            | uniq -c \
            | sort -k1,1rn \
            | head -n "$opt_limit" \
            | awk '{c=$1; $1=""; sub(/^ /,""); printf "%s\t%s\n", $0, c}'
        set -o pipefail
        ;;
    distinct)
        parse_opts "$@"
        if [[ -z "$opt_field" ]]; then
            echo "distinct: --field is required" >&2
            exit 1
        fi
        field_stream "$opt_field" | sort -u
        ;;
    count)
        parse_opts "$@"
        select_records | wc -l
        ;;
    window)
        parse_opts "$@"
        case "$opt_bucket" in
            hour) trunc_len=13 ;;
            day)  trunc_len=10 ;;
            *)
                echo "window: --bucket must be 'hour' or 'day'" >&2
                exit 1
                ;;
        esac
        bucket_field="${opt_field:-timestamp}"
        jq -r --arg src "$opt_source" --arg host "$opt_host" --arg cat "$opt_category" \
              --arg from "$opt_from" --arg to "$opt_to" --arg field "$bucket_field" \
              --argjson n "$trunc_len" \
              "select($SELECT_JQ)
               | getpath(\$field | split(\".\"))
               | select(. != null)
               | .[0:\$n]" \
              "$DATA_FILE" \
            | sort \
            | uniq -c \
            | sort -k2,2 \
            | awk '{c=$1; $1=""; sub(/^ /,""); printf "%s\t%s\n", $0, c}'
        ;;
    *)
        echo "unknown command: $verb" >&2
        exit 1
        ;;
esac
