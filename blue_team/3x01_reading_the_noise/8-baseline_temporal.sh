#!/bin/bash

set -euo pipefail

BASELINE_DAYS="${BASELINE_DAYS:-7}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LABELED_FILE="$SCRIPT_DIR/labeled_events.json"
OUT_FILE="$SCRIPT_DIR/temporal_profile.json"

set +o pipefail
WSTART=$(jq -r '.timestamp' "$LABELED_FILE" | sort | head -n 1)
set -o pipefail
WEND=$(date -u -d "$WSTART + ${BASELINE_DAYS} days" +"%Y-%m-%dT%H:%M:%SZ")

jq -n --arg wstart "$WSTART" --arg wend "$WEND" --argjson days "$BASELINE_DAYS" '
  reduce (inputs | select(.timestamp >= $wstart and .timestamp < $wend)) as $e
    (
      {hourly: {}, daily: {}};
      ($e.timestamp[11:13]) as $h
      | ($e.timestamp[0:10]) as $d
      | .hourly[$h] = ((.hourly[$h] // 0) + 1)
      | .daily[$d] = ((.daily[$d] // 0) + 1)
    )
  | . as $r
  | (["00","01","02","03","04","05","06","07","08","09","10","11","12","13","14","15","16","17","18","19","20","21","22","23"]) as $hrs
  | {
      window: {start: $wstart, end: $wend, days: $days},
      hourly_avg: (
        $hrs | map({key: ., value: ((($r.hourly[.] // 0) / $days * 100 | round) / 100)}) | from_entries
      ),
      daily_totals: ($r.daily),
      busiest_hour: ($hrs | max_by($r.hourly[.] // 0)),
      quietest_hour: ($hrs | min_by($r.hourly[.] // 0))
    }
' "$LABELED_FILE" > "$OUT_FILE"

busiest=$(jq -r '.busiest_hour' "$OUT_FILE")
quietest=$(jq -r '.quietest_hour' "$OUT_FILE")

printf 'baseline window : %s -> %s\n' "$WSTART" "$WEND"
printf 'busiest hour    : %s:00\n' "$busiest"
printf 'quietest hour   : %s:00\n' "$quietest"
echo "temporal_profile.json written"
