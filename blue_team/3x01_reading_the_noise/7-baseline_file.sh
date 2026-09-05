#!/bin/bash

set -euo pipefail

BASELINE_DAYS="${BASELINE_DAYS:-7}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LABELED_FILE="$SCRIPT_DIR/labeled_events.json"
OUT_FILE="$SCRIPT_DIR/baseline_file.json"

set +o pipefail
WSTART=$(jq -r '.timestamp' "$LABELED_FILE" | sort | head -n 1)
set -o pipefail
WEND=$(date -u -d "$WSTART + ${BASELINE_DAYS} days" +"%Y-%m-%dT%H:%M:%SZ")

jq -n --arg wstart "$WSTART" --arg wend "$WEND" '
  def is_file_label: . == "file_read_sensitive" or . == "file_write_sensitive" or . == "file_permission_change";

  reduce (inputs | select(.timestamp >= $wstart and .timestamp < $wend and (.canonical_label | is_file_label))) as $e
    (
      {per_host: {}, totals: {}};
      ($e.hostname) as $host
      | ($e.canonical_label) as $label
      | .totals[$label] = ((.totals[$label] // 0) + 1)
      | (if $host != null then
           .per_host[$host][$label] = ((.per_host[$host][$label] // 0) + 1)
         else . end)
    )
  | . as $r
  | {
      window: {start: $wstart, end: $wend},
      per_host: (
        $r.per_host | map_values({
          file_read_sensitive: (.file_read_sensitive // 0),
          file_write_sensitive: (.file_write_sensitive // 0),
          file_permission_change: (.file_permission_change // 0)
        })
      ),
      totals: {
        file_read_sensitive: ($r.totals.file_read_sensitive // 0),
        file_write_sensitive: ($r.totals.file_write_sensitive // 0),
        file_permission_change: ($r.totals.file_permission_change // 0)
      }
    }
' "$LABELED_FILE" > "$OUT_FILE"

hosts=$(jq '.per_host | length' "$OUT_FILE")
reads=$(jq '.totals.file_read_sensitive' "$OUT_FILE")
writes=$(jq '.totals.file_write_sensitive' "$OUT_FILE")
perms=$(jq '.totals.file_permission_change' "$OUT_FILE")

printf 'baseline window : %s -> %s\n' "$WSTART" "$WEND"
printf 'hosts with file activity : %s\n' "$hosts"
printf 'reads=%s writes=%s permission_changes=%s\n' "$reads" "$writes" "$perms"
echo "baseline_file.json written"
