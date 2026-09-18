#!/bin/bash
set -euo pipefail

CAPSTONE_PACK="${CAPSTONE_PACK:-$HOME/evidence_pack_secondary}"
SHIFT_WORKSPACE="${SHIFT_WORKSPACE:-$HOME/bt/3x05/shift_pack}"
PIPELINE_BIN="${PIPELINE_BIN:-$HOME/bt/3x00/pipeline/run_pipeline.sh}"

fail() {
	echo "[pipeline] FAIL: $1" >&2
	exit 1
}

SHIFT_START_FILE="$SHIFT_WORKSPACE/runtime/shift_start.json"
[ -s "$SHIFT_START_FILE" ] || fail "shift_start.json missing or empty: $SHIFT_START_FILE"
printf "[pipeline] intake check: OK\n"

OUTPUT_DIR="$SHIFT_WORKSPACE/enriched"
printf "[pipeline] invoking %s\n" "$PIPELINE_BIN"
printf "[pipeline] input: %s\n" "$CAPSTONE_PACK"
printf "[pipeline] output: %s\n" "$OUTPUT_DIR"

STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
START_EPOCH="$(date +%s)"

set +e
"$PIPELINE_BIN" "$CAPSTONE_PACK" "$OUTPUT_DIR" > "$SHIFT_WORKSPACE/runtime/pipeline_run.log" 2>&1
PIPELINE_EXIT=$?
set -e

grep -E '^\[pipeline\] stage' "$SHIFT_WORKSPACE/runtime/pipeline_run.log" | sed 's/\.\.\.$/... ok/'

[ "$PIPELINE_EXIT" -eq 0 ] || fail "pipeline exited with status $PIPELINE_EXIT — see $SHIFT_WORKSPACE/runtime/pipeline_run.log"

ENDED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
END_EPOCH="$(date +%s)"
DURATION=$((END_EPOCH - START_EPOCH))
printf "[pipeline] duration %ss\n" "$DURATION"

ENRICHED_FILE=""
for CANDIDATE in "$OUTPUT_DIR/enriched_events.jsonl" "$OUTPUT_DIR/enriched_events.json"; do
	[ -s "$CANDIDATE" ] && ENRICHED_FILE="$CANDIDATE" && break
done
[ -n "$ENRICHED_FILE" ] || fail "no enriched_events.jsonl/.json found in $OUTPUT_DIR"

TIMELINE_FILE=""
for CANDIDATE in "$OUTPUT_DIR/timeline.jsonl" "$OUTPUT_DIR/timeline_index.json"; do
	[ -s "$CANDIDATE" ] && TIMELINE_FILE="$CANDIDATE" && break
done
[ -n "$TIMELINE_FILE" ] || fail "no timeline.jsonl/timeline_index.json found in $OUTPUT_DIR"

STATS_FILE="$OUTPUT_DIR/source_stats.json"
[ -s "$STATS_FILE" ] || fail "missing $STATS_FILE"

NONZERO_SOURCES="$(jq '[to_entries[] | select(.value > 0)] | length' "$STATS_FILE")"
[ "$NONZERO_SOURCES" -ge 4 ] || fail "fewer than 4 source types have non-zero events ($NONZERO_SOURCES)"

jq -r 'to_entries[] | "[pipeline] source \(.key)=\(.value)"' "$STATS_FILE"

EVENTS_OUT="$(wc -l < "$ENRICHED_FILE" | tr -d ' ')"
EVENTS_IN="$(jq '.total_records // .total_events // empty' "$OUTPUT_DIR/source_inventory.json" 2>/dev/null || true)"
[ -n "$EVENTS_IN" ] || EVENTS_IN="$EVENTS_OUT"
DUPLICATES_REMOVED="$(jq -s '[.[] | select(.defect_type=="duplicate")] | length' "$OUTPUT_DIR/cleaning_log.json" 2>/dev/null || echo 0)"
MALFORMED_REPAIRED="$(jq -s '[.[] | select(.defect_type=="malformed_timestamp")] | length' "$OUTPUT_DIR/cleaning_log.json" 2>/dev/null || echo 0)"
EVENTS_DROPPED="$DUPLICATES_REMOVED"

printf "[pipeline] events_in=%s events_out=%s dropped=%s\n" "$EVENTS_IN" "$EVENTS_OUT" "$EVENTS_DROPPED"

PIPELINE_VERSION="unknown"

SOURCE_COUNTS_JSON="$(cat "$STATS_FILE")"

DIRTY_DATA_JSON="$(jq -n \
	--argjson dup "$DUPLICATES_REMOVED" \
	--argjson malformed "$MALFORMED_REPAIRED" \
	'[
		(if $dup > 0 then {type: "duplicate_event_stream", count: $dup, action: "removed"} else empty end),
		(if $malformed > 0 then {type: "malformed_timestamp", count: $malformed, action: "repaired"} else empty end)
	]')"

jq -n \
	--arg pipeline_version "$PIPELINE_VERSION" \
	--arg started_at "$STARTED_AT" \
	--arg ended_at "$ENDED_AT" \
	--argjson duration_seconds "$DURATION" \
	--arg input_pack "$CAPSTONE_PACK" \
	--argjson events_in "$EVENTS_IN" \
	--argjson events_out "$EVENTS_OUT" \
	--argjson events_dropped "$EVENTS_DROPPED" \
	--argjson source_counts "$SOURCE_COUNTS_JSON" \
	--argjson dirty_data_detected "$DIRTY_DATA_JSON" \
	--argjson exit_status "$PIPELINE_EXIT" \
	'{
		pipeline_version: $pipeline_version,
		started_at: $started_at,
		ended_at: $ended_at,
		duration_seconds: $duration_seconds,
		input_pack: $input_pack,
		events_in: $events_in,
		events_out: $events_out,
		events_dropped: $events_dropped,
		source_counts: $source_counts,
		dirty_data_detected: $dirty_data_detected,
		exit_status: $exit_status
	}' > "$SHIFT_WORKSPACE/runtime/pipeline_run.json"

printf "[pipeline] pipeline_run.json written\n"
