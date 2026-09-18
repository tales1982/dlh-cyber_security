#!/bin/bash
set -euo pipefail

SHIFT_WORKSPACE="${SHIFT_WORKSPACE:-$HOME/bt/3x05/shift_pack}"
CATALOG_DIR="${CATALOG_DIR:-$HOME/bt/3x02/catalog}"

fail() {
	echo "[detect] FAIL: $1" >&2
	exit 1
}

PIPELINE_RUN_FILE="$SHIFT_WORKSPACE/runtime/pipeline_run.json"
[ -s "$PIPELINE_RUN_FILE" ] || fail "pipeline_run.json missing or empty"
[ "$(jq -r '.exit_status' "$PIPELINE_RUN_FILE")" = "0" ] || fail "pipeline exit_status was not 0"
printf "[detect] pipeline check: OK\n"

RULES_DIR="$CATALOG_DIR/rules/sigma"
mapfile -t RULE_FILES < <(find "$RULES_DIR" -maxdepth 1 -name '*.yml' | sort)
RULES_TOTAL="${#RULE_FILES[@]}"
[ "$RULES_TOTAL" -ge 1 ] || fail "no .yml rule files found under $RULES_DIR"
printf "[detect] catalog loaded: %s rules\n" "$RULES_TOTAL"

ENRICHED_FILE=""
for CANDIDATE in "$SHIFT_WORKSPACE/enriched/enriched_events.jsonl" "$SHIFT_WORKSPACE/enriched/enriched_events.json"; do
	[ -s "$CANDIDATE" ] && ENRICHED_FILE="$CANDIDATE" && break
done
[ -n "$ENRICHED_FILE" ] || fail "no enriched events file found"

RUNNER="$HOME/bt/3x02/catalog/3-sigma_runner.sh"
[ -x "$RUNNER" ] || fail "sigma runner not executable: $RUNNER"

# Point the runner's BASELINE_PKG at the artifacts 2-run_baselines.sh already
# produced, so canonical_label enrichment and the rare-process check inside
# the runner have real data instead of degrading to empty defaults.
BASELINE_PKG_DIR="$SHIFT_WORKSPACE/.sigma_baseline_pkg"
mkdir -p "$BASELINE_PKG_DIR/baselines"
BASELINE_SRC_DIR="$HOME/bt/3x01/baseline"
ln -sf "$BASELINE_SRC_DIR/event_taxonomy.json" "$BASELINE_PKG_DIR/baselines/event_taxonomy.json"
ln -sf "$BASELINE_SRC_DIR/baseline_process.json" "$BASELINE_PKG_DIR/baselines/baseline_process.json"
export BASELINE_PKG="$BASELINE_PKG_DIR"

# Evaluation window: the last day of the pack (the actual "shift"), pulled
# from the baseline run so it is not hardcoded to a specific pack.
EVAL_START=""
EVAL_END=""
if [ -s "$SHIFT_WORKSPACE/runtime/baseline_run.json" ] && [ -s "$BASELINE_SRC_DIR/baseline_summary.json" ]; then
	EVAL_START="$(jq -r '.evaluation_window.start' "$BASELINE_SRC_DIR/baseline_summary.json")"
	EVAL_END="$(jq -r '.evaluation_window.end' "$BASELINE_SRC_DIR/baseline_summary.json")"
fi

printf "[detect] invoking detection runner\n"

STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
RAW_DIR="$SHIFT_WORKSPACE/.rule_matches"
mkdir -p "$RAW_DIR"

RULES_FIRED=0
for RULE_FILE in "${RULE_FILES[@]}"; do
	RULE_NAME="$(basename "$RULE_FILE" .yml)"
	RUNNER_ARGS=("$RULE_FILE" "$ENRICHED_FILE")
	[ -n "$EVAL_START" ] && [ "$EVAL_START" != "null" ] && RUNNER_ARGS+=(--window "${EVAL_START},${EVAL_END}")
	if "$RUNNER" "${RUNNER_ARGS[@]}" > "$RAW_DIR/$RULE_NAME.json" 2>"$RAW_DIR/$RULE_NAME.err"; then
		MATCH_COUNT="$(jq '.match_count // 0' "$RAW_DIR/$RULE_NAME.json" 2>/dev/null || echo 0)"
		[ "$MATCH_COUNT" -gt 0 ] && RULES_FIRED=$((RULES_FIRED + 1))
	else
		echo "[detect] warning: rule $RULE_NAME failed — see $RAW_DIR/$RULE_NAME.err" >&2
	fi
done

# --- assemble alert_queue.json from every rule's matches -------------------
ALERTS_JSON="$(jq -s -c '
	[.[] | . as $r | ($r.matches // [])[] | {
		alert_id: ($r.rule_id + "-" + (.event_ref | gsub("[^0-9]"; ""))),
		rule_id: $r.rule_id,
		rule_title: $r.rule_title,
		severity: $r.level,
		host: (.hostname // "unknown" | ascii_downcase),
		timestamp: .timestamp,
		event_ref: .event_ref
	}]
' "$RAW_DIR"/*.json 2>/dev/null || echo "[]")"

ALERTS_TOTAL="$(echo "$ALERTS_JSON" | jq 'length')"
[ "$ALERTS_TOTAL" -gt 0 ] || fail "alerts_total is zero — catalog or enriched events are broken"

echo "$ALERTS_JSON" > "$SHIFT_WORKSPACE/alerts/alert_queue.json"

SEVERITY_JSON="$(echo "$ALERTS_JSON" | jq '
	{critical: 0, high: 0, medium: 0, low: 0}
	+ (group_by(.severity) | map({(.[0].severity | if . == "informational" then "low" else . end): length}) | add // {})
')"

BY_RULE_JSON="$(echo "$ALERTS_JSON" | jq '
	group_by(.rule_id) | map({key: .[0].rule_id, value: length}) | from_entries
')"

printf "[detect] matched: %s rules / %s alerts\n" "$RULES_FIRED" "$ALERTS_TOTAL"
echo "$SEVERITY_JSON" | jq -r '"[detect] severity critical=\(.critical) high=\(.high) medium=\(.medium) low=\(.low)"'
printf "[detect] top rules:\n"
echo "$BY_RULE_JSON" | jq -r 'to_entries | sort_by(-.value) | .[] | "  \(.key)\t: \(.value) alerts"'

ENDED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

jq -n \
	--argjson catalog_rules_total "$RULES_TOTAL" \
	--argjson catalog_rules_fired "$RULES_FIRED" \
	--argjson alerts_total "$ALERTS_TOTAL" \
	--argjson alerts_by_severity "$SEVERITY_JSON" \
	--argjson alerts_by_rule "$BY_RULE_JSON" \
	--arg started_at "$STARTED_AT" \
	--arg ended_at "$ENDED_AT" \
	'{
		catalog_rules_total: $catalog_rules_total,
		catalog_rules_fired: $catalog_rules_fired,
		alerts_total: $alerts_total,
		alerts_by_severity: $alerts_by_severity,
		alerts_by_rule: $alerts_by_rule,
		started_at: $started_at,
		ended_at: $ended_at,
		exit_status: 0
	}' > "$SHIFT_WORKSPACE/runtime/catalog_run.json"

printf "[detect] alert_queue.json written\n"
printf "[detect] catalog_run.json written\n"
