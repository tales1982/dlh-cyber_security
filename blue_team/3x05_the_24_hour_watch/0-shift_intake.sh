#!/bin/bash
set -euo pipefail

CAPSTONE_PACK="${CAPSTONE_PACK:-$HOME/evidence_pack_secondary}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x05_assets/capstone_pack/meta}"
WAZUH_EXPORTS="${WAZUH_EXPORTS:-$HOME/3x05_assets/wazuh_exports}"
SHIFT_WORKSPACE="${SHIFT_WORKSPACE:-$HOME/bt/3x05/shift_pack}"
PIPELINE_BIN="${PIPELINE_BIN:-$HOME/bt/3x00/pipeline/run_pipeline.sh}"
BASELINE_BIN="${BASELINE_BIN:-$HOME/bt/3x01/baseline/build_baseline.sh}"
CATALOG_DIR="${CATALOG_DIR:-$HOME/bt/3x02/catalog}"
TRIAGE_BIN="${TRIAGE_BIN:-$HOME/bt/3x03/triage/triage.sh}"

fail() {
	echo "[intake] FAIL: $1" >&2
	exit 1
}

# --- binaries ---
for BIN in jq python3 yq sigma; do
	command -v "$BIN" >/dev/null 2>&1 || fail "$BIN not found on PATH"
done

JQ_V="$(jq --version)"; JQ_V="${JQ_V#jq-}"
printf "[intake] jq %s OK\n" "$JQ_V"

PY_V="$(python3 --version)"; PY_V="${PY_V#Python }"
printf "[intake] python3 %s OK\n" "$PY_V"

YQ_V="$(yq --version)"; YQ_V="${YQ_V#*version v}"
printf "[intake] yq %s OK\n" "$YQ_V"

SIGMA_V="$(sigma version | cut -d' ' -f1)"
printf "[intake] sigma-cli %s OK\n" "$SIGMA_V"

command -v sha256sum >/dev/null 2>&1 || fail "sha256sum not found on PATH"
printf "[intake] sha256sum OK\n"

# --- prior-project binaries ---
[ -x "$PIPELINE_BIN" ] || fail "PIPELINE_BIN not executable: $PIPELINE_BIN"
printf "[intake] PIPELINE_BIN OK\n"

[ -x "$BASELINE_BIN" ] || fail "BASELINE_BIN not executable: $BASELINE_BIN"
printf "[intake] BASELINE_BIN OK\n"

[ -d "$CATALOG_DIR" ] && [ -r "$CATALOG_DIR" ] || fail "CATALOG_DIR not a readable directory: $CATALOG_DIR"
SIGMA_RULE_COUNT="$(find "$CATALOG_DIR" -type f -iname "*.yml" | wc -l)"
[ "$SIGMA_RULE_COUNT" -ge 1 ] || fail "CATALOG_DIR has no .yml rules: $CATALOG_DIR"
printf "[intake] CATALOG_DIR OK (%s rules)\n" "$SIGMA_RULE_COUNT"

[ -x "$TRIAGE_BIN" ] || fail "TRIAGE_BIN not executable: $TRIAGE_BIN"
printf "[intake] TRIAGE_BIN OK\n"

# --- capstone pack ---
[ -d "$CAPSTONE_PACK" ] || fail "CAPSTONE_PACK not a directory: $CAPSTONE_PACK"
PACK_CONTENTS="$(find "$CAPSTONE_PACK" -maxdepth 1 -type f -o -maxdepth 1 -type d ! -path "$CAPSTONE_PACK" | wc -l)"
[ "$PACK_CONTENTS" -ge 1 ] || fail "CAPSTONE_PACK is empty: $CAPSTONE_PACK"
printf "[intake] CAPSTONE_PACK OK\n"
printf "[intake] CAPSTONE_PACK contents: %s\n" "$(ls "$CAPSTONE_PACK" | tr '\n' ' ')"

# --- asset context files ---
ASSET_FILES=(assets.json ioc_feed.json hc_red7_advisory.md change_tickets.json prior_shift_notes.md)
for F in "${ASSET_FILES[@]}"; do
	[ -f "$ASSETS_DIR/$F" ] || fail "missing $ASSETS_DIR/$F"
done
printf "[intake] ASSETS_DIR: %s meta files OK\n" "${#ASSET_FILES[@]}"

# --- wazuh export files ---
WAZUH_FILES=(incident_A_search_results.json incident_B_search_results.json incident_C_search_results.json campaign_dashboard_summary.md)
for F in "${WAZUH_FILES[@]}"; do
	[ -f "$WAZUH_EXPORTS/$F" ] || fail "missing $WAZUH_EXPORTS/$F"
done
printf "[intake] WAZUH_EXPORTS: %s export files OK\n" "${#WAZUH_FILES[@]}"

# --- ioc feed + advisory ---
IOC_COUNT="$(jq '.iocs | length' "$ASSETS_DIR/ioc_feed.json")"
printf "[intake] ioc_feed.json OK (%s entries)\n" "$IOC_COUNT"

ADVISORY_LINE="$(grep -m1 "HC-RED7" "$ASSETS_DIR/hc_red7_advisory.md" || true)"
[ -n "$ADVISORY_LINE" ] || fail "HC-RED7 not found in advisory"
printf "[intake] advisory HC-RED7 loaded\n"

# --- workspace layout ---
mkdir -p \
	"$SHIFT_WORKSPACE/runtime" \
	"$SHIFT_WORKSPACE/enriched" \
	"$SHIFT_WORKSPACE/alerts" \
	"$SHIFT_WORKSPACE/investigations" \
	"$SHIFT_WORKSPACE/campaign" \
	"$SHIFT_WORKSPACE/reports" \
	"$SHIFT_WORKSPACE/response" \
	"$SHIFT_WORKSPACE/handoff"

touch \
	"$SHIFT_WORKSPACE/MANIFEST.json" \
	"$SHIFT_WORKSPACE/runtime/pipeline_run.json" \
	"$SHIFT_WORKSPACE/runtime/baseline_run.json" \
	"$SHIFT_WORKSPACE/runtime/catalog_run.json" \
	"$SHIFT_WORKSPACE/enriched/enriched_events.jsonl" \
	"$SHIFT_WORKSPACE/enriched/timeline.jsonl" \
	"$SHIFT_WORKSPACE/enriched/baseline.json" \
	"$SHIFT_WORKSPACE/enriched/source_stats.json" \
	"$SHIFT_WORKSPACE/alerts/alert_queue.json" \
	"$SHIFT_WORKSPACE/alerts/shift_briefing.json" \
	"$SHIFT_WORKSPACE/alerts/triage_log.jsonl" \
	"$SHIFT_WORKSPACE/alerts/incidents.json" \
	"$SHIFT_WORKSPACE/investigations/incident_A.json" \
	"$SHIFT_WORKSPACE/investigations/incident_B.json" \
	"$SHIFT_WORKSPACE/investigations/incident_C_cli.json" \
	"$SHIFT_WORKSPACE/investigations/incident_C_export.json" \
	"$SHIFT_WORKSPACE/campaign/campaign_assessment.json" \
	"$SHIFT_WORKSPACE/reports/incident_A.md" \
	"$SHIFT_WORKSPACE/reports/incident_B.md" \
	"$SHIFT_WORKSPACE/reports/incident_C.md" \
	"$SHIFT_WORKSPACE/response/tuning_recommendations.json" \
	"$SHIFT_WORKSPACE/response/containment.json" \
	"$SHIFT_WORKSPACE/response/ioc_package.json" \
	"$SHIFT_WORKSPACE/handoff/shift_handoff.md"

printf "[intake] workspace layout created at %s\n" "$SHIFT_WORKSPACE"

# --- shift_start.json ---
SHIFT_ID="SHIFT-$(date -u +%Y%m%d-%H%M)"
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ANALYST_HOST="$(hostname)"

jq -n \
	--arg shift_id "$SHIFT_ID" \
	--arg analyst_host "$ANALYST_HOST" \
	--arg started_at "$STARTED_AT" \
	--arg jq_v "$JQ_V" \
	--arg py_v "$PY_V" \
	--arg yq_v "$YQ_V" \
	--arg sigma_v "$SIGMA_V" \
	--arg capstone_pack "$CAPSTONE_PACK" \
	--argjson ioc_feed_count "$IOC_COUNT" \
	--arg advisory_cluster_id "HC-RED7" \
	'{
		shift_id: $shift_id,
		analyst_host: $analyst_host,
		started_at: $started_at,
		tools: {
			jq: $jq_v,
			python3: $py_v,
			yq: $yq_v,
			"sigma-cli": $sigma_v,
			sha256sum: "present"
		},
		prior_project_bins: {
			pipeline: true,
			baseline: true,
			catalog: true,
			triage: true
		},
		capstone_pack: $capstone_pack,
		ioc_feed_count: $ioc_feed_count,
		advisory_cluster_id: $advisory_cluster_id,
		wazuh_exports_verified: true
	}' > "$SHIFT_WORKSPACE/runtime/shift_start.json"

printf "[intake] shift_start.json written\n"
