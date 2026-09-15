#!/bin/bash
set -euo pipefail

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
mkdir -p workspace

META_FILE="$ASSETS_DIR/wazuh_exports/index_metadata.json"
INDEX_NAME="$(jq -r '.source_index' "$META_FILE")"
TOTAL_DOCS="$(jq -r '.total_documents' "$META_FILE")"
TIME_EARLIEST="$(jq -r '.time_range.earliest' "$META_FILE")"
TIME_LATEST="$(jq -r '.time_range.latest' "$META_FILE")"
DOCS_FMT="$(python3 -c "print(f'{$TOTAL_DOCS:,}')")"

printf "mode          : wazuh_export (no live dashboard required)\n"
printf "index         : %s\n" "$INDEX_NAME"
printf "documents     : %s\n" "$DOCS_FMT"
printf "time range    : %s to %s\n" "$TIME_EARLIEST" "$TIME_LATEST"

CRED_FILE="$ASSETS_DIR/dashboard_credentials.json"
USERNAME="$(jq -r '.username' "$CRED_FILE")"
printf "credentials   : %s (from dashboard_credentials.json)\n" "$USERNAME"

MAP_FILE="$ASSETS_DIR/wazuh_exports/field_mapping.json"
MAP_COUNT="$(jq '.mappings | length' "$MAP_FILE")"
printf "field mapping : loaded (%s mappings)\n" "$MAP_COUNT"
jq -r '.mappings[0:10][] | "\(.normalized)\t\(.wazuh)"' "$MAP_FILE" \
	| awk -F'\t' '{printf "  %-12s -> %s\n", $1, $2}'

REQUIRED_FILES=(
	"$ASSETS_DIR/wazuh_exports/field_mapping.json"
	"$ASSETS_DIR/wazuh_exports/index_metadata.json"
	"$ASSETS_DIR/wazuh_exports/anchor_search_results.json"
	"$ASSETS_DIR/wazuh_exports/scenario_a_search_results.json"
	"$ASSETS_DIR/wazuh_exports/scenario_b_search_results.json"
	"$ASSETS_DIR/wazuh_exports/scenario_c_search_results.json"
	"$ASSETS_DIR/wazuh_exports/anchor_dashboard_trace.json"
	"$ASSETS_DIR/wazuh_exports/scenario_a_dashboard_trace.json"
	"$ASSETS_DIR/wazuh_exports/scenario_b_dashboard_trace.json"
	"$ASSETS_DIR/wazuh_exports/scenario_c_dashboard_trace.json"
	"$ASSETS_DIR/query_results/kql_anchor_query.json"
	"$ASSETS_DIR/query_results/lucene_anchor_query.json"
	"$ASSETS_DIR/query_results/kql_scenario_a.json"
	"$ASSETS_DIR/query_results/kql_scenario_b.json"
	"$ASSETS_DIR/query_results/kql_scenario_c.json"
)

FILES_OK=1
VERIFIED_COUNT=0
for FILE_PATH in "${REQUIRED_FILES[@]}"; do
	if [ -f "$FILE_PATH" ]; then
		VERIFIED_COUNT=$((VERIFIED_COUNT + 1))
	else
		echo "error: missing required export file: $FILE_PATH" >&2
		FILES_OK=0
	fi
done

if [ "$FILES_OK" -eq 1 ]; then
	printf "export files  : all present (%s files verified)\n" "$VERIFIED_COUNT"
else
	printf "export files  : MISSING FILES (%s/%s verified)\n" "$VERIFIED_COUNT" "${#REQUIRED_FILES[@]}"
	exit 1
fi

INITIALIZED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

jq -n \
	--arg source_index "$INDEX_NAME" \
	--argjson total_documents "$TOTAL_DOCS" \
	--arg earliest "$TIME_EARLIEST" \
	--arg latest "$TIME_LATEST" \
	--arg initialized_at "$INITIALIZED_AT" \
	'{
		mode: "wazuh_export",
		source_index: $source_index,
		total_documents: $total_documents,
		time_range: {earliest: $earliest, latest: $latest},
		export_files_verified: true,
		field_mapping_loaded: true,
		initialized_at: $initialized_at
	}' > workspace/workspace_init.json

printf "workspace_init.json written\n"
