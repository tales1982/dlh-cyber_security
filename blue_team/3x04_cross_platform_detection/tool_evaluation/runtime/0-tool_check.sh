#!/bin/bash
set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
CATALOG_DIR="${CATALOG_DIR:-$HOME/3x02_package/detection_catalog}"
TRIAGE_PKG="${TRIAGE_PKG:-$HOME/3x03_package/triage_package}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
WAZUH_EXPORTS="${WAZUH_EXPORTS:-$HOME/3x04_assets/wazuh_exports}"
FAILED=0

if command -v jq >/dev/null 2>&1; then
	JQ_VERSION="$(jq --version)"
	JQ_VERSION="${JQ_VERSION#jq-}"
	printf "jq          : %s\n" "$JQ_VERSION"
else
	printf "jq          : NOT FOUND\n"
	FAILED=1
fi

if command -v python3 >/dev/null 2>&1; then
	PYTHON_VERSION="$(python3 --version)"
	PYTHON_VERSION="${PYTHON_VERSION#Python }"
	printf "python3     : %s\n" "$PYTHON_VERSION"
else
	printf "python3     : NOT FOUND\n"
	FAILED=1
fi
if command -v xmllint >/dev/null 2>&1; then
	XMLLINT_VERSION="$(xmllint --version 2>&1 | head -n1)"
	XMLLINT_VERSION="${XMLLINT_VERSION#*version }"
	printf "xmllint     : %s\n" "$XMLLINT_VERSION"
else
	printf "xmllint     : NOT FOUND\n"
	FAILED=1
fi
if command -v curl >/dev/null 2>&1; then
	CURL_VERSION="$(curl --version 2>&1 | head -n1 | cut -d' ' -f2)"
	printf "curl        : %s\n" "$CURL_VERSION"
else
	printf "curl        : NOT FOUND\n"
	FAILED=1
fi
if command -v yq >/dev/null 2>&1; then
	YQ_VERSION="$(yq --version)"
	YQ_VERSION="${YQ_VERSION#*version v}"
	printf "yq          : %s\n" "$YQ_VERSION"
else
	printf "yq          : NOT FOUND\n"
	FAILED=1
fi
if command -v sigma >/dev/null 2>&1; then
	SIGMA_VERSION="$(sigma version | cut -d' ' -f1)"
	printf "sigma-cli   : %s\n" "$SIGMA_VERSION"
else
	printf "sigma-cli   : NOT FOUND\n"
	FAILED=1
fi

for VAR_NAME in HANDOFF_DIR BASELINE_PKG CATALOG_DIR TRIAGE_PKG ASSETS_DIR; do
	VAR_VALUE="${!VAR_NAME}"
	if [ ! -d "$VAR_VALUE" ]; then
		echo "error: $VAR_NAME NAO existe: $VAR_VALUE" >&2
		FAILED=1
	fi
done

ENRICHED_FILE="$HANDOFF_DIR/data/enriched_events.json"
if [ -f "$ENRICHED_FILE" ] && [ -s "$ENRICHED_FILE" ]; then
	printf "handoff     : ok (enriched_events.json present)\n"
else
	echo "error: $ENRICHED_FILE missing or empty" >&2
	FAILED=1
fi

SIGMA_DIR="$CATALOG_DIR/rules/sigma"
if [ -d "$SIGMA_DIR" ]; then
	SIGMA_COUNT="$(find "$SIGMA_DIR" -type f \( -iname "*.yml" -o -iname "*.yaml" \) | wc -l)"
	printf "catalog     : ok (%s sigma rules)\n" "$SIGMA_COUNT"
else
	echo "error: $SIGMA_DIR not found" >&2
	FAILED=1
fi

WAZUH_OK=1
[ -f "$ASSETS_DIR/wazuh_exports/field_mapping.json" ] || WAZUH_OK=0
[ -f "$ASSETS_DIR/wazuh_exports/index_metadata.json" ] || WAZUH_OK=0
for SCENARIO in anchor scenario_a scenario_b scenario_c; do
	[ -f "$ASSETS_DIR/wazuh_exports/${SCENARIO}_search_results.json" ] || WAZUH_OK=0
	[ -f "$ASSETS_DIR/wazuh_exports/${SCENARIO}_dashboard_trace.json" ] || WAZUH_OK=0
done
if [ "$WAZUH_OK" -eq 1 ]; then
	printf "wazuh_exports : ok (field_mapping, index_metadata, 4 search_results, 4 dashboard_traces)\n"
else
	echo "error: missing wazuh export files under $ASSETS_DIR/wazuh_exports" >&2
	FAILED=1
fi

ANCHOR_FILE="$ASSETS_DIR/anchor_event.json"
if [ -f "$ANCHOR_FILE" ]; then
	TARGET_HOST="$(jq -r '.target_host' "$ANCHOR_FILE")"
	WINDOW_START="$(jq -r '.time_window.start' "$ANCHOR_FILE")"
	WINDOW_END="$(jq -r '.time_window.end' "$ANCHOR_FILE")"
	MATCH_COUNT="$(jq -c --arg host "$TARGET_HOST" --arg start "$WINDOW_START" --arg window_end "$WINDOW_END" \
		'select(.hostname == $host and .timestamp >= $start and .timestamp <= $window_end)' \
		"$ENRICHED_FILE" | wc -l)"
	if [ "$MATCH_COUNT" -ge 1 ]; then
		printf "anchor      : ok (%s matched in enriched_events.json)\n" "$TARGET_HOST"
	else
		echo "error: no events matched anchor scenario in enriched_events.json" >&2
		FAILED=1
	fi
else
	echo "error: $ANCHOR_FILE not found" >&2
	FAILED=1
fi

if [ "$FAILED" -eq 0 ]; then
	printf "all checks  : passed\n"
else
	printf "all checks  : failed\n"
fi

exit "$FAILED"
