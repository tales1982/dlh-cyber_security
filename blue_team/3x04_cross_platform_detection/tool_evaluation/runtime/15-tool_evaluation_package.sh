#!/bin/bash
set -euo pipefail

PACKAGE_DIR="tool_evaluation"
rm -rf "$PACKAGE_DIR"
mkdir -p "$PACKAGE_DIR/findings" "$PACKAGE_DIR/comparison" "$PACKAGE_DIR/playbook" "$PACKAGE_DIR/brief" "$PACKAGE_DIR/workspace" "$PACKAGE_DIR/runtime"

FINDING_FILES=(
	anchor_cli.json anchor_export.json
	scenario_a_cli.json scenario_a_export.json
	scenario_b_cli.json scenario_b_export.json
	scenario_c_cli.json scenario_c_export.json
)
echo "copying findings   ... ${#FINDING_FILES[@]} files"
for F in "${FINDING_FILES[@]}"; do
	SRC="findings/$F"
	[ -f "$SRC" ] && [ -s "$SRC" ] || { echo "error: missing or empty required file: $SRC" >&2; exit 1; }
	cp "$SRC" "$PACKAGE_DIR/findings/$F"
done

COMPARISON_FILES=(tradeoff_table.json tradeoff_table.md workflow_comparison.json)
echo "copying comparison ... ${#COMPARISON_FILES[@]} files"
for F in "${COMPARISON_FILES[@]}"; do
	SRC="comparison/$F"
	[ -f "$SRC" ] && [ -s "$SRC" ] || { echo "error: missing or empty required file: $SRC" >&2; exit 1; }
	cp "$SRC" "$PACKAGE_DIR/comparison/$F"
done

echo "copying playbook   ... 1 file"
SRC="playbook/tool_agnostic_playbook.md"
[ -f "$SRC" ] && [ -s "$SRC" ] || { echo "error: missing or empty required file: $SRC" >&2; exit 1; }
cp "$SRC" "$PACKAGE_DIR/playbook/tool_agnostic_playbook.md"

echo "copying brief      ... 1 file"
SRC="vendor_brief.md"
[ -f "$SRC" ] && [ -s "$SRC" ] || { echo "error: missing or empty required file: $SRC" >&2; exit 1; }
cp "$SRC" "$PACKAGE_DIR/brief/vendor_brief.md"

echo "copying workspace  ... 1 file"
SRC="workspace/workspace_init.json"
[ -f "$SRC" ] && [ -s "$SRC" ] || { echo "error: missing or empty required file: $SRC" >&2; exit 1; }
cp "$SRC" "$PACKAGE_DIR/workspace/workspace_init.json"

RUNTIME_SCRIPTS=(
	0-tool_check.sh
	1-wazuh_workspace.sh
	2-cli_anchor.sh
	3-export_anchor.sh
	4-cli_scenario_a.sh
	5-cli_scenario_b.sh
	6-cli_scenario_c.sh
	7-export_scenario_a.sh
	8-export_scenario_b.sh
	9-export_scenario_c.sh
	12-tradeoff_analysis.sh
	13-workflow_comparison.sh
	15-tool_evaluation_package.sh
)
echo "copying runtime    ... ${#RUNTIME_SCRIPTS[@]} files"
for F in "${RUNTIME_SCRIPTS[@]}"; do
	[ -f "$F" ] && [ -s "$F" ] || { echo "error: missing or empty required file: $F" >&2; exit 1; }
	cp "$F" "$PACKAGE_DIR/runtime/$F"
done

MANIFEST_ENTRIES="[]"
while IFS= read -r -d '' FILE_PATH; do
	REL_PATH="${FILE_PATH#"$PACKAGE_DIR"/}"
	SIZE="$(stat -c%s "$FILE_PATH")"
	SHA="$(sha256sum "$FILE_PATH" | cut -d' ' -f1)"
	ENTRY="$(jq -n --arg path "$REL_PATH" --argjson size "$SIZE" --arg sha256 "$SHA" '{path: $path, size: $size, sha256: $sha256}')"
	MANIFEST_ENTRIES="$(echo "$MANIFEST_ENTRIES" | jq --argjson e "$ENTRY" '. + [$e]')"
done < <(find "$PACKAGE_DIR" -type f -print0 | sort -z)

GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ENTRY_COUNT="$(echo "$MANIFEST_ENTRIES" | jq 'length')"

jq -n --argjson entries "$MANIFEST_ENTRIES" --arg generated_at "$GENERATED_AT" \
	'{generated_at: $generated_at, entries: $entries}' > "$PACKAGE_DIR/MANIFEST.json"

printf "MANIFEST.json      : %s entries\n" "$ENTRY_COUNT"

FAIL=0
for F in "${FINDING_FILES[@]}"; do [ -s "$PACKAGE_DIR/findings/$F" ] || FAIL=1; done
[ -s "$PACKAGE_DIR/playbook/tool_agnostic_playbook.md" ] || FAIL=1
[ -s "$PACKAGE_DIR/brief/vendor_brief.md" ] || FAIL=1

if [ "$FAIL" -eq 0 ]; then
	printf "sanity check       : ok\n"
	printf "tool_evaluation/ ready\n"
else
	printf "sanity check       : FAILED\n" >&2
	exit 1
fi
