#!/bin/bash
set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
export HANDOFF_DIR BASELINE_PKG

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNNER="$SCRIPT_DIR/3-sigma_runner.sh"
RULES_DIR="rules/sigma"
SUMMARY_FILE="$BASELINE_PKG/baselines/baseline_summary.json"
OUTPUT_FILE="fp_baseline.json"
TUNE_THRESHOLD=10

if [[ ! -x "$RUNNER" ]]; then
    echo "error: runner not found or not executable: $RUNNER" >&2
    exit 1
fi

if [[ ! -f "$SUMMARY_FILE" ]]; then
    echo "error: baseline summary not found: $SUMMARY_FILE" >&2
    exit 1
fi

if [[ ! -d "$RULES_DIR" ]]; then
    echo "error: rules directory not found: $RULES_DIR (run from the project root)" >&2
    exit 1
fi

mapfile -t RULE_FILES < <(find "$RULES_DIR" -maxdepth 1 -name '*.yml' | sort)

if [[ "${#RULE_FILES[@]}" -eq 0 ]]; then
    echo "error: no rule files found under $RULES_DIR" >&2
    exit 1
fi

read -r WINDOW_START WINDOW_END DURATION_DAYS <<< "$(python3 -c "
import json
with open('$SUMMARY_FILE') as f:
    summary = json.load(f)
window = summary.get('baseline_window', {})
print(window['start'], window['end'], window.get('duration_days') or 7)
")"

DISPLAY_END=$(python3 -c "
from datetime import datetime, timedelta
end = datetime.fromisoformat('$WINDOW_END'.replace('Z', '+00:00'))
print((end - timedelta(days=1)).date().isoformat())
")
DISPLAY_START=$(python3 -c "
from datetime import datetime
print(datetime.fromisoformat('$WINDOW_START'.replace('Z', '+00:00')).date().isoformat())
")

echo "evaluating ${#RULE_FILES[@]} rules against baseline window $DISPLAY_START -> $DISPLAY_END"

RESULTS_JSON="[]"
for rule_file in "${RULE_FILES[@]}"; do
    rule_meta=$(python3 -c "
import json, yaml
with open('$rule_file') as f:
    rule = yaml.safe_load(f)
print(json.dumps({'id': rule['id'], 'title': rule['title'], 'level': rule['level']}))
")
    fp_count=$("$RUNNER" "$rule_file" --window "$WINDOW_START,$WINDOW_END" --count-only)

    RESULTS_JSON=$(python3 -c "
import json, sys

results = json.loads(sys.argv[1])
meta = json.loads(sys.argv[2])
fp_count = int(sys.argv[3])
duration_days = float(sys.argv[4]) or 1.0
rule_path = sys.argv[5]

results.append({
    'rule_file': rule_path,
    'rule_id': meta['id'],
    'rule_title': meta['title'],
    'level': meta['level'],
    'fp_count': fp_count,
    'baseline_window_start': sys.argv[6],
    'baseline_window_end': sys.argv[7],
    'fp_rate_per_day': round(fp_count / duration_days, 3),
})
print(json.dumps(results))
" "$RESULTS_JSON" "$rule_meta" "$fp_count" "$DURATION_DAYS" "$rule_file" "$WINDOW_START" "$WINDOW_END")
done

echo "$RESULTS_JSON" | python3 -c "
import json, sys

results = json.load(sys.stdin)
persisted = [{k: v for k, v in entry.items() if k != 'rule_file'} for entry in results]
with open('$OUTPUT_FILE', 'w') as f:
    json.dump(persisted, f, indent=2)
    f.write('\n')

for entry in sorted(results, key=lambda r: r['fp_count'], reverse=True):
    name = entry['rule_file'].split('/')[-1]
    parts = name[:-4].split('_', 1)
    number = parts[0] if len(parts) == 2 and parts[0].isdigit() else '???'
    short_name = parts[1] if len(parts) == 2 else name[:-4]
    tune_marker = '   [TUNE]' if entry['fp_count'] > $TUNE_THRESHOLD else ''
    print(f\"  {number} {short_name:<30} fp={entry['fp_count']:3d}{tune_marker}\")
"

echo "$OUTPUT_FILE written"
