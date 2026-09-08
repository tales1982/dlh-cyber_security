#!/bin/bash
set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
export HANDOFF_DIR BASELINE_PKG

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNNER="$SCRIPT_DIR/3-sigma_runner.sh"
RULES_DIR="rules/sigma"
TUNED_DIR="rules/sigma/tuned"
SUMMARY_FILE="$BASELINE_PKG/baselines/baseline_summary.json"
RANKED_ANOMALIES_FILE="$BASELINE_PKG/anomalies/ranked_anomalies.json"
LABELED_EVENTS_FILE="$BASELINE_PKG/taxonomy/labeled_events.json"
FP_BASELINE_FILE="fp_baseline.json"
OUTPUT_FILE="rule_quality.json"

for f in "$SUMMARY_FILE" "$RANKED_ANOMALIES_FILE" "$LABELED_EVENTS_FILE" "$FP_BASELINE_FILE"; do
    if [[ ! -f "$f" ]]; then
        echo "error: required input not found: $f" >&2
        exit 1
    fi
done

if [[ ! -d "$RULES_DIR" ]]; then
    echo "error: rules directory not found: $RULES_DIR (run from the project root)" >&2
    exit 1
fi

mapfile -t BASE_RULE_FILES < <(find "$RULES_DIR" -maxdepth 1 -name '*.yml' | sort)
if [[ "${#BASE_RULE_FILES[@]}" -eq 0 ]]; then
    echo "error: no rule files found under $RULES_DIR" >&2
    exit 1
fi

ACTIVE_RULE_FILES=()
for rule_file in "${BASE_RULE_FILES[@]}"; do
    tuned_candidate="$TUNED_DIR/$(basename "$rule_file")"
    if [[ -f "$tuned_candidate" ]]; then
        ACTIVE_RULE_FILES+=("$tuned_candidate")
    else
        ACTIVE_RULE_FILES+=("$rule_file")
    fi
done

read -r EVAL_START EVAL_END <<< "$(python3 -c "
import json
with open('$SUMMARY_FILE') as f:
    summary = json.load(f)
window = summary.get('evaluation_window', {})
print(window['start'], window['end'])
")"

echo "evaluating ${#ACTIVE_RULE_FILES[@]} rules against labeled ground truth"

# --- ground truth: (hostname, timestamp) refs from ranked_anomalies.json,
# resolved against labeled_events.json to attach canonical_label so fn_count
# can be scoped to "ground truth events of the same category" per rule. ---
python3 -c "
import json

with open('$RANKED_ANOMALIES_FILE') as f:
    ranked = json.load(f)

ref_keys = set()
for entry in ranked:
    for ref in entry.get('refs', []):
        host, ts = ref.get('host'), ref.get('timestamp')
        if host and ts:
            ref_keys.add((host, ts))

resolved = []
with open('$LABELED_EVENTS_FILE') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        record = json.loads(line)
        key = (record.get('hostname'), record.get('timestamp'))
        if key in ref_keys:
            resolved.append({
                'hostname': key[0],
                'timestamp': key[1],
                'canonical_label': record.get('canonical_label'),
            })

with open('.ground_truth.json', 'w') as f:
    json.dump(resolved, f)
print(f'ground truth: {len(ref_keys)} refs, {len(resolved)} resolved via labeled_events.json', file=__import__('sys').stderr)
"

RESULTS_JSON="[]"
for rule_file in "${ACTIVE_RULE_FILES[@]}"; do
    matches_json=$("$RUNNER" "$rule_file" --window "$EVAL_START,$EVAL_END")

    RESULTS_JSON=$(python3 -c "
import json, sys, yaml

results = json.loads(sys.argv[1])
rule_file = sys.argv[2]
run_output = json.loads(sys.argv[3])

with open('.ground_truth.json') as f:
    ground_truth = json.load(f)
with open('$FP_BASELINE_FILE') as f:
    fp_baseline = {e['rule_id']: e['fp_count'] for e in json.load(f)}
with open(rule_file) as f:
    rule = yaml.safe_load(f)

# Category resolution: prefer canonical_label values literally referenced in
# the rule's own detection selections (this covers rule 001 exactly, with no
# hardcoding). Rules that select on other fields (event_id/LogonType,
# process_name/raw_message) fall back to a small logsource->category table,
# since that is the only generic signal the rule declares about what kind of
# event it targets.
LOGSOURCE_CATEGORY_FALLBACK = {
    ('service', 'auth'): {'login_failure', 'login_success'},
    ('service', 'security'): {'login_success', 'login_failure', 'privilege_escalation'},
    ('category', 'process_creation'): {'child_process_spawn', 'process_start'},
}

def selection_dicts(detection):
    for key, value in detection.items():
        if key in ('condition', 'timeframe'):
            continue
        if isinstance(value, dict):
            yield value
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    yield item

target_categories = set()
for sel in selection_dicts(rule['detection']):
    for field_spec, value_spec in sel.items():
        field = field_spec.split('|', 1)[0]
        if field == 'canonical_label':
            values = value_spec if isinstance(value_spec, list) else [value_spec]
            target_categories.update(values)

if not target_categories:
    logsource = rule.get('logsource', {})
    for key, value in logsource.items():
        target_categories.update(LOGSOURCE_CATEGORY_FALLBACK.get((key, value), set()))

if not target_categories:
    target_categories = {g['canonical_label'] for g in ground_truth}

category_refs = {
    (g['hostname'], g['timestamp'])
    for g in ground_truth
    if g['canonical_label'] in target_categories
}
all_ground_truth_refs = {(g['hostname'], g['timestamp']) for g in ground_truth}

matches = run_output.get('matches', [])
match_refs = [(m['hostname'], m['timestamp']) for m in matches]

tp_refs = {r for r in match_refs if r in all_ground_truth_refs}
tp_count = sum(1 for r in match_refs if r in all_ground_truth_refs)
non_intersecting = sum(1 for r in match_refs if r not in all_ground_truth_refs)
fp_count = non_intersecting + fp_baseline.get(rule['id'], 0)
fn_count = len(category_refs - tp_refs)

precision = tp_count / (tp_count + fp_count) if (tp_count + fp_count) > 0 else 0.0
recall = tp_count / (tp_count + fn_count) if (tp_count + fn_count) > 0 else 0.0
f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

results.append({
    'rule_file': rule_file,
    'rule_id': rule['id'],
    'rule_title': rule['title'],
    'level': rule['level'],
    'tp_count': tp_count,
    'fp_count': fp_count,
    'fn_count': fn_count,
    'precision': round(precision, 4),
    'recall': round(recall, 4),
    'f1': round(f1, 4),
    'target_categories': sorted(target_categories),
})
print(json.dumps(results))
" "$RESULTS_JSON" "$rule_file" "$matches_json")
done

rm -f .ground_truth.json

echo "$RESULTS_JSON" | python3 -c "
import json, sys

results = json.load(sys.stdin)
persisted = [{k: v for k, v in e.items() if k != 'rule_file'} for e in results]
with open('$OUTPUT_FILE', 'w') as f:
    json.dump(persisted, f, indent=2)
    f.write('\n')

def label(entry):
    name = entry['rule_file'].split('/')[-1]
    parts = name[:-4].split('_', 1)
    number = parts[0] if len(parts) == 2 and parts[0].isdigit() else '???'
    short_name = parts[1] if len(parts) == 2 else name[:-4]
    return number, short_name

ranked = sorted(results, key=lambda r: r['f1'], reverse=True)

print('strongest')
for entry in ranked[:5]:
    number, short_name = label(entry)
    marker = '   [STRONG]' if entry['f1'] >= 0.7 else ''
    print(f\"  {number} {short_name:<28} f1={entry['f1']:.2f}  p={entry['precision']:.2f} r={entry['recall']:.2f}{marker}\")

print('weakest')
for entry in list(reversed(ranked))[:5]:
    number, short_name = label(entry)
    marker = '   [WEAK]' if entry['f1'] < 0.3 else ''
    print(f\"  {number} {short_name:<28} f1={entry['f1']:.2f}  p={entry['precision']:.2f} r={entry['recall']:.2f}{marker}\")
"

echo "$OUTPUT_FILE written"
