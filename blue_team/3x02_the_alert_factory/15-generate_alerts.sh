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
PRIORITIZATION_FILE="rule_prioritization.json"
ASSET_INVENTORY_FILE="$HANDOFF_DIR/context/asset_inventory.json"
EVIDENCE_FILE="$HANDOFF_DIR/data/normalized_events.json"
OUTPUT_FILE="alert_queue.json"
SCHEMA_FILE="alert_queue_schema.json"
DEDUP_WINDOW_SECONDS=60

for f in "$SUMMARY_FILE" "$PRIORITIZATION_FILE" "$ASSET_INVENTORY_FILE" "$EVIDENCE_FILE"; do
    if [[ ! -f "$f" ]]; then
        echo "error: required input not found: $f" >&2
        exit 1
    fi
done

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

RAW_MATCHES_JSON="[]"
for rule_file in "${ACTIVE_RULE_FILES[@]}"; do
    run_output=$("$RUNNER" "$rule_file" --window "$EVAL_START,$EVAL_END")
    RAW_MATCHES_JSON=$(python3 -c "
import json, sys, yaml

collected = json.loads(sys.argv[1])
rule_file = sys.argv[2]
run_output = json.loads(sys.argv[3])

with open(rule_file) as f:
    rule = yaml.safe_load(f)

techniques = sorted({
    tag.split('.', 1)[1].upper()
    for tag in rule.get('tags', [])
    if tag.startswith('attack.t')
})

for match in run_output.get('matches', []):
    collected.append({
        'rule_file': rule_file,
        'rule_id': rule['id'],
        'rule_title': rule['title'],
        'rule_level': rule['level'],
        'attack_techniques': techniques,
        'timestamp': match['timestamp'],
        'hostname': match['hostname'],
        'event_ref': match['event_ref'],
    })
print(json.dumps(collected))
" "$RAW_MATCHES_JSON" "$rule_file" "$run_output")
done

echo "$RAW_MATCHES_JSON" | python3 -c "
import hashlib
import json
import sys
import uuid
from datetime import datetime, timezone

raw_matches = json.load(sys.stdin)

with open('$PRIORITIZATION_FILE') as f:
    priorities = {e['rule_id']: e for e in json.load(f)}
with open('$ASSET_INVENTORY_FILE') as f:
    assets = {a['hostname']: a for a in json.load(f)}

# normalized_events.json has no canonical_label field of its own (same as the
# runner's own enrich_record) - reapply the same taxonomy match used there.
taxonomy_path = '$BASELINE_PKG/baselines/event_taxonomy.json'
try:
    with open(taxonomy_path) as f:
        taxonomy = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    taxonomy = []


def taxonomy_rule_matches(record, rule):
    if rule.get('source_type') and record.get('source_type') != rule['source_type']:
        return False
    for field, expected in rule.get('match', {}).items():
        actual = record.get(field)
        if expected is None:
            if actual is not None:
                return False
            continue
        if isinstance(expected, str) and '*' in expected:
            import re
            pattern = '^' + re.escape(expected).replace(r'\*', '.*') + '$'
            if actual is None or not re.match(pattern, str(actual), re.S):
                return False
        elif actual != expected:
            return False
    return True


def compute_canonical_label(record):
    for rule in taxonomy:
        if taxonomy_rule_matches(record, rule):
            return rule.get('label')
    return 'unlabeled'

# Resolve every referenced line of normalized_events.json in a single pass,
# instead of re-opening the 160MB+ file once per alert.
needed_lines = {
    int(m['event_ref'].split(':', 1)[1])
    for m in raw_matches
    if m['event_ref'].startswith('line:')
}
line_records = {}
raw_lines = {}
if needed_lines:
    with open('$EVIDENCE_FILE') as f:
        for idx, line in enumerate(f):
            if idx in needed_lines:
                line_records[idx] = json.loads(line)
                raw_lines[idx] = line.rstrip('\n')
            if len(line_records) == len(needed_lines):
                break

ALERT_NAMESPACE = uuid.UUID('7c3a3e2e-1a3d-4b8a-9c1a-6a1a2b3c4d5e')

alerts = []
for match in raw_matches:
    idx = int(match['event_ref'].split(':', 1)[1])
    record = line_records.get(idx, {})
    raw_line = raw_lines.get(idx, '')

    priority = priorities.get(match['rule_id'], {})
    hostname = match['hostname']

    alerts.append({
        'alert_id': str(uuid.uuid5(ALERT_NAMESPACE, f\"{match['rule_id']}:{match['event_ref']}\")),
        'generated_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'rule_id': match['rule_id'],
        'rule_title': match['rule_title'],
        'rule_level': match['rule_level'],
        'priority_score': priority.get('priority_score', 0.0),
        'event_ref': match['event_ref'],
        'event_summary': {
            'timestamp': record.get('timestamp', match['timestamp']),
            'hostname': hostname,
            'user': record.get('user'),
            'src_ip': record.get('src_ip'),
            'dst_ip': record.get('dst_ip'),
            'process_name': record.get('process_name'),
            'canonical_label': compute_canonical_label(record) if record else None,
            'event_category': record.get('event_category'),
        },
        'asset_context': assets.get(hostname),
        'attack_techniques': match['attack_techniques'],
        'status': 'new',
        'evidence_hash': hashlib.sha256(raw_line.encode('utf-8')).hexdigest(),
    })

# Deduplicate: collapse alerts on the same (rule_id, hostname, user) that
# fire within DEDUP_WINDOW_SECONDS of the most recently kept alert in that
# group - a burst becomes a single alert, timestamped at its first event.
def parse_ts(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00'))

groups = {}
for alert in alerts:
    key = (alert['rule_id'], alert['event_summary']['hostname'], alert['event_summary']['user'])
    groups.setdefault(key, []).append(alert)

deduped = []
for key, group in groups.items():
    group.sort(key=lambda a: parse_ts(a['event_summary']['timestamp']))
    kept_ts = None
    for alert in group:
        ts = parse_ts(alert['event_summary']['timestamp'])
        if kept_ts is None or (ts - kept_ts).total_seconds() > $DEDUP_WINDOW_SECONDS:
            deduped.append(alert)
            kept_ts = ts

deduped.sort(key=lambda a: (-a['priority_score'], a['event_summary']['timestamp']))

with open('$OUTPUT_FILE', 'w') as f:
    json.dump(deduped, f, indent=2)
    f.write('\n')

print(f'rules executed            : ${#ACTIVE_RULE_FILES[@]}')
print(f'raw matches               : {len(alerts)}')
print(f'after deduplication       : {len(deduped)}')
print('top 5 alerts')
for rank, alert in enumerate(deduped[:5], start=1):
    rule_file_by_id = {m['rule_id']: m['rule_file'] for m in raw_matches}
    name = rule_file_by_id.get(alert['rule_id'], '').split('/')[-1][:-4]
    parts = name.split('_', 1)
    number = parts[0] if len(parts) == 2 and parts[0].isdigit() else '???'
    short_name = parts[1] if len(parts) == 2 else name
    host = alert['event_summary']['hostname']
    print(f\"{rank:2d}  {alert['priority_score']:4.1f}  {alert['rule_level']:<8}  {number} {short_name:<28} {host}\")

print(f'{\"$OUTPUT_FILE\":<24}: {len(deduped)} alerts')
"

python3 -c "
import json

schema = {
    'description': 'Field-level contract for alert_queue.json, consumed by 3x03 Triage Shift.',
    'type': 'array',
    'items': {
        'type': 'object',
        'properties': {
            'alert_id': {'type': 'string', 'format': 'uuid', 'description': 'Deterministic uuid5(rule_id + event_ref).'},
            'generated_at': {'type': 'string', 'format': 'date-time', 'description': 'ISO 8601 UTC time this alert_queue.json was generated (wall clock, not idempotent across runs by design).'},
            'rule_id': {'type': 'string', 'format': 'uuid'},
            'rule_title': {'type': 'string'},
            'rule_level': {'type': 'string', 'enum': ['informational', 'low', 'medium', 'high', 'critical']},
            'priority_score': {'type': 'number', 'description': 'From rule_prioritization.json (T14).'},
            'event_ref': {'type': 'string', 'description': 'line:<N> offset into normalized_events.json at generation time.'},
            'event_summary': {
                'type': 'object',
                'properties': {
                    'timestamp': {'type': 'string', 'format': 'date-time'},
                    'hostname': {'type': ['string', 'null']},
                    'user': {'type': ['string', 'null']},
                    'src_ip': {'type': ['string', 'null']},
                    'dst_ip': {'type': ['string', 'null']},
                    'process_name': {'type': ['string', 'null']},
                    'canonical_label': {'type': ['string', 'null']},
                    'event_category': {'type': ['string', 'null']},
                },
            },
            'asset_context': {'type': ['object', 'null'], 'description': 'Looked up by hostname in asset_inventory.json; null if the hostname is not in the inventory.'},
            'attack_techniques': {'type': 'array', 'items': {'type': 'string'}},
            'status': {'type': 'string', 'enum': ['new']},
            'evidence_hash': {'type': 'string', 'description': 'sha256 hex digest of the matched raw NDJSON line.'},
        },
        'required': [
            'alert_id', 'generated_at', 'rule_id', 'rule_title', 'rule_level',
            'priority_score', 'event_ref', 'event_summary', 'asset_context',
            'attack_techniques', 'status', 'evidence_hash',
        ],
    },
}

with open('$SCHEMA_FILE', 'w') as f:
    json.dump(schema, f, indent=2)
    f.write('\n')
print('$SCHEMA_FILE : written')
"
