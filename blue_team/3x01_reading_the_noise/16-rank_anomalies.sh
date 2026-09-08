#!/bin/bash
set -euo pipefail

# Not one of the numbered 3x01 tasks - a small one-time synthesis step built
# while working on 3x02's T13 (Per-Rule Quality Metrics). 3x02 needs a single
# ranked ground-truth file combining every anomaly type this project already
# detected (auth, process, network, correlated); this script builds it from
# the four anomalies_*.json / correlated_anomalies.json files already
# produced by 10-anomalies_auth.sh, 11-anomalies_process.sh,
# 12-anomalies_network.sh and 13-correlate_anomalies.sh, with no new
# detection logic of its own.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_FILE="$SCRIPT_DIR/ranked_anomalies.json"

SEVERITY_SCORE='{"low":1,"medium":2,"high":3,"critical":4}'

python3 -c "
import json

severity_score = $SEVERITY_SCORE

def load(name):
    try:
        with open(f'$SCRIPT_DIR/{name}') as f:
            return json.load(f)
    except FileNotFoundError:
        return []

entries = []

for item in load('anomalies_auth.json'):
    entries.append({
        'source': 'auth',
        'anomaly_type': item['anomaly_type'],
        'severity': item['severity'],
        'score': severity_score.get(item['severity'], 0),
        'host': item['host'],
        'user': item.get('user'),
        'refs': [{'host': item['host'], 'timestamp': ts} for ts in item.get('event_refs', [])],
    })

for item in load('anomalies_process.json'):
    entries.append({
        'source': 'process',
        'anomaly_type': item['anomaly_type'],
        'severity': item['severity'],
        'score': severity_score.get(item['severity'], 0),
        'host': item['host'],
        'user': item.get('user'),
        'refs': [{'host': item['host'], 'timestamp': ts} for ts in item.get('event_refs', [])],
    })

for item in load('anomalies_network.json'):
    entries.append({
        'source': 'network',
        'anomaly_type': item.get('anomaly_type'),
        'severity': item.get('severity'),
        'score': severity_score.get(item.get('severity'), 0),
        'host': item.get('host'),
        'user': item.get('user'),
        'refs': [{'host': item.get('host'), 'timestamp': ts} for ts in item.get('event_refs', [])],
    })

for item in load('correlated_anomalies.json'):
    entries.append({
        'source': 'correlated',
        'anomaly_type': '+'.join(item.get('anomaly_types', [])),
        'severity': None,
        'score': item.get('score', 0),
        'host': item.get('host'),
        'user': None,
        'refs': [{'host': m.get('host'), 'timestamp': m.get('timestamp')} for m in item.get('member_refs', [])],
    })

entries.sort(key=lambda e: e['score'], reverse=True)
for rank, entry in enumerate(entries, start=1):
    entry['rank'] = rank

with open('$OUT_FILE', 'w') as f:
    json.dump(entries, f, indent=2)
    f.write('\n')

print(f'{len(entries)} ranked anomalies written to $OUT_FILE')
"
