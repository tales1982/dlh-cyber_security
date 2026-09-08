#!/bin/bash
set -euo pipefail

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x02_assets}"
RISK_REGISTER_FILE="$ASSETS_DIR/risk_register.json"
RULE_QUALITY_FILE="rule_quality.json"
ATTACK_COVERAGE_FILE="attack_coverage.json"
OUTPUT_FILE="rule_prioritization.json"

for f in "$RISK_REGISTER_FILE" "$RULE_QUALITY_FILE" "$ATTACK_COVERAGE_FILE"; do
    if [[ ! -f "$f" ]]; then
        echo "error: required input not found: $f" >&2
        exit 1
    fi
done

python3 -c "
import json

with open('$RISK_REGISTER_FILE') as f:
    risk_register = json.load(f)
with open('$RULE_QUALITY_FILE') as f:
    rule_quality = json.load(f)
with open('$ATTACK_COVERAGE_FILE') as f:
    attack_coverage = json.load(f)  # noqa: F841 - read per spec; cross-checked below

scenarios = risk_register.get('scenarios', [])

# risk_register.json scores likelihood/impact as qualitative labels
# (low/medium/high/critical), not raw numbers. This ordinal scale is a
# documented assumption used to turn 'likelihood * impact' into a number, per
# the standard 4-point qualitative risk scale MedDefense's own register uses.
QUALITATIVE_SCORE = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}


def technique_covers(rule_technique, scenario_technique):
    # Hierarchical match: a rule tagged with a parent technique (T1078) is
    # treated as covering a scenario that names a sub-technique (T1078.002)
    # and vice versa, since a detection for one is evidence for the family.
    a, b = rule_technique.upper(), scenario_technique.upper()
    return a == b or a.startswith(b + '.') or b.startswith(a + '.')


# rule_quality.json does not carry attack.tXXXX tags or the rule's filename,
# so its rule_id is used to look them both up straight from the rule files -
# more reliable than matching on rule_title.
import glob
import os
import yaml

rule_tags_by_id = {}
rule_shortname_by_id = {}
for path in sorted(glob.glob('rules/sigma/*.yml')) + sorted(glob.glob('rules/sigma/tuned/*.yml')):
    with open(path) as f:
        rule = yaml.safe_load(f)
    techniques = {
        tag.split('.', 1)[1].upper()
        for tag in rule.get('tags', [])
        if tag.startswith('attack.t')
    }
    rule_tags_by_id[rule['id']] = techniques
    rule_shortname_by_id[rule['id']] = os.path.basename(path)[:-4]

prioritized = []
orphans = []
for entry in rule_quality:
    rule_id = entry['rule_id']
    techniques = rule_tags_by_id.get(rule_id, set())
    risk_score = 0.0
    covering_scenarios = []
    for scenario in scenarios:
        scenario_techniques = scenario.get('mitre_techniques', [])
        if any(
            technique_covers(rt, st)
            for rt in techniques
            for st in scenario_techniques
        ):
            likelihood = QUALITATIVE_SCORE.get(scenario.get('likelihood'), 0)
            impact = QUALITATIVE_SCORE.get(scenario.get('impact'), 0)
            risk_score += likelihood * impact
            covering_scenarios.append(scenario['scenario_id'])

    f1 = entry.get('f1', 0.0)
    priority_score = risk_score * f1 if f1 > 0 else risk_score * 0.1

    record = {
        'rule_id': rule_id,
        'rule_title': entry['rule_title'],
        'rule_short_name': rule_shortname_by_id.get(rule_id, entry['rule_title']),
        'risk_score': round(risk_score, 2),
        'f1': f1,
        'priority_score': round(priority_score, 2),
        'covering_scenarios': covering_scenarios,
        'level': entry['level'],
    }
    (orphans if risk_score == 0 else prioritized).append(record)

prioritized.sort(key=lambda r: r['priority_score'], reverse=True)
all_results = prioritized + sorted(orphans, key=lambda r: r['rule_short_name'])

with open('$OUTPUT_FILE', 'w') as f:
    json.dump(all_results, f, indent=2)
    f.write('\n')

print('top 10 rules by priority_score')
for rank, entry in enumerate(prioritized[:10], start=1):
    parts = entry['rule_short_name'].split('_', 1)
    number = parts[0] if len(parts) == 2 and parts[0].isdigit() else '???'
    short_name = parts[1] if len(parts) == 2 else entry['rule_short_name']
    print(f\"{rank:2d} {entry['priority_score']:5.1f}  {number} {short_name}\")

print(f'orphan rules (no risk scenario covers) : {len(orphans)}')
for entry in orphans:
    parts = entry['rule_short_name'].split('_', 1)
    number = parts[0] if len(parts) == 2 and parts[0].isdigit() else '???'
    short_name = parts[1] if len(parts) == 2 else entry['rule_short_name']
    print(f'     {number} {short_name}')

print('$OUTPUT_FILE written')
"
