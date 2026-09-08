#!/bin/bash
set -euo pipefail

# T12 was not provided alongside T10/T13/T14/T15/T17, but T14 reads
# attack_coverage.json as an input. This builds it for real: cross-references
# every technique in ASSETS_DIR/attack_taxonomy.json against the attack.tXXXX
# tags actually present on the rules under rules/sigma/, so T14 has a genuine
# coverage map instead of a guess.

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x02_assets}"
RULES_DIR="rules/sigma"
TAXONOMY_FILE="$ASSETS_DIR/attack_taxonomy.json"
OUTPUT_FILE="attack_coverage.json"

if [[ ! -f "$TAXONOMY_FILE" ]]; then
    echo "error: attack taxonomy not found: $TAXONOMY_FILE" >&2
    exit 1
fi

if [[ ! -d "$RULES_DIR" ]]; then
    echo "error: rules directory not found: $RULES_DIR (run from the project root)" >&2
    exit 1
fi

mapfile -t RULE_FILES < <(find "$RULES_DIR" -maxdepth 1 -name '*.yml' | sort)

python3 -c "
import json
import sys
import yaml

with open('$TAXONOMY_FILE') as f:
    taxonomy = json.load(f)

rule_files = sys.argv[1:]

rule_tags = {}
for rule_file in rule_files:
    with open(rule_file) as f:
        rule = yaml.safe_load(f)
    techniques = {
        tag.split('.', 1)[1].upper()
        for tag in rule.get('tags', [])
        if tag.startswith('attack.t')
    }
    rule_tags[rule_file.split('/')[-1][:-4]] = techniques

coverage = []
for technique in taxonomy.get('techniques', []):
    tid = technique['technique_id']
    covering = sorted(
        name for name, techs in rule_tags.items() if tid.upper() in techs
    )
    coverage.append({
        'technique_id': tid,
        'name': technique.get('name'),
        'tactic': technique.get('tactic'),
        'covered': bool(covering),
        'covering_rules': covering,
    })

covered_count = sum(1 for c in coverage if c['covered'])
with open('$OUTPUT_FILE', 'w') as f:
    json.dump(coverage, f, indent=2)
    f.write('\n')

print(f'{covered_count}/{len(coverage)} ATT&CK techniques covered by the current catalog')
print('$OUTPUT_FILE written')
" "${RULE_FILES[@]}"
