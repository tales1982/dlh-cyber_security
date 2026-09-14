#!/bin/bash
set -euo pipefail

CATALOG_DIR="${CATALOG_DIR:-$HOME/3x02_package/detection_catalog}"

QUEUE_FILE="$CATALOG_DIR/alerts/alert_queue.json"
SCHEMA_FILE="$CATALOG_DIR/alerts/alert_queue_schema.json"
RULES_DIR="$CATALOG_DIR/rules/sigma"
OUTPUT_FILE="queue_assessment.json"

for f in "$QUEUE_FILE" "$SCHEMA_FILE"; do
    if [[ ! -f "$f" ]]; then
        echo "error: required input not found: $f" >&2
        exit 1
    fi
done

python3 - "$QUEUE_FILE" "$SCHEMA_FILE" "$RULES_DIR" "$OUTPUT_FILE" <<'PYEOF'
import json
import re
import sys
from datetime import datetime, date

queue_path, schema_path, rules_dir, output_path = sys.argv[1:5]

# The Sigma tag convention used by this catalog's rules is a fixed,
# documented pair of tag families: "attack.<tactic_slug>" and
# "attack.t<technique>". The tactic slug -> tactic ID mapping is the
# canonical MITRE ATT&CK Enterprise tactic list, which is stable (unlike
# the hundreds of technique IDs), so it is safe to embed here rather than
# depend on an extra input file.
TACTIC_SLUG_TO_ID = {
    "reconnaissance": "TA0043",
    "resource_development": "TA0042",
    "initial_access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege_escalation": "TA0004",
    "defense_evasion": "TA0005",
    "credential_access": "TA0006",
    "discovery": "TA0007",
    "lateral_movement": "TA0008",
    "collection": "TA0009",
    "command_and_control": "TA0011",
    "exfiltration": "TA0010",
    "impact": "TA0040",
}
TACTIC_ID_TO_NAME = {v: k for k, v in TACTIC_SLUG_TO_ID.items()}

UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

PRIORITY_BANDS = [
    ("critical", 20, float("inf")),
    ("high", 10, 20),
    ("medium", 5, 10),
    ("low", 1, 5),
]


def is_datetime(value):
    if not isinstance(value, str):
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def check_type(value, expected):
    types = expected if isinstance(expected, list) else [expected]
    for t in types:
        if t == "null" and value is None:
            return True
        if t == "string" and isinstance(value, str):
            return True
        if t == "number" and isinstance(value, (int, float)) and not isinstance(value, bool):
            return True
        if t == "object" and isinstance(value, dict):
            return True
        if t == "array" and isinstance(value, list):
            return True
    return False


def validate_alert(alert, item_schema):
    errors = []
    if not isinstance(alert, dict):
        return ["alert is not an object"]

    properties = item_schema.get("properties", {})
    for field in item_schema.get("required", []):
        if field not in alert:
            errors.append(f"missing required field '{field}'")

    for field, value in alert.items():
        prop_schema = properties.get(field)
        if prop_schema is None:
            continue
        expected_type = prop_schema.get("type")
        if expected_type and not check_type(value, expected_type):
            errors.append(f"field '{field}' has wrong type (expected {expected_type})")
            continue
        if value is None:
            continue

        fmt = prop_schema.get("format")
        if fmt == "uuid" and not UUID_RE.match(value):
            errors.append(f"field '{field}' is not a valid uuid: {value!r}")
        if fmt == "date-time" and not is_datetime(value):
            errors.append(f"field '{field}' is not a valid date-time: {value!r}")

        enum = prop_schema.get("enum")
        if enum and value not in enum:
            errors.append(f"field '{field}' value {value!r} not in enum {enum}")

        if expected_type == "object" and isinstance(value, dict):
            nested_props = prop_schema.get("properties", {})
            for nested_field, nested_value in value.items():
                nested_schema = nested_props.get(nested_field)
                if nested_schema is None:
                    continue
                nested_type = nested_schema.get("type")
                if nested_type and not check_type(nested_value, nested_type):
                    errors.append(
                        f"field '{field}.{nested_field}' has wrong type (expected {nested_type})"
                    )

        if expected_type == "array" and isinstance(value, list):
            item_type = prop_schema.get("items", {}).get("type")
            if item_type:
                for i, element in enumerate(value):
                    if not check_type(element, item_type):
                        errors.append(
                            f"field '{field}[{i}]' has wrong type (expected {item_type})"
                        )

    return errors


def priority_band(score):
    for name, lo, hi in PRIORITY_BANDS:
        if lo <= score < hi:
            return name
    return "low" if score < 1 else "critical"


def load_rule_tactics(rules_dir):
    """Map rule_id (uuid) -> sorted list of tactic IDs, derived from each
    Sigma rule's own `tags:` block. Tuned rule variants (rules_dir/tuned/)
    override their base counterpart, matching the runner's rule selection."""
    import os

    rule_id_to_tactics = {}
    if not os.path.isdir(rules_dir):
        return rule_id_to_tactics

    base_files = sorted(
        os.path.join(rules_dir, name)
        for name in os.listdir(rules_dir)
        if name.endswith(".yml")
    )
    tuned_dir = os.path.join(rules_dir, "tuned")
    active_files = []
    for base_file in base_files:
        tuned_candidate = os.path.join(tuned_dir, os.path.basename(base_file))
        active_files.append(tuned_candidate if os.path.isfile(tuned_candidate) else base_file)

    tag_line_re = re.compile(r"^\s*-\s*(\S+)\s*$")
    id_line_re = re.compile(r"^id:\s*(\S+)\s*$")

    for rule_file in active_files:
        rule_id = None
        tactics = set()
        in_tags = False
        with open(rule_file) as f:
            for line in f:
                id_match = id_line_re.match(line)
                if id_match:
                    rule_id = id_match.group(1)
                    continue
                if line.startswith("tags:"):
                    in_tags = True
                    continue
                if in_tags:
                    tag_match = tag_line_re.match(line)
                    if not tag_match:
                        in_tags = False
                        continue
                    tag = tag_match.group(1)
                    if tag.startswith("attack."):
                        slug = tag[len("attack."):]
                        if slug in TACTIC_SLUG_TO_ID:
                            tactics.add(TACTIC_SLUG_TO_ID[slug])
        if rule_id:
            rule_id_to_tactics[rule_id] = sorted(tactics)

    return rule_id_to_tactics


with open(schema_path) as f:
    schema = json.load(f)
item_schema = schema.get("items", {})

with open(queue_path) as f:
    queue = json.load(f)

rule_tactics = load_rule_tactics(rules_dir)

validation_errors = []
priority_counts = {name: 0 for name, _, _ in PRIORITY_BANDS}
rule_counts = {}
hostname_counts = {}
tactic_counts = {}
host_scores = {}
timestamps = []
generated_ats = []
unmapped_tactic_alerts = 0

for index, alert in enumerate(queue):
    errors = validate_alert(alert, item_schema)
    if errors:
        validation_errors.append({
            "index": index,
            "alert_id": alert.get("alert_id") if isinstance(alert, dict) else None,
            "errors": errors,
        })
    if not isinstance(alert, dict):
        continue

    score = alert.get("priority_score")
    if isinstance(score, (int, float)):
        priority_counts[priority_band(score)] += 1

    rule_id = alert.get("rule_id")
    rule_title = alert.get("rule_title", "unknown")
    key = (rule_id, rule_title)
    rule_counts[key] = rule_counts.get(key, 0) + 1

    event_summary = alert.get("event_summary") or {}
    hostname = event_summary.get("hostname")
    if hostname:
        hostname_counts[hostname] = hostname_counts.get(hostname, 0) + 1
        if isinstance(score, (int, float)):
            host_scores[hostname] = host_scores.get(hostname, 0) + score

    ts = event_summary.get("timestamp")
    if ts:
        timestamps.append(ts)

    generated_at = alert.get("generated_at")
    if generated_at:
        generated_ats.append(generated_at)

    tactics = rule_tactics.get(rule_id, [])
    if tactics:
        for tactic_id in tactics:
            tactic_counts[tactic_id] = tactic_counts.get(tactic_id, 0) + 1
    else:
        unmapped_tactic_alerts += 1

by_rule = sorted(
    (
        {"rule_id": rid, "rule_title": title, "count": count}
        for (rid, title), count in rule_counts.items()
    ),
    key=lambda e: (-e["count"], e["rule_title"]),
)

by_hostname = sorted(
    (
        {"hostname": hostname, "count": count}
        for hostname, count in hostname_counts.items()
    ),
    key=lambda e: (-e["count"], e["hostname"]),
)

by_attack_tactic = sorted(
    (
        {
            "tactic_id": tactic_id,
            "tactic_name": TACTIC_ID_TO_NAME.get(tactic_id, "unknown"),
            "count": count,
        }
        for tactic_id, count in tactic_counts.items()
    ),
    key=lambda e: (-e["count"], e["tactic_id"]),
)
if unmapped_tactic_alerts:
    by_attack_tactic.append({
        "tactic_id": None,
        "tactic_name": "unmapped",
        "count": unmapped_tactic_alerts,
    })

top_targets = sorted(
    (
        {"hostname": hostname, "score": round(score, 2)}
        for hostname, score in host_scores.items()
    ),
    key=lambda e: (-e["score"], e["hostname"]),
)[:3]

time_span = {
    "start": min(timestamps) if timestamps else None,
    "end": max(timestamps) if timestamps else None,
}

assessment = {
    "queue_size": len(queue),
    "validation_errors": validation_errors,
    "by_priority_band": priority_counts,
    "by_rule": by_rule,
    "by_hostname": by_hostname,
    "by_attack_tactic": by_attack_tactic,
    "time_span": time_span,
    "top_targets": top_targets,
}

with open(output_path, "w") as f:
    json.dump(assessment, f, indent=2, sort_keys=False)
    f.write("\n")

shift_date = max(generated_ats)[:10] if generated_ats else date.today().isoformat()

print(f"=== SHIFT BRIEFING {shift_date} ===")
print(f"queue size           : {len(queue)} alerts")
print(f"validation errors    : {len(validation_errors):>2}")
print(f"time span             : {time_span['start']} -> {time_span['end']}")
print("priority bands")
for name, _, _ in PRIORITY_BANDS:
    print(f"  {name:<9}: {priority_counts[name]:>3}")
top_rules = by_rule[:5]
print(f"top rules ({len(top_rules)})")
for entry in top_rules:
    print(f"  {entry['rule_title']:<45} {entry['count']}")
print(f"top hosts ({len(top_targets)} by cumulative score)")
for entry in top_targets:
    print(f"  {entry['hostname']:<15} score {entry['score']}")
print(f"attack tactics covered : {len([e for e in by_attack_tactic if e['tactic_id']])}")
print(f"{output_path} written")
PYEOF
