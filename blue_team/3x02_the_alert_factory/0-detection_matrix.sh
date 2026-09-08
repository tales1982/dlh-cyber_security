#!/bin/bash
set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"

EVENTS_FILE="$HANDOFF_DIR/data/enriched_events.json"
SCHEMA_FILE="$HANDOFF_DIR/schema/event_schema.json"
BASELINE_FILE="$BASELINE_PKG/baselines/baseline_summary.json"
OUTPUT_FILE="detection_matrix.json"

for f in "$EVENTS_FILE" "$SCHEMA_FILE" "$BASELINE_FILE"; do
    if [[ ! -f "$f" ]]; then
        echo "error: required input not found: $f" >&2
        exit 1
    fi
done

python3 - "$EVENTS_FILE" "$SCHEMA_FILE" "$BASELINE_FILE" "$OUTPUT_FILE" <<'PYEOF'
import json
import os
import sys
from datetime import datetime

events_path, schema_path, baseline_path, output_path = sys.argv[1:5]

STABLE_THRESHOLD = 0.95
HIGH_CARDINALITY_RATIO = 0.5
SIGNIFICANT_CATEGORY_SHARE = 0.01
MIN_DAILY_DENSITY_FOR_ANOMALY = 5.0

SIGNATURE_CANDIDATE_FIELDS = ["signature", "raw_message", "process_name", "command_line"]
BEHAVIORAL_CANDIDATE_FIELDS = ["user", "hostname", "pid", "src_ip", "dst_ip"]
CORRELATION_CANDIDATE_FIELDS = ["src_ip", "dst_ip", "user", "hostname"]

# Default event_category -> ATT&CK tactic ID mapping. This is a documented
# assumption: the required inputs for this task are enriched_events.json,
# event_schema.json and baseline_summary.json only, none of which carry a
# category->tactic mapping. ASSETS_DIR/attack_taxonomy.json (a MITRE ATT&CK
# snapshot: top-level "tactics"/"techniques" lists plus a rule_to_technique_map
# keyed by Sigma rule filename) has no such mapping either - it is a rule-level
# taxonomy, not an event-category-level one, and task 0 has no rules yet to
# look up. So it is used below only to validate that every tactic ID emitted
# here is a real, current tactic ID, not to replace this mapping.
DEFAULT_CATEGORY_TACTICS = {
    "authentication": ["TA0001", "TA0006"],
    "audit": ["TA0006"],
    "process": ["TA0002"],
    "privilege_escalation": ["TA0004"],
    "account_management": ["TA0003", "TA0004"],
    "network": ["TA0008", "TA0010", "TA0011"],
    "network_flow": ["TA0008", "TA0010", "TA0011"],
    "network_alert": ["TA0001", "TA0007", "TA0010", "TA0011"],
    "file": ["TA0005", "TA0009", "TA0010"],
}


def flatten(record):
    flat = {}
    for key, value in record.items():
        if isinstance(value, dict):
            for sub_key, sub_value in value.items():
                flat[f"{key}.{sub_key}"] = sub_value
        else:
            flat[key] = value
    return flat


def parse_timestamp(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def load_valid_tactic_ids():
    assets_dir = os.environ.get("ASSETS_DIR")
    if not assets_dir:
        return None
    taxonomy_path = os.path.join(assets_dir, "attack_taxonomy.json")
    if not os.path.isfile(taxonomy_path):
        return None
    try:
        with open(taxonomy_path) as f:
            taxonomy = json.load(f)
        return {t["tactic_id"] for t in taxonomy.get("tactics", []) if "tactic_id" in t}
    except (json.JSONDecodeError, OSError, TypeError, KeyError):
        return None


with open(schema_path) as f:
    event_schema = json.load(f)

schema_fields = {field["name"] for field in event_schema.get("fields", [])}
required_schema_fields = {
    field["name"] for field in event_schema.get("fields", []) if field.get("required")
}

# The candidate field lists above are drawn from the canonical schema, not
# invented ad hoc. Fail fast if one of them drifts from event_schema.json
# (e.g. a field gets renamed there) instead of silently under-detecting.
for candidate_list in (SIGNATURE_CANDIDATE_FIELDS, BEHAVIORAL_CANDIDATE_FIELDS, CORRELATION_CANDIDATE_FIELDS):
    unknown = [field for field in candidate_list if field not in schema_fields]
    if unknown:
        sys.exit(f"error: candidate field(s) {unknown} are not declared in {schema_path}")

with open(baseline_path) as f:
    baseline_summary = json.load(f)

baseline_window = baseline_summary.get("baseline_window", {})
window_start = parse_timestamp(baseline_window.get("start"))
window_end = parse_timestamp(baseline_window.get("end"))
duration_days = baseline_window.get("duration_days") or 1

stats = {}


def source_bucket(source_type):
    if source_type not in stats:
        stats[source_type] = {
            "record_count": 0,
            "baseline_window_count": 0,
            "field_presence": {},
            "field_values": {},
            "category_counts": {},
        }
    return stats[source_type]


with open(events_path) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        record = json.loads(line)
        source_type = record.get("source_type")
        if not source_type:
            continue

        bucket = source_bucket(source_type)
        bucket["record_count"] += 1

        category = record.get("event_category")
        bucket["category_counts"][category] = bucket["category_counts"].get(category, 0) + 1

        ts = parse_timestamp(record.get("timestamp"))
        if ts is not None and window_start is not None and window_end is not None:
            if window_start <= ts < window_end:
                bucket["baseline_window_count"] += 1

        for field, value in flatten(record).items():
            if value is None:
                continue
            bucket["field_presence"][field] = bucket["field_presence"].get(field, 0) + 1
            values = bucket["field_values"].setdefault(field, set())
            try:
                values.add(value if not isinstance(value, list) else json.dumps(value, sort_keys=True))
            except TypeError:
                values.add(str(value))

category_tactics = DEFAULT_CATEGORY_TACTICS
valid_tactic_ids = load_valid_tactic_ids()

matrix = []
for source_type in sorted(stats):
    bucket = stats[source_type]
    record_count = bucket["record_count"]

    stable_fields = sorted(
        field
        for field, count in bucket["field_presence"].items()
        if count / record_count >= STABLE_THRESHOLD
    )
    stable_set = set(stable_fields)

    missing_required = sorted(required_schema_fields - stable_set)
    if missing_required:
        print(
            f"warning: {source_type}: schema-required field(s) {missing_required} "
            "are not stable (<95% present) for this source",
            file=sys.stderr,
        )

    high_cardinality_fields = sorted(
        field
        for field, values in bucket["field_values"].items()
        if len(values) > HIGH_CARDINALITY_RATIO * record_count
    )
    high_cardinality_set = set(high_cardinality_fields)

    supported_types = []
    rationale = {}

    signature_hits = [
        field for field in SIGNATURE_CANDIDATE_FIELDS
        if field in stable_set and field not in high_cardinality_set
    ]
    if signature_hits:
        supported_types.append("signature")
        rationale["signature"] = (
            f"stable, repeatable field(s) {signature_hits} support exact/keyword pattern matching"
        )
    else:
        rationale["signature"] = (
            "no candidate field is both stable and low-cardinality "
            f"(checked {SIGNATURE_CANDIDATE_FIELDS})"
        )

    daily_density = bucket["baseline_window_count"] / duration_days
    if daily_density >= MIN_DAILY_DENSITY_FOR_ANOMALY:
        supported_types.append("anomaly")
        rationale["anomaly"] = (
            f"{daily_density:.1f} records/day across the {duration_days}-day baseline window "
            f"is sufficient to model a normal-volume distribution (threshold {MIN_DAILY_DENSITY_FOR_ANOMALY})"
        )
    else:
        rationale["anomaly"] = (
            f"{daily_density:.1f} records/day across the {duration_days}-day baseline window "
            f"is below the {MIN_DAILY_DENSITY_FOR_ANOMALY} threshold needed for a reliable baseline"
        )

    behavioral_hits = [
        field for field in BEHAVIORAL_CANDIDATE_FIELDS
        if field in stable_set and field not in high_cardinality_set
    ]
    if behavioral_hits:
        supported_types.append("behavioral")
        rationale["behavioral"] = (
            f"stable, repeatable entity field(s) {behavioral_hits} allow sequencing multiple "
            "events per entity over time"
        )
    else:
        rationale["behavioral"] = (
            "no stable entity field repeats often enough to build a per-entity sequence "
            f"(checked {BEHAVIORAL_CANDIDATE_FIELDS})"
        )

    correlation_hits = [field for field in CORRELATION_CANDIDATE_FIELDS if field in stable_set]
    if correlation_hits:
        supported_types.append("correlation")
        rationale["correlation"] = (
            f"stable join key(s) {correlation_hits} can be matched against the same field in other sources"
        )
    else:
        rationale["correlation"] = (
            f"no stable field is shared with other sources to join on (checked {CORRELATION_CANDIDATE_FIELDS})"
        )

    significant_categories = [
        category
        for category, count in bucket["category_counts"].items()
        if category and count / record_count >= SIGNIFICANT_CATEGORY_SHARE
    ]
    tactics = set()
    for category in significant_categories:
        tactics.update(category_tactics.get(category, []))
    if valid_tactic_ids is not None:
        dropped = tactics - valid_tactic_ids
        if dropped:
            print(
                f"warning: {source_type}: tactic ID(s) {sorted(dropped)} are not present in "
                f"{os.environ.get('ASSETS_DIR')}/attack_taxonomy.json - dropped",
                file=sys.stderr,
            )
        tactics &= valid_tactic_ids

    matrix.append({
        "source_type": source_type,
        "record_count": record_count,
        "stable_fields": stable_fields,
        "high_cardinality_fields": high_cardinality_fields,
        "supported_detection_types": supported_types,
        "rationale": rationale,
        "recommended_attack_tactics": sorted(tactics),
    })

with open(output_path, "w") as f:
    json.dump(matrix, f, indent=2, sort_keys=False)
    f.write("\n")

CANONICAL_ORDER = ["signature", "anomaly", "behavioral", "correlation"]
for entry in matrix:
    ordered = [t for t in CANONICAL_ORDER if t in entry["supported_detection_types"]]
    print(f"{entry['source_type']:<16} {len(ordered)} types  [{' '.join(ordered)}]")

print(f"{len(matrix)} source types analyzed")
print(f"{output_path} written")
PYEOF
