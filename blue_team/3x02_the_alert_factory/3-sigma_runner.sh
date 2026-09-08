#!/bin/bash
set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
export HANDOFF_DIR BASELINE_PKG

usage() {
    echo "usage: $0 <rule.yml> [evidence.json] [--dry-run] [--count-only] [--window <start_iso,end_iso>]" >&2
}

RULE_FILE=""
EVIDENCE_FILE=""
DRY_RUN=0
COUNT_ONLY=0
WINDOW=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --count-only)
            COUNT_ONLY=1
            shift
            ;;
        --window)
            if [[ $# -lt 2 ]]; then
                echo "error: --window requires an argument" >&2
                exit 1
            fi
            WINDOW="$2"
            shift 2
            ;;
        --*)
            echo "error: unknown flag: $1" >&2
            usage
            exit 1
            ;;
        *)
            if [[ -z "$RULE_FILE" ]]; then
                RULE_FILE="$1"
            elif [[ -z "$EVIDENCE_FILE" ]]; then
                EVIDENCE_FILE="$1"
            else
                echo "error: unexpected argument: $1" >&2
                exit 1
            fi
            shift
            ;;
    esac
done

if [[ -z "$RULE_FILE" ]]; then
    usage
    exit 1
fi

if [[ ! -f "$RULE_FILE" ]]; then
    echo "error: rule file not found: $RULE_FILE" >&2
    exit 1
fi

if [[ -z "$EVIDENCE_FILE" ]]; then
    EVIDENCE_FILE="$HANDOFF_DIR/data/normalized_events.json"
fi

if [[ "$DRY_RUN" -eq 0 && ! -f "$EVIDENCE_FILE" ]]; then
    echo "error: evidence file not found: $EVIDENCE_FILE" >&2
    exit 1
fi

WINDOW_START=""
WINDOW_END=""
if [[ -n "$WINDOW" ]]; then
    WINDOW_START="${WINDOW%%,*}"
    WINDOW_END="${WINDOW#*,}"
fi

python3 - "$RULE_FILE" "$EVIDENCE_FILE" "$DRY_RUN" "$COUNT_ONLY" "$WINDOW_START" "$WINDOW_END" <<'PYEOF'
import json
import os
import re
import sys
import time
from datetime import datetime

try:
    import yaml
except ImportError:
    print("error: PyYAML is required (pip install --user pyyaml)", file=sys.stderr)
    sys.exit(1)

(rule_path, evidence_path, dry_run_flag, count_only_flag,
 window_start_raw, window_end_raw) = sys.argv[1:7]
dry_run = dry_run_flag == "1"
count_only = count_only_flag == "1"

REQUIRED_TOP_LEVEL = [
    "title", "id", "status", "description", "logsource",
    "detection", "falsepositives", "level", "tags",
]
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I
)

# --- Windows event_id derivation -------------------------------------------
# The normalized schema (3x00's 5-normalize.sh) does not pass raw event_id
# through to enriched_events.json/normalized_events.json: it consumes it once
# to classify (event_category, severity, action) via this exact table, then
# drops it. Since the mapping is a function (no two event_ids share the same
# (event_category, action) pair here), it is invertible with certainty - this
# is not a guess, it is the documented inverse of that table.
WIN_SECURITY_EVENT_ID = {
    ("authentication", "success"): 4624,
    ("authentication", "failure"): 4625,
    ("account_management", "success"): 4720,
    ("privilege_escalation", "success"): 4672,
}

# Matches the "Process Create: <child> spawned by <parent>" / "... by <parent>"
# raw_message shape already used by 3x01's 11-anomalies_process.sh to recover
# a parent/child process pair that the normalized schema does not carry as a
# literal field.
PROCESS_CREATE_RE = re.compile(
    r"^Process Create:\s*(?P<child>.+?)\s+(?:spawned by|by)\s+(?P<parent>.+)$"
)

# linux_text auth records (sshd via syslog) carry the client IP only inside
# raw_message ("Failed password for USER from IP port PORT ssh2" / "Accepted
# password for USER from IP port PORT ssh2") - the normalized src_ip field is
# always null for this source_type in the current 3x00 pipeline output. This
# is the standard OpenSSH log format, not a guess: the same "from <ip> port"
# shape holds across every sshd auth line this pipeline produces.
SSHD_SRC_IP_RE = re.compile(r"\bfrom\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\b")


def parse_timestamp(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def timeframe_seconds(spec):
    if not spec:
        return 0
    spec = str(spec).strip()
    match = re.match(r"^(\d+)\s*([smhd])$", spec)
    if not match:
        raise ValueError(f"unsupported timeframe: {spec}")
    amount, unit = int(match.group(1)), match.group(2)
    multiplier = {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    return amount * multiplier


def validate_rule_structure(rule):
    if not isinstance(rule, dict):
        raise ValueError("rule file did not parse to a YAML mapping")
    missing = [key for key in REQUIRED_TOP_LEVEL if key not in rule]
    if missing:
        raise ValueError(f"missing required key(s): {missing}")
    if not UUID4_RE.match(str(rule["id"])):
        raise ValueError(f"id is not a valid UUID v4: {rule['id']}")
    if rule["level"] not in VALID_LEVELS:
        raise ValueError(f"level must be one of {sorted(VALID_LEVELS)}, got {rule['level']!r}")
    if not any(str(tag).startswith("attack.t") for tag in rule.get("tags", [])):
        raise ValueError("at least one attack.tXXXX tag is required")
    if not isinstance(rule["detection"], dict) or "condition" not in rule["detection"]:
        raise ValueError("detection block missing condition")


def load_json_or_default(path, default):
    if not path or not os.path.isfile(path):
        return default
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return default


def load_taxonomy(baseline_pkg):
    path = os.path.join(baseline_pkg, "baselines", "event_taxonomy.json") if baseline_pkg else None
    data = load_json_or_default(path, [])
    return data if isinstance(data, list) else []


def load_baseline_process_index(baseline_pkg):
    path = os.path.join(baseline_pkg, "baselines", "baseline_process.json") if baseline_pkg else None
    data = load_json_or_default(path, {})
    per_host = data.get("per_host", {}) if isinstance(data, dict) else {}
    return {
        host: {proc.get("process_name") for proc in procs}
        for host, procs in per_host.items()
    }


def taxonomy_rule_matches(record, rule):
    if rule.get("source_type") and record.get("source_type") != rule["source_type"]:
        return False
    for field, expected in rule.get("match", {}).items():
        actual = record.get(field)
        if expected is None:
            if actual is not None:
                return False
            continue
        if isinstance(expected, str) and "*" in expected:
            pattern = "^" + re.escape(expected).replace(r"\*", ".*") + "$"
            if actual is None or not re.match(pattern, str(actual), re.S):
                return False
        elif actual != expected:
            return False
    return True


def compute_canonical_label(record, taxonomy):
    for rule in taxonomy:
        if taxonomy_rule_matches(record, rule):
            return rule.get("label")
    return "unlabeled"


def compute_event_id(record):
    if record.get("event_id") is not None:
        return record["event_id"]
    if record.get("source_type") != "windows_json":
        return None
    return WIN_SECURITY_EVENT_ID.get((record.get("event_category"), record.get("action")))


def compute_parent_process_name(record):
    if record.get("parent_process_name") is not None:
        return record["parent_process_name"]
    match = PROCESS_CREATE_RE.match((record.get("raw_message") or "").strip())
    return match.group("parent") if match else None


def compute_src_ip(record):
    if record.get("src_ip") is not None:
        return record["src_ip"]
    if record.get("source_type") != "linux_text":
        return None
    match = SSHD_SRC_IP_RE.search(record.get("raw_message") or "")
    return match.group("ip") if match else None


def enrich_record(record, ts, taxonomy, baseline_by_host):
    enriched = dict(record)
    enriched["hour_of_day"] = ts.hour if ts is not None else None
    enriched["canonical_label"] = compute_canonical_label(record, taxonomy)
    enriched["event_id"] = compute_event_id(record)
    enriched["parent_process_name"] = compute_parent_process_name(record)
    enriched["src_ip"] = compute_src_ip(record)
    host_processes = baseline_by_host.get(record.get("hostname"), set())
    process_name = record.get("process_name")
    enriched["baseline_seen"] = process_name in host_processes if process_name is not None else False
    return enriched


def field_matches(record, field_spec, value_spec):
    field, _, modifier = field_spec.partition("|")
    actual = record.get(field)
    values = value_spec if isinstance(value_spec, list) else [value_spec]
    for expected in values:
        if modifier == "":
            if actual == expected or (actual is not None and str(actual) == str(expected)):
                return True
        elif modifier == "contains":
            if isinstance(actual, str) and str(expected) in actual:
                return True
        elif modifier == "startswith":
            if isinstance(actual, str) and actual.startswith(str(expected)):
                return True
        elif modifier == "endswith":
            if isinstance(actual, str) and actual.endswith(str(expected)):
                return True
        else:
            raise ValueError(f"unsupported field modifier: {modifier}")
    return False


def selection_matches(record, selection_def):
    if isinstance(selection_def, list):
        return any(selection_matches(record, item) for item in selection_def)
    return all(
        field_matches(record, field_spec, value_spec)
        for field_spec, value_spec in selection_def.items()
    )


CONDITION_TOKEN_RE = re.compile(r"\(|\)|\bnot\b|\band\b|\bor\b|[A-Za-z_][A-Za-z0-9_]*")


def evaluate_condition(condition, selection_results):
    def replace(match):
        token = match.group(0)
        if token in ("and", "or", "not", "(", ")"):
            return token
        if token not in selection_results:
            raise ValueError(f"unknown selection referenced in condition: {token}")
        return "True" if selection_results[token] else "False"

    expr = CONDITION_TOKEN_RE.sub(replace, condition)
    return eval(expr, {"__builtins__": {}}, {})  # noqa: S307 - tokens are True/False/and/or/not/() only


AGG_CONDITION_RE = re.compile(
    r"^\s*(?P<sel>[A-Za-z_][A-Za-z0-9_]*)\s*\|\s*count\([^)]*\)\s*by\s+"
    r"(?P<field>[A-Za-z_][A-Za-z0-9_]*)\s*>\s*(?P<threshold>\d+)\s*$"
)


def aggregate_matches(events, threshold, window_seconds):
    events = sorted(events, key=lambda e: e["ts"])
    matched_idx = set()
    left = 0
    for right in range(len(events)):
        while (events[right]["ts"] - events[left]["ts"]).total_seconds() > window_seconds:
            left += 1
        if (right - left + 1) > threshold:
            matched_idx.update(range(left, right + 1))
    return [events[i] for i in sorted(matched_idx)]


def logsource_allows(record, logsource):
    product = logsource.get("product")
    if product in ("windows", "linux"):
        expected_source_type = {"windows": "windows_json", "linux": "linux_text"}[product]
        return record.get("source_type") == expected_source_type
    return True


# --- load and validate the rule ---
try:
    with open(rule_path) as f:
        rule = yaml.safe_load(f)
    validate_rule_structure(rule)
except Exception as exc:  # noqa: BLE001 - surfaced to the caller either way
    if dry_run:
        print(f"INVALID: {exc}")
        sys.exit(1)
    print(json.dumps({"error": str(exc)}))
    sys.exit(1)

if dry_run:
    print("VALID")
    sys.exit(0)

start_time = time.perf_counter()

HANDOFF_DIR = os.environ.get("HANDOFF_DIR", "")
BASELINE_PKG = os.environ.get("BASELINE_PKG", "")

taxonomy = load_taxonomy(BASELINE_PKG)
baseline_by_host = load_baseline_process_index(BASELINE_PKG)

window_start = parse_timestamp(window_start_raw) if window_start_raw else None
window_end = parse_timestamp(window_end_raw) if window_end_raw else None

detection = rule["detection"]
logsource = rule.get("logsource", {})
condition = str(detection["condition"])
selection_names = [key for key in detection if key not in ("condition", "timeframe")]

agg_match = AGG_CONDITION_RE.match(condition)
matches = []

with open(evidence_path) as f:
    if agg_match:
        sel_name = agg_match.group("sel")
        group_field = agg_match.group("field")
        threshold = int(agg_match.group("threshold"))
        window_seconds = timeframe_seconds(detection.get("timeframe") or rule.get("timeframe"))
        if sel_name not in detection:
            sys.exit(f"error: aggregation selection '{sel_name}' not found in detection block")
        selection_def = detection[sel_name]

        groups = {}
        for idx, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if not logsource_allows(record, logsource):
                continue
            ts = parse_timestamp(record.get("timestamp"))
            if window_start is not None and (ts is None or ts < window_start):
                continue
            if window_end is not None and (ts is None or ts >= window_end):
                continue
            enriched = enrich_record(record, ts, taxonomy, baseline_by_host)
            if ts is None or not selection_matches(enriched, selection_def):
                continue
            group_value = enriched.get(group_field)
            if group_value is None:
                continue
            groups.setdefault(group_value, []).append({
                "ts": ts,
                "timestamp": record.get("timestamp"),
                "hostname": record.get("hostname"),
                "event_ref": f"line:{idx}",
            })
        for group_events in groups.values():
            matches.extend(aggregate_matches(group_events, threshold, window_seconds))
    else:
        for idx, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if not logsource_allows(record, logsource):
                continue
            ts = parse_timestamp(record.get("timestamp"))
            if window_start is not None and (ts is None or ts < window_start):
                continue
            if window_end is not None and (ts is None or ts >= window_end):
                continue
            enriched = enrich_record(record, ts, taxonomy, baseline_by_host)
            selection_results = {
                name: selection_matches(enriched, detection[name]) for name in selection_names
            }
            if evaluate_condition(condition, selection_results):
                matches.append({
                    "timestamp": record.get("timestamp"),
                    "hostname": record.get("hostname"),
                    "event_ref": f"line:{idx}",
                })

execution_time_ms = round((time.perf_counter() - start_time) * 1000, 2)

if count_only:
    print(len(matches))
else:
    output = {
        "rule_id": rule["id"],
        "rule_title": rule["title"],
        "level": rule["level"],
        "evidence_path": evidence_path,
        "match_count": len(matches),
        "matches": matches,
        "execution_time_ms": execution_time_ms,
    }
    print(json.dumps(output, indent=2))
PYEOF
