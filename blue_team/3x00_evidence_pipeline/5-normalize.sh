#!/bin/bash
#
# 5-normalize.sh - transforms windows_events.json and linux_events.json
# (produced by Tasks 2 and 3) into normalized_events.json, conforming to
# the schema declared in event_schema.json. Records missing a required
# field, or with an unparseable timestamp, go to quarantine.json instead.
#
# Usage: ./5-normalize.sh
#   reads windows_events.json / linux_events.json / event_schema.json
#   from the current working directory.

set -euo pipefail

WINDOWS_FILE="windows_events.json"
LINUX_FILE="linux_events.json"
SCHEMA_FILE="event_schema.json"
NORMALIZED_FILE="normalized_events.json"
QUARANTINE_FILE="quarantine.json"

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: required command 'python3' not found." >&2
    exit 2
fi

for f in "$WINDOWS_FILE" "$LINUX_FILE" "$SCHEMA_FILE"; do
    if [ ! -f "$f" ]; then
        echo "Error: required file not found: $f" >&2
        exit 2
    fi
done

python3 - "$WINDOWS_FILE" "$LINUX_FILE" "$SCHEMA_FILE" "$NORMALIZED_FILE" "$QUARANTINE_FILE" <<'PYTHON_EOF'
import json
import sys
from datetime import datetime, timezone

windows_file, linux_file, schema_file, normalized_file, quarantine_file = sys.argv[1:6]

with open(schema_file, "r", encoding="utf-8") as f:
    schema = json.load(f)

REQUIRED_FIELDS = [f["name"] for f in schema["fields"] if f["required"]]
ALL_FIELDS = [f["name"] for f in schema["fields"]]

CURRENT_YEAR = datetime.now(timezone.utc).year
MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
          "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}


def to_iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_timestamp(raw, style):
    """Returns an ISO-8601 UTC string, or None if raw cannot be parsed."""
    if not raw:
        return None
    try:
        if style == "iso":
            # Already ISO-8601 (windows_json, or student telemetry linux
            # records whose timestamp_raw was copied from their own
            # already-normalized "timestamp" field).
            cleaned = raw.replace("Z", "+00:00")
            dt = datetime.fromisoformat(cleaned)
            return to_iso(dt.astimezone(timezone.utc))
        if style == "syslog":
            # "Mon DD HH:MM:SS" - classic syslog, no year in the source.
            month_name, day, hms = raw.split(" ", 2)
            hh, mm, ss = hms.split(":")
            dt = datetime(CURRENT_YEAR, MONTHS[month_name], int(day),
                           int(hh), int(mm), int(ss), tzinfo=timezone.utc)
            return to_iso(dt)
        if style == "audit_epoch":
            # "epoch.milliseconds" as produced by Task 3's auditd parser.
            dt = datetime.fromtimestamp(float(raw), tz=timezone.utc)
            return to_iso(dt)
    except (ValueError, KeyError):
        return None
    return None


# --- category/severity/action lookup tables ---------------------------------
# These mirror the "mapping table" source_mapping entries declared in
# event_schema.json for event_category/severity/action.

WIN_SECURITY_EVENTS = {
    4624: ("authentication", "info", "success"),
    4625: ("authentication", "medium", "failure"),
    4720: ("account_management", "medium", "success"),
    4672: ("privilege_escalation", "high", "success"),
}
WIN_SYSMON_EVENTS = {
    1: "process", 3: "network", 11: "file", 13: "file", 22: "network",
}
LINUX_AUTH_PROGRAMS = {"sudo", "su", "login", "sshd", "polkitd"}
LINUX_PROCESS_AUDIT_TYPES = {"SYSCALL", "PATH", "CWD", "PROCTITLE",
                              "SERVICE_START", "SERVICE_STOP"}
LINUX_AUTH_AUDIT_TYPES = {"USER_START", "USER_END", "USER_LOGIN"}


def windows_category_severity_action(rec):
    channel = rec.get("channel") or ""
    event_id = rec.get("event_id")
    if channel == "Security" and event_id in WIN_SECURITY_EVENTS:
        return WIN_SECURITY_EVENTS[event_id]
    if channel == "Sysmon":
        return (WIN_SYSMON_EVENTS.get(event_id, "process"), "info", None)
    if "PowerShell" in channel:
        return ("process", "info", None)
    return ("audit", "info", None)


def linux_category_severity_action(rec):
    program = rec.get("program")
    audit_type = rec.get("audit_type")
    message = (rec.get("raw_message") or "").lower()

    if program in LINUX_AUTH_PROGRAMS:
        category = "authentication"
    elif program in ("cron", "CRON"):
        category = "process"
    elif audit_type in LINUX_AUTH_AUDIT_TYPES:
        category = "authentication"
    elif audit_type in LINUX_PROCESS_AUDIT_TYPES:
        category = "process"
    else:
        category = "audit"

    if "fail" in message:
        severity, action = "high", "failure"
    elif "accepted" in message or "opened" in message or "success" in message:
        severity, action = "info", "success"
    else:
        severity, action = "info", None

    return (category, severity, action)


def digit_or_none(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def normalize_windows(rec):
    event_data = rec.get("event_data") or {}
    category, severity, action = windows_category_severity_action(rec)
    timestamp = parse_timestamp(rec.get("timestamp_raw"), "iso")
    return {
        "timestamp": timestamp,
        "hostname": rec.get("hostname"),
        "source_type": "windows_json",
        "source_origin": rec.get("source_origin"),
        "event_category": category,
        "severity": severity,
        "user": event_data.get("TargetUserName"),
        "process_name": event_data.get("Image") or rec.get("provider"),
        "pid": digit_or_none(event_data.get("ProcessId")),
        "command_line": event_data.get("CommandLine"),
        "src_ip": event_data.get("IpAddress"),
        "dst_ip": None,
        "src_port": digit_or_none(event_data.get("IpPort")),
        "dst_port": None,
        "protocol": None,
        "action": action,
        "raw_message": rec.get("raw_message"),
    }, timestamp


def normalize_linux(rec):
    is_auditd = rec.get("audit_type") is not None
    parsed_fields = rec.get("parsed_fields") or {}

    if "timestamp" in rec and rec.get("source_origin") == "student_telemetry":
        style = "iso"
    elif is_auditd:
        style = "audit_epoch"
    else:
        style = "syslog"
    timestamp = parse_timestamp(rec.get("timestamp_raw"), style)

    category, severity, action = linux_category_severity_action(rec)

    command_line = None
    message = parsed_fields.get("message") or ""
    if "COMMAND=" in message:
        command_line = message.split("COMMAND=", 1)[1].strip()
    elif "command" in rec:
        command_line = rec.get("command")

    return {
        "timestamp": timestamp,
        "hostname": rec.get("hostname"),
        "source_type": "linux_text",
        "source_origin": rec.get("source_origin"),
        "event_category": category,
        "severity": severity,
        "user": rec.get("user"),
        "process_name": rec.get("program") or parsed_fields.get("comm"),
        "pid": digit_or_none(rec.get("pid")),
        "command_line": command_line,
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "protocol": None,
        "action": action,
        "raw_message": rec.get("raw_message"),
    }, timestamp


def read_ndjson(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


normalized_out = []
quarantine_out = []
counts = {"windows_json": {"normalized": 0, "quarantined": 0},
          "linux_text": {"normalized": 0, "quarantined": 0}}


def process(records_iter, normalize_fn, source_type):
    for rec in records_iter:
        normalized, timestamp = normalize_fn(rec)
        for field in ALL_FIELDS:
            normalized.setdefault(field, None)

        missing = [f for f in REQUIRED_FIELDS if normalized.get(f) in (None, "")]
        if timestamp is None:
            missing = list(dict.fromkeys(missing + ["timestamp"]))

        if missing:
            quarantine_out.append({
                "source_type": source_type,
                "quarantine_reason": "missing required field(s): " + ", ".join(missing),
                "record": normalized,
            })
            counts[source_type]["quarantined"] += 1
        else:
            normalized_out.append(normalized)
            counts[source_type]["normalized"] += 1


process(read_ndjson(windows_file), normalize_windows, "windows_json")
process(read_ndjson(linux_file), normalize_linux, "linux_text")

with open(normalized_file, "w", encoding="utf-8") as f:
    for rec in normalized_out:
        f.write(json.dumps(rec) + "\n")

with open(quarantine_file, "w", encoding="utf-8") as f:
    for rec in quarantine_out:
        f.write(json.dumps(rec) + "\n")

total_norm = sum(c["normalized"] for c in counts.values())
total_quar = sum(c["quarantined"] for c in counts.values())

for source_type in ("windows_json", "linux_text"):
    c = counts[source_type]
    print(f"{source_type:<16} : normalized {c['normalized']:6d}  quarantined {c['quarantined']:6d}")
print(f"{'total':<16} : normalized {total_norm:6d}  quarantined {total_quar:6d}")
print(f"{normalized_file} written")
print(f"{quarantine_file}  written")
PYTHON_EOF
