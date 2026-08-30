#!/bin/bash
#
# 2-windows_parse.sh - merges the three Windows NDJSON evidence files
# (security.json, sysmon.json, powershell.json) plus the Module 2 student
# telemetry windows events into a single windows_events.json, ready for
# normalization downstream.
#
# Usage: ./2-windows_parse.sh [pack_root]
#   pack_root defaults to $HOME/evidence_pack_primary

set -euo pipefail

PACK_ROOT="${1:-$HOME/evidence_pack_primary}"
WINDOWS_DIR="${PACK_ROOT}/windows"
STUDENT_FILE="${PACK_ROOT}/student_telemetry/windows_events.json"
OUTPUT_FILE="windows_events.json"

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: required command 'python3' not found." >&2
    exit 2
fi

for f in security.json sysmon.json powershell.json; do
    if [ ! -f "${WINDOWS_DIR}/${f}" ]; then
        echo "Error: required file not found: ${WINDOWS_DIR}/${f}" >&2
        exit 2
    fi
done

if [ ! -f "$STUDENT_FILE" ]; then
    echo "Error: required file not found: $STUDENT_FILE" >&2
    exit 2
fi

python3 - "$WINDOWS_DIR" "$STUDENT_FILE" "$OUTPUT_FILE" <<'PYTHON_EOF'
import json
import sys

windows_dir = sys.argv[1]
student_file = sys.argv[2]
output_file = sys.argv[3]

REQUIRED_FIELDS = ["timestamp_raw", "hostname", "event_id", "channel",
                   "provider", "raw_message", "event_data", "source_origin"]

EVIDENCE_FILES = ["security.json", "sysmon.json", "powershell.json"]


def read_ndjson(path):
    records = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


out_lines = []

for fname in EVIDENCE_FILES:
    records = read_ndjson(f"{windows_dir}/{fname}")
    for rec in records:
        # Already set by the evidence pack per the task's own note - verify
        # and only fill it in if it were somehow missing.
        if not rec.get("source_origin"):
            rec["source_origin"] = "evidence_pack"
        for field in REQUIRED_FIELDS:
            rec.setdefault(field, None)
        out_lines.append(json.dumps(rec))
    print(f"reading {fname:<19}... {len(records):5d} records")

# The student telemetry file (Module 2 output) uses a different field
# naming convention than the evidence pack. Where a student field is the
# same underlying information under a different name, it is reused rather
# than left null; where there is genuinely nothing equivalent (provider),
# it stays null instead of being invented.
student_records = read_ndjson(student_file)
for rec in student_records:
    if not rec.get("source_origin"):
        rec["source_origin"] = "student_telemetry"
    rec.setdefault("timestamp_raw", rec.get("timestamp"))
    rec.setdefault("channel", rec.get("source_type"))
    rec.setdefault("provider", None)
    if "event_data" not in rec:
        extra = {k: rec[k] for k in ("user", "command_line", "event_category") if k in rec}
        rec["event_data"] = extra if extra else None
    for field in REQUIRED_FIELDS:
        rec.setdefault(field, None)
    out_lines.append(json.dumps(rec))
print(f"appending student telemetry ... {len(student_records):5d} records")

with open(output_file, "w", encoding="utf-8") as f:
    for line in out_lines:
        f.write(line + "\n")

print(f"{output_file}: {len(out_lines)} records")
PYTHON_EOF
