#!/bin/bash
#
# 3-linux_parse.sh - parses auth.log, audit.log and syslog into structured
# NDJSON records, appends student telemetry, ready for normalization.
#
# Usage: ./3-linux_parse.sh [pack_root]
#   pack_root defaults to $HOME/evidence_pack_primary

set -euo pipefail

PACK_ROOT="${1:-$HOME/evidence_pack_primary}"
LINUX_DIR="${PACK_ROOT}/linux"
STUDENT_FILE="${PACK_ROOT}/student_telemetry/linux_events.json"
OUTPUT_FILE="linux_events.json"

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: required command 'python3' not found." >&2
    exit 2
fi

for f in auth.log audit.log syslog; do
    if [ ! -f "${LINUX_DIR}/${f}" ]; then
        echo "Error: required file not found: ${LINUX_DIR}/${f}" >&2
        exit 2
    fi
done

if [ ! -f "$STUDENT_FILE" ]; then
    echo "Error: required file not found: $STUDENT_FILE" >&2
    exit 2
fi

python3 - "$LINUX_DIR" "$STUDENT_FILE" "$OUTPUT_FILE" <<'PYTHON_EOF'
import json
import re
import sys

linux_dir = sys.argv[1]
student_file = sys.argv[2]
output_file = sys.argv[3]

# --- syslog-style prefix (auth.log and syslog share this grammar) ----------
# Mon DD HH:MM:SS hostname program[pid]: message
# The first 15 characters are always the timestamp (fixed width).
SYSLOG_PREFIX = re.compile(r'^(\S+) ([^ \[:]+)(?:\[(\d+)\])?: ?(.*)$')

# Three different "recipes" for finding a username inside the free-text
# message, tried in order - one per family of programs. None matching is
# expected and fine (the task says "user if present").
USER_RECIPES = [
    re.compile(r'\bfor user (\S+?)[.\s(]'),   # su/polkitd/login/CRON: "for user X"
    re.compile(r'\bfor user (\S+)$'),         # same, but X runs to end of line
    re.compile(r'\bof user (\S+?)\.?$'),      # systemd-logind: "of user X."
    re.compile(r'^(\S+) : TTY='),             # sudo: username is the first word
    re.compile(r'\bfor (\S+) from \d'),       # sshd: "for X from <ip>"
]


def extract_user(message):
    for pattern in USER_RECIPES:
        m = pattern.search(message)
        if m:
            return m.group(1)
    return None


def parse_syslog_line(line):
    m = SYSLOG_PREFIX.match(line[16:] if len(line) > 16 else line)
    # line[:15] is the fixed-width timestamp; line[15] is the separating space.
    timestamp_raw = line[:15]
    if not m:
        return {
            "timestamp_raw": timestamp_raw,
            "hostname": None,
            "program": None,
            "pid": None,
            "user": None,
            "raw_message": line,
            "parsed_fields": {},
            "source_origin": "evidence_pack",
        }
    hostname, program, pid, message = m.groups()
    return {
        "timestamp_raw": timestamp_raw,
        "hostname": hostname,
        "program": program,
        "pid": int(pid) if pid else None,
        "user": extract_user(message),
        "raw_message": line,
        "parsed_fields": {"message": message},
        "source_origin": "evidence_pack",
    }


# --- auditd key=value grammar -----------------------------------------------
AUDIT_TYPE = re.compile(r'^type=(\S+)')
AUDIT_ID = re.compile(r'msg=audit\((\d+)\.(\d+):(\d+)\)')
KV_PAIR = re.compile(r'(\w+)=("[^"]*"|\'[^\']*\'|\S+)')


def parse_audit_line(line):
    type_match = AUDIT_TYPE.match(line)
    id_match = AUDIT_ID.search(line)
    audit_type = type_match.group(1) if type_match else None
    if id_match:
        epoch, ms, serial = id_match.groups()
        group_id = f"{epoch}.{ms}:{serial}"
        timestamp_raw = f"{epoch}.{ms}"
    else:
        group_id = None
        timestamp_raw = None

    fields = {}
    for key, value in KV_PAIR.findall(line):
        fields[key] = value.strip("\"'")

    return {
        "audit_type": audit_type,
        "group_id": group_id,
        "timestamp_raw": timestamp_raw,
        "pid": int(fields["pid"]) if fields.get("pid", "").isdigit() else None,
        "user": fields.get("acct"),
        "raw_message": line,
        "fields": fields,
    }


def group_audit_lines(lines):
    """Auditd can emit several lines (SYSCALL, CWD, PATH, ...) that share
    the same audit(epoch.ms:serial) id, all describing one logical event.
    They are combined into a single record here; a line with no id of its
    own (should not normally happen) becomes its own group."""
    groups = {}
    order = []
    ungrouped_counter = 0
    for line in lines:
        parsed = parse_audit_line(line)
        key = parsed["group_id"]
        if key is None:
            ungrouped_counter += 1
            key = f"__ungrouped_{ungrouped_counter}"
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(parsed)

    records = []
    for key in order:
        members = groups[key]
        merged_fields = {}
        types = []
        pid = None
        user = None
        timestamp_raw = None
        raw_lines = []
        for m in members:
            if m["audit_type"]:
                types.append(m["audit_type"])
            merged_fields.update(m["fields"])
            pid = pid or m["pid"]
            user = user or m["user"]
            timestamp_raw = timestamp_raw or m["timestamp_raw"]
            raw_lines.append(m["raw_message"])
        merged_fields["audit_group_id"] = key
        records.append({
            "timestamp_raw": timestamp_raw,
            "hostname": None,  # auditd lines do not carry a hostname field
            "audit_type": ",".join(types) if types else None,
            "pid": pid,
            "user": user,
            "raw_message": "\n".join(raw_lines),
            "parsed_fields": merged_fields,
            "source_origin": "evidence_pack",
        })
    return records


out_lines = []

# --- auth.log and syslog: same grammar --------------------------------------
for fname in ("auth.log", "syslog"):
    count = 0
    with open(f"{linux_dir}/{fname}", "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            out_lines.append(json.dumps(parse_syslog_line(line)))
            count += 1
    print(f"parsing {fname:<12} ... {count:6d} lines  -> {count:6d} records")

# --- audit.log: grouped by audit(...) id -------------------------------------
with open(f"{linux_dir}/audit.log", "r", encoding="utf-8", errors="replace") as f:
    audit_lines = [line.rstrip("\n") for line in f if line.strip()]
audit_records = group_audit_lines(audit_lines)
for rec in audit_records:
    out_lines.append(json.dumps(rec))
print(f"parsing {'audit.log':<12} ... {len(audit_lines):6d} lines  -> "
      f"{len(audit_records):6d} records (grouped)")

# --- student telemetry --------------------------------------------------------
with open(student_file, "r", encoding="utf-8", errors="replace") as f:
    student_lines = [line.strip() for line in f if line.strip()]

for line in student_lines:
    rec = json.loads(line)
    if not rec.get("source_origin"):
        rec["source_origin"] = "student_telemetry"
    rec.setdefault("timestamp_raw", rec.get("timestamp"))
    rec.setdefault("program", rec.get("source_type"))
    rec.setdefault("pid", None)
    if "parsed_fields" not in rec:
        extra = {k: rec[k] for k in ("command", "event_category") if k in rec}
        rec["parsed_fields"] = extra
    out_lines.append(json.dumps(rec))

print(f"appending student telemetry ... {len(student_lines):6d} records")

with open(output_file, "w", encoding="utf-8") as f:
    for line in out_lines:
        f.write(line + "\n")

print(f"{output_file}: written")
PYTHON_EOF
