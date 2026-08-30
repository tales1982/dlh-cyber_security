#!/bin/bash
#
# 0-source_inventory.sh - walks the evidence pack's windows/, linux/ and
# network/ directories and produces a structured manifest (source_inventory.json)
# recording, per file: path, source_type, size_bytes, sha256, record_count,
# and a best-effort first_event_time/last_event_time.
#
# Usage: ./0-source_inventory.sh [pack_root]
#   pack_root defaults to $HOME/evidence_pack_primary
set -euo pipefail

WORKDIR="${WORKDIR:-$(pwd)}"
EVIDENCE_PACK="${EVIDENCE_PACK:-$HOME/evidence_pack_primary}"
OUTPUT_FILE="${WORKDIR}/source_inventory.json"

if [[ ! -d "$EVIDENCE_PACK" ]]; then
    echo "ERROR: evidence pack directory not found: $EVIDENCE_PACK" >&2
    exit 1
fi

for subdir in windows linux network; do
    if [[ ! -d "${EVIDENCE_PACK}/${subdir}" ]]; then
        echo "WARNING: ${EVIDENCE_PACK}/${subdir}/ not found, skipping" >&2
    fi
done

python3 - "${WORKDIR}" "${EVIDENCE_PACK}" "${OUTPUT_FILE}" <<'PYTHON_EOF'
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

workdir = sys.argv[1]
evidence_pack = sys.argv[2]
output_file = sys.argv[3]

MONTHS = {"Jan":"01","Feb":"02","Mar":"03","Apr":"04","May":"05","Jun":"06",
          "Jul":"07","Aug":"08","Sep":"09","Oct":"10","Nov":"11","Dec":"12"}

def sha256_of(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def classify(dir_name, filename):
    if dir_name == "windows":
        return "windows_json"
    if dir_name == "linux":
        return "linux_text"
    if dir_name == "network":
        if filename.endswith(".csv"):
            return "network_csv"
        return "network_json"
    return "unknown"

def try_iso_normalize(ts_str):
    """Try to normalize a timestamp string to ISO 8601 UTC."""
    if not ts_str:
        return None
    ts_str = ts_str.strip()
    # Already ISO 8601 with Z
    if re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", ts_str):
        return ts_str
    # ISO 8601 with +00:00
    if ts_str.endswith("+00:00"):
        return ts_str[:-6] + "Z"
    # ISO 8601 with +0000 offset (e.g. Suricata)
    m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.\d+[+\-]\d{4}$", ts_str)
    if m:
        return m.group(1) + "Z"
    # ISO 8601 with fractional seconds and Z
    m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.\d+Z$", ts_str)
    if m:
        return m.group(1) + "Z"
    # MM/DD/YYYY HH:MM:SS AM/PM (PCAP summary)
    try:
        dt = datetime.strptime(ts_str, "%m/%d/%Y %I:%M:%S %p").replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        pass
    # Pure epoch seconds (integer or float as string)
    try:
        val = float(ts_str)
        if 1_000_000_000 < val < 2_000_000_000:
            dt = datetime.fromtimestamp(val, tz=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        pass
    return None

def extract_timestamp_from_json_obj(obj):
    """Try every known JSON timestamp field on an object."""
    for field in ("timestamp_raw", "timestamp", "start_time"):
        if field in obj:
            ts = try_iso_normalize(str(obj[field]))
            if ts:
                return ts
    # Epoch as integer in a timestamp field
    for field in ("timestamp", "epoch", "time"):
        if field in obj:
            ts = try_iso_normalize(str(obj[field]))
            if ts:
                return ts
    return None

def extract_timestamp_auditd(line):
    m = re.search(r"msg=audit\((\d+\.\d+):\d+\)", line)
    if m:
        epoch = float(m.group(1))
        dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    return None

def extract_timestamp_syslog(line):
    m = re.match(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})", line)
    if m:
        month_name, day, hh, mm, ss = m.groups()
        mon = MONTHS.get(month_name)
        if mon:
            return f"2026-{mon}-{int(day):02d}T{hh}:{mm}:{ss}Z"
    return None

def extract_timestamp_csv_epoch(line):
    parts = line.strip().split(",")
    if len(parts) >= 1 and parts[0].strip().isdigit():
        try:
            dt = datetime.fromtimestamp(int(parts[0].strip()), tz=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except (ValueError, OSError):
            pass
    return None

def parse_json_records(filepath):
    """Parse a JSON file that may be NDJSON or a single JSON array."""
    with open(filepath, "r", errors="replace") as f:
        content = f.read()

    # Try single JSON array first
    try:
        data = json.loads(content)
        if isinstance(data, list):
            return [obj for obj in data if isinstance(obj, dict)]
        if isinstance(data, dict):
            return [data]
    except json.JSONDecodeError:
        pass

    # Fall back to NDJSON
    records = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                records.append(obj)
        except json.JSONDecodeError:
            continue
    return records

def process_file(filepath, dir_name):
    rel_path = os.path.relpath(filepath, evidence_pack)
    filename = os.path.basename(filepath)
    source_type = classify(dir_name, filename)
    size_bytes = os.path.getsize(filepath)
    sha = sha256_of(filepath)

    first_event_time = None
    last_event_time = None
    line_count = 0
    record_count = 0

    if source_type == "windows_json":
        records = parse_json_records(filepath)
        record_count = len(records)
        for obj in records:
            ts = extract_timestamp_from_json_obj(obj)
            if ts:
                if first_event_time is None:
                    first_event_time = ts
                last_event_time = ts
        with open(filepath, "r", errors="replace") as f:
            line_count = sum(1 for l in f if l.strip())

    elif source_type == "linux_text":
        with open(filepath, "r", errors="replace") as f:
            lines = [l for l in f.readlines() if l.strip()]
        line_count = len(lines)
        record_count = line_count
        for line in lines:
            stripped = line.strip()
            ts = extract_timestamp_auditd(stripped)
            if ts is None:
                ts = extract_timestamp_syslog(stripped)
            if ts:
                if first_event_time is None:
                    first_event_time = ts
                last_event_time = ts

    elif source_type == "network_csv":
        with open(filepath, "r", errors="replace") as f:
            lines = [l for l in f.readlines() if l.strip()]
        line_count = len(lines)
        record_count = max(len(lines) - 1, 0)
        for i, line in enumerate(lines):
            if i == 0 and not line.strip().split(",")[0].strip().isdigit():
                continue
            ts = extract_timestamp_csv_epoch(line)
            if ts:
                if first_event_time is None:
                    first_event_time = ts
                last_event_time = ts

    elif source_type == "network_json":
        records = parse_json_records(filepath)
        record_count = len(records)
        for obj in records:
            ts = extract_timestamp_from_json_obj(obj)
            if ts:
                if first_event_time is None:
                    first_event_time = ts
                last_event_time = ts
        with open(filepath, "r", errors="replace") as f:
            line_count = sum(1 for l in f if l.strip())

    else:
        with open(filepath, "r", errors="replace") as f:
            line_count = sum(1 for l in f if l.strip())
        record_count = line_count

    return {
        "path": rel_path,
        "source_type": source_type,
        "size_bytes": size_bytes,
        "sha256": sha,
        "line_count": line_count,
        "record_count": record_count,
        "first_event_time": first_event_time,
        "last_event_time": last_event_time,
    }

# --- recursively walk each category -------------------------------------------
categories = ["windows", "linux", "network"]
manifest_files = []
category_stats = {}

for dir_name in categories:
    dir_path = os.path.join(evidence_pack, dir_name)
    if not os.path.isdir(dir_path):
        continue
    entries = []
    total_bytes = 0
    for root, dirs, files in os.walk(dir_path):
        dirs.sort()
        for fname in sorted(files):
            fpath = os.path.join(root, fname)
            if not os.path.isfile(fpath):
                continue
            entry = process_file(fpath, dir_name)
            entries.append(entry)
            total_bytes += entry["size_bytes"]
    manifest_files.extend(entries)
    category_stats[dir_name] = {"file_count": len(entries), "total_bytes": total_bytes}

# --- write manifest ------------------------------------------------------------
manifest = {
    "evidence_pack": evidence_pack,
    "file_count": len(manifest_files),
    "files": manifest_files,
    "summary": category_stats,
}

with open(output_file, "w") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")

# --- print human-readable summary ----------------------------------------------
def fmt_bytes(n):
    if n >= 1_000_000_000:
        return f"{n / 1_000_000_000:.1f} GB"
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f} MB"
    if n >= 1_000:
        return f"{n / 1_000:.1f} KB"
    return f"{n} B"

total_files = 0
total_bytes = 0

for cat in ["windows", "linux", "network"]:
    stats = category_stats.get(cat, {"file_count": 0, "total_bytes": 0})
    total_files += stats["file_count"]
    total_bytes += stats["total_bytes"]
    print(f"{cat:8s}: {stats['file_count']:3d} files | {fmt_bytes(stats['total_bytes']):>8s}")

print(f"{'total':8s}: {total_files:3d} files | {fmt_bytes(total_bytes):>8s}")
print(f"manifest written to source_inventory.json")

PYTHON_EOF