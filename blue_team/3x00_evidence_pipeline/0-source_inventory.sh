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

PACK_ROOT="${1:-$HOME/evidence_pack_primary}"
WORKDIR="$(pwd)"
OUTPUT_FILE="${WORKDIR}/source_inventory.json"

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: required command 'python3' not found." >&2
    exit 2
fi

if [ ! -d "$PACK_ROOT" ]; then
    echo "Error: evidence pack root '$PACK_ROOT' not found." >&2
    exit 2
fi

for subdir in windows linux network; do
    if [ ! -d "${PACK_ROOT}/${subdir}" ]; then
        echo "Warning: ${PACK_ROOT}/${subdir}/ not found, skipping." >&2
    fi
done

python3 - "$PACK_ROOT" "$OUTPUT_FILE" <<'PYTHON_EOF'
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone

evidence_pack = sys.argv[1]
output_file = sys.argv[2]

MONTHS = {"Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04", "May": "05", "Jun": "06",
          "Jul": "07", "Aug": "08", "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12"}

# No year is present in classic syslog timestamps. There is nothing in the
# source data to disambiguate it from, so the current year is used - a
# documented, unavoidable limitation of that format, not a guess we can do
# better than without external context.
CURRENT_YEAR = datetime.now(timezone.utc).year


def sha256_of(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def classify(dir_name, filename):
    if dir_name == "windows":
        return "windows_json"
    if dir_name == "linux":
        return "linux_text"
    # network/: only .csv is ever anything but JSON in this pack's layout;
    # every other extension under network/ is treated as network_json,
    # since the task defines exactly four source_type values and none of
    # them is a catch-all "unknown".
    if filename.endswith(".csv"):
        return "network_csv"
    return "network_json"


def try_iso_normalize(ts_str):
    """Parse a raw timestamp string in any of the pack's known formats and
    return it as canonical ISO-8601 UTC (YYYY-MM-DDTHH:MM:SSZ), or None if
    it cannot be parsed - never trusts the raw string's own ordering."""
    if not ts_str:
        return None
    ts_str = ts_str.strip()

    # Already ISO-8601 with Z, second precision.
    if re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", ts_str):
        return ts_str

    # ISO-8601 with fractional seconds and Z (drop the fraction).
    m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.\d+Z$", ts_str)
    if m:
        return m.group(1) + "Z"

    # ISO-8601 with a numeric UTC offset, e.g. +00:00 or +0000, optionally
    # with fractional seconds (Suricata's eve.json format).
    m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?([+-]\d{2}:?\d{2})$", ts_str)
    if m:
        base, offset = m.groups()
        offset = offset.replace(":", "")
        try:
            dt = datetime.strptime(base + offset, "%Y-%m-%dT%H:%M:%S%z")
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            return None

    # US-format 12h clock, as used by pcap_summary.json, documented as CST
    # (UTC-6). The naive wall-clock value is parsed first, then genuinely
    # shifted by +6 hours to land on the correct UTC instant - not just
    # relabeled as if it had already been UTC.
    try:
        dt = datetime.strptime(ts_str, "%m/%d/%Y %I:%M:%S %p")
        dt_utc = (dt + timedelta(hours=6)).replace(tzinfo=timezone.utc)
        return dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        pass

    # Bare epoch seconds (integer or float as text).
    try:
        val = float(ts_str)
        if 1_000_000_000 < val < 2_000_000_000:
            dt = datetime.fromtimestamp(val, tz=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        pass

    return None


def extract_timestamp_from_json_obj(obj):
    """Try every known JSON timestamp field, in priority order, on a
    single parsed record."""
    for field in ("timestamp_raw", "timestamp", "start_time"):
        if field in obj:
            ts = try_iso_normalize(str(obj[field]))
            if ts:
                return ts
    return None


def extract_timestamp_auditd(line):
    m = re.search(r"msg=audit\((\d+)(?:\.\d+)?:\d+\)", line)
    if not m:
        return None
    try:
        dt = datetime.fromtimestamp(int(m.group(1)), tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OSError):
        return None


def extract_timestamp_syslog(line):
    m = re.match(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})", line)
    if not m:
        return None
    month_name, day, hh, mm, ss = m.groups()
    mon = MONTHS.get(month_name)
    if not mon:
        return None
    try:
        datetime(CURRENT_YEAR, int(mon), int(day), int(hh), int(mm), int(ss))
    except ValueError:
        return None
    return f"{CURRENT_YEAR}-{mon}-{int(day):02d}T{hh}:{mm}:{ss}Z"


def extract_timestamp_csv_epoch(first_field):
    if not first_field.strip().isdigit():
        return None
    try:
        dt = datetime.fromtimestamp(int(first_field.strip()), tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OSError):
        return None


def parse_json_records(filepath):
    """Read a JSON file that may be NDJSON (one document per line) or a
    single pretty-printed JSON array/object. Malformed individual lines
    are skipped, not fatal - a source file with a handful of corrupt
    records is expected, real-world evidence, not a reason to abort."""
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    try:
        data = json.loads(content)
        if isinstance(data, list):
            return [obj for obj in data if isinstance(obj, dict)]
        if isinstance(data, dict):
            return [data]
    except json.JSONDecodeError:
        pass

    records = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            records.append(obj)
    return records


def process_file(filepath, dir_name):
    rel_path = os.path.relpath(filepath, evidence_pack)
    filename = os.path.basename(filepath)
    source_type = classify(dir_name, filename)
    size_bytes = os.path.getsize(filepath)
    sha = sha256_of(filepath)

    first_event_time = None
    last_event_time = None
    record_count = 0

    def update_range(ts):
        nonlocal first_event_time, last_event_time
        if ts is None:
            return
        if first_event_time is None or ts < first_event_time:
            first_event_time = ts
        if last_event_time is None or ts > last_event_time:
            last_event_time = ts

    if source_type in ("windows_json", "network_json"):
        records = parse_json_records(filepath)
        record_count = len(records)
        for obj in records:
            update_range(extract_timestamp_from_json_obj(obj))

    elif source_type == "linux_text":
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            lines = [line.rstrip("\n") for line in f if line.strip()]
        record_count = len(lines)
        for line in lines:
            ts = extract_timestamp_auditd(line)
            if ts is None:
                ts = extract_timestamp_syslog(line)
            update_range(ts)

    elif source_type == "network_csv":
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            lines = [line.rstrip("\n") for line in f if line.strip()]
        header_present = bool(lines) and not lines[0].split(",")[0].strip().isdigit()
        data_lines = lines[1:] if header_present else lines
        record_count = len(data_lines)
        for line in data_lines:
            first_field = line.split(",")[0] if line else ""
            update_range(extract_timestamp_csv_epoch(first_field))

    return {
        "path": rel_path,
        "source_type": source_type,
        "size_bytes": size_bytes,
        "sha256": sha,
        "record_count": record_count,
        "first_event_time": first_event_time,
        "last_event_time": last_event_time,
    }


categories = ["windows", "linux", "network"]
manifest_files = []
category_stats = {}

for dir_name in categories:
    dir_path = os.path.join(evidence_pack, dir_name)
    if not os.path.isdir(dir_path):
        category_stats[dir_name] = {"file_count": 0, "total_bytes": 0}
        continue
    entries = []
    total_bytes = 0
    for fname in sorted(os.listdir(dir_path)):
        fpath = os.path.join(dir_path, fname)
        if not os.path.isfile(fpath):
            continue
        try:
            entry = process_file(fpath, dir_name)
        except OSError as exc:
            print(f"Warning: could not read '{fpath}': {exc}", file=sys.stderr)
            continue
        entries.append(entry)
        total_bytes += entry["size_bytes"]
    manifest_files.extend(entries)
    category_stats[dir_name] = {"file_count": len(entries), "total_bytes": total_bytes}

total_files = sum(s["file_count"] for s in category_stats.values())
total_bytes_all = sum(s["total_bytes"] for s in category_stats.values())

manifest = {
    "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "pack_root": evidence_pack,
    "summary": {
        "windows": category_stats.get("windows", {"file_count": 0, "total_bytes": 0}),
        "linux": category_stats.get("linux", {"file_count": 0, "total_bytes": 0}),
        "network": category_stats.get("network", {"file_count": 0, "total_bytes": 0}),
        "total": {"file_count": total_files, "total_bytes": total_bytes_all},
    },
    "files": manifest_files,
}

with open(output_file, "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")


def fmt_mb(n):
    return f"{n / 1_000_000:5.1f} MB"


for cat in ["windows", "linux", "network"]:
    stats = category_stats.get(cat, {"file_count": 0, "total_bytes": 0})
    print(f"{cat:7s} : {stats['file_count']} files  |  {fmt_mb(stats['total_bytes'])}")

print(f"{'total':7s} : {total_files} files  |  {fmt_mb(total_bytes_all)}")
print(f"manifest written to {os.path.basename(output_file)}")
PYTHON_EOF
