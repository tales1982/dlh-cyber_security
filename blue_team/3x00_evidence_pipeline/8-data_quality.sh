#!/bin/bash
#
# 8-data_quality.sh - detects and repairs the planted data-quality defects
# in normalized_events.json: malformed timestamps, duplicate events,
# inconsistent hostname casing, encoding errors, and suspected wrong
# timezone. Writes cleaned_events.json (the repaired dataset) and
# cleaning_log.json (one entry per correction/flag applied).
#
# Usage: ./8-data_quality.sh
#   reads normalized_events.json from the current working directory.

set -euo pipefail

NORMALIZED_FILE="normalized_events.json"
CLEANED_FILE="cleaned_events.json"
LOG_FILE="cleaning_log.json"

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: required command 'python3' not found." >&2
    exit 2
fi

if [ ! -f "$NORMALIZED_FILE" ]; then
    echo "Error: required file not found: $NORMALIZED_FILE" >&2
    exit 2
fi

python3 - "$NORMALIZED_FILE" "$CLEANED_FILE" "$LOG_FILE" <<'PYTHON_EOF'
import json
import sys
from datetime import datetime, timedelta, timezone

normalized_file, cleaned_file, log_file = sys.argv[1:4]

ISO_FORMATS = [
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S",
]


def try_parse_iso(value):
    """Attempts a strict ISO-8601 parse, then a short list of fallback
    formats. Returns (parsed_datetime, canonical_string) or (None, None)
    if every attempt fails."""
    if not value or not isinstance(value, str):
        return None, None
    for fmt in ISO_FORMATS:
        try:
            dt = datetime.strptime(value, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt, dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue
    return None, None


with open(normalized_file, "r", encoding="utf-8", errors="replace") as f:
    records = [json.loads(line) for line in f if line.strip()]

log_entries = []
cleaned = []

# --- Pass 1: timestamp validation/repair, hostname case, encoding --------
malformed_detected = 0
malformed_repaired = 0
malformed_dropped = 0
hostname_normalized = 0
encoding_detected = 0
encoding_repaired = 0

parsed_timestamps = []  # (record_id, datetime) for every surviving record

for record_id, rec in enumerate(records):
    original_ts = rec.get("timestamp")
    dt, canonical = try_parse_iso(original_ts)

    if dt is None:
        malformed_detected += 1
        log_entries.append({
            "defect_type": "malformed_timestamp",
            "original_value": original_ts,
            "corrected_value": None,
            "record_id": record_id,
            "reason": "timestamp does not parse under ISO-8601 or any known fallback format; record dropped (unrepairable)",
        })
        malformed_dropped += 1
        continue
    if canonical != original_ts:
        malformed_detected += 1
        malformed_repaired += 1
        log_entries.append({
            "defect_type": "malformed_timestamp",
            "original_value": original_ts,
            "corrected_value": canonical,
            "record_id": record_id,
            "reason": "timestamp did not match the canonical ISO-8601 UTC format; repaired via fallback format parsing",
        })
        rec["timestamp"] = canonical

    # Hostname case normalization.
    hostname = rec.get("hostname")
    if hostname and hostname != hostname.lower():
        log_entries.append({
            "defect_type": "hostname_case",
            "original_value": hostname,
            "corrected_value": hostname.lower(),
            "record_id": record_id,
            "reason": "hostname was not lowercase; normalized so the same host is not counted as multiple distinct hosts",
        })
        rec["hostname"] = hostname.lower()
        hostname_normalized += 1

    # Encoding errors: a literal U+FFFD replacement character in
    # raw_message means the original byte was already lost upstream by
    # the time this stage sees it - it can be detected and flagged here,
    # but genuine repair (re-decoding the true byte) is only possible at
    # the point the file is first read, not from already-lossy text.
    raw_message = rec.get("raw_message") or ""
    if "�" in raw_message:
        encoding_detected += 1
        log_entries.append({
            "defect_type": "encoding_error",
            "original_value": raw_message,
            "corrected_value": None,
            "record_id": record_id,
            "reason": "raw_message contains a replacement character (U+FFFD); the original byte was already lost before reaching this stage and cannot be recovered here",
        })

    rec["_record_id"] = record_id
    cleaned.append(rec)
    parsed_timestamps.append((record_id, dt))

# --- Pass 2: duplicates -----------------------------------------------------
seen = {}
duplicates_detected = 0
deduped = []
for rec in cleaned:
    key = (rec.get("timestamp"), rec.get("hostname"), rec.get("source_type"), rec.get("raw_message"))
    if key in seen:
        duplicates_detected += 1
        log_entries.append({
            "defect_type": "duplicate",
            "original_value": key[3],
            "corrected_value": None,
            "record_id": rec.get("_record_id"),
            "reason": f"identical (timestamp, hostname, source_type, raw_message) already kept from record_id {seen[key]}; this repeat was dropped",
        })
        continue
    seen[key] = rec.get("_record_id")
    deduped.append(rec)
cleaned = deduped

# --- Pass 3: suspected wrong timezone ---------------------------------------
# Expected range is derived from the data itself (2nd/98th percentile of
# all surviving timestamps), not hardcoded, so this generalizes to a pack
# with a different time window without modification.
tz_flagged = 0
if parsed_timestamps:
    sorted_dts = sorted(dt for _, dt in parsed_timestamps)
    n = len(sorted_dts)
    p2 = sorted_dts[int(n * 0.02)]
    p98 = sorted_dts[min(int(n * 0.98), n - 1)]
    tolerance = timedelta(hours=12)
    expected_start = p2 - tolerance
    expected_end = p98 + tolerance

    for record_id, dt in parsed_timestamps:
        if dt < expected_start or dt > expected_end:
            tz_flagged += 1
            log_entries.append({
                "defect_type": "suspected_wrong_tz",
                "original_value": dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "corrected_value": None,
                "record_id": record_id,
                "reason": f"timestamp falls outside the evidence pack's expected date range "
                          f"({expected_start.strftime('%Y-%m-%dT%H:%M:%SZ')} to "
                          f"{expected_end.strftime('%Y-%m-%dT%H:%M:%SZ')}) by more than 12 hours",
            })

# Strip the internal bookkeeping key before writing out.
for rec in cleaned:
    rec.pop("_record_id", None)

with open(cleaned_file, "w", encoding="utf-8") as f:
    for rec in cleaned:
        f.write(json.dumps(rec) + "\n")

with open(log_file, "w", encoding="utf-8") as f:
    for entry in log_entries:
        f.write(json.dumps(entry) + "\n")

print(f"malformed timestamps   : {malformed_detected:6d} detected  {malformed_repaired:6d} repaired  {malformed_dropped:6d} dropped")
print(f"duplicates             : {duplicates_detected:6d} detected  {duplicates_detected:6d} removed")
print(f"hostname case          : {hostname_normalized:6d} normalized")
print(f"encoding errors        : {encoding_detected:6d} detected  {encoding_repaired:6d} repaired")
print(f"suspected wrong tz      : {tz_flagged:6d} flagged")
print(f"{cleaned_file}    written")
print(f"{log_file}      written")
PYTHON_EOF
