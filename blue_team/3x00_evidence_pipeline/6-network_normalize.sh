#!/bin/bash
#
# 6-network_normalize.sh - normalizes firewall.csv, suricata_eve.json and
# pcap_summary.json into the unified schema (event_schema.json), appends
# the result to normalized_events.json and writes a standalone
# network_events.json.
#
# Usage: ./6-network_normalize.sh [pack_root]
#   pack_root defaults to $HOME/evidence_pack_primary
#   reads/writes normalized_events.json and network_events.json from the
#   current working directory.

set -euo pipefail

PACK_ROOT="${1:-$HOME/evidence_pack_primary}"
NETWORK_DIR="${PACK_ROOT}/network"
NORMALIZED_FILE="normalized_events.json"
NETWORK_OUTPUT_FILE="network_events.json"

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: required command 'python3' not found." >&2
    exit 2
fi

for f in firewall.csv suricata_eve.json pcap_summary.json; do
    if [ ! -f "${NETWORK_DIR}/${f}" ]; then
        echo "Error: required file not found: ${NETWORK_DIR}/${f}" >&2
        exit 2
    fi
done

python3 - "$NETWORK_DIR" "$NORMALIZED_FILE" "$NETWORK_OUTPUT_FILE" <<'PYTHON_EOF'
import csv
import json
import sys
from datetime import datetime, timedelta, timezone

network_dir, normalized_file, network_output_file = sys.argv[1:4]

SCHEMA_FIELDS = [
    "timestamp", "hostname", "source_type", "source_origin", "event_category",
    "severity", "user", "process_name", "pid", "command_line", "src_ip",
    "dst_ip", "src_port", "dst_port", "protocol", "action", "signature",
    "raw_message",
]


def to_iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def blank_record():
    return {field: None for field in SCHEMA_FIELDS}


def digit_or_none(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# --- firewall.csv: Unix epoch seconds in column 1 --------------------------
def normalize_firewall(row):
    rec = blank_record()
    try:
        dt = datetime.fromtimestamp(int(row["timestamp"]), tz=timezone.utc)
        rec["timestamp"] = to_iso(dt)
    except (ValueError, OSError, KeyError):
        rec["timestamp"] = None
    rec["source_type"] = "firewall"
    rec["source_origin"] = "evidence_pack"
    rec["event_category"] = "network"
    action = row.get("action")
    rec["action"] = action  # preserved verbatim: "ALLOW" or "BLOCK"
    rec["severity"] = "medium" if action == "BLOCK" else "info"
    rec["src_ip"] = row.get("src_ip")
    rec["dst_ip"] = row.get("dst_ip")
    rec["src_port"] = digit_or_none(row.get("src_port"))
    rec["dst_port"] = digit_or_none(row.get("dst_port"))
    rec["protocol"] = row.get("protocol")
    rec["raw_message"] = (
        f"firewall: {action} {row.get('protocol')} "
        f"{row.get('src_ip')}:{row.get('src_port')} -> "
        f"{row.get('dst_ip')}:{row.get('dst_port')} (rule {row.get('rule_id')})"
    )
    return rec


# --- suricata_eve.json: ISO-8601 with microseconds + numeric offset --------
SURICATA_SEVERITY = {1: "high", 2: "medium", 3: "low"}


def normalize_suricata(obj):
    rec = blank_record()
    raw_ts = obj.get("timestamp")
    try:
        # e.g. "2026-03-18T00:00:31.026524+0000"
        dt = datetime.strptime(raw_ts, "%Y-%m-%dT%H:%M:%S.%f%z")
        rec["timestamp"] = to_iso(dt.astimezone(timezone.utc))
    except (ValueError, TypeError):
        rec["timestamp"] = None
    rec["source_type"] = "suricata"
    rec["source_origin"] = "evidence_pack"
    rec["event_category"] = "network_alert"
    alert = obj.get("alert") or {}
    rec["signature"] = alert.get("signature")
    rec["severity"] = SURICATA_SEVERITY.get(alert.get("severity"), "low")
    rec["action"] = alert.get("action")
    rec["src_ip"] = obj.get("src_ip")
    rec["dst_ip"] = obj.get("dest_ip")
    rec["src_port"] = digit_or_none(obj.get("src_port"))
    rec["dst_port"] = digit_or_none(obj.get("dest_port"))
    rec["protocol"] = obj.get("proto")
    rec["raw_message"] = (
        f"suricata: {rec['signature']} ({alert.get('category')}) "
        f"{rec['src_ip']}:{rec['src_port']} -> {rec['dst_ip']}:{rec['dst_port']}"
    )
    return rec


# --- pcap_summary.json: US-format 12h clock, documented as CST (UTC-6) -----
def normalize_pcap(obj):
    rec = blank_record()
    raw_ts = obj.get("start_time")
    try:
        dt = datetime.strptime(raw_ts, "%m/%d/%Y %I:%M:%S %p")
        dt_utc = (dt + timedelta(hours=6)).replace(tzinfo=timezone.utc)
        rec["timestamp"] = to_iso(dt_utc)
    except (ValueError, TypeError):
        rec["timestamp"] = None
    rec["source_type"] = "pcap"
    rec["source_origin"] = "evidence_pack"
    rec["event_category"] = "network_flow"
    rec["severity"] = "info"
    rec["src_ip"] = obj.get("src_ip")
    rec["dst_ip"] = obj.get("dst_ip")
    rec["src_port"] = digit_or_none(obj.get("src_port"))
    rec["dst_port"] = digit_or_none(obj.get("dst_port"))
    rec["protocol"] = obj.get("protocol")
    rec["raw_message"] = (
        f"pcap flow: {rec['protocol']} {rec['src_ip']}:{rec['src_port']} -> "
        f"{rec['dst_ip']}:{rec['dst_port']} "
        f"({obj.get('packets')} pkts, {obj.get('bytes_total')} bytes, "
        f"{obj.get('duration_seconds')}s, flags={obj.get('flags')})"
    )
    return rec


network_records = []

# --- firewall.csv ------------------------------------------------------------
with open(f"{network_dir}/firewall.csv", "r", encoding="utf-8", errors="replace", newline="") as f:
    reader = csv.DictReader(f)
    firewall_count = 0
    for row in reader:
        network_records.append(normalize_firewall(row))
        firewall_count += 1
print(f"{'firewall.csv':<20} : {firewall_count:7d} records normalized")

# --- suricata_eve.json (NDJSON) -----------------------------------------------
suricata_count = 0
with open(f"{network_dir}/suricata_eve.json", "r", encoding="utf-8", errors="replace") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        network_records.append(normalize_suricata(obj))
        suricata_count += 1
print(f"{'suricata_eve.json':<20} : {suricata_count:7d} records normalized")

# --- pcap_summary.json (NDJSON) -----------------------------------------------
pcap_count = 0
with open(f"{network_dir}/pcap_summary.json", "r", encoding="utf-8", errors="replace") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        network_records.append(normalize_pcap(obj))
        pcap_count += 1
print(f"{'pcap_summary.json':<20} : {pcap_count:7d} records normalized")

# --- write standalone network_events.json -------------------------------------
with open(network_output_file, "w", encoding="utf-8") as f:
    for rec in network_records:
        f.write(json.dumps(rec) + "\n")

# --- append to normalized_events.json (append mode, does not touch existing
# windows/linux records already written there by Task 5) --------------------
with open(normalized_file, "a", encoding="utf-8") as f:
    for rec in network_records:
        f.write(json.dumps(rec) + "\n")

print(f"appended to {normalized_file}")
print(f"{network_output_file} written")
PYTHON_EOF
