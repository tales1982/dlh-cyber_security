#!/bin/bash
set -euo pipefail

CATALOG_DIR="${CATALOG_DIR:-$HOME/3x02_package/detection_catalog}"
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x03_assets}"

QUEUE_FILE="$CATALOG_DIR/alerts/alert_queue.json"
ASSET_FILE="$HANDOFF_DIR/context/asset_inventory.json"
EVENTS_FILE="$HANDOFF_DIR/data/enriched_events.json"
BASELINE_FILE="$BASELINE_PKG/baselines/baseline_summary.json"
IOC_FILE="$ASSETS_DIR/ioc_context.json"
OUTPUT_FILE="enriched_queue.json"

mkdir -p tickets

for f in "$QUEUE_FILE" "$ASSET_FILE" "$EVENTS_FILE" "$BASELINE_FILE" "$IOC_FILE"; do
    if [[ ! -f "$f" ]]; then
        echo "error: required input not found: $f" >&2
        exit 1
    fi
done

python3 - "$QUEUE_FILE" "$ASSET_FILE" "$EVENTS_FILE" "$BASELINE_FILE" "$IOC_FILE" "$OUTPUT_FILE" <<'PYEOF'
import json
import os
import sys

queue_path, asset_path, events_path, baseline_path, ioc_path, output_path = sys.argv[1:7]

PRIORITY_BANDS = [
    ("critical", 20, float("inf")),
    ("high", 10, 20),
    ("medium", 5, 10),
    ("low", 1, 5),
]


def priority_band(score):
    for name, lo, hi in PRIORITY_BANDS:
        if lo <= score < hi:
            return name
    return "low" if score < 1 else "critical"


with open(queue_path) as f:
    queue = json.load(f)

# asset_inventory.json has been observed in two shapes across this pipeline:
# a bare list of asset records, or an object wrapping them under "assets".
# Some richer lab deployments also carry inventory-wide metadata alongside
# the asset list (service_account_prefix, management_subnets); read them if
# present, otherwise the FP signatures that depend on them simply never
# match (logged once below) instead of crashing on a thinner local fixture.
with open(asset_path) as f:
    asset_raw = json.load(f)
if isinstance(asset_raw, dict):
    asset_records = asset_raw.get("assets", [])
    service_account_prefix = asset_raw.get("service_account_prefix")
    management_subnets = asset_raw.get("management_subnets", [])
else:
    asset_records = asset_raw
    service_account_prefix = None
    management_subnets = []

assets_by_hostname = {a["hostname"]: a for a in asset_records if a.get("hostname")}

if service_account_prefix is None:
    print(
        "warning: asset inventory has no 'service_account_prefix' - "
        "service-account FP signature will never match",
        file=sys.stderr,
    )
if not management_subnets:
    print(
        "warning: asset inventory has no 'management_subnets' - "
        "management-subnet FP signature will never match",
        file=sys.stderr,
    )

with open(baseline_path) as f:
    baseline = json.load(f)

with open(ioc_path) as f:
    ioc_context = json.load(f)

# --- resolve each alert's event_ref to its enriched_events.json record ----
# event_ref ("line:<N>", 0-indexed) was captured against normalized_events.json
# at generation time (3x02/3-sigma_runner.sh). Cleaning between normalize and
# enrich drops/quarantines some records, so line N in enriched_events.json is
# NOT guaranteed to be the same event. alert_queue.json already carries a
# content fingerprint of the matched event in event_summary (timestamp,
# hostname, user, src_ip, dst_ip, process_name) plus event_category, which is
# also a real field on the enriched record - so events are joined by that
# composite key instead of trusting the raw line offset.
def event_key(record):
    return (
        record.get("timestamp"),
        record.get("hostname"),
        record.get("user"),
        record.get("process_name"),
        record.get("src_ip"),
        record.get("dst_ip"),
        record.get("event_category"),
    )


needed_keys = set()
for alert in queue:
    summary = alert.get("event_summary") or {}
    needed_keys.add((
        summary.get("timestamp"),
        summary.get("hostname"),
        summary.get("user"),
        summary.get("process_name"),
        summary.get("src_ip"),
        summary.get("dst_ip"),
        summary.get("event_category"),
    ))

event_by_key = {}
with open(events_path) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        record = json.loads(line)
        key = event_key(record)
        if key in needed_keys and key not in event_by_key:
            event_by_key[key] = record

auth_per_host = baseline.get("auth", {}).get("per_host", {})
process_per_host = baseline.get("process", {}).get("per_host", {})
network_per_src_ip = baseline.get("network", {}).get("per_src_ip", {})
file_per_host = baseline.get("file", {}).get("per_host", {})


def build_baseline_host_profile(hostname, host_ip):
    process_entries = process_per_host.get(hostname, [])
    return {
        "auth": auth_per_host.get(hostname),
        "process": {
            "expected": sorted({e["process_name"] for e in process_entries}),
            "entries": process_entries,
        },
        "network": {
            "host_ip": host_ip,
            "profile": network_per_src_ip.get(host_ip) if host_ip else None,
        },
        "file": file_per_host.get(hostname),
    }


def ioc_lookup(value):
    if not value:
        return None
    entry = ioc_context.get(value)
    if entry is None:
        return None
    return {
        "indicator": value,
        "reputation": entry.get("reputation"),
        "categories": entry.get("categories", []),
        "first_seen": entry.get("first_seen"),
        "last_seen": entry.get("last_seen"),
        "geolocation": entry.get("geolocation"),
        "ioc_flag": entry.get("reputation") != "clean",
    }


assets_joined = 0
missing_asset_records = 0
baseline_profiles_joined = 0
alerts_with_ioc_hits = 0
ioc_hit_reputation_counts = {}

enriched_queue = []
for alert in queue:
    summary = alert.get("event_summary") or {}
    hostname = summary.get("hostname")

    key = (
        summary.get("timestamp"),
        summary.get("hostname"),
        summary.get("user"),
        summary.get("process_name"),
        summary.get("src_ip"),
        summary.get("dst_ip"),
        summary.get("event_category"),
    )
    event_record = event_by_key.get(key)
    event_asset = (event_record or {}).get("asset") or {}

    inventory_asset = assets_by_hostname.get(hostname)
    asset = None
    if inventory_asset or event_asset:
        asset = {
            "hostname": hostname,
            "ip": (inventory_asset or {}).get("ip"),
            "criticality": (inventory_asset or {}).get("criticality") or event_asset.get("criticality"),
            "role": event_asset.get("role"),
            "data_classification": (inventory_asset or {}).get("data_classification"),
            "owner": (inventory_asset or {}).get("owner") or event_asset.get("owner"),
            "network_zone": event_asset.get("zone"),
            "business_impact_multiplier": (inventory_asset or {}).get("business_impact_multiplier"),
        }
        assets_joined += 1
    else:
        missing_asset_records += 1

    host_ip = (inventory_asset or {}).get("ip")
    baseline_host_profile = build_baseline_host_profile(hostname, host_ip)
    if baseline_host_profile["auth"] or baseline_host_profile["process"]["entries"] or \
            baseline_host_profile["network"]["profile"] or baseline_host_profile["file"]:
        baseline_profiles_joined += 1

    ioc_hits = []
    for candidate in (summary.get("src_ip"), summary.get("dst_ip")):
        hit = ioc_lookup(candidate)
        if hit and not any(h["indicator"] == hit["indicator"] for h in ioc_hits):
            ioc_hits.append(hit)

    flagged_hits = [h for h in ioc_hits if h["ioc_flag"]]
    if flagged_hits:
        alerts_with_ioc_hits += 1
        severity_order = ["malicious", "suspicious", "unknown"]
        worst = min(
            flagged_hits,
            key=lambda h: severity_order.index(h["reputation"]) if h["reputation"] in severity_order else len(severity_order),
        )
        bucket = worst["reputation"] if worst["reputation"] in severity_order else "unknown"
        ioc_hit_reputation_counts[bucket] = ioc_hit_reputation_counts.get(bucket, 0) + 1

    score = alert.get("priority_score", 0)

    enriched_entry = dict(alert)
    enriched_entry["asset"] = asset
    enriched_entry["baseline_host_profile"] = baseline_host_profile
    enriched_entry["event_record"] = event_record
    enriched_entry["ioc_hits"] = ioc_hits
    enriched_entry["priority_band"] = priority_band(score)
    enriched_queue.append(enriched_entry)

with open(output_path, "w") as f:
    json.dump(enriched_queue, f, indent=2, sort_keys=False)
    f.write("\n")

size_kb = os.path.getsize(output_path) / 1024

print(f"alerts processed          : {len(queue)}")
print(f"assets joined              : {assets_joined}")
print(f"missing asset records      : {missing_asset_records}")
print(f"alerts with IOC hits       : {alerts_with_ioc_hits}")
for reputation in ("malicious", "suspicious", "unknown"):
    print(f"  {reputation:<24}: {ioc_hit_reputation_counts.get(reputation, 0)}")
print(f"baseline profiles joined   : {baseline_profiles_joined}")
print(f"{output_path} written ({size_kb:.0f} KB)")
PYEOF
