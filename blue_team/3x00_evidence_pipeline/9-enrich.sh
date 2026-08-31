#!/bin/bash
#
# 9-enrich.sh - enriches cleaned_events.json with asset inventory context
# (role, criticality, os, owner, zone, looked up by hostname) and network
# zone context (src_zone/dst_zone, looked up by CIDR) from the evidence
# pack's context/ files. Writes enriched_events.json.
#
# Usage: ./9-enrich.sh [pack_root]
#   pack_root defaults to $HOME/evidence_pack_primary
#   reads cleaned_events.json from the current working directory.

set -euo pipefail

PACK_ROOT="${1:-$HOME/evidence_pack_primary}"
CLEANED_FILE="cleaned_events.json"
ASSET_FILE="${PACK_ROOT}/context/asset_inventory.json"
ZONES_FILE="${PACK_ROOT}/context/network_zones.json"
OUTPUT_FILE="enriched_events.json"

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: required command 'python3' not found." >&2
    exit 2
fi

for f in "$CLEANED_FILE" "$ASSET_FILE" "$ZONES_FILE"; do
    if [ ! -f "$f" ]; then
        echo "Error: required file not found: $f" >&2
        exit 2
    fi
done

python3 - "$CLEANED_FILE" "$ASSET_FILE" "$ZONES_FILE" "$OUTPUT_FILE" <<'PYTHON_EOF'
import ipaddress
import json
import sys

cleaned_file, asset_file, zones_file, output_file = sys.argv[1:5]

# --- asset inventory: hostname (case-insensitive) -> asset context --------
with open(asset_file, "r", encoding="utf-8") as f:
    asset_data = json.load(f)

assets_by_hostname = {}
for asset in asset_data.get("assets", []):
    hostname = asset.get("hostname")
    if not hostname:
        continue
    assets_by_hostname[hostname.lower()] = {
        "role": asset.get("role"),
        "criticality": asset.get("criticality"),
        "os": asset.get("os"),
        "owner": asset.get("owner"),
        "zone": asset.get("zone"),
    }

# --- network zones: CIDR -> zone_id, most specific network first ----------
# A zone with 0.0.0.0/0 (a catch-all "INTERNET" zone) would otherwise match
# every IP first if checked in file order, so entries are sorted by prefix
# length descending (more specific /24s before the /0 catch-all).
with open(zones_file, "r", encoding="utf-8") as f:
    zones_data = json.load(f)

zone_networks = []
for zone in zones_data.get("zones", []):
    zone_id = zone.get("zone_id")
    for cidr in zone.get("cidrs", []):
        try:
            zone_networks.append((ipaddress.ip_network(cidr), zone_id))
        except ValueError:
            continue
zone_networks.sort(key=lambda item: item[0].prefixlen, reverse=True)


def resolve_zone(ip_str):
    if not ip_str:
        return None
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return "unknown"
    for network, zone_id in zone_networks:
        if ip in network:
            return zone_id
    return "unknown"


total = 0
asset_matched = 0
unknown_hosts = 0
src_zone_resolved = 0
dst_zone_resolved = 0

with open(cleaned_file, "r", encoding="utf-8", errors="replace") as f_in, \
     open(output_file, "w", encoding="utf-8") as f_out:
    for line in f_in:
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        total += 1

        hostname = rec.get("hostname")
        asset_ctx = assets_by_hostname.get(hostname.lower()) if hostname else None
        rec["asset"] = asset_ctx
        if asset_ctx:
            asset_matched += 1
        else:
            unknown_hosts += 1

        src_ip = rec.get("src_ip")
        dst_ip = rec.get("dst_ip")
        rec["src_zone"] = resolve_zone(src_ip) if src_ip else None
        rec["dst_zone"] = resolve_zone(dst_ip) if dst_ip else None
        if rec["src_zone"] and rec["src_zone"] != "unknown":
            src_zone_resolved += 1
        if rec["dst_zone"] and rec["dst_zone"] != "unknown":
            dst_zone_resolved += 1

        f_out.write(json.dumps(rec) + "\n")

def pct(n):
    return round((n / total) * 100, 1) if total else 0.0

print(f"events processed    : {total}")
print(f"asset context added : {asset_matched} ({pct(asset_matched)}%)")
print(f"src_zone resolved   : {src_zone_resolved} ({pct(src_zone_resolved)}%)")
print(f"dst_zone resolved   : {dst_zone_resolved} ({pct(dst_zone_resolved)}%)")
print(f"unknown hosts       : {unknown_hosts}")
print(f"{output_file} written")
PYTHON_EOF
