#!/bin/bash
set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
ASSET_FILE="$HANDOFF_DIR/context/asset_inventory.json"
QUEUE_FILE="enriched_queue.json"
OUTPUT_FILE="tickets/batch2_clearcut_fp.json"

mkdir -p tickets

for f in "$QUEUE_FILE" "$ASSET_FILE"; do
    if [[ ! -f "$f" ]]; then
        echo "error: required input not found: $f" >&2
        exit 1
    fi
done

python3 - "$QUEUE_FILE" "$ASSET_FILE" "$OUTPUT_FILE" <<'PYEOF'
import ipaddress
import json
import sys
import uuid
from datetime import datetime, timezone

queue_path, asset_path, output_path = sys.argv[1:4]

TICKET_NAMESPACE = uuid.UUID("7add14fe-7eeb-5bc3-b3f4-336bf74ca6d4")
# Documented estimate: closing an obvious FP should be fast - see
# triage_methodology.md ("If you spend as much time on a clear false
# positive as on a real incident, you will never finish the shift").
CLEARCUT_FP_ESTIMATED_SECONDS = 45

RULE_CATEGORY_BY_EVENT_CATEGORY = {
    "authentication": "auth",
    "account_management": "auth",
    "privilege_escalation": "auth",
    "process": "process",
    "audit": "process",
    "network": "network",
    "network_flow": "network",
    "network_alert": "network",
    "file": "file",
}

# The literal "svc_" prefix is the documented example convention from the
# triage methodology's FP signature #1. asset_inventory.json may declare its
# own inventory-wide prefix (richer lab schema); fall back to the documented
# example when it does not, rather than never matching this signature.
DEFAULT_SERVICE_ACCOUNT_PREFIX = "svc_"


def baseline_violation(category, alert):
    summary = alert.get("event_summary") or {}
    profile = alert.get("baseline_host_profile") or {}

    if category == "auth":
        label = summary.get("canonical_label")
        return not label or label not in (profile.get("auth") or {})
    if category == "process":
        expected = set((profile.get("process") or {}).get("expected", []))
        process_name = summary.get("process_name")
        return not process_name or process_name not in expected
    if category == "network":
        network_profile = (profile.get("network") or {}).get("profile")
        return network_profile is None
    if category == "file":
        label = summary.get("canonical_label")
        return not label or label not in (profile.get("file") or {})
    return False


with open(queue_path) as f:
    enriched_queue = json.load(f)

with open(asset_path) as f:
    asset_raw = json.load(f)
if isinstance(asset_raw, dict):
    service_account_prefix = asset_raw.get("service_account_prefix", DEFAULT_SERVICE_ACCOUNT_PREFIX)
    management_subnets = asset_raw.get("management_subnets", [])
else:
    service_account_prefix = DEFAULT_SERVICE_ACCOUNT_PREFIX
    management_subnets = []

management_networks = []
for cidr in management_subnets:
    try:
        management_networks.append(ipaddress.ip_network(cidr))
    except ValueError:
        print(f"warning: skipping invalid management_subnets entry: {cidr!r}", file=sys.stderr)

if not management_networks:
    print(
        "warning: no usable management_subnets in asset inventory - "
        "management-subnet FP signature will never match",
        file=sys.stderr,
    )


def in_management_subnet(ip_str):
    if not ip_str or not management_networks:
        return False
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(addr in net for net in management_networks)


tickets = []
rows = []

for alert in enriched_queue:
    summary = alert.get("event_summary") or {}
    event_category = summary.get("event_category")
    category = RULE_CATEGORY_BY_EVENT_CATEGORY.get(event_category)
    user = summary.get("user")
    process_name = summary.get("process_name")
    src_ip = summary.get("src_ip")

    fp_reason = None
    justification = None

    if user and user.startswith(service_account_prefix) and category in ("auth", "process"):
        fp_reason = "service_account_activity"
        justification = (
            f"user '{user}' matches the service account prefix "
            f"'{service_account_prefix}' on an {category} rule"
        )
    elif category == "network" and in_management_subnet(src_ip):
        fp_reason = "management_subnet"
        justification = f"src_ip '{src_ip}' falls inside a management subnet on a network rule"
    else:
        expected = set((alert.get("baseline_host_profile") or {}).get("process", {}).get("expected", []))
        if process_name and process_name in expected:
            fp_reason = "baseline_match"
            justification = (
                f"process_name '{process_name}' is in the baseline expected-process "
                f"set for host '{summary.get('hostname')}'"
            )
        else:
            ioc_hits = alert.get("ioc_hits") or []
            all_clean = all(h.get("reputation") == "clean" for h in ioc_hits)
            deviation = baseline_violation(category, alert) if category else False
            if all_clean and not deviation:
                fp_reason = "clean_ioc_no_deviation"
                justification = (
                    "all ioc_hits are reputation 'clean' (or none present) and no baseline "
                    f"deviation was found for category '{category}'"
                )

    if fp_reason is None:
        continue

    ticket = {
        "ticket_id": str(uuid.uuid5(TICKET_NAMESPACE, alert["alert_id"])),
        "alert_id": alert["alert_id"],
        "classification": "false_positive",
        "justification": justification,
        "evidence_refs": [alert["event_ref"]],
        "ioc_hits": alert.get("ioc_hits", []),
        "attack_techniques": alert.get("attack_techniques", []),
        "recommended_action": "tune_rule",
        "fp_reason": fp_reason,
        "analyst_time_seconds": CLEARCUT_FP_ESTIMATED_SECONDS,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    tickets.append(ticket)
    rows.append((alert["alert_id"], alert.get("rule_title", "unknown"), fp_reason))

with open(output_path, "w") as f:
    json.dump(tickets, f, indent=2, sort_keys=False)
    f.write("\n")

print("batch 2 clear-cut false positives")
for alert_id, rule_title, fp_reason in rows:
    print(f"  {alert_id:<14} {rule_title:<32} CLOSE  {fp_reason}")
print(f"batch size                : {len(tickets)}")
print(f"tickets written           : {len(tickets)}")
print(output_path)
PYEOF
