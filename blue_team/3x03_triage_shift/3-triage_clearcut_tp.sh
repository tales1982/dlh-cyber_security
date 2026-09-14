#!/bin/bash
set -euo pipefail

QUEUE_FILE="enriched_queue.json"
OUTPUT_FILE="tickets/batch1_clearcut_tp.json"

mkdir -p tickets

if [[ ! -f "$QUEUE_FILE" ]]; then
    echo "error: required input not found: $QUEUE_FILE (run 2-context_assembly.sh first)" >&2
    exit 1
fi

python3 - "$QUEUE_FILE" "$OUTPUT_FILE" <<'PYEOF'
import json
import sys
import uuid
from datetime import datetime, timezone

queue_path, output_path = sys.argv[1:3]

TICKET_NAMESPACE = uuid.UUID("7add14fe-7eeb-5bc3-b3f4-336bf74ca6d4")
# Documented estimate: with priority, IOC, and baseline all agreeing, the
# methodology expects a fast escalation, not a fresh investigation - see
# triage_methodology.md Priority Ordering Rule / SLA (critical: 15 minutes).
CLEARCUT_TP_ESTIMATED_SECONDS = 90
CORRELATION_WINDOW_SECONDS = 3600

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


def parse_ts(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def baseline_violation(category, alert, event_record):
    """Returns (violated, field, detail) - True when the action/process/port
    this alert observed has zero occurrences in the host's baseline window,
    i.e. it has never been seen before for this host (see thresholds.value
    for unknown_process_penalty / unknown_port_penalty in baseline_summary.json,
    which score exactly this "never seen in baseline" condition)."""
    summary = alert.get("event_summary") or {}
    profile = alert.get("baseline_host_profile") or {}
    hostname = summary.get("hostname")

    if category == "auth":
        canonical_label = summary.get("canonical_label")
        auth_profile = profile.get("auth") or {}
        if not canonical_label or canonical_label not in auth_profile:
            return True, "baseline_host_profile.auth", (
                f"canonical_label '{canonical_label}' has no baseline occurrences for host '{hostname}'"
            )
        return False, None, None

    if category == "process":
        process_name = summary.get("process_name")
        expected = set((profile.get("process") or {}).get("expected", []))
        if not process_name or process_name not in expected:
            return True, "baseline_host_profile.process.expected", (
                f"process_name '{process_name}' is not in the baseline expected-process set for host '{hostname}'"
            )
        return False, None, None

    if category == "network":
        network_profile = (profile.get("network") or {}).get("profile")
        dst_port = (event_record or {}).get("dst_port")
        known_ports = (network_profile or {}).get("known_dst_ports", [])
        if network_profile is None or dst_port not in known_ports:
            return True, "baseline_host_profile.network.profile.known_dst_ports", (
                f"dst_port '{dst_port}' is not in the baseline known_dst_ports for host '{hostname}'"
            )
        return False, None, None

    if category == "file":
        canonical_label = summary.get("canonical_label")
        file_profile = profile.get("file") or {}
        if not canonical_label or canonical_label not in file_profile:
            return True, "baseline_host_profile.file", (
                f"canonical_label '{canonical_label}' has no baseline occurrences for host '{hostname}'"
            )
        return False, None, None

    return False, None, None


with open(queue_path) as f:
    enriched_queue = json.load(f)

tickets = []
rows = []

for alert in enriched_queue:
    if alert.get("priority_band") != "critical":
        continue

    ioc_hits = alert.get("ioc_hits") or []
    malicious_hits = [h for h in ioc_hits if h.get("reputation") == "malicious"]
    if not malicious_hits:
        continue

    summary = alert.get("event_summary") or {}
    event_category = summary.get("event_category")
    category = RULE_CATEGORY_BY_EVENT_CATEGORY.get(event_category)
    violated, field, detail = baseline_violation(category, alert, alert.get("event_record"))
    if not violated:
        continue

    hostname = summary.get("hostname")
    alert_ts = parse_ts(summary.get("timestamp"))
    correlated_refs = []
    if alert_ts is not None:
        for other in enriched_queue:
            if other is alert or other.get("event_ref") == alert.get("event_ref"):
                continue
            other_summary = other.get("event_summary") or {}
            if other_summary.get("hostname") != hostname:
                continue
            other_ts = parse_ts(other_summary.get("timestamp"))
            if other_ts is None:
                continue
            if abs((other_ts - alert_ts).total_seconds()) <= CORRELATION_WINDOW_SECONDS:
                correlated_refs.append(other["event_ref"])

    evidence_refs = [alert["event_ref"]] + sorted(set(correlated_refs))

    ioc_categories = sorted({c for h in malicious_hits for c in h.get("categories", [])})
    justification = (
        f"malicious IOC hit on '{malicious_hits[0]['indicator']}' "
        f"(categories: {', '.join(ioc_categories) or 'uncategorized'}) and {detail}"
    )

    ticket = {
        "ticket_id": str(uuid.uuid5(TICKET_NAMESPACE, alert["alert_id"])),
        "alert_id": alert["alert_id"],
        "classification": "true_positive",
        "justification": justification,
        "evidence_refs": evidence_refs,
        "ioc_hits": malicious_hits,
        "attack_techniques": alert.get("attack_techniques", []),
        "recommended_action": "escalate_tier2",
        "analyst_time_seconds": CLEARCUT_TP_ESTIMATED_SECONDS,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    tickets.append(ticket)
    rows.append((alert["alert_id"], alert.get("rule_title", "unknown"), hostname, "malicious", "ESCALATE"))

with open(output_path, "w") as f:
    json.dump(tickets, f, indent=2, sort_keys=False)
    f.write("\n")

print("batch 1 clear-cut true positives")
for alert_id, rule_title, hostname, reputation, action in rows:
    print(f"  {alert_id:<14} {rule_title:<32} {hostname:<16} {reputation:<10} {action}")
print(f"batch size                : {len(tickets)}")
print(f"tickets written           : {len(tickets)}")
print(output_path)
PYEOF
