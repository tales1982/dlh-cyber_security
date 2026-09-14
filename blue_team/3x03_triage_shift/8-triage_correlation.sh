#!/bin/bash
set -euo pipefail

QUEUE_FILE="enriched_queue.json"
OUTPUT_FILE="tickets/batch6_incidents.json"

mkdir -p tickets

if [[ ! -f "$QUEUE_FILE" ]]; then
    echo "error: required input not found: $QUEUE_FILE (run 2-context_assembly.sh first)" >&2
    exit 1
fi

python3 - "$QUEUE_FILE" "$OUTPUT_FILE" <<'PYEOF'
import glob
import json
import os
import sys
from datetime import datetime, timezone

queue_path, output_path = sys.argv[1:3]

CORRELATION_WINDOW_SECONDS = 600
HIGH_CONFIDENCE_MIN_ALERTS = 3


def parse_ts(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


with open(queue_path) as f:
    enriched_queue = json.load(f)

alerts_by_id = {a["alert_id"]: a for a in enriched_queue}

# --- load every ticket already written by batches 1-5+ so incidents can  --
# --- inherit an already-true_positive classification, and so their      --
# --- individual tickets can be marked grouped: true afterwards.         --
output_abs = os.path.abspath(output_path)
ticket_files = {}
alert_ticket_location = {}
for path in sorted(glob.glob("tickets/batch*.json")):
    if os.path.abspath(path) == output_abs:
        continue
    with open(path) as f:
        try:
            tickets = json.load(f)
        except json.JSONDecodeError:
            continue
    ticket_files[path] = tickets
    for index, ticket in enumerate(tickets):
        alert_id = ticket.get("alert_id")
        if alert_id:
            alert_ticket_location[alert_id] = (path, index)

# --- group alerts into incidents: chain-merge same-hostname alerts whose -
# --- timestamps are within CORRELATION_WINDOW_SECONDS of their neighbor  -
by_hostname = {}
for alert in enriched_queue:
    hostname = (alert.get("event_summary") or {}).get("hostname")
    ts = parse_ts((alert.get("event_summary") or {}).get("timestamp"))
    if not hostname or ts is None:
        continue
    by_hostname.setdefault(hostname, []).append((ts, alert))

groups = []
for hostname, entries in by_hostname.items():
    entries.sort(key=lambda e: e[0])
    current_group = [entries[0]]
    for ts, alert in entries[1:]:
        if (ts - current_group[-1][0]).total_seconds() <= CORRELATION_WINDOW_SECONDS:
            current_group.append((ts, alert))
        else:
            if len(current_group) >= 2:
                groups.append((hostname, current_group))
            current_group = [(ts, alert)]
    if len(current_group) >= 2:
        groups.append((hostname, current_group))

incidents = []
rows = []
alerts_regrouped = 0

for hostname, entries in sorted(groups, key=lambda g: g[1][0][0]):
    entries.sort(key=lambda e: e[0])
    contributing_alerts = [a["alert_id"] for _, a in entries]
    start_ts = entries[0][0]
    end_ts = entries[-1][0]
    start_iso = entries[0][1]["event_summary"]["timestamp"]
    end_iso = entries[-1][1]["event_summary"]["timestamp"]

    confidence = "high_confidence" if len(entries) >= HIGH_CONFIDENCE_MIN_ALERTS else "medium_confidence"

    any_existing_tp = any(
        alert_ticket_location.get(aid) is not None
        and ticket_files[alert_ticket_location[aid][0]][alert_ticket_location[aid][1]].get("classification") == "true_positive"
        for aid in contributing_alerts
    )
    if any_existing_tp:
        classification = "true_positive"
    else:
        top_alert = max(entries, key=lambda e: e[1].get("priority_score", 0))[1]
        classification = "true_positive" if top_alert.get("priority_band") in ("critical", "high") else "false_positive"

    attack_techniques = sorted({t for _, a in entries for t in a.get("attack_techniques", [])})

    criticalities = {(a.get("asset") or {}).get("criticality") for _, a in entries}
    on_critical_or_high_asset = bool(criticalities & {"CRITICAL", "HIGH"})
    if confidence == "high_confidence" and on_critical_or_high_asset:
        recommended_action = "escalate_tier2"
    else:
        recommended_action = "monitor"

    ticket = {
        "ticket_id": f"incident_{hostname}_{start_iso}",
        "classification": classification,
        "contributing_alerts": contributing_alerts,
        "incident_window": {"start": start_iso, "end": end_iso},
        "confidence": confidence,
        "attack_techniques": attack_techniques,
        "recommended_action": recommended_action,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    incidents.append(ticket)
    alerts_regrouped += len(contributing_alerts)

    action_label = {"escalate_tier2": "escalate", "monitor": "monitor"}[recommended_action]
    rows.append((ticket["ticket_id"], len(contributing_alerts), confidence, action_label))

    for aid in contributing_alerts:
        location = alert_ticket_location.get(aid)
        if location is not None:
            path, index = location
            ticket_files[path][index]["grouped"] = True

with open(output_path, "w") as f:
    json.dump(incidents, f, indent=2, sort_keys=False)
    f.write("\n")

for path, tickets in ticket_files.items():
    with open(path, "w") as f:
        json.dump(tickets, f, indent=2, sort_keys=False)
        f.write("\n")

print("batch 6 correlated incidents")
for ticket_id, count, confidence, action_label in rows:
    print(f"  {ticket_id:<45} alerts={count}  {confidence}  {action_label}")
print(f"incidents assembled      : {len(incidents)}")
print(f"alerts regrouped         : {alerts_regrouped}")
print(output_path)
PYEOF
