#!/bin/bash
set -euo pipefail

QUEUE_FILE="enriched_queue.json"
OUTPUT_FILE="incidents.json"

if [[ ! -f "$QUEUE_FILE" ]]; then
    echo "error: required input not found: $QUEUE_FILE (run 2-context_assembly.sh first)" >&2
    exit 1
fi

python3 - "$QUEUE_FILE" "$OUTPUT_FILE" <<'PYEOF'
import glob
import json
import re
import sys
from datetime import datetime, timezone

queue_path, output_path = sys.argv[1:3]

# recommended_containment is picked from this fixed table by the first
# matching condition - ioc category signals take precedence over rule-name
# keyword signals since they are the more direct evidence of attacker intent.
CONTAINMENT_TABLE = [
    (lambda ioc_cats, rule_text: ioc_cats & {"c2", "botnet", "ransomware", "tor_exit_node"}, "isolate_host"),
    (lambda ioc_cats, rule_text: ioc_cats & {"exfiltration", "cloud_storage_abuse"}, "block_ip_at_egress"),
    (lambda ioc_cats, rule_text: "brute_force" in rule_text or "brute force" in rule_text, "block_source_ip"),
    (lambda ioc_cats, rule_text: "credential" in rule_text or "privileged" in rule_text or "privilege" in rule_text, "disable_account"),
    (lambda ioc_cats, rule_text: bool(ioc_cats), "block_ip_at_egress"),
]
DEFAULT_CONTAINMENT = "isolate_host"


def parse_ts(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def short_description(event_record):
    if not event_record:
        return None
    raw = event_record.get("raw_message")
    if raw:
        return raw if len(raw) <= 120 else raw[:117] + "..."
    return event_record.get("event_category")


def pick_containment(ioc_categories, rule_titles):
    rule_text = " ".join(rule_titles).lower()
    for predicate, action in CONTAINMENT_TABLE:
        if predicate(ioc_categories, rule_text):
            return action
    return DEFAULT_CONTAINMENT


with open(queue_path) as f:
    enriched_queue = json.load(f)
alerts_by_id = {a["alert_id"]: a for a in enriched_queue}

individual_tickets = []
incident_tickets = []
for path in sorted(glob.glob("tickets/batch*.json")):
    with open(path) as f:
        try:
            tickets = json.load(f)
        except json.JSONDecodeError:
            continue
    for ticket in tickets:
        if "contributing_alerts" in ticket:
            incident_tickets.append(ticket)
        elif "alert_id" in ticket:
            individual_tickets.append(ticket)

ELIGIBLE_ACTIONS = {"escalate_tier2", "monitor"}

sources = []  # each: {"alert_ids": [...], "rule_titles_alert_ids": [...]}
for ticket in individual_tickets:
    if ticket.get("grouped"):
        continue
    if ticket.get("classification") == "true_positive" and ticket.get("recommended_action") in ELIGIBLE_ACTIONS:
        sources.append({"alert_ids": [ticket["alert_id"]]})
for ticket in incident_tickets:
    if ticket.get("classification") == "true_positive" and ticket.get("recommended_action") in ELIGIBLE_ACTIONS:
        sources.append({"alert_ids": ticket.get("contributing_alerts", [])})

# --- order sources deterministically (earliest contributing timestamp,   -
# --- then alert_id) so re-runs assign the same sequence numbers.         -
def source_sort_key(source):
    timestamps = [
        parse_ts((alerts_by_id.get(aid, {}).get("event_summary") or {}).get("timestamp"))
        for aid in source["alert_ids"]
    ]
    timestamps = [t for t in timestamps if t is not None]
    earliest = min(timestamps) if timestamps else datetime.max.replace(tzinfo=timezone.utc)
    return (earliest, tuple(sorted(source["alert_ids"])))


sources.sort(key=source_sort_key)

incident_date = None
for alert in enriched_queue:
    if alert.get("generated_at"):
        incident_date = alert["generated_at"][:10].replace("-", "")
        break
if incident_date is None:
    incident_date = datetime.now(timezone.utc).strftime("%Y%m%d")

incidents = []
for seq, source in enumerate(sources, start=1):
    contributing = [alerts_by_id[aid] for aid in source["alert_ids"] if aid in alerts_by_id]
    if not contributing:
        continue

    contributing.sort(key=lambda a: (a.get("event_summary") or {}).get("timestamp") or "")
    top_alert = max(contributing, key=lambda a: a.get("priority_score", 0))
    hostname = (top_alert.get("event_summary") or {}).get("hostname")

    incident_id = f"INC-{incident_date}-{seq:04d}"

    if len(contributing) == 1:
        summary = f"{top_alert.get('rule_title', 'unknown rule')} detected on {hostname}."
    else:
        summary = (
            f"{top_alert.get('rule_title', 'unknown rule')} and {len(contributing) - 1} "
            f"correlated alert(s) detected on {hostname}."
        )

    timeline = []
    for alert in contributing:
        summary_fields = alert.get("event_summary") or {}
        timeline.append({
            "timestamp": summary_fields.get("timestamp"),
            "hostname": summary_fields.get("hostname"),
            "event_category": summary_fields.get("event_category"),
            "description": short_description(alert.get("event_record")),
        })

    affected_assets = []
    seen_hosts = set()
    for alert in contributing:
        asset = alert.get("asset")
        if not asset or asset.get("hostname") in seen_hosts:
            continue
        seen_hosts.add(asset.get("hostname"))
        affected_assets.append({
            "hostname": asset.get("hostname"),
            "criticality": asset.get("criticality"),
            "data_classification": asset.get("data_classification"),
            "network_zone": asset.get("network_zone"),
        })

    ioc_values = []
    seen_ioc = set()
    ioc_categories = set()
    for alert in contributing:
        summary_fields = alert.get("event_summary") or {}
        event_record = alert.get("event_record") or {}
        candidates = [
            ("ip", summary_fields.get("src_ip")),
            ("ip", summary_fields.get("dst_ip")),
            ("user", summary_fields.get("user")),
            ("process", summary_fields.get("process_name")),
        ]
        for kind, value in candidates:
            if value and (kind, value) not in seen_ioc:
                seen_ioc.add((kind, value))
                ioc_values.append({"type": kind, "value": value})
        for hit in alert.get("ioc_hits", []):
            if hit.get("ioc_flag"):
                ioc_categories.update(hit.get("categories", []))

    attack_techniques = sorted({t for a in contributing for t in a.get("attack_techniques", [])})

    rule_titles = [a.get("rule_title", "") for a in contributing]
    recommended_containment = pick_containment(ioc_categories, rule_titles)

    incidents.append({
        "incident_id": incident_id,
        "summary": summary,
        "timeline": timeline,
        "affected_assets": affected_assets,
        "iocs": ioc_values,
        "attack_techniques": attack_techniques,
        "recommended_containment": recommended_containment,
        "related_incidents": [],
        "_hostnames": {a["hostname"] for a in affected_assets if a["hostname"]},
        "_ioc_values": {v["value"] for v in ioc_values},
        "_rule_title": top_alert.get("rule_title", "unknown"),
        "_hostname_display": hostname,
    })

# --- related_incidents: any other incident sharing a hostname or IOC     -
for incident in incidents:
    related = []
    for other in incidents:
        if other is incident:
            continue
        if incident["_hostnames"] & other["_hostnames"] or incident["_ioc_values"] & other["_ioc_values"]:
            related.append(other["incident_id"])
    incident["related_incidents"] = sorted(related)

rows = []
for incident in incidents:
    rows.append((incident["incident_id"], incident["_hostname_display"], incident["_rule_title"], incident["recommended_containment"]))
    for internal_field in ("_hostnames", "_ioc_values", "_rule_title", "_hostname_display"):
        incident.pop(internal_field, None)

with open(output_path, "w") as f:
    json.dump(incidents, f, indent=2, sort_keys=False)
    f.write("\n")

print("incidents assembled")
for incident_id, hostname, rule_title, containment in rows:
    print(f"  {incident_id:<18} {hostname:<15}{rule_title:<45} {containment}")
print(f"total incidents          : {len(incidents)}")
print(f"{output_path} written")
PYEOF
