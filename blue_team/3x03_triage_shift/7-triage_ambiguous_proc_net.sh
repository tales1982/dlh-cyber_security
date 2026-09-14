#!/bin/bash
set -euo pipefail

BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
BASELINE_FILE="$BASELINE_PKG/baselines/baseline_summary.json"
QUEUE_FILE="enriched_queue.json"
OUTPUT_FILE="tickets/batch5_proc_net.json"

mkdir -p tickets

for f in "$QUEUE_FILE" "$BASELINE_FILE"; do
    if [[ ! -f "$f" ]]; then
        echo "error: required input not found: $f" >&2
        exit 1
    fi
done

python3 - "$QUEUE_FILE" "$BASELINE_FILE" "$OUTPUT_FILE" <<'PYEOF'
import glob
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone

queue_path, baseline_path, output_path = sys.argv[1:4]

TICKET_NAMESPACE = uuid.UUID("7add14fe-7eeb-5bc3-b3f4-336bf74ca6d4")
AMBIGUOUS_PROC_NET_ESTIMATED_SECONDS = 180

RULE_CATEGORY_BY_EVENT_CATEGORY = {
    "process": "process",
    "audit": "process",
    "network": "network",
    "network_flow": "network",
    "network_alert": "network",
}

SEVERITY_ORDER = ["malicious", "suspicious", "unknown"]
# "Process Create: X by Y" / "... spawned by Y" - the same raw_message parent
# convention 3x02's 003_interpreter_abuse.yml rule already relies on when no
# literal parent_process field is present in the normalized schema.
PARENT_PROCESS_RE = re.compile(r"\bby\s+(\S.*)$", re.IGNORECASE)


def already_ticketed_alert_ids(exclude_path):
    ticketed = set()
    exclude_abs = os.path.abspath(exclude_path)
    for path in sorted(glob.glob("tickets/batch*.json")):
        if os.path.abspath(path) == exclude_abs:
            continue
        with open(path) as f:
            try:
                tickets = json.load(f)
            except json.JSONDecodeError:
                continue
        for ticket in tickets:
            if "alert_id" in ticket:
                ticketed.add(ticket["alert_id"])
            for aid in ticket.get("contributing_alerts", []):
                ticketed.add(aid)
    return ticketed


def worst_hit(hits):
    flagged = [h for h in hits if h.get("ioc_flag")]
    if not flagged:
        return None
    return min(
        flagged,
        key=lambda h: SEVERITY_ORDER.index(h["reputation"]) if h["reputation"] in SEVERITY_ORDER else len(SEVERITY_ORDER),
    )


def baseline_violation(category, alert):
    summary = alert.get("event_summary") or {}
    profile = alert.get("baseline_host_profile") or {}
    if category == "process":
        expected = set((profile.get("process") or {}).get("expected", []))
        process_name = summary.get("process_name")
        return not process_name or process_name not in expected
    if category == "network":
        network_profile = (profile.get("network") or {}).get("profile")
        return network_profile is None
    return False


def parent_process_of(event_record):
    if not event_record:
        return None
    raw_message = event_record.get("raw_message") or ""
    match = PARENT_PROCESS_RE.search(raw_message)
    return match.group(1).strip() if match else None


with open(queue_path) as f:
    enriched_queue = json.load(f)

with open(baseline_path) as f:
    baseline = json.load(f)

process_per_host = baseline.get("process", {}).get("per_host", {})
top_destinations = {d["dst_ip"] for d in baseline.get("network", {}).get("top_destinations", [])}

already_ticketed = already_ticketed_alert_ids(output_path)

tickets = []
rows = []

for alert in enriched_queue:
    if alert["alert_id"] in already_ticketed:
        continue
    summary = alert.get("event_summary") or {}
    category = RULE_CATEGORY_BY_EVENT_CATEGORY.get(summary.get("event_category"))
    if category is None:
        continue

    event_record = alert.get("event_record")
    hostname = summary.get("hostname")
    process_name = summary.get("process_name")
    parent_process = parent_process_of(event_record)
    command_line = (event_record or {}).get("command_line")
    dst_ip = summary.get("dst_ip")
    dst_port = (event_record or {}).get("dst_port")

    asset = alert.get("asset") or {}
    criticality = asset.get("criticality")

    ioc_hits = alert.get("ioc_hits") or []
    worst = worst_hit(ioc_hits)
    reputation = worst["reputation"] if worst else None

    # "present in baseline_host_profile for a different host": the process
    # was seen as normal activity on some OTHER host's baseline (unusual
    # here, ordinary there), or the destination is a globally common one
    # (baseline_summary.json network.top_destinations) rather than unique
    # to this alert.
    known_elsewhere = False
    if process_name:
        for other_host, entries in process_per_host.items():
            if other_host == hostname:
                continue
            if any(e.get("process_name") == process_name for e in entries):
                known_elsewhere = True
                break
    if not known_elsewhere and dst_ip and dst_ip in top_destinations:
        known_elsewhere = True

    classification = None
    recommended_action = None
    fp_reason = None
    justification = None

    if reputation == "malicious":
        classification = "true_positive"
        recommended_action = "escalate_tier2"
        justification = f"ioc_hit on '{worst['indicator']}' has reputation 'malicious'"
    elif reputation == "suspicious" and criticality in ("CRITICAL", "HIGH"):
        classification = "true_positive"
        recommended_action = "monitor"
        justification = (
            f"ioc_hit on '{worst['indicator']}' has reputation 'suspicious' on a {criticality} asset"
        )
    elif reputation == "suspicious" and criticality in ("MEDIUM", "LOW") and known_elsewhere:
        classification = "false_positive"
        recommended_action = "tune_rule"
        fp_reason = "suspicious_but_baseline_known_elsewhere"
        justification = (
            f"ioc_hit on '{worst['indicator']}' is 'suspicious' but "
            f"{'process_name '+repr(process_name) if process_name and known_elsewhere else 'dst_ip '+repr(dst_ip)} "
            f"is already established in another host's baseline, on a {criticality} asset"
        )
    elif (reputation in (None, "clean")) and not baseline_violation(category, alert):
        classification = "false_positive"
        recommended_action = "tune_rule"
        fp_reason = "clean_ioc_no_deviation"
        field = "process_name" if category == "process" else "network"
        justification = (
            f"no malicious/suspicious ioc_hit and baseline_host_profile.{field} shows no "
            f"deviation for host '{hostname}'"
        )
    else:
        classification = "true_positive"
        recommended_action = "monitor"
        justification = (
            f"ambiguous: reputation={reputation}, criticality={criticality}, "
            f"process_name={process_name!r}, parent_process={parent_process!r}, "
            f"dst_ip={dst_ip!r}, dst_port={dst_port!r}, known_elsewhere={known_elsewhere}, "
            f"baseline_deviation={baseline_violation(category, alert)}"
        )

    ticket = {
        "ticket_id": str(uuid.uuid5(TICKET_NAMESPACE, alert["alert_id"])),
        "alert_id": alert["alert_id"],
        "classification": classification,
        "justification": justification,
        "evidence_refs": [alert["event_ref"]],
        "ioc_hits": ioc_hits,
        "attack_techniques": alert.get("attack_techniques", []),
        "recommended_action": recommended_action,
        "analyst_time_seconds": AMBIGUOUS_PROC_NET_ESTIMATED_SECONDS,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if fp_reason:
        ticket["fp_reason"] = fp_reason

    tickets.append(ticket)
    action_label = {"escalate_tier2": "escalate", "monitor": "monitor", "tune_rule": "tune_rule"}[recommended_action]
    rows.append((alert["alert_id"], alert.get("rule_title", "unknown"), classification, action_label))

with open(output_path, "w") as f:
    json.dump(tickets, f, indent=2, sort_keys=False)
    f.write("\n")

print("batch 5 ambiguous process and network")
for alert_id, rule_title, classification, action_label in rows:
    print(f"  {alert_id:<14} {rule_title:<32} {classification:<15} {action_label}")
print(f"batch size                : {len(tickets)}")
print(f"tickets written           : {len(tickets)}")
print(output_path)
PYEOF
