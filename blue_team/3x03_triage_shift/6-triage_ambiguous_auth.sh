#!/bin/bash
set -euo pipefail

BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"

BASELINE_FILE="$BASELINE_PKG/baselines/baseline_summary.json"
EVENTS_FILE="$HANDOFF_DIR/data/enriched_events.json"
QUEUE_FILE="enriched_queue.json"
OUTPUT_FILE="tickets/batch4_auth.json"

mkdir -p tickets

for f in "$QUEUE_FILE" "$BASELINE_FILE" "$EVENTS_FILE"; do
    if [[ ! -f "$f" ]]; then
        echo "error: required input not found: $f" >&2
        exit 1
    fi
done

python3 - "$QUEUE_FILE" "$BASELINE_FILE" "$EVENTS_FILE" "$OUTPUT_FILE" <<'PYEOF'
import glob
import json
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone

queue_path, baseline_path, events_path, output_path = sys.argv[1:5]

TICKET_NAMESPACE = uuid.UUID("7add14fe-7eeb-5bc3-b3f4-336bf74ca6d4")
AMBIGUOUS_AUTH_ESTIMATED_SECONDS = 240  # deeper cross-referencing than a clear-cut batch
FAILURE_BURST_WINDOW_SECONDS = 3600
HISTORY_EVENTS_PER_USER = 20

RULE_CATEGORY_BY_EVENT_CATEGORY = {
    "authentication": "auth",
    "account_management": "auth",
    "privilege_escalation": "auth",
}


def parse_ts(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


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


with open(queue_path) as f:
    enriched_queue = json.load(f)

with open(baseline_path) as f:
    baseline = json.load(f)

auth = baseline.get("auth", {})
known_accounts = set(auth.get("known_accounts", []))
max_failures_1h = auth.get("max_failures_1h_window", 0)

already_ticketed = already_ticketed_alert_ids(output_path)

candidates = []
for alert in enriched_queue:
    if alert["alert_id"] in already_ticketed:
        continue
    summary = alert.get("event_summary") or {}
    if RULE_CATEGORY_BY_EVENT_CATEGORY.get(summary.get("event_category")) != "auth":
        continue
    candidates.append(alert)

# --- build each candidate user's historical login pattern + last N events -
needed_users = {(c.get("event_summary") or {}).get("user") for c in candidates}
needed_users.discard(None)

user_history = {u: {"hosts": set(), "src_ips": set(), "events": []} for u in needed_users}

if needed_users:
    with open(events_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if record.get("event_category") != "authentication":
                continue
            user = record.get("user")
            if user not in user_history:
                continue
            hist = user_history[user]
            if record.get("action") == "success" and record.get("hostname"):
                hist["hosts"].add(record["hostname"])
            if record.get("src_ip"):
                hist["src_ips"].add(record["src_ip"])
            hist["events"].append(record)

for hist in user_history.values():
    hist["events"].sort(key=lambda r: r.get("timestamp") or "")
    hist["last_20"] = hist["events"][-HISTORY_EVENTS_PER_USER:]

tickets = []
rows = []

for alert in candidates:
    summary = alert.get("event_summary") or {}
    user = summary.get("user")
    hostname = summary.get("hostname")
    src_ip = summary.get("src_ip")
    asset = alert.get("asset") or {}
    criticality = asset.get("criticality")
    alert_ts = parse_ts(summary.get("timestamp"))

    hist = user_history.get(user, {"hosts": set(), "src_ips": set(), "events": []})
    known_ip = bool(src_ip) and src_ip in hist["src_ips"]
    unknown_ip = not known_ip
    never_logged_in_to_host = hostname not in hist["hosts"]
    is_known_account = user in known_accounts

    ioc_hits = alert.get("ioc_hits") or []
    has_ioc_hit = any(h.get("ioc_flag") for h in ioc_hits)

    failure_burst = 0
    if alert_ts is not None:
        window_start = alert_ts - timedelta(seconds=FAILURE_BURST_WINDOW_SECONDS)
        failure_burst = sum(
            1 for e in hist["events"]
            if e.get("action") == "failure"
            and e.get("hostname") == hostname
            and (ts := parse_ts(e.get("timestamp"))) is not None
            and window_start < ts <= alert_ts
        )

    classification = None
    recommended_action = None
    fp_reason = None
    justification = None

    if unknown_ip and criticality in ("CRITICAL", "HIGH") and never_logged_in_to_host:
        classification = "true_positive"
        recommended_action = "escalate_tier2"
        justification = (
            f"src_ip '{src_ip}' is not in the baseline src_ip set for user '{user}' and "
            f"'{user}' has never logged into '{hostname}' before, on a {criticality} asset"
        )
    elif unknown_ip and criticality in ("MEDIUM", "LOW") and not has_ioc_hit:
        classification = "false_positive"
        recommended_action = "tune_rule"
        fp_reason = "unknown_ip_low_asset"
        justification = (
            f"src_ip '{src_ip}' is unseen for user '{user}' but the asset criticality is "
            f"{criticality} and no ioc_hit is flagged"
        )
    elif known_ip and max_failures_1h <= failure_burst <= max_failures_1h * 2:
        classification = "false_positive"
        recommended_action = "tune_rule"
        fp_reason = "baseline_edge_burst"
        justification = (
            f"src_ip '{src_ip}' is known for user '{user}' and the 1h failure burst "
            f"({failure_burst}) is between max_failures_1h_window ({max_failures_1h}) "
            f"and 2x that threshold ({max_failures_1h * 2})"
        )
    else:
        classification = "true_positive"
        recommended_action = "monitor"
        justification = (
            f"ambiguous: src_ip '{src_ip}' known={known_ip}, user '{user}' in "
            f"known_accounts={is_known_account}, never_logged_in_to_host={never_logged_in_to_host}, "
            f"criticality={criticality}, failure_burst={failure_burst} "
            f"(max_failures_1h_window={max_failures_1h}), ioc_hit={has_ioc_hit}"
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
        "analyst_time_seconds": AMBIGUOUS_AUTH_ESTIMATED_SECONDS,
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

print("batch 4 ambiguous authentication")
for alert_id, rule_title, classification, action_label in rows:
    print(f"  {alert_id:<14} {rule_title:<32} {classification:<15} {action_label}")
print(f"batch size                : {len(tickets)}")
print(f"tickets written           : {len(tickets)}")
print(output_path)
PYEOF
