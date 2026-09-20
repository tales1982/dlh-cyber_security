#!/bin/bash
set -euo pipefail

SHIFT_WORKSPACE="${SHIFT_WORKSPACE:-$HOME/bt/3x05/shift_pack}"
TRIAGE_LOG="$SHIFT_WORKSPACE/alerts/triage_log.jsonl"

fail() {
	echo "[group] FAIL: $1" >&2
	exit 1
}

[ -s "$TRIAGE_LOG" ] || fail "triage_log.jsonl missing or empty"

TP_COUNT="$(jq -c 'select(.classification=="TP")' "$TRIAGE_LOG" | wc -l | tr -d ' ')"
printf "[group] TP alerts: %s\n" "$TP_COUNT"
printf "[group] grouping by temporal proximity, shared user, IOC match\n"

TODAY="$(date -u +%Y%m%d)"

RESULT_JSON="$(python3 - "$TRIAGE_LOG" "$TODAY" <<'PYEOF'
import json, sys
from datetime import datetime, timedelta

triage_path, today = sys.argv[1:3]

tps = []
with open(triage_path) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        if rec.get("classification") == "TP":
            tps.append(rec)

n = len(tps)
parent = list(range(n))

def find(x):
    while parent[x] != x:
        parent[x] = parent[parent[x]]
        x = parent[x]
    return x

def union(a, b):
    ra, rb = find(a), find(b)
    if ra != rb:
        parent[ra] = rb

def ts(rec):
    return datetime.fromisoformat(rec["timestamp"].replace("Z", "+00:00"))

# Rule 1: same host (lowercased) + within 15 minutes of each other.
by_host = {}
for i, rec in enumerate(tps):
    by_host.setdefault(rec["host"].lower(), []).append(i)
for host, idxs in by_host.items():
    idxs.sort(key=lambda i: ts(tps[i]))
    for a, b in zip(idxs, idxs[1:]):
        if abs((ts(tps[b]) - ts(tps[a])).total_seconds()) <= 900:
            union(a, b)

# Rule 2: shared non-null user, regardless of host.
by_user = {}
for i, rec in enumerate(tps):
    u = rec.get("user")
    if u:
        by_user.setdefault(u, []).append(i)
for u, idxs in by_user.items():
    for a, b in zip(idxs, idxs[1:]):
        union(a, b)

# Rule 3: shared IOC match value.
by_ioc = {}
for i, rec in enumerate(tps):
    for ioc in (rec.get("matches_ioc") or []):
        by_ioc.setdefault(ioc, []).append(i)
for ioc, idxs in by_ioc.items():
    for a, b in zip(idxs, idxs[1:]):
        union(a, b)

groups = {}
for i in range(n):
    groups.setdefault(find(i), []).append(i)

# Preserve surfacing order: order groups by the earliest alert index they contain.
ordered = sorted(groups.values(), key=lambda idxs: min(idxs))

CATEGORY_BY_RULE_HINT = {
    "credential": "credential_abuse",
    "brute": "credential_abuse",
    "logon": "credential_abuse",
    "service": "persistence",
    "beacon": "c2",
    "c2": "c2",
    "exfil": "staging",
    "lateral": "lateral_movement",
}

def guess_category(rule_titles):
    text = " ".join(rule_titles).lower()
    for hint, cat in CATEGORY_BY_RULE_HINT.items():
        if hint in text:
            return cat
    return "unknown"

letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
incidents = []
for gi, idxs in enumerate(ordered):
    members = [tps[i] for i in idxs]
    hosts = sorted({m["host"].lower() for m in members})
    users = sorted({m["user"] for m in members if m.get("user")})
    iocs = sorted({ioc for m in members for ioc in (m.get("matches_ioc") or [])})
    alert_ids = [m["alert_id"] for m in members]
    times = sorted(ts(m) for m in members)

    if len(idxs) == 1:
        rule = "residual"
    elif iocs:
        rule = "ioc_match"
    elif users:
        rule = "shared_user"
    else:
        rule = "temporal"

    if iocs:
        confidence = "high"
    elif any(m.get("baseline_deviation") for m in members):
        confidence = "medium"
    else:
        confidence = "low"

    incidents.append({
        "incident_id": f"INC-{today}-{letters[gi] if gi < len(letters) else gi}",
        "host_list": hosts,
        "user_list": users,
        "ioc_list": iocs,
        "alert_ids": alert_ids,
        "first_seen": times[0].strftime("%Y-%m-%dT%H:%M:%SZ"),
        "last_seen": times[-1].strftime("%Y-%m-%dT%H:%M:%SZ"),
        "grouping_rule": rule,
        "tentative_category": guess_category([m.get("rule_id", "") for m in members]),
        "confidence": confidence,
    })

print(json.dumps(incidents))
PYEOF
)"

INCIDENT_COUNT="$(echo "$RESULT_JSON" | jq 'length')"
UNMATCHED_TP="$(echo "$RESULT_JSON" | jq '[.[] | select(.alert_ids | length == 1)] | length')"

echo "$RESULT_JSON" | jq -r '.[] | "[group] \(.incident_id): \(.alert_ids | length) alerts  host=\(.host_list[0] // "n/a")  rule=\(.grouping_rule)"'
printf "[group] incident_count=%s\n" "$INCIDENT_COUNT"

GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SHIFT_ID="unknown"
if [ -s "$SHIFT_WORKSPACE/runtime/shift_start.json" ]; then
	SHIFT_ID="$(jq -r '.shift_id' "$SHIFT_WORKSPACE/runtime/shift_start.json")"
fi

jq -n \
	--arg shift_id "$SHIFT_ID" \
	--arg generated_at "$GENERATED_AT" \
	--argjson incidents "$RESULT_JSON" \
	--argjson incident_count "$INCIDENT_COUNT" \
	--argjson unmatched_tp_count "$UNMATCHED_TP" \
	'{
		shift_id: $shift_id,
		generated_at: $generated_at,
		incidents: $incidents,
		incident_count: $incident_count,
		unmatched_tp_count: $unmatched_tp_count
	}' > "$SHIFT_WORKSPACE/alerts/incidents.json"

printf "[group] incidents.json written\n"

[ "$INCIDENT_COUNT" -ge 3 ] || fail "incident_count ($INCIDENT_COUNT) is below the required minimum of 3 — re-examine Task 3/5 (catalog coverage or over-aggressive NOISE classification)"
