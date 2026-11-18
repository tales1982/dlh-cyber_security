#!/usr/bin/env python3
"""MedDefense credential exposure playbook.

Ingests one credential access or lateral movement alert, enriches the
source IP, checks the username against privileged_accounts.json, applies
the decision table, creates a case and, when the outcome requires it,
writes the host to isolation_queue.json for analyst authorization.

Decision table (materials/playbooks/credential_exposure_decision_logic.md):

    IP verdict   Domain Admin  Server Admin  Severity  Status     Queue
    BLOCK        any           any           Critical  escalated  yes
    INVESTIGATE  true          any           Critical  escalated  yes
    INVESTIGATE  false         true          High      open       no
    INVESTIGATE  false         false         High      open       no
    ALLOW        true          any           High      escalated  no
    ALLOW        false         true          Medium    open       no
    ALLOW        false         false         Medium    open       no

Automation boundary: the isolation queue is a human-authorization queue.
This playbook never isolates a host and never calls an EDR API; an
analyst must authorize isolation in the EDR console.

Usage:
    python3 playbook_credential_exposure.py alerts/ALT-20260428-007.json

Exit code 0 for any verdict; 1 only for unrecoverable errors.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

import case_manager
from enrich_ioc import enrich_ioc

PLAYBOOK = "CREDENTIAL_EXPOSURE"
AUDIT_LOG = "playbook_audit.log"
ISOLATION_QUEUE = "isolation_queue.json"
PRIVILEGED_ACCOUNTS = "privileged_accounts.json"
REQUIRED_FIELDS = ("alert_id", "raw_log")

# Static ATT&CK mapping for techniques seen in MedDefense endpoint alerts:
# technique ID -> (ATT&CK name, short description used in queue reasons).
MITRE_TECHNIQUES = {
    "T1003.001": ("OS Credential Dumping: LSASS Memory", "LSASS dump"),
    "T1550.002": ("Use Alternate Authentication Material: Pass the Hash",
                  "Pass the hash"),
    "T1021.002": ("Remote Services: SMB/Windows Admin Shares",
                  "Admin share access"),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell",
                  "PowerShell execution"),
    "T1078.002": ("Valid Accounts: Domain Accounts", "Domain account use"),
    "T1021.001": ("Remote Services: Remote Desktop Protocol", "RDP session"),
}

# (ip_verdict, is_da, is_sa) -> (severity, status, queue, verdict)
# is_sa is ignored (None) when the account is a Domain Admin.
DECISION_TABLE = {
    ("BLOCK", True, None): ("Critical", "escalated", True, "ESCALATE"),
    ("BLOCK", False, True): ("Critical", "escalated", True, "ESCALATE"),
    ("BLOCK", False, False): ("Critical", "escalated", True, "ESCALATE"),
    ("INVESTIGATE", True, None): ("Critical", "escalated", True, "ESCALATE"),
    ("INVESTIGATE", False, True): ("High", "open", False, "MANUAL_REVIEW"),
    ("INVESTIGATE", False, False): ("High", "open", False, "MANUAL_REVIEW"),
    ("ALLOW", True, None): ("High", "escalated", False, "ESCALATE"),
    ("ALLOW", False, True): ("Medium", "open", False, "MANUAL_REVIEW"),
    ("ALLOW", False, False): ("Medium", "open", False, "MANUAL_REVIEW"),
}

log = logging.getLogger("credential_exposure")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def find_file(name: str) -> Path:
    """Look in the current directory first, then next to this script."""
    path = Path(name)
    if path.is_file():
        return path
    return Path(__file__).resolve().parent / name


def load_privileged_accounts() -> dict:
    path = find_file(PRIVILEGED_ACCOUNTS)
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    return {
        "domain_admins": {u.lower() for u in data.get("domain_admins", [])},
        "server_admins": {u.lower() for u in data.get("server_admins", [])},
    }


def privilege_of(username: str, accounts: dict) -> tuple[bool, bool, str]:
    user = (username or "").lower()
    is_da = user in accounts["domain_admins"]
    is_sa = user in accounts["server_admins"]
    label = ("Domain Admin" if is_da else
             "Server Admin" if is_sa else "Standard")
    return is_da, is_sa, label


def decide(ip_verdict: str, is_da: bool, is_sa: bool):
    key = (ip_verdict, True, None) if is_da else (ip_verdict, False, is_sa)
    return DECISION_TABLE.get(key, DECISION_TABLE[("INVESTIGATE", False,
                                                   False)])


def enrich_source(source_ip: str | None) -> dict:
    """Enrich the source IP; missing IP or failure becomes INVESTIGATE."""
    if not source_ip:
        log.warning("source_ip missing; treated as INVESTIGATE")
        return {"ioc": "unknown", "type": "unknown", "ip_class": "N/A",
                "feed_result": {}, "score": 30, "verdict": "INVESTIGATE",
                "note": "source_ip missing from alert"}
    try:
        return enrich_ioc(source_ip)
    except Exception as exc:  # never abort the run on enrichment
        log.error("enrichment failed for %s: %s", source_ip, exc)
        return {"ioc": source_ip, "type": "ipv4", "ip_class": "N/A",
                "feed_result": {}, "score": 30, "verdict": "INVESTIGATE",
                "note": "enrichment error: {}".format(exc)}


def ip_phrase(enr: dict) -> str:
    feed = enr.get("feed_result", {})
    verdict = enr["verdict"]
    if verdict == "BLOCK":
        if feed.get("category") == "c2":
            return "known C2 IP"
        return "known malicious IP"
    if verdict == "INVESTIGATE":
        return "suspicious IP"
    if enr.get("ip_class") in ("private", "loopback"):
        return "internal IP"
    return "allowlisted IP"


def append_isolation_queue(entry: dict) -> None:
    path = Path(ISOLATION_QUEUE)
    queue = []
    if path.is_file():
        try:
            queue = json.loads(path.read_text(encoding="utf-8") or "[]")
        except json.JSONDecodeError:
            # Never overwrite evidence: keep the unreadable file aside.
            backup = path.with_suffix(".corrupt.json")
            path.rename(backup)
            log.warning("isolation queue unreadable; moved to %s", backup)
            queue = []
        if not isinstance(queue, list):
            queue = [queue]
    queue.append(entry)
    path.write_text(json.dumps(queue, indent=2) + "\n", encoding="utf-8")


def main(argv=None) -> int:
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr,
                        format="WARNING: %(message)s")
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: python3 playbook_credential_exposure.py ALERT.json",
              file=sys.stderr)
        return 1

    try:
        with open(argv[0], encoding="utf-8") as handle:
            alert = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        print("error: cannot read alert {}: {}".format(argv[0], exc),
              file=sys.stderr)
        return 1
    missing = [f for f in REQUIRED_FIELDS
               if not isinstance(alert, dict) or not alert.get(f)]
    if missing or not isinstance(alert.get("raw_log"), dict):
        print("error: alert missing required fields: {}".format(
            ", ".join(missing) or "raw_log"), file=sys.stderr)
        return 1

    try:
        accounts = load_privileged_accounts()
    except (OSError, json.JSONDecodeError) as exc:
        print("error: cannot read {}: {}".format(PRIVILEGED_ACCOUNTS, exc),
              file=sys.stderr)
        return 1

    run_at = utc_now()
    alert_id = alert["alert_id"]
    raw = alert["raw_log"]
    source_ip = raw.get("source_ip")
    username = raw.get("username") or "unknown"
    host = raw.get("host") or "UNKNOWN-HOST"
    technique = raw.get("mitre_technique") or "unknown"
    tech_name, tech_short = MITRE_TECHNIQUES.get(
        technique, ("Unknown technique", "Credential activity"))

    enr = enrich_source(source_ip)
    is_da, is_sa, privilege = privilege_of(username, accounts)
    severity, status, queue, verdict = decide(enr["verdict"], is_da, is_sa)

    reason = "{} from {} {} by {} {}".format(
        tech_short, ip_phrase(enr), source_ip or "unknown", privilege,
        username)
    feed = enr.get("feed_result", {})
    title = "Credential Exposure: {} on {} by {} account {}".format(
        tech_short, host, privilege, username)
    description = (
        "Rule {} | Host {} ({}) | Process {} -> {} | Command: {} | "
        "MITRE {} {}").format(
        alert.get("rule_name"), host, raw.get("device_group"),
        raw.get("process") or "n/a", raw.get("target_process") or "n/a",
        raw.get("command_line"), technique, tech_name)
    case_iocs = []
    if source_ip:
        case_iocs.append({"ioc_value": enr["ioc"], "ioc_type": enr["type"],
                          "verdict": enr["verdict"], "score": enr["score"]})

    note = (
        "Playbook verdict: {}. Source IP {}: verdict {} score {} "
        "(ip_class {}, reverse_dns {}, category {}, tags {}, feed source {}). "
        "User {}: {}. MITRE {} {}. Decision: IP verdict {} + {} -> {} / {}. "
        "Reasoning: {}.{}").format(
        verdict, enr["ioc"], enr["verdict"], enr["score"],
        enr.get("ip_class"), enr.get("reverse_dns", "N/A"),
        feed.get("category", "none"), ",".join(feed.get("tags", [])) or
        "none", feed.get("source", "none"), username, privilege, technique,
        tech_name, enr["verdict"], privilege, severity, status, reason,
        " Host queued for isolation pending analyst authorization; no "
        "automatic isolation performed." if queue else
        " No isolation queued; analyst manual review required."
        if status == "open" else
        " Privileged account anomaly escalated; no isolation queued.")

    try:
        case_id = case_manager.create_case(alert_id, severity, title,
                                           description, case_iocs)
        if status != "open":
            case_manager.update_case_status(case_id, status)
        case_manager.add_case_note(case_id, note)
    except (sqlite3.Error, ValueError) as exc:
        print("error: database write failed: {}".format(exc),
              file=sys.stderr)
        return 1

    try:
        if queue:
            append_isolation_queue({
                "queued_at": run_at,
                "host": host,
                "alert_id": alert_id,
                "case_id": case_id,
                "reason": reason,
                "action_required": "Analyst must authorize isolation via "
                                   "EDR console before execution",
                "status": "pending_authorization",
            })
        with open(AUDIT_LOG, "a", encoding="utf-8") as handle:
            handle.write(
                "{} | {} | {} | Host:{} | User:{} | IPVerdict:{} | "
                "Privilege:{} | Case:{} | Severity:{} | IsolationQueued:{}\n"
                .format(run_at, PLAYBOOK, alert_id, host, username,
                        enr["verdict"], privilege, case_id, severity,
                        "yes" if queue else "no"))
    except OSError as exc:
        print("error: cannot write output files: {}".format(exc),
              file=sys.stderr)
        return 1

    if queue:
        action = "Host written to isolation_queue.json for analyst authorization"
    elif status == "escalated":
        action = "Escalated to on-call analyst; no isolation queued"
    else:
        action = "Queued for analyst manual review; no isolation queued"

    print("[{}] CREDENTIAL EXPOSURE PLAYBOOK".format(run_at))
    print("Alert      : {}".format(alert_id))
    print("Rule       : {}".format(alert.get("rule_name", "unknown_rule")))
    print("Host       : {}".format(host))
    print("User       : {}  Privilege: {}".format(username, privilege))
    print("Source IP  : {}  Verdict: {}  Score: {}".format(
        source_ip or "missing", enr["verdict"], enr["score"]))
    print("MITRE      : {} {}".format(technique, tech_name))
    print("Verdict    : {}".format(verdict))
    print("Case       : {}  Severity: {}  Status: {}".format(
        case_id, severity, status))
    print("Action     : {}".format(action))
    return 0


if __name__ == "__main__":
    sys.exit(main())
