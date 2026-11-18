#!/usr/bin/env python3
"""MedDefense phishing triage playbook.

Ingests one structured phishing alert, extracts and deduplicates its
IOCs (sender IP, sender email domain, URL hostnames), enriches each one
with enrich_ioc(), applies the decision ladder and records the result
as a case with an audit log line.

Decision ladder (materials/playbooks/phishing_triage_decision_logic.md):
    any IOC BLOCK        -> ESCALATE  Critical  escalated
    any IOC INVESTIGATE  -> REVIEW    High      open
    all IOCs ALLOW       -> CLOSE     Low       closed (no_indicators_of_compromise)

Automation boundary: this playbook enriches, classifies and creates
cases. It never blocks a sender or quarantines a mailbox; those are
response actions that need an analyst.

Usage:
    python3 playbook_phishing_triage.py alerts/ALT-20260428-001.json

Exit code 0 for any verdict; 1 only for unrecoverable errors (unreadable
or malformed alert, missing required fields, database write failure).
"""

from __future__ import annotations

import ipaddress
import json
import logging
import sqlite3
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

import case_manager
from enrich_ioc import enrich_ioc, load_feed

PLAYBOOK = "PHISHING_TRIAGE"
AUDIT_LOG = "playbook_audit.log"
CLOSE_RESOLUTION = "no_indicators_of_compromise"
REQUIRED_FIELDS = ("alert_id", "raw_log")

DECISIONS = {
    "BLOCK": ("ESCALATE", "Critical", "escalated"),
    "INVESTIGATE": ("REVIEW", "High", "open"),
    "ALLOW": ("CLOSE", "Low", "closed"),
}
ACTIONS = {
    "ESCALATE": "SOC notification queued for on-call analyst",
    "REVIEW": "Queued for analyst manual review",
    "CLOSE": "Auto-closed: " + CLOSE_RESOLUTION,
}

log = logging.getLogger("phishing_triage")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ioc_kind(value: str) -> str:
    try:
        return "ipv{}".format(ipaddress.ip_address(value).version)
    except ValueError:
        return "domain"


def extract_iocs(raw_log: dict) -> list[dict]:
    """Return candidate IOCs in order, each marked dedup or not.

    Each item: {"value", "type", "source", "dedup"}.
    """
    candidates = []

    from_ip = raw_log.get("from_ip")
    if from_ip:
        candidates.append((str(from_ip).strip(), "from_ip"))
    else:
        log.warning("from_ip missing; sender IP IOC skipped")

    sender = raw_log.get("from") or ""
    if "@" in sender:
        domain = sender.rsplit("@", 1)[1].strip().strip(">").lower()
        if domain:
            candidates.append((domain, "from_domain"))
    else:
        log.warning("from address missing or has no domain; skipped")

    urls = raw_log.get("body_urls") or []
    if not isinstance(urls, list):
        log.warning("body_urls is not a list; skipped")
        urls = []
    for url in urls:
        try:
            host = urlparse(str(url).strip()).hostname
        except ValueError:
            host = None
        if not host:
            log.warning("malformed URL skipped: %r", url)
            continue
        candidates.append((host.lower(), "body_url"))

    seen = set()
    iocs = []
    for value, source in candidates:
        iocs.append({"value": value, "type": ioc_kind(value),
                     "source": source, "dedup": value in seen})
        seen.add(value)
    return iocs


def enrich_all(iocs: list[dict]) -> list[dict]:
    """Enrich every non-duplicate IOC; failures become INVESTIGATE."""
    try:
        feed = load_feed()
    except (OSError, json.JSONDecodeError) as exc:
        log.error("threat intel feed unavailable: %s", exc)
        feed = None

    results = []
    for ioc in iocs:
        if ioc["dedup"]:
            continue
        try:
            if feed is None:
                raise RuntimeError("feed not loaded")
            res = enrich_ioc(ioc["value"], feed=feed)
            res["type"] = ioc["type"]
        except Exception as exc:  # never abort the run on one IOC
            log.error("enrichment failed for %s: %s", ioc["value"], exc)
            res = {"ioc": ioc["value"], "type": ioc["type"],
                   "feed_result": {}, "score": 30, "verdict": "INVESTIGATE",
                   "note": "enrichment error: {}".format(exc)}
        results.append(res)
    return results


def decide(results: list[dict]) -> tuple[str, str, str]:
    verdicts = {r["verdict"] for r in results}
    for level in ("BLOCK", "INVESTIGATE"):
        if level in verdicts:
            return DECISIONS[level]
    return DECISIONS["ALLOW"]


def describe(res: dict) -> str:
    feed = res.get("feed_result", {})
    parts = [feed.get("category")] + list(feed.get("tags", [])[:1])
    parts = [p for p in parts if p]
    if parts:
        return "({})".format(", ".join(parts))
    if res.get("note"):
        return "({})".format(res["note"])
    if feed.get("in_benign_list"):
        return "(allowlisted)"
    return "(not in feed)"


def case_title(verdict: str, results: list[dict]) -> str:
    if verdict == "ESCALATE":
        hits = [r for r in results if r["verdict"] == "BLOCK"]
        if any(r.get("feed_result", {}).get("category") == "c2"
               and r["type"].startswith("ipv") for r in hits):
            return "Phishing: Known C2 IP Escalated"
        return "Phishing: Known malicious IOC Escalated"
    if verdict == "REVIEW":
        return "Phishing: Suspicious sender review"
    return "Phishing: No indicators, auto-closed"


def ioc_summary(results: list[dict]) -> str:
    return ", ".join("{} ({}/{})".format(r["ioc"], r["verdict"], r["score"])
                     for r in results) or "none"


def main(argv=None) -> int:
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr,
                        format="WARNING: %(message)s")
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: python3 playbook_phishing_triage.py ALERT.json",
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

    run_at = utc_now()
    alert_id = alert["alert_id"]
    raw_log = alert["raw_log"]
    rule = alert.get("rule_name", "unknown_rule")

    iocs = extract_iocs(raw_log)
    results = enrich_all(iocs)
    verdict, severity, status = decide(results)
    counts = {v: sum(1 for r in results if r["verdict"] == v)
              for v in ("BLOCK", "INVESTIGATE", "ALLOW")}

    description = (
        "Rule {} | From: {} ({}) | To: {} | Subject: {} | "
        "SPF/DKIM/DMARC: {}/{}/{}").format(
        rule, raw_log.get("from"), raw_log.get("from_ip"), raw_log.get("to"),
        raw_log.get("subject"), raw_log.get("spf"), raw_log.get("dkim"),
        raw_log.get("dmarc"))
    case_iocs = [{"ioc_value": r["ioc"], "ioc_type": r["type"],
                  "verdict": r["verdict"], "score": r["score"]}
                 for r in results]

    try:
        case_id = case_manager.create_case(
            alert_id, severity, case_title(verdict, results), description,
            case_iocs)
        note = "Playbook verdict: {}. IOCs: {}".format(
            verdict, ioc_summary(results))
        if verdict == "ESCALATE":
            case_manager.update_case_status(case_id, "escalated")
            triggers = [r for r in results if r["verdict"] == "BLOCK"]
            note += ". Escalation triggered by: {}".format(", ".join(
                "{} {}".format(r["ioc"], describe(r)) for r in triggers))
        case_manager.add_case_note(case_id, note)
        if verdict == "CLOSE":
            case_manager.close_case(case_id, CLOSE_RESOLUTION)
    except (sqlite3.Error, ValueError) as exc:
        print("error: database write failed: {}".format(exc),
              file=sys.stderr)
        return 1

    try:
        with open(AUDIT_LOG, "a", encoding="utf-8") as handle:
            handle.write(
                "{} | {} | {} | IOCs:{} | BLOCK:{},INVESTIGATE:{},ALLOW:{} "
                "| Verdict:{} | Case:{} | Severity:{}\n".format(
                    run_at, PLAYBOOK, alert_id, len(results), counts["BLOCK"],
                    counts["INVESTIGATE"], counts["ALLOW"], verdict, case_id,
                    severity))
    except OSError as exc:
        print("error: cannot write audit log: {}".format(exc),
              file=sys.stderr)
        return 1

    dedup = sum(1 for i in iocs if i["dedup"])
    width = max([len(r["ioc"]) for r in results] + [len(i["value"])
                                                    for i in iocs] + [10])
    print("[{}] PHISHING TRIAGE PLAYBOOK".format(run_at))
    print("Alert      : {}".format(alert_id))
    print("Rule       : {}".format(rule))
    print("IOCs       : {} extracted, {} enriched, {} dedup skipped".format(
        len(iocs), len(results), dedup))
    for r in results:
        print("  {}  {:<6}  {:<11} score={:<3} {}".format(
            r["ioc"].ljust(width), r["type"], r["verdict"], r["score"],
            describe(r)))
    for i in iocs:
        if i["dedup"]:
            print("  {}  [dedup, skipped]".format(i["value"].ljust(width)))
    print("Verdict    : {}".format(verdict))
    print("Case       : {}  Severity: {}  Status: {}".format(
        case_id, severity, status))
    print("Action     : {}".format(ACTIONS[verdict]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
