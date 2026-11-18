#!/usr/bin/env python3
"""MedDefense case manager: SQLite-backed security cases.

The output system for every automated playbook decision. Cases, notes
and IOCs are stored in cases.db (current directory), created on first
import with the schema in materials/case_management/case_schema_reference.sql.

Module use:
    import case_manager
    cid = case_manager.create_case("ALT-...", "High", "Title", "Desc", iocs)
    case_manager.add_case_note(cid, "text")

CLI use:
    python3 case_manager.py list                      # open cases
    python3 case_manager.py list --status escalated
    python3 case_manager.py list --status all
    python3 case_manager.py get CASE-20260428-001
    python3 case_manager.py close CASE-20260428-001 "benign; confirmed newsletter sender"
    python3 case_manager.py note CASE-20260428-001 "analyst comment"

Standard library only.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone

DB_PATH = "cases.db"
VALID_STATUSES = ("open", "investigating", "escalated", "closed")
# Statuses shown by the default "list": everything still needing work.
ACTIVE_STATUSES = ("open", "investigating", "escalated")

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    case_id     TEXT PRIMARY KEY,
    alert_id    TEXT NOT NULL,
    severity    TEXT NOT NULL,
    title       TEXT NOT NULL,
    description TEXT,
    status      TEXT NOT NULL DEFAULT 'open',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    resolution  TEXT
);

CREATE TABLE IF NOT EXISTS case_notes (
    note_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     TEXT NOT NULL,
    note        TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);

CREATE TABLE IF NOT EXISTS case_iocs (
    ioc_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     TEXT NOT NULL,
    ioc_value   TEXT NOT NULL,
    ioc_type    TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    score       INTEGER NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _connect(db_path: str | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path or DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: str = DB_PATH) -> None:
    """Create the database and the three tables if they do not exist."""
    global DB_PATH
    DB_PATH = db_path
    with _connect(db_path) as conn:
        conn.executescript(SCHEMA)


def generate_case_id() -> str:
    """Return CASE-YYYYMMDD-NNN, NNN sequential within the UTC day.

    The sequence comes from the count of today's cases in cases.db. If
    that ID is already taken (for example after a manual delete), the
    next free number is used.
    """
    day = datetime.now(timezone.utc).strftime("%Y%m%d")
    prefix = "CASE-{}-".format(day)
    with _connect() as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM cases WHERE case_id LIKE ?",
            (prefix + "%",)).fetchone()[0]
        seq = count + 1
        while conn.execute("SELECT 1 FROM cases WHERE case_id = ?",
                           ("{}{:03d}".format(prefix, seq),)).fetchone():
            seq += 1
    return "{}{:03d}".format(prefix, seq)


def _ioc_row(ioc: dict) -> tuple:
    """Accept case IOC dicts or raw enrich_ioc() results."""
    value = ioc.get("ioc_value", ioc.get("ioc"))
    ioc_type = ioc.get("ioc_type", ioc.get("type"))
    if value is None or ioc_type is None:
        raise ValueError("IOC needs ioc_value and ioc_type: {}".format(ioc))
    return (str(value), str(ioc_type), str(ioc.get("verdict", "INVESTIGATE")),
            int(ioc.get("score", 0)))


def create_case(alert_id: str, severity: str, title: str, description: str,
                iocs: list[dict]) -> str:
    """Insert a case and its IOCs; return the case_id."""
    now = utc_now()
    case_id = generate_case_id()
    rows = [_ioc_row(i) for i in (iocs or [])]
    with _connect() as conn:
        conn.execute(
            "INSERT INTO cases (case_id, alert_id, severity, title, "
            "description, status, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, 'open', ?, ?)",
            (case_id, alert_id, severity, title, description, now, now))
        conn.executemany(
            "INSERT INTO case_iocs (case_id, ioc_value, ioc_type, verdict, "
            "score) VALUES (?, ?, ?, ?, ?)",
            [(case_id,) + r for r in rows])
    return case_id


def _case_exists(conn: sqlite3.Connection, case_id: str) -> bool:
    return conn.execute("SELECT 1 FROM cases WHERE case_id = ?",
                        (case_id,)).fetchone() is not None


def add_case_note(case_id: str, note: str) -> bool:
    """Append a note and touch updated_at; False if the case is unknown."""
    now = utc_now()
    with _connect() as conn:
        if not _case_exists(conn, case_id):
            return False
        conn.execute(
            "INSERT INTO case_notes (case_id, note, created_at) "
            "VALUES (?, ?, ?)", (case_id, note, now))
        conn.execute("UPDATE cases SET updated_at = ? WHERE case_id = ?",
                     (now, case_id))
    return True


def update_case_status(case_id: str, status: str) -> bool:
    """Set the status; False for an invalid status or unknown case."""
    if status not in VALID_STATUSES:
        return False
    with _connect() as conn:
        cur = conn.execute(
            "UPDATE cases SET status = ?, updated_at = ? WHERE case_id = ?",
            (status, utc_now(), case_id))
        return cur.rowcount == 1


def close_case(case_id: str, resolution: str) -> bool:
    """Close the case with a resolution; False if the case is unknown."""
    with _connect() as conn:
        cur = conn.execute(
            "UPDATE cases SET status = 'closed', resolution = ?, "
            "updated_at = ? WHERE case_id = ?",
            (resolution, utc_now(), case_id))
        return cur.rowcount == 1


def get_case(case_id: str) -> dict | None:
    """Return the case with nested notes and IOCs, or None."""
    with _connect() as conn:
        row = conn.execute("SELECT * FROM cases WHERE case_id = ?",
                           (case_id,)).fetchone()
        if row is None:
            return None
        case = {k: row[k] for k in ("case_id", "alert_id", "severity",
                                    "title", "description", "status",
                                    "created_at", "updated_at",
                                    "resolution")}
        case["notes"] = [
            {"note": n["note"], "created_at": n["created_at"]}
            for n in conn.execute(
                "SELECT note, created_at FROM case_notes WHERE case_id = ? "
                "ORDER BY note_id", (case_id,))]
        case["iocs"] = [
            {"ioc_value": i["ioc_value"], "ioc_type": i["ioc_type"],
             "verdict": i["verdict"], "score": i["score"]}
            for i in conn.execute(
                "SELECT ioc_value, ioc_type, verdict, score FROM case_iocs "
                "WHERE case_id = ? ORDER BY ioc_id", (case_id,))]
    return case


def list_cases(status: str | None = None) -> list[dict]:
    """Return case summaries, optionally filtered by status."""
    query = ("SELECT case_id, alert_id, severity, title, status, created_at "
             "FROM cases")
    params: tuple = ()
    if status:
        query += " WHERE status = ?"
        params = (status,)
    query += " ORDER BY case_id"
    with _connect() as conn:
        return [dict(r) for r in conn.execute(query, params)]


def _print_table(cases: list[dict], label: str) -> None:
    headers = ("Case ID", "Alert ID", "Severity", "Title", "Status")
    keys = ("case_id", "alert_id", "severity", "title", "status")
    widths = [len(h) for h in headers]
    for case in cases:
        for i, key in enumerate(keys):
            widths[i] = max(widths[i], len(str(case[key])))
    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"

    def row(values):
        return "| " + " | ".join(
            str(v).ljust(w) for v, w in zip(values, widths)) + " |"

    print(sep)
    print(row(headers))
    print(sep)
    for case in cases:
        print(row([case[k] for k in keys]))
    print(sep)
    print("{} case{} (filter: {})".format(
        len(cases), "" if len(cases) == 1 else "s", label))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="MedDefense case manager")
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="list cases")
    p_list.add_argument("--status",
                        help="open, investigating, escalated, closed or all "
                             "(default: every status except closed)")
    p_get = sub.add_parser("get", help="show one case")
    p_get.add_argument("case_id")
    p_close = sub.add_parser("close", help="close a case")
    p_close.add_argument("case_id")
    p_close.add_argument("resolution")
    p_note = sub.add_parser("note", help="add a note to a case")
    p_note.add_argument("case_id")
    p_note.add_argument("note")
    args = parser.parse_args(argv)

    if args.command == "list":
        if args.status is None:
            cases = [c for c in list_cases() if c["status"] in ACTIVE_STATUSES]
            label = " + ".join(ACTIVE_STATUSES)
        elif args.status == "all":
            cases, label = list_cases(), "all"
        elif args.status in VALID_STATUSES:
            cases, label = list_cases(args.status), args.status
        else:
            print("error: invalid status: {}".format(args.status),
                  file=sys.stderr)
            return 1
        _print_table(cases, label)
        return 0

    if args.command == "get":
        case = get_case(args.case_id)
        if case is None:
            print("error: case not found: {}".format(args.case_id),
                  file=sys.stderr)
            return 1
        print(json.dumps(case, indent=2))
        return 0

    if args.command == "close":
        if not close_case(args.case_id, args.resolution):
            print("error: case not found: {}".format(args.case_id),
                  file=sys.stderr)
            return 1
        print("{} closed: {}".format(args.case_id, args.resolution))
        return 0

    if args.command == "note":
        if not add_case_note(args.case_id, args.note):
            print("error: case not found: {}".format(args.case_id),
                  file=sys.stderr)
            return 1
        print("Note added to {}".format(args.case_id))
        return 0
    return 1


# Create cases.db in the current directory on first import.
init_db()

if __name__ == "__main__":
    sys.exit(main())
