#!/usr/bin/env python3
"""MedDefense IAM account audit.

Reads an account inventory (accounts.csv), applies the checks below and
writes severity-scored findings to iam_findings.json.

Severity follows materials/iam_audit/severity_model.md:
  Critical  direct domain takeover, privileged persistence or a repeat of
            the prior incident path (service account or orphaned account
            in Domain Admins, departed user in Domain Admins)
  High      strong attack path that needs one more condition
            (departed user still enabled, dormant privileged user,
            privileged user without MFA)
  Medium    meaningful exposure or detection weakness (service account
            with Server/Workstation Admins, high-risk user without MFA,
            disabled account that kept its groups)
  Low       hygiene (standing Domain Admin on named daily accounts)

One finding is produced per account. When several checks fire on the
same account, the finding keeps the highest severity and lists every
condition that fired, so the report has one remediation per account.

Usage:
  python3 audit_iam.py
  python3 audit_iam.py --input accounts.csv --output iam_findings.json \
      --audit-date 2026-11-18 --dormant-days 90

Standard library only.
"""

import argparse
import csv
import json
import re
import sys
from collections import Counter
from datetime import date
from pathlib import Path

SEVERITY_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

# Groups that grant administrative control over servers, workstations
# or the whole domain.
DOMAIN_ADMIN = "Domain Admins"
PRIVILEGED_GROUPS = {"Domain Admins", "Server Admins", "Workstation Admins"}

# Description text that shows the person no longer works here.
DEPARTED_PATTERN = re.compile(
    r"contract ended|left organization|terminated|separated", re.I)
# Description text that shows the account no longer has a function, or
# the person changed role and kept old rights.
ORPHANED_PATTERN = re.compile(
    r"migration complete|no current function|rights not removed|"
    r"transferred", re.I)
# Description text that shows a known high-risk user.
HIGH_RISK_PATTERN = re.compile(r"phishing", re.I)
# Description text that shows a privilege was granted without a review.
UNREVIEWED_GRANT_PATTERN = re.compile(
    r"review later|granted by vendor|per vendor|legacy config", re.I)

# Category order inside the same severity: categories that match the
# incident path come first, so the CISO reads them first.
CATEGORIES = {
    "SA_DA": (0, "Service account over-privilege",
              "Service account privilege review"),
    "DEPARTED_PRIV": (1, "Departed user with privileged access",
                      "Leaver de-provisioning review"),
    "ORPHANED_PRIV": (2, "Orphaned privileged account",
                      "Privileged account ownership review"),
    "DEPARTED": (3, "Departed user still enabled",
                 "Leaver de-provisioning review"),
    "SA_PRIV": (4, "Service account over-privilege",
                "Service account privilege review"),
    "HIGH_RISK_NO_MFA": (5, "MFA gap on high-risk user",
                         "MFA enrollment review"),
    "DISABLED_GROUPS": (6, "Disabled account retains privileged groups",
                        "Leaver de-provisioning review"),
    "STANDING_DA": (7, "Standing Domain Admin on named account",
                    "Privileged access model review"),
}


def to_bool(value):
    """Return True/False for TRUE/FALSE, None for N/A or empty."""
    value = (value or "").strip().upper()
    if value == "TRUE":
        return True
    if value == "FALSE":
        return False
    return None


def parse_groups(value):
    return [g.strip() for g in (value or "").split(";") if g.strip()]


def load_accounts(path):
    """Read accounts.csv and keep the file line number of each row."""
    accounts = []
    with open(path, newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        # Line 1 is the header, so the first data row is line 2.
        for line_no, row in enumerate(reader, start=2):
            row = {k: (v or "").strip() for k, v in row.items()}
            row["_line"] = line_no
            row["_groups"] = parse_groups(row.get("privileged_groups"))
            row["_enabled"] = to_bool(row.get("enabled"))
            row["_mfa"] = to_bool(row.get("mfa_enrolled"))
            try:
                row["_days"] = int(row.get("last_login_days_ago") or 0)
            except ValueError:
                row["_days"] = None
            accounts.append(row)
    return accounts


def evaluate(acct, dormant_days):
    """Return (category_key, severity, conditions) or None."""
    groups = set(acct["_groups"])
    priv = groups & PRIVILEGED_GROUPS
    is_service = acct.get("account_type", "").lower() == "service"
    enabled = acct["_enabled"]
    mfa = acct["_mfa"]
    days = acct["_days"]
    desc = acct.get("description", "")
    dormant = days is not None and days > dormant_days

    conditions = []
    if DOMAIN_ADMIN in groups:
        conditions.append("Member of Domain Admins")
    elif priv:
        conditions.append("Member of " + ", ".join(sorted(priv)))
    if dormant and enabled:
        conditions.append(
            "Dormant: last login {} days ago (threshold {})".format(
                days, dormant_days))
    if mfa is False and enabled:
        conditions.append("MFA not enrolled")
    if DEPARTED_PATTERN.search(desc):
        conditions.append("Description shows the user has left: " + desc)
    elif ORPHANED_PATTERN.search(desc):
        conditions.append(
            "Description shows no current owner or function: " + desc)
    if UNREVIEWED_GRANT_PATTERN.search(desc):
        conditions.append(
            "Privilege granted without review: " + desc)
    if HIGH_RISK_PATTERN.search(desc):
        conditions.append("High-risk user: " + desc)

    # Disabled accounts: only flag when they kept privileged groups.
    if enabled is False:
        if priv or groups & {"Helpdesk"}:
            return ("DISABLED_GROUPS", "Medium", [
                "Account disabled but still a member of "
                + ", ".join(acct["_groups"]),
                "Description: " + desc,
            ])
        return None

    if is_service:
        if DOMAIN_ADMIN in groups:
            return ("SA_DA", "Critical", conditions)
        if priv:
            return ("SA_PRIV", "Medium", conditions)
        return None

    departed = bool(DEPARTED_PATTERN.search(desc))
    orphaned = bool(ORPHANED_PATTERN.search(desc))

    if departed and DOMAIN_ADMIN in groups:
        return ("DEPARTED_PRIV", "Critical", conditions)
    if orphaned and DOMAIN_ADMIN in groups:
        return ("ORPHANED_PRIV", "Critical", conditions)
    if departed or orphaned:
        sev = "High" if (priv or dormant) else "Medium"
        key = "DEPARTED" if departed else "ORPHANED_PRIV"
        return (key, sev, conditions)
    if priv and (dormant or mfa is False):
        return ("ORPHANED_PRIV", "High", conditions)
    if mfa is False and HIGH_RISK_PATTERN.search(desc):
        return ("HIGH_RISK_NO_MFA", "Medium", conditions)
    if DOMAIN_ADMIN in groups:
        return ("STANDING_DA", "Low", conditions + [
            "Active, MFA enrolled; Domain Admin rights are held "
            "permanently on the same account used for daily work"])
    return None


REMEDIATION = {
    "SA_DA": [
        "Remove the account from Domain Admins.",
        "Rotate the password and record the change ticket.",
        "If the account has no current function, disable it, keep it "
        "disabled for 30 days, then delete it.",
        "If the function is still needed, move it to a scoped group or "
        "a Vault dynamic credential with a short TTL.",
        "Verify the dependent job still runs and record the result.",
    ],
    "DEPARTED_PRIV": [
        "Disable the account immediately.",
        "Remove all group memberships.",
        "Reset the password and revoke any active sessions or tokens.",
        "Review logons after the departure date in the SIEM.",
        "Delete the account after 30 days if the review is clean.",
    ],
    "ORPHANED_PRIV": [
        "Remove the account from privileged groups.",
        "Confirm the owner and business need with the manager.",
        "Disable the account if no owner confirms it within 7 days.",
        "Enroll MFA before any privileged access is restored.",
    ],
    "DEPARTED": [
        "Disable the account and remove group memberships.",
        "Confirm the leave date with HR and review logons after it.",
        "Delete the account after the retention period.",
    ],
    "SA_PRIV": [
        "Replace the admin group with a least-privilege role scoped to "
        "the agent's function.",
        "Store the credential in Vault and rotate it on a schedule.",
        "Verify the agent still collects data after the change.",
    ],
    "HIGH_RISK_NO_MFA": [
        "Enroll MFA before the next login.",
        "Assign targeted phishing training.",
        "Add the account to a SIEM watchlist for 90 days.",
    ],
    "DISABLED_GROUPS": [
        "Remove all group memberships from the disabled account.",
        "Fix the off-boarding checklist so groups are removed when the "
        "account is disabled.",
    ],
    "STANDING_DA": [
        "Create a separate admin account for privileged tasks.",
        "Remove Domain Admins from the daily account.",
        "Move Domain Admin use to JIT elevation with approval and logging.",
    ],
}


def build_findings(accounts, dormant_days, incident_accounts):
    raw = []
    for acct in accounts:
        result = evaluate(acct, dormant_days)
        if result is None:
            continue
        key, severity, conditions = result
        cat_rank, category, check = CATEGORIES[key]
        raw.append((acct, key, severity, conditions, cat_rank, category,
                    check))

    raw.sort(key=lambda r: (SEVERITY_RANK[r[2]], r[4],
                            -(r[0]["_days"] or 0)))

    findings = []
    for idx, (acct, key, severity, conditions, _rank, category,
              check) in enumerate(raw, start=1):
        findings.append({
            "finding_id": "IAM-{:03d}".format(idx),
            "username": acct["username"],
            "display_name": acct.get("display_name", ""),
            "department": acct.get("department", ""),
            "account_type": acct.get("account_type", ""),
            "enabled": acct["_enabled"],
            "last_login_days_ago": acct["_days"],
            "mfa_enrolled": acct.get("mfa_enrolled", ""),
            "privileged_groups": acct["_groups"],
            "description": acct.get("description", ""),
            "category": category,
            "check": check,
            "severity": severity,
            "conditions": conditions,
            "incident_path_match": acct["username"] in incident_accounts,
            "evidence": "accounts.csv line {}".format(acct["_line"]),
            "remediation": REMEDIATION[key],
            "status": "Open",
        })
    return findings


def mfa_coverage(accounts):
    """MFA coverage for enabled human accounts in privileged groups."""
    priv_users = [
        a for a in accounts
        if a.get("account_type", "").lower() == "user"
        and a["_enabled"]
        and set(a["_groups"]) & PRIVILEGED_GROUPS
    ]
    with_mfa = sorted(a["username"] for a in priv_users if a["_mfa"])
    without = sorted(a["username"] for a in priv_users if a["_mfa"] is False)
    total = len(priv_users)
    pct = round(100.0 * len(with_mfa) / total, 1) if total else 0.0
    return {
        "scope": "Enabled user accounts in Domain Admins, Server Admins "
                 "or Workstation Admins (service accounts excluded: MFA "
                 "is N/A)",
        "privileged_user_accounts": total,
        "with_mfa": len(with_mfa),
        "without_mfa": len(without),
        "coverage_percent": pct,
        "accounts_without_mfa": without,
    }


def parse_args(argv):
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="MedDefense IAM audit")
    parser.add_argument("--input", default=str(here / "accounts.csv"),
                        help="account inventory CSV")
    parser.add_argument("--output", default=str(here / "iam_findings.json"),
                        help="findings JSON to write")
    parser.add_argument("--audit-date", default=date.today().isoformat(),
                        help="audit date written to the output (YYYY-MM-DD)")
    parser.add_argument("--dormant-days", type=int, default=90,
                        help="days without login before an account is "
                             "dormant (default 90)")
    return parser.parse_args(argv)


# Accounts named in materials/iam_audit/incident_identity_path.md as
# resembling the path used in the prior incident.
INCIDENT_PATH_ACCOUNTS = {
    "svc_epic_int", "svc_helpdesk", "svc_backup",
    "t.morrison", "admin.legacy", "j.yamamoto",
}


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    in_path = Path(args.input)
    if not in_path.is_file():
        print("error: input not found: {}".format(in_path), file=sys.stderr)
        return 1

    accounts = load_accounts(in_path)
    findings = build_findings(accounts, args.dormant_days,
                              INCIDENT_PATH_ACCOUNTS)
    counts = Counter(f["severity"] for f in findings)

    output = {
        "audit_metadata": {
            "organization": "MedDefense",
            "audit_date": args.audit_date,
            "source_file": in_path.name,
            "accounts_reviewed": len(accounts),
            "dormant_threshold_days": args.dormant_days,
            "severity_model": "materials/iam_audit/severity_model.md",
            "generated_by": "audit_iam.py",
        },
        "summary": {
            "total_findings": len(findings),
            "by_severity": {s: counts.get(s, 0) for s in SEVERITY_RANK},
            "incident_path_matches": sorted(
                f["finding_id"] for f in findings
                if f["incident_path_match"]),
            "mfa_coverage_privileged_users": mfa_coverage(accounts),
        },
        "findings": findings,
    }

    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(output, handle, indent=2)
        handle.write("\n")

    print("Accounts reviewed: {}".format(len(accounts)))
    print("Findings: {} (Critical {}, High {}, Medium {}, Low {})".format(
        len(findings), counts.get("Critical", 0), counts.get("High", 0),
        counts.get("Medium", 0), counts.get("Low", 0)))
    for f in findings:
        print("{}  {:<8}  {:<14}  {}".format(
            f["finding_id"], f["severity"], f["username"], f["category"]))
    print("Written: {}".format(args.output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
