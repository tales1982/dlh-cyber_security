#!/bin/bash
# validate_rules.sh - test the 5x03 Sigma rules against the incident and clean Sysmon samples
#
# Usage: ./validate_rules.sh [DATA_DIR]
#   DATA_DIR holds incident_sysmon.jsonl and clean_sysmon.jsonl
#   (default: the script directory, then ./5x03, then the current directory)
#
# Rules tested:
#   sigma_powershell_msbuild_lolbin.yml   (Task 3, process_creation)
#   sigma_msbuild_network_connection.yml  (Task 4, network_connection)
#
# For each rule and each sample it prints the number of matched events, the
# match rate as a percentage of all events in the sample, a verdict, and for
# the clean sample the matched events with the false positive pattern.
# The network rule is run on the clean sample twice: as originally written
# (filter_nuget disabled) and after tuning, to document the tuning.
#
# Matching engine: a Sigma-compatible matcher in Python 3 (standard library
# only). It reads the rule files with PyYAML when available, otherwise it
# uses the same detection logic embedded below. If sigma-cli is installed,
# the rule syntax is also checked with "sigma check".

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

find_data_dir() {
    local d
    for d in "${1:-}" "$SCRIPT_DIR" "$SCRIPT_DIR/5x03" "$PWD" "$PWD/5x03"; do
        [[ -n "$d" && -f "$d/incident_sysmon.jsonl" && -f "$d/clean_sysmon.jsonl" ]] && { echo "$d"; return 0; }
    done
    return 1
}

DATA_DIR="$(find_data_dir "${1:-}")" || {
    echo "ERROR: incident_sysmon.jsonl / clean_sysmon.jsonl not found (pass the folder as argument)" >&2
    exit 2
}
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 is required" >&2; exit 2; }

python3 - "$SCRIPT_DIR" "$DATA_DIR" <<'PY'
import ipaddress
import json
import os
import re
import sys
from collections import Counter

script_dir, data_dir = sys.argv[1], sys.argv[2]
FP_TARGET = 0.1  # percent of total events in the clean sample

# Same detection logic as the .yml files (used when PyYAML is not installed)
EMBEDDED = {
    "sigma_powershell_msbuild_lolbin.yml": {
        "title": "PowerShell Spawning Trusted Developer Utility (LOLBin Proxy Execution)",
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection_parent": {"ParentImage|endswith": [
                "\\powershell.exe", "\\pwsh.exe", "\\powershell_ise.exe",
                "\\wscript.exe", "\\cscript.exe", "\\mshta.exe"]},
            "selection_child": {"Image|endswith": [
                "\\MSBuild.exe", "\\csc.exe", "\\vbc.exe", "\\jsc.exe",
                "\\InstallUtil.exe", "\\RegAsm.exe", "\\RegSvcs.exe"]},
            "condition": "selection_parent and selection_child",
        },
    },
    "sigma_msbuild_network_connection.yml": {
        "title": "Trusted Developer Utility Outbound Connection to Public IP (LOLBin C2)",
        "logsource": {"category": "network_connection", "product": "windows"},
        "detection": {
            "selection": {
                "Image|endswith": [
                    "\\MSBuild.exe", "\\csc.exe", "\\vbc.exe", "\\jsc.exe",
                    "\\InstallUtil.exe", "\\RegAsm.exe", "\\RegSvcs.exe"],
                "Initiated": "true",
            },
            "filter_private": {"DestinationIp|cidr": [
                "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]},
            "filter_nuget": {"DestinationHostname|endswith": ".nuget.org"},
            "condition": "selection and not 1 of filter_*",
        },
    },
}
RULE_FILES = list(EMBEDDED)
# Selections added during tuning; disabled to show the original rule's result
TUNING_FILTERS = {"sigma_msbuild_network_connection.yml": ["filter_nuget"]}

FIELD_MAP = {
    "Image": "image", "ParentImage": "parent_image", "CommandLine": "cmdline",
    "User": "user", "ComputerName": "host", "ProcessId": "pid",
    "DestinationIp": "dst_ip", "DestinationPort": "dst_port",
    "DestinationHostname": "dst_hostname", "SourceIp": "src_ip",
    "Initiated": "initiated", "TargetObject": "target_object",
    "TargetFilename": "target",
}
CATEGORY_EVENT = {"process_creation": 1, "network_connection": 3, "image_load": 7,
                  "file_event": 11, "registry_set": 13}


def load_rule(name):
    path = os.path.join(script_dir, name)
    try:
        import yaml
        with open(path) as fh:
            return yaml.safe_load(fh)
    except Exception:
        return EMBEDDED[name]


def as_str(v):
    if v is None:
        return None
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def match_value(value, mods, pattern):
    ev, pat = as_str(value), as_str(pattern)
    if ev is None:
        return False
    if "cidr" in mods:
        try:
            return ipaddress.ip_address(ev) in ipaddress.ip_network(pat, strict=False)
        except ValueError:
            return False
    ev, pat = ev.lower(), pat.lower()
    if "endswith" in mods:
        return ev.endswith(pat)
    if "startswith" in mods:
        return ev.startswith(pat)
    if "contains" in mods:
        return pat in ev
    return ev == pat


def match_selection(event, sel):
    for block in (sel if isinstance(sel, list) else [sel]):
        ok = True
        for key, pats in block.items():
            field, *mods = key.split("|")
            value = event.get(FIELD_MAP.get(field, field))
            pats = pats if isinstance(pats, list) else [pats]
            test = all if "all" in mods else any
            if not test(match_value(value, mods, p) for p in pats):
                ok = False
                break
        if ok:
            return True
    return False


def eval_condition(cond, res):
    def expand(m):
        names = [n for n in res if re.fullmatch(m.group(2).replace("*", ".*"), n)]
        vals = [str(res[n]) for n in names] or ["False"]
        return "(" + (" or " if m.group(1) == "1" else " and ").join(vals) + ")"
    expr = re.sub(r"\b(1|all) of (\w+\*?)", expand, cond)
    expr = re.sub(r"\b([A-Za-z_]\w*)\b",
                  lambda m: m.group(1) if m.group(1) in ("and", "or", "not", "True", "False")
                  else str(res.get(m.group(1), False)), expr)
    return bool(eval(expr, {"__builtins__": {}}, {}))


def matches(rule, event, disabled=()):
    cat = rule["logsource"].get("category")
    if cat in CATEGORY_EVENT and event.get("event_id") != CATEGORY_EVENT[cat]:
        return False
    det = rule["detection"]
    res = {k: (False if k in disabled else match_selection(event, v))
           for k, v in det.items() if k != "condition"}
    return eval_condition(det["condition"], res)


def base(p):
    return os.path.basename((p or "").replace("\\", "/"))


def describe(e):
    if e.get("event_id") == 3:
        return "{} {} {} PID {} -> {}:{} ({})".format(
            e["ts"], e["host"], base(e["image"]), e.get("pid"), e.get("dst_ip"),
            e.get("dst_port"), e.get("dst_hostname") or "no hostname")
    return "{} {} {} -> {} PID {} | {}".format(
        e["ts"], e["host"], base(e.get("parent_image")), base(e["image"]),
        e.get("pid"), e.get("cmdline", ""))


def fp_pattern(hits):
    keys = Counter()
    for e in hits:
        if e.get("event_id") == 3:
            keys["{} connections to {}".format(base(e["image"]), e.get("dst_hostname") or e.get("dst_ip"))] += 1
        else:
            keys["{} spawned by {}".format(base(e["image"]), base(e.get("parent_image")))] += 1
    return "; ".join("{} matches are {}".format(n, k) for k, n in keys.most_common())


def rate(n, total):
    return 100.0 * n / total if total else 0.0


samples = {}
for name in ("incident_sysmon.jsonl", "clean_sysmon.jsonl"):
    with open(os.path.join(data_dir, name)) as fh:
        samples[name] = [json.loads(l) for l in fh if l.strip()]

overall_ok = True
for rule_file in RULE_FILES:
    rule = load_rule(rule_file)
    print("### Rule: {} ({})".format(rule_file, rule.get("title", "")))
    print()

    # Incident sample: the rule must fire
    events = samples["incident_sysmon.jsonl"]
    hits = [e for e in events if matches(rule, e)]
    print("[incident_sysmon.jsonl]")
    print("Total events: {:,}".format(len(events)))
    print("Matches: {}".format(len(hits)))
    print("Match rate: {:.3f}%".format(rate(len(hits), len(events))))
    if hits:
        detail = " and ".join("PID {} at {}".format(e.get("pid"), e["ts"][11:]) for e in hits)
        print("Verdict: PASS (expected matches on {})".format(detail))
    else:
        print("Verdict: FAIL (rule did not fire on the incident)")
        overall_ok = False
    print()

    # Clean sample: false positive rate must stay under the target
    events = samples["clean_sysmon.jsonl"]
    tuning = TUNING_FILTERS.get(rule_file, [])
    first = [e for e in events if matches(rule, e, disabled=tuning)]
    fpr = rate(len(first), len(events))
    print("[clean_sysmon.jsonl]")
    print("Total events: {:,}".format(len(events)))
    print("Matches: {}".format(len(first)))
    print("False positive rate: {:.3f}%".format(fpr))
    if not first:
        print("Verdict: PASS")
    else:
        print("Verdict: REVIEW : {}".format(fp_pattern(first)))
        print("Matched events:")
        for e in first:
            print("  - " + describe(e))
        if tuning:
            print("Action: adding filter for DestinationHostname|endswith '.nuget.org'; re-running")
    print()

    if first and tuning:
        tuned = [e for e in events if matches(rule, e)]
        fpr = rate(len(tuned), len(events))
        print("[clean_sysmon.jsonl after tuning]")
        print("Matches: {}".format(len(tuned)))
        print("False positive rate: {:.3f}%".format(fpr))
        print("Verdict: {}".format("PASS" if fpr < FP_TARGET else "REVIEW"))
        for e in tuned:
            print("  - " + describe(e))
        print()
    if fpr >= FP_TARGET:
        overall_ok = False

print("Overall: {}".format("PASS" if overall_ok else "REVIEW"))
sys.exit(0 if overall_ok else 1)
PY
status=$?

if command -v sigma >/dev/null 2>&1; then
    echo
    echo "[sigma check]"
    sigma check "$SCRIPT_DIR/sigma_powershell_msbuild_lolbin.yml" \
                "$SCRIPT_DIR/sigma_msbuild_network_connection.yml" 2>&1 | tail -n 3
fi

exit $status
