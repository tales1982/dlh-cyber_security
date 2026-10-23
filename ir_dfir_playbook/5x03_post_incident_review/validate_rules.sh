#!/usr/bin/env bash
# validate_rules.sh - test the 5x03 Sigma rules against the incident and clean Sysmon samples
#
# Usage: ./validate_rules.sh [DATA_DIR]
#   DATA_DIR holds incident_sysmon.jsonl and clean_sysmon.jsonl
#   (default: the script directory, then ./5x03)
#
# For each rule and sample it prints: total events, matches, match rate,
# a verdict, and for the clean sample the matched events grouped by pattern.
# For the clean sample it also runs the rule with its filter_* blocks
# disabled, to show the false positives the tuning removed.
#
# Matching: a small Sigma evaluator (Python + PyYAML) that supports
# |endswith, |startswith, |contains, |cidr, plain equality, lists (OR),
# and conditions with and / or / not / parentheses / "1 of x*" / "all of x*".
# If sigma-cli is installed, the rule syntax is also checked with "sigma check".

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${1:-$SCRIPT_DIR}"
if [[ ! -f "$DATA_DIR/incident_sysmon.jsonl" && -d "$SCRIPT_DIR/5x03" ]]; then
    DATA_DIR="$SCRIPT_DIR/5x03"
fi

RULES=(
    "$SCRIPT_DIR/sigma_powershell_msbuild_lolbin.yml"
    "$SCRIPT_DIR/sigma_msbuild_network_connection.yml"
)
SAMPLES=(
    "$DATA_DIR/incident_sysmon.jsonl"
    "$DATA_DIR/clean_sysmon.jsonl"
)
FP_TARGET="0.1"   # percent of total events in the clean sample

for f in "${RULES[@]}" "${SAMPLES[@]}"; do
    [[ -f "$f" ]] || { echo "ERROR: missing $f" >&2; exit 2; }
done

command -v python3 >/dev/null || { echo "ERROR: python3 required" >&2; exit 2; }
python3 -c 'import yaml' 2>/dev/null || { echo "ERROR: PyYAML required (pip install pyyaml)" >&2; exit 2; }

echo "=== Syntax check ==="
if command -v sigma >/dev/null 2>&1; then
    sigma check "${RULES[@]}" | tail -n 3
elif command -v yamllint >/dev/null 2>&1; then
    yamllint -d relaxed "${RULES[@]}" && echo "yamllint: OK"
else
    echo "sigma-cli / yamllint not installed, skipping syntax check"
fi
echo

python3 -I - "$FP_TARGET" "${RULES[@]}" -- "${SAMPLES[@]}" <<'PY'
import ipaddress
import json
import os
import re
import sys
from collections import Counter

import yaml

args = sys.argv[1:]
fp_target = float(args[0])
sep = args.index("--")
rules, samples = args[1:sep], args[sep + 1:]

# Sigma field name -> field in the provided Sysmon JSONL
FIELD_MAP = {
    "Image": "image",
    "ParentImage": "parent_image",
    "CommandLine": "cmdline",
    "User": "user",
    "ComputerName": "host",
    "ProcessId": "pid",
    "DestinationIp": "dst_ip",
    "DestinationPort": "dst_port",
    "DestinationHostname": "dst_hostname",
    "SourceIp": "src_ip",
    "Initiated": "initiated",
    "TargetObject": "target_object",
    "TargetFilename": "target",
}
# Sigma logsource category -> Sysmon event ID
CATEGORY_EVENT = {
    "process_creation": 1,
    "network_connection": 3,
    "image_load": 7,
    "file_event": 11,
    "registry_set": 13,
}


def as_str(v):
    if v is None:
        return None
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def match_value(event_value, modifiers, pattern):
    ev = as_str(event_value)
    if ev is None:
        return False
    pat = as_str(pattern)
    if "cidr" in modifiers:
        try:
            return ipaddress.ip_address(ev) in ipaddress.ip_network(pat, strict=False)
        except ValueError:
            return False
    ev_l, pat_l = ev.lower(), pat.lower()
    if "endswith" in modifiers:
        return ev_l.endswith(pat_l)
    if "startswith" in modifiers:
        return ev_l.startswith(pat_l)
    if "contains" in modifiers:
        return pat_l in ev_l
    return ev_l == pat_l


def match_selection(event, selection):
    blocks = selection if isinstance(selection, list) else [selection]
    for block in blocks:  # list of maps = OR
        ok = True
        for key, patterns in block.items():  # keys in a map = AND
            field, *mods = key.split("|")
            value = event.get(FIELD_MAP.get(field, field))
            pats = patterns if isinstance(patterns, list) else [patterns]
            if "all" in mods:
                hit = all(match_value(value, mods, p) for p in pats)
            else:
                hit = any(match_value(value, mods, p) for p in pats)
            if not hit:
                ok = False
                break
        if ok:
            return True
    return False


def eval_condition(condition, results):
    def expand(m):
        quant, pattern = m.group(1), m.group(2)
        names = [n for n in results if re.fullmatch(pattern.replace("*", ".*"), n)]
        vals = [str(results[n]) for n in names] or ["False"]
        joiner = " or " if quant == "1" else " and "
        return "(" + joiner.join(vals) + ")"

    expr = re.sub(r"\b(1|all) of (\w+\*?)", expand, condition)
    expr = re.sub(r"\b([A-Za-z_]\w*)\b",
                  lambda m: m.group(1) if m.group(1) in ("and", "or", "not", "True", "False")
                  else str(results.get(m.group(1), False)), expr)
    return bool(eval(expr, {"__builtins__": {}}, {}))


def rule_matches(rule, event, disable_filters=False):
    cat = rule["logsource"].get("category")
    if cat in CATEGORY_EVENT and event.get("event_id") != CATEGORY_EVENT[cat]:
        return False
    det = rule["detection"]
    results = {}
    for name, sel in det.items():
        if name == "condition":
            continue
        if disable_filters and name.startswith("filter"):
            results[name] = False
        else:
            results[name] = match_selection(event, sel)
    return eval_condition(det["condition"], results)


def describe(e):
    if e.get("event_id") == 3:
        return "{} {} {} -> {}:{} ({})".format(
            e["ts"], e["host"], os.path.basename(e["image"].replace("\\", "/")),
            e.get("dst_ip"), e.get("dst_port"), e.get("dst_hostname") or "no hostname")
    return "{} {} PID {} {} -> {} | {}".format(
        e["ts"], e["host"], e.get("pid"),
        os.path.basename((e.get("parent_image") or "").replace("\\", "/")),
        os.path.basename(e["image"].replace("\\", "/")), e.get("cmdline", ""))


def pattern_key(e):
    img = os.path.basename(e["image"].replace("\\", "/"))
    if e.get("event_id") == 3:
        return "{} connections to {} ({})".format(img, e.get("dst_hostname") or "no hostname", e.get("dst_ip"))
    parent = os.path.basename((e.get("parent_image") or "").replace("\\", "/"))
    return "{} spawned by {}".format(img, parent)


def report(label, total, hits, clean, show_list):
    rate = 100.0 * len(hits) / total if total else 0.0
    print("[{}]".format(label))
    print("Total events: {:,}".format(total))
    print("Matches: {}".format(len(hits)))
    if clean:
        print("False positive rate: {:.3f}%".format(rate))
        if not hits:
            print("Verdict: PASS")
        elif rate < fp_target:
            print("Verdict: PASS (under {}% target)".format(fp_target))
        else:
            print("Verdict: REVIEW : over the {}% target".format(fp_target))
        if hits and show_list:
            print("False positive pattern:")
            for pat, n in Counter(pattern_key(e) for e in hits).most_common():
                print("  {:>3} x {}".format(n, pat))
            print("Matched events:")
            for e in hits:
                print("  - " + describe(e))
    else:
        print("Match rate: {:.3f}%".format(rate))
        print("Verdict: {}".format("PASS" if hits else "FAIL (rule did not fire on the incident)"))
        for e in hits:
            print("  - " + describe(e))
    print()
    return rate


exit_code = 0
for rule_path in rules:
    with open(rule_path) as fh:
        rule = yaml.safe_load(fh)
    has_filters = any(k.startswith("filter") for k in rule["detection"])
    print("=" * 72)
    print("Rule: {} ({})".format(rule["title"], os.path.basename(rule_path)))
    print("=" * 72)
    for sample in samples:
        with open(sample) as fh:
            events = [json.loads(line) for line in fh if line.strip()]
        name = os.path.basename(sample)
        clean = name.startswith("clean")
        if clean and has_filters:
            before = [e for e in events if rule_matches(rule, e, disable_filters=True)]
            report(name + " before tuning (filter_* disabled)", len(events), before, True, True)
            hits = [e for e in events if rule_matches(rule, e)]
            rate = report(name + " after tuning", len(events), hits, True, True)
        else:
            hits = [e for e in events if rule_matches(rule, e)]
            rate = report(name, len(events), hits, clean, clean)
        if (clean and rate >= fp_target) or (not clean and not hits):
            exit_code = 1

print("Overall: {}".format("PASS" if exit_code == 0 else "REVIEW"))
sys.exit(exit_code)
PY
