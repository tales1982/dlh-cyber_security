#!/usr/bin/env python3
"""MedDefense IOC enrichment engine.

Classifies an IP address, domain or URL against the local threat intel
feed (ioc_feed.json) and standard library network introspection, and
returns a structured verdict: BLOCK, INVESTIGATE or ALLOW.

Module use:
    from enrich_ioc import enrich_ioc
    result = enrich_ioc("198.51.100.42")

CLI use:
    python3 enrich_ioc.py 198.51.100.42
    python3 enrich_ioc.py --batch iocs.txt --output results.json

Scoring follows materials/threat_intel/ioc_scoring_reference.md. A BLOCK
verdict is a strong malicious indicator for case escalation; it never
triggers a response action by itself.

Standard library only.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

DEFAULT_FEED = "ioc_feed.json"
BLOCK_THRESHOLD = 80
UNKNOWN_SCORE = 30
DNS_TIMEOUT = 3

# ipaddress does not separate the RFC 5737 / RFC 3849 documentation
# ranges from other addresses (recent Python versions even report them
# as private), so they are checked explicitly and before anything else.
DOCUMENTATION_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
]

# Feed entry fields copied into feed_result.
FEED_FIELDS = ("confidence", "category", "tags", "first_seen", "last_seen",
               "source")

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z][a-z0-9-]{0,62}$",
    re.IGNORECASE)
URL_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)

NOTES = {
    "private": "Private address range; internal network traffic",
    "loopback": "Loopback address; local host traffic",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def url_hostname(value: str) -> str | None:
    """Return the hostname of a URL, or None if it has none."""
    try:
        host = urlparse(value.strip()).hostname
    except ValueError:
        return None
    return host or None


def _is_ip(value: str) -> int | None:
    """Return 4 or 6 if value is an IP address, else None."""
    try:
        return ipaddress.ip_address(value).version
    except ValueError:
        return None


def detect_ioc_type(value: str) -> str:
    """Return "ipv4", "ipv6", "domain" or "url".

    A value that is none of these (malformed) is returned as "unknown";
    enrich_ioc() scores it INVESTIGATE so it reaches an analyst instead of
    failing silently.
    """
    value = (value or "").strip()
    version = _is_ip(value)
    if version == 4:
        return "ipv4"
    if version == 6:
        return "ipv6"
    if URL_RE.match(value):
        return "url"
    if DOMAIN_RE.match(value.rstrip(".")):
        return "domain"
    return "unknown"


def classify_ip(ip: str) -> str:
    """Return private, loopback, link_local, documentation, multicast
    or public."""
    addr = ipaddress.ip_address(ip)
    if any(addr in net for net in DOCUMENTATION_NETWORKS
           if net.version == addr.version):
        return "documentation"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link_local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_private:
        return "private"
    return "public"


def reverse_dns(ip: str) -> str:
    """Return the PTR hostname, "NXDOMAIN" or "TIMEOUT"."""
    socket.setdefaulttimeout(DNS_TIMEOUT)
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.timeout:
        return "TIMEOUT"
    except socket.herror:
        return "NXDOMAIN"
    except OSError:
        # gaierror and other resolver errors: no usable PTR record.
        return "NXDOMAIN"


def load_feed(feed_path: str = DEFAULT_FEED) -> dict:
    """Load the feed from feed_path; fall back to the script directory."""
    path = Path(feed_path)
    if not path.is_file() and not path.is_absolute():
        alt = Path(__file__).resolve().parent / feed_path
        if alt.is_file():
            path = alt
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def check_feed(value: str, feed: dict) -> dict:
    """Look up value in the malicious and benign lists of the feed."""
    key = value.strip().lower().rstrip(".")
    result = {"in_malicious_feed": False, "in_benign_list": False}

    malicious = {}
    malicious.update({k.lower(): v
                      for k, v in feed.get("malicious_ips", {}).items()})
    malicious.update({k.lower(): v
                      for k, v in feed.get("malicious_domains", {}).items()})
    benign = {v.lower() for v in feed.get("benign_ips", [])}
    benign |= {v.lower() for v in feed.get("benign_domains", [])}

    if key in malicious:
        result["in_malicious_feed"] = True
        entry = malicious[key]
        for field in FEED_FIELDS:
            if field in entry:
                result[field] = entry[field]
    if key in benign:
        result["in_benign_list"] = True
    return result


def score_ioc(feed_result: dict, ip_class: str) -> tuple[int, str]:
    """Return (score, verdict) from the feed result and IP class."""
    if ip_class in ("private", "loopback"):
        return 0, "ALLOW"
    if feed_result.get("in_benign_list"):
        return 0, "ALLOW"
    if feed_result.get("in_malicious_feed"):
        confidence = int(feed_result.get("confidence", 0))
        if confidence >= BLOCK_THRESHOLD:
            return confidence, "BLOCK"
        return confidence, "INVESTIGATE"
    return UNKNOWN_SCORE, "INVESTIGATE"


def enrich_ioc(value: str, feed_path: str = DEFAULT_FEED,
               feed: dict | None = None) -> dict:
    """Enrich one IOC and return the full verdict structure."""
    value = (value or "").strip()
    if feed is None:
        feed = load_feed(feed_path)

    ioc_type = detect_ioc_type(value)
    target = value
    if ioc_type == "url":
        target = url_hostname(value) or ""

    target_is_ip = _is_ip(target) is not None
    ip_class = classify_ip(target) if target_is_ip else "N/A"
    rdns = reverse_dns(target) if target_is_ip else "N/A"

    note = None
    if ioc_type == "unknown" or (ioc_type == "url" and not target):
        feed_result = {"in_malicious_feed": False, "in_benign_list": False}
        score, verdict = UNKNOWN_SCORE, "INVESTIGATE"
        note = "Malformed IOC; routed to analyst review"
    else:
        feed_result = check_feed(target, feed)
        score, verdict = score_ioc(feed_result, ip_class)
        note = NOTES.get(ip_class)

    result = {
        "ioc": value,
        "type": ioc_type,
        "ip_class": ip_class,
        "reverse_dns": rdns,
        "feed_result": feed_result,
        "score": score,
        "verdict": verdict,
    }
    if ioc_type == "url":
        result["hostname"] = target or None
    if note:
        result["note"] = note
    result["enriched_at"] = utc_now()
    return result


def run_batch(batch_file: str, output: str, feed_path: str) -> int:
    path = Path(batch_file)
    if not path.is_file():
        print("error: batch file not found: {}".format(batch_file),
              file=sys.stderr)
        return 1
    feed = load_feed(feed_path)
    seen = set()
    results = []
    for line in path.read_text(encoding="utf-8").splitlines():
        value = line.strip()
        if not value or value.startswith("#") or value in seen:
            continue
        seen.add(value)
        results.append(enrich_ioc(value, feed_path, feed=feed))

    with open(output, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2)
        handle.write("\n")

    counts = {v: 0 for v in ("BLOCK", "INVESTIGATE", "ALLOW")}
    for item in results:
        counts[item["verdict"]] += 1
    print("Processed: {} | BLOCK: {} | INVESTIGATE: {} | ALLOW: {}".format(
        len(results), counts["BLOCK"], counts["INVESTIGATE"],
        counts["ALLOW"]))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Enrich an IP, domain or URL against the local feed")
    parser.add_argument("ioc", nargs="?", help="IOC to enrich")
    parser.add_argument("--batch", help="file with one IOC per line")
    parser.add_argument("--output", default="results.json",
                        help="batch output file (default results.json)")
    parser.add_argument("--feed", default=DEFAULT_FEED,
                        help="threat intel feed (default ioc_feed.json)")
    args = parser.parse_args(argv)

    try:
        if args.batch:
            return run_batch(args.batch, args.output, args.feed)
        if not args.ioc:
            parser.error("provide an IOC or --batch FILE")
        print(json.dumps(enrich_ioc(args.ioc, args.feed), indent=2))
        return 0
    except (OSError, json.JSONDecodeError) as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
