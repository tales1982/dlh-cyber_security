#!/bin/bash
#
# 2-segmentation_rules.sh
#
# MedDefense Health Systems - Perimeter and Network Defense (2x04)
#
# Mike Torres's diagram, made structured: every zone, every CIDR, every
# flow that is allowed to cross a zone boundary and why. This script does
# not touch the network - it produces the one file every other task in
# this project (nftables, Windows Firewall, the change log) reads as its
# source of truth. Get this wrong and every downstream rule is wrong too.
#
# CIDR plan (documented here because nowhere else defines it):
#   DMZ      10.10.10.0/24  public-facing app tier
#   INTERNAL 10.10.0.0/22   servers (10.10.1.0/24) + clinical workstations
#                           (10.10.2.0/24) + the third subnet observed on
#                           billing-srv-01's second NIC (10.10.3.0/24)
#   MGMT     10.10.20.0/24  administration + the internal DNS resolver
#   MEDDEV   10.10.4.0/24   medical device VLAN (DICOM/PACS, EHR display)
#   (guest wifi, 10.10.5.0/24, is deliberately NOT a modeled zone - it has
#   no membership in any zone set, so it falls under default-deny by
#   construction. T10's "unauthorized SMB from guest" Suricata rule exists
#   as defense-in-depth for exactly this untrusted, unzoned range.)
#
# Usage: ./2-segmentation_rules.sh [output.json]

set -uo pipefail

OUT_JSON="${1:-segmentation_rules.json}"

jq -n '
def zone($name; $cidr; $purpose; $out_note):
    {name: $name, cidr: $cidr, purpose: $purpose,
     default_inbound: "drop", default_outbound: "accept (\($out_note))"};

def flow($src; $dst; $proto; $dport; $just; $exc; $hosts):
    {src_zone: $src, dst_zone: $dst, proto: $proto, dport: $dport,
     justification: $just, exception_for: $exc, src_hosts: $hosts};

def deny($src; $dst):
    {src_zone: $src, dst_zone: $dst, proto: "any", dport: "any",
     rule: "deny_all", justification: "no allow flow defined for this zone pair"};

[
  zone("DMZ"; "10.10.10.0/24"; "public-facing services"; "restricted to required upstream deps only"),
  zone("INTERNAL"; "10.10.0.0/22"; "clinical applications and databases"; "monitored, no additional restriction"),
  zone("MGMT"; "10.10.20.0/24"; "administration and internal DNS resolver"; "no additional restriction"),
  zone("MEDDEV"; "10.10.4.0/24"; "medical device VLAN (DICOM/PACS, EHR display)"; "accept only to INTERNAL and MGMT, never to DMZ or the Internet")
] as $zones
|
[
  flow("MGMT"; "INTERNAL"; "tcp"; 22; "administration"; null; null),
  flow("MGMT"; "DMZ"; "tcp"; 22; "administration"; null; null),
  flow("MGMT"; "MEDDEV"; "tcp"; 22; "administration of medical device hosts"; null; null),
  flow("MGMT"; "MEDDEV"; "tcp"; 4242; "DICOM administration/config push"; null; null),

  flow("INTERNAL"; "INTERNAL"; "tcp"; 443; "clinical workstations to internal EHR/web app tier"; null; ["10.10.2.0/24"]),
  flow("INTERNAL"; "INTERNAL"; "tcp"; 3306; "clinical workstations to internal database tier"; null; ["10.10.2.0/24"]),

  flow("DMZ"; "INTERNAL"; "tcp"; 3306; "DICOM imaging to PACS"; null; ["10.10.10.11"]),

  flow("MEDDEV"; "INTERNAL"; "tcp"; 4242; "DICOM imaging to PACS"; null; null),
  flow("MEDDEV"; "INTERNAL"; "tcp"; 443; "EHR web integration for device display"; null; null),

  flow("DMZ"; "MGMT"; "udp"; 53; "DNS resolution"; null; null),
  flow("DMZ"; "MGMT"; "tcp"; 53; "DNS resolution (zone transfer / large replies)"; null; null),
  flow("INTERNAL"; "MGMT"; "udp"; 53; "DNS resolution"; null; null),
  flow("INTERNAL"; "MGMT"; "tcp"; 53; "DNS resolution (zone transfer / large replies)"; null; null),
  flow("MEDDEV"; "MGMT"; "udp"; 53; "DNS resolution"; null; null),
  flow("MEDDEV"; "MGMT"; "tcp"; 53; "DNS resolution (zone transfer / large replies)"; null; null)
] as $flows
|
# Explicit deny_all for every cross-zone pair that has no allow flow above -
# MEDDEV to DMZ and to the Internet, and everything into MEDDEV except MGMT.
[
  deny("DMZ"; "MEDDEV"),
  deny("INTERNAL"; "DMZ"),
  deny("INTERNAL"; "MEDDEV"),
  deny("MEDDEV"; "DMZ")
] as $denies
|
{
  zones: $zones,
  flows: $flows,
  deny_rules: $denies,
  summary: {
    flow_count: ($flows | length),
    allow_count: ($flows | length),
    deny_count: ($denies | length),
    cross_zone_pairs: (
      [$zones[].name] as $names
      | [$names[] as $s | $names[] as $d | select($s != $d) | {src: $s, dst: $d}]
      | length
    )
  }
}
' > "$OUT_JSON"

# --- Human-readable summary --------------------------------------------------
echo "Zones: $(jq '.zones | length' "$OUT_JSON")"
echo "Allow flows: $(jq '.summary.allow_count' "$OUT_JSON")   Deny rules: $(jq '.summary.deny_count' "$OUT_JSON")"
echo "Cross-zone pairs: $(jq '.summary.cross_zone_pairs' "$OUT_JSON")"
echo "Report saved to: $OUT_JSON"
