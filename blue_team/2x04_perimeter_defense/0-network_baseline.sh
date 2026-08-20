#!/bin/bash
#
# 0-network_baseline.sh
#
# MedDefense Health Systems - Perimeter and Network Defense (2x04)
#
# Mike Torres's opinion ("the network is flat") is not evidence. This script
# is: it answers, from the host's own interfaces, where packets go, who is
# listening, who is already talking and how DNS is resolved. Every firewall
# rule written in this project has to be justified against this baseline.
#
# Read-only. This script makes no configuration changes to the system.
#
# Usage: sudo ./0-network_baseline.sh [output.json]

set -uo pipefail

OUT_JSON="${1:-network_baseline.json}"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
HOSTNAME_VAL="$(hostname)"

# --- Interfaces --------------------------------------------------------
# Enumerate active network interfaces with `ip -j addr show` and retain
# name, MAC address, link state and all assigned addresses.
INTERFACES_JSON="$(ip -j addr show 2>/dev/null | jq '
    map({
      name: .ifname,
      mac: (.address // "00:00:00:00:00:00"),
      link_state: .operstate,
      addresses: [(.addr_info // [])[] | {family, address: .local, prefixlen}]
    })
' 2>/dev/null)"
[ -z "$INTERFACES_JSON" ] && INTERFACES_JSON="[]"

# --- Routes --------------------------------------------------------------
# Capture the routing table with `ip -j route show`, including the default
# gateway.
ROUTES_JSON="$(ip -j route show 2>/dev/null | jq '
    map({
      dst: (.dst // "default"),
      gateway: (.gateway // null),
      dev: .dev,
      protocol: (.protocol // null),
      scope: (.scope // null)
    })
' 2>/dev/null)"
[ -z "$ROUTES_JSON" ] && ROUTES_JSON="[]"

# --- ARP / neighbor table -------------------------------------------------
# Capture the ARP neighbors table with `ip -j neigh show` and retain IP,
# MAC and state.
NEIGHBORS_JSON="$(ip -j neigh show 2>/dev/null | jq '
    map({ip: .dst, mac: (.lladdr // null), state: ((.state // ["UNKNOWN"]) | join(","))})
' 2>/dev/null)"
[ -z "$NEIGHBORS_JSON" ] && NEIGHBORS_JSON="[]"

# --- Listening sockets (ss has no -j on this iproute2 build - text parse) --
# Enumerate listening TCP and UDP sockets with `ss -tulnpH` and resolve
# each socket to its owning process and PID.
# Columns for `ss -tulnpH`: Netid State Recv-Q Send-Q Local:Port Peer:Port Process
parse_listening() {
    ss -tulnpH 2>/dev/null | while read -r netid _state _recvq _sendq local peer proc_rest; do
        [ -z "$netid" ] && continue
        # Last colon splits address from port for both IPv4 and bracketed IPv6.
        local_addr="${local%:*}"
        local_port="${local##*:}"
        proc_name="unknown"
        pid="null"
        if [[ "$proc_rest" =~ \(\(\"([^\"]+)\",pid=([0-9]+) ]]; then
            proc_name="${BASH_REMATCH[1]}"
            pid="${BASH_REMATCH[2]}"
        fi
        jq -nc --arg proto "$netid" --arg addr "$local_addr" --arg port "$local_port" \
            --arg proc "$proc_name" --argjson pid "$pid" \
            '{proto: $proto, bind_addr: $addr, port: ($port | if test("^[0-9]+$") then tonumber else $port end),
              process: $proc, pid: $pid}'
    done
}
LISTENING_JSON="$(parse_listening | jq -s '.')"
[ -z "$LISTENING_JSON" ] && LISTENING_JSON="[]"

# --- Established connections ------------------------------------------------
# Enumerate established outbound connections with `ss -tnpH state established`
# and resolve each connection to its owning process and PID.
# `ss -tnpH state established` omits Netid/State (implied tcp/ESTAB by the filter).
parse_established() {
    ss -tnpH state established 2>/dev/null | while read -r _recvq _sendq local peer proc_rest; do
        [ -z "$local" ] && continue
        local_addr="${local%:*}"; local_port="${local##*:}"
        peer_addr="${peer%:*}"; peer_port="${peer##*:}"
        proc_name="unknown"; pid="null"
        if [[ "$proc_rest" =~ \(\(\"([^\"]+)\",pid=([0-9]+) ]]; then
            proc_name="${BASH_REMATCH[1]}"
            pid="${BASH_REMATCH[2]}"
        fi
        jq -nc --arg la "$local_addr" --arg lp "$local_port" --arg pa "$peer_addr" --arg pp "$peer_port" \
            --arg proc "$proc_name" --argjson pid "$pid" \
            '{local_addr: $la, local_port: ($lp|tonumber? // $lp), peer_addr: $pa,
              peer_port: ($pp|tonumber? // $pp), process: $proc, pid: $pid}'
    done
}
ESTABLISHED_JSON="$(parse_established | jq -s '.')"
[ -z "$ESTABLISHED_JSON" ] && ESTABLISHED_JSON="[]"

# --- DNS resolvers -----------------------------------------------------
# Capture the DNS resolver configuration from /etc/resolv.conf and from
# `resolvectl status --no-pager` if systemd-resolved is active.
mapfile -t RESOLV_NS < <(grep -E '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}')
RESOLVCONF_JSON="$(printf '%s\n' "${RESOLV_NS[@]:-}" | jq -R . | jq -s 'map(select(length>0))')"

RESOLVED_JSON="null"
if command -v resolvectl >/dev/null 2>&1 && systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    RESOLVED_TEXT="$(resolvectl status --no-pager 2>/dev/null)"
    RESOLVED_JSON="$(jq -n --arg t "$RESOLVED_TEXT" '$t')"
fi

DNS_JSON="$(jq -n --argjson resolv_conf "$RESOLVCONF_JSON" --argjson resolved_status "$RESOLVED_JSON" \
    '{resolv_conf_nameservers: $resolv_conf, resolvectl_status: $resolved_status}')"

# --- Assemble -----------------------------------------------------------
jq -n \
    --arg ts "$TS" --arg hostname "$HOSTNAME_VAL" \
    --argjson interfaces "$INTERFACES_JSON" --argjson routes "$ROUTES_JSON" \
    --argjson neighbors "$NEIGHBORS_JSON" --argjson listening "$LISTENING_JSON" \
    --argjson established "$ESTABLISHED_JSON" --argjson dns "$DNS_JSON" \
    '{timestamp: $ts, hostname: $hostname, interfaces: $interfaces, routes: $routes,
      neighbors: $neighbors, listening_sockets: $listening,
      established_connections: $established, dns_resolvers: $dns}' > "$OUT_JSON"

# --- Human-readable summary --------------------------------------------------
UP_IFACES_JSON="$(jq -c '[.interfaces[] | select(.link_state=="UP") | .name]' "$OUT_JSON")"
LISTENER_COUNT="$(jq '.listening_sockets | length' "$OUT_JSON")"
echo "Hostname: $HOSTNAME_VAL"
echo "Up interfaces: $UP_IFACES_JSON"
echo "Listening sockets: $LISTENER_COUNT"
echo "Established connections: $(jq '.established_connections | length' "$OUT_JSON")"
echo "Baseline saved to: $OUT_JSON"
