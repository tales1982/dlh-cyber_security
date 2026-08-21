#!/bin/bash
#
# 11-pcap_investigation.sh
#
# MedDefense Health Systems - Perimeter and Network Defense (2x04)
#
# An alert is a pointer, not an investigation. This is what a Tier 2
# analyst does next: open the capture, extract the exact conversation,
# walk the protocol stack, characterize the activity. No signature, no
# ruleset - just bytes, via tshark.
#
# Usage: sudo ./11-pcap_investigation.sh [pcap]

set -uo pipefail

PCAP="${1:-/home/analyst/MedDefense_Lab/PCAPs/suspicious_session.pcap}"
OUT_JSON="pcap_findings.json"

if [ ! -f "$PCAP" ]; then
    echo "error: pcap not found: $PCAP" >&2
    exit 1
fi

echo "[*] PCAP: $PCAP"
STATS="$(capinfos -c -u "$PCAP" 2>/dev/null)"
PACKET_COUNT="$(echo "$STATS" | grep -oE 'Number of packets:\s*[0-9,]+' | grep -oE '[0-9,]+$' | tr -d ',')"
DURATION="$(echo "$STATS" | grep -oE 'Capture duration:\s*[0-9.]+' | grep -oE '[0-9.]+$')"
echo "[*] Duration: ${DURATION:-0} s     Packets: ${PACKET_COUNT:-0}"

# --- Conversation stats (TCP + UDP), top 10 by total bytes -----------------
parse_conv() {
    local proto="$1"
    tshark -q -z "conv,${proto}" -r "$PCAP" 2>/dev/null | awk -v proto="$proto" '
        $2 == "<->" {
            gsub(/[<>-]/, "", $2)
            printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", proto, $1, $3, $4, $5, $7, $8
        }
    '
}
build_conv_json() {
    local proto="$1"
    parse_conv "$proto" | while IFS=$'\t' read -r p a b fa ba fb bb; do
        [ -z "$a" ] && continue
        total_f=$((fa + fb)); total_b=$((ba + bb))
        jq -nc --arg proto "$p" --arg a "$a" --arg b "$b" \
            --argjson frames "$total_f" --argjson bytes "$total_b" \
            '{proto: $proto, a: $a, b: $b, frames: $frames, bytes: $bytes}'
    done | jq -s 'sort_by(-.bytes) | .[0:10]'
}
TCP_CONV_JSON="$(build_conv_json tcp)"
UDP_CONV_JSON="$(build_conv_json udp)"
echo "[*] Extracting TCP conversations...      ($(jq 'length' <<<"$TCP_CONV_JSON"))"
echo "[*] Extracting UDP conversations...      ($(jq 'length' <<<"$UDP_CONV_JSON"))"

# --- DNS queries -----------------------------------------------------------
DNS_JSON="$(tshark -Y 'dns.flags.response==0' -T fields -e frame.time_epoch -e ip.src -e dns.qry.name -e dns.qry.type -r "$PCAP" 2>/dev/null \
    | awk -F'\t' 'NF>=3 {printf "%s\t%s\t%s\t%s\n", $1, $2, $3, ($4==""?"unknown":$4)}' \
    | jq -R -s '
        split("\n") | map(select(length>0) | split("\t"))
        | map({time: .[0], src: .[1], query: .[2], qtype: .[3]})')"
[ "$DNS_JSON" = "null" ] || [ -z "$DNS_JSON" ] && DNS_JSON="[]"
echo "[*] Extracting DNS queries...            ($(jq 'length' <<<"$DNS_JSON"))"

# --- HTTP requests -----------------------------------------------------
HTTP_JSON="$(tshark -Y http.request -T fields -e frame.time_epoch -e ip.src -e ip.dst -e http.host -e http.request.method -e http.request.uri -r "$PCAP" 2>/dev/null \
    | jq -R -s '
        split("\n") | map(select(length>0) | split("\t"))
        | map({time: .[0], src: .[1], dst: .[2], host: (.[3] // ""), method: (.[4] // ""), uri: (.[5] // "")})')"
[ "$HTTP_JSON" = "null" ] || [ -z "$HTTP_JSON" ] && HTTP_JSON="[]"
echo "[*] Extracting HTTP requests...          ($(jq 'length' <<<"$HTTP_JSON"))"

# --- TLS SNI -----------------------------------------------------------
TLS_JSON="$(tshark -Y 'tls.handshake.type==1' -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tls.handshake.extensions_server_name -r "$PCAP" 2>/dev/null \
    | jq -R -s '
        split("\n") | map(select(length>0) | split("\t"))
        | map({time: .[0], src: .[1], dst: .[2], sni: (.[3] // "")})')"
[ "$TLS_JSON" = "null" ] || [ -z "$TLS_JSON" ] && TLS_JSON="[]"
echo "[*] Extracting TLS SNI...                ($(jq 'length' <<<"$TLS_JSON"))"

# --- File transfers ---------------------------------------------------
FILES_JSON="$(tshark -Y 'http.content_type or smb2.filename' -T fields -e frame.time_epoch -e ip.src -e ip.dst -e http.content_type -e smb2.filename -r "$PCAP" 2>/dev/null \
    | jq -R -s '
        split("\n") | map(select(length>0) | split("\t"))
        | map({time: .[0], src: .[1], dst: .[2], http_content_type: (.[3] // ""), smb_filename: (.[4] // "")})')"
[ "$FILES_JSON" = "null" ] || [ -z "$FILES_JSON" ] && FILES_JSON="[]"
echo "[*] Extracting file transfers...         ($(jq 'length' <<<"$FILES_JSON"))"

# --- Protocol distribution (direct children of "ip" in the phs tree) -------
PHS_RAW="$(tshark -q -z io,phs -r "$PCAP" 2>/dev/null)"
IP_TOTAL="$(echo "$PHS_RAW" | awk '/^  ip /{gsub(/frames:/,"",$2); print $2; exit}')"
PROTO_DIST_JSON="$(echo "$PHS_RAW" | awk '
    /^    [a-z0-9.]+ / && !/^      / {
        proto=$1; gsub(/frames:/,"",$2); print proto"\t"$2
    }' | jq -R -s --argjson total "${IP_TOTAL:-0}" '
        split("\n") | map(select(length>0) | split("\t"))
        | map({proto: .[0], frames: (.[1]|tonumber),
               pct: (if $total > 0 then (((.[1]|tonumber) / $total * 1000 | round) / 10) else 0 end)})')"
[ "$PROTO_DIST_JSON" = "null" ] || [ -z "$PROTO_DIST_JSON" ] && PROTO_DIST_JSON="[]"
PHS_SUMMARY="$(jq -r 'map("\(.proto) \(.pct)%") | join(", ")' <<<"$PROTO_DIST_JSON")"
echo "[*] Protocol distribution...             ($PHS_SUMMARY)"

# --- Assemble -----------------------------------------------------------
jq -n \
    --arg pcap "$PCAP" --argjson duration "${DURATION:-0}" --argjson packets "${PACKET_COUNT:-0}" \
    --argjson tcp_conversations "$TCP_CONV_JSON" --argjson udp_conversations "$UDP_CONV_JSON" \
    --argjson dns_queries "$DNS_JSON" --argjson http_requests "$HTTP_JSON" \
    --argjson tls_sni "$TLS_JSON" --argjson file_transfers "$FILES_JSON" \
    --argjson protocol_distribution "$PROTO_DIST_JSON" \
    '{pcap: $pcap, duration_seconds: $duration, packet_count: $packets,
      tcp_conversations: $tcp_conversations, udp_conversations: $udp_conversations,
      dns_queries: $dns_queries, http_requests: $http_requests, tls_sni: $tls_sni,
      file_transfers: $file_transfers, protocol_distribution: $protocol_distribution}' > "$OUT_JSON"

# --- Stdout summary ------------------------------------------------------
echo "Top conversations:"
jq -r '(.tcp_conversations + .udp_conversations) | sort_by(-.bytes) | .[0:5] | .[]
    | "  \(.a) <-> \(.b)  \(.proto)  \(.frames) pkts  \(.bytes) bytes"' "$OUT_JSON"

echo "Long DNS labels (> 50 chars):"
LONG_LABELS="$(jq -r '.dns_queries[] | .query | select((split(".")[0] | length) > 50)' "$OUT_JSON")"
if [ -n "$LONG_LABELS" ]; then
    while IFS= read -r q; do
        label_len="$(echo "$q" | cut -d. -f1 | wc -c)"
        echo "  $q  ($((label_len - 1)) chars)"
    done <<<"$LONG_LABELS"
else
    echo "  (none)"
fi

echo "Report saved to: $OUT_JSON"
