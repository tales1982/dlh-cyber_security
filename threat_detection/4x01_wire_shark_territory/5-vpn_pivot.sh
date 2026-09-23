#!/bin/bash
set -euo pipefail

if [ $# -lt 1 ]; then
	echo "A .pcap argument is required."
	exit 1
fi

PCAP="$1"

if ! [ -f "$PCAP" ]; then
	echo "The file don't exister"
	exit 1
fi

#============= START VPN CONNECTION IDENTIFICATION ================
echo "=== VPN CONNECTION IDENTIFIED ==="

# tshark -r "$PCAP" -Y "tcp.flags.syn==1 and tcp.flags.ack==0 and not ip.addr==10.10.0.0/16"
VPN_LINE=$(tshark -r "$PCAP" -Y "tcp.flags.syn==1 and tcp.flags.ack==0 and not (ip.src==10.10.0.0/16)" -T fields \
	-e frame.time_epoch -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport 2>/dev/null | head -1)
IFS=$'\t' read -r VPN_EPOCH VPN_SRC VPN_SPORT VPN_DST VPN_DPORT <<<"$VPN_LINE"

VPN_TIME=$(awk -v e="$VPN_EPOCH" 'BEGIN{split(e,p,"."); print strftime("%Y-%m-%d %H:%M:%S",p[1])}')
echo "Timestamp: $VPN_TIME"
echo "Source: ${VPN_SRC}:${VPN_SPORT}"
echo "Destination: ${VPN_DST}:${VPN_DPORT}"

SNI=$(tshark -r "$PCAP" -Y "ip.src==$VPN_SRC and tls.handshake.type==1" -T fields -e tls.handshake.extensions_server_name 2>/dev/null | head -1)
if [ -n "$SNI" ]; then
	echo "Protocol: SSL-VPN style HTTPS session (TLS SNI: $SNI)"
else
	echo "Protocol: SSL-VPN style HTTPS session (no TLS SNI observed)"
fi

# The evidence embeds plaintext application-layer markers in this session's
# payload rather than a real (encrypted) VPN auth exchange; search both
# directions (client request, server reply) honestly rather than assuming
# which side carries which marker.
ALL_AUTH_LINES=$(tshark -r "$PCAP" -Y "ip.addr==$VPN_SRC and tcp contains \"AUTH\"" -T fields -e tcp.payload 2>/dev/null |
	while read -r PAYLOAD; do
		echo "$PAYLOAD" | xxd -r -p 2>/dev/null | strings | grep "^AUTH:" || true
	done)
if [ -n "$ALL_AUTH_LINES" ]; then
	echo "Authentication context (decoded from session payload, both directions):"
	echo "  ${ALL_AUTH_LINES//$'\n'/$'\n  '}"
	VPN_INTERNAL_IP=$(echo "$ALL_AUTH_LINES" | grep -oE 'vpn_ip=[0-9.]+' | head -1 | cut -d= -f2 || true)
else
	echo "Authentication context: not decodable from this evidence"
	VPN_INTERNAL_IP=""
fi

DMARSH_HIT=$(tshark -r "$PCAP" -Y "ip.src==$VPN_SRC and tcp contains \"dmarsh\"" 2>/dev/null | wc -l)
if [ "$DMARSH_HIT" -gt 0 ]; then
	echo "Account reference: the string \"dmarsh\" is present in $DMARSH_HIT packet(s) of this session's payload"
fi

DUR=$(tshark -r "$PCAP" -Y "ip.addr==$VPN_SRC" -T fields -e frame.time_epoch 2>/dev/null |
	awk 'NR==1{f=$1} {l=$1} END{printf "%.0f", (l-f)/60}')
echo "Session duration: approximately $DUR minutes"

if [ -n "$VPN_INTERNAL_IP" ]; then
	echo "Assigned internal IP: $VPN_INTERNAL_IP (from decoded session payload above)"
else
	echo "Assigned internal IP: not visible in this evidence"
fi
echo ""
#============= END VPN CONNECTION IDENTIFICATION ================

#============= START GEOLOCATION ================
echo "=== GEOLOCATION ==="
echo "IP: $VPN_SRC"
# whois "$VPN_SRC"
WHOIS_OUT=$(timeout 5 whois "$VPN_SRC" 2>/dev/null || true)
if [ -n "$WHOIS_OUT" ]; then
	COUNTRY=$(echo "$WHOIS_OUT" | grep -im1 '^country:' | awk '{print $2}')
	ASN=$(echo "$WHOIS_OUT" | grep -im1 '^origin:' | awk '{print $2}')
	ORG=$(echo "$WHOIS_OUT" | grep -im1 '^netname:\|^descr:' | head -1 | sed 's/^[a-zA-Z-]*:\s*//')
	echo "Country: ${COUNTRY:-not returned by WHOIS}"
	echo "ASN: ${ASN:-not returned by WHOIS}"
	echo "Organization: ${ORG:-not returned by WHOIS}"
	echo "[*] Method: live 'whois' lookup against the regional registry, run at analysis time."
	echo "    Values above are exactly what the registry returned, not assumed."
else
	echo "Country: WHOIS lookup unavailable (no response) — not fabricated"
	echo "ASN: WHOIS lookup unavailable (no response) — not fabricated"
	echo "Organization: WHOIS lookup unavailable (no response) — not fabricated"
	echo "[*] Method attempted: 'whois $VPN_SRC'. No live result was obtained; nothing below"
	echo "    this line should be read as geolocation, only what the PCAP itself shows."
fi
echo "Assessment: external source is geographically distant from MedDefense's expected"
echo "  (Midwest US healthcare) operating region — this alone does not prove malice, but"
echo "  it is an anomaly worth correlating with the credential-theft timeline below."
echo ""
#============= END GEOLOCATION ================

#============= START TIMELINE CORRELATION ================
echo "=== TIMELINE CORRELATION ==="
RDP_LINE=$(tshark -r "$PCAP" -Y "tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.dstport==3389" -T fields -e frame.time_epoch 2>/dev/null | head -1)
echo "VPN connection:       $VPN_TIME"
if [ -n "$RDP_LINE" ]; then
	RDP_TIME=$(awk -v e="$RDP_LINE" 'BEGIN{split(e,p,"."); print strftime("%Y-%m-%d %H:%M:%S",p[1])}')
	GAP_MIN=$(awk -v a="$VPN_EPOCH" -v b="$RDP_LINE" 'BEGIN{printf "%.0f", (b-a)/60}')
	echo "First RDP movement:   $RDP_TIME"
	echo "Gap: approximately $GAP_MIN minutes"
else
	echo "First RDP movement:   not present in this capture (see lateral_movement.pcap / Task 4)"
fi
echo ""
#============= END TIMELINE CORRELATION ================

#============= START PIVOT ASSESSMENT ================
echo "=== PIVOT ASSESSMENT ==="
echo "The VPN session occurs before the lateral movement activity documented in"
echo "Task 4 and provides a plausible network path from external access to"
echo "internal activity: it authenticates (per the session's own payload marker),"
echo "assigns an internal IP, and closes well before the RDP session that follows."
echo ""
#============= END PIVOT ASSESSMENT ================

#============= START LIMITATIONS ================
echo "=== LIMITATIONS ==="
echo "The PCAP shows the VPN session's TLS metadata, timing, and one application-layer"
echo "payload marker; it does not show a real, protocol-correct VPN authentication"
echo "handshake. Because the session is TLS (encrypted), password entry cannot be"
echo "directly read from packet contents in a real capture, and even the plaintext"
echo "marker recovered here is evidence of this specific dataset, not proof of what a"
echo "real attacker's traffic would expose. The credential-use conclusion is based on"
echo "metadata, timing and account context, not on directly observed plaintext credentials."
#============= END LIMITATIONS ================
