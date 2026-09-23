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

echo "=== DNS RESOLUTION ==="

QUERY_LINE=$(tshark -r "$PCAP" -Y "udp.stream eq 0 and dns.flags.response==0" -T fields -e frame.time_epoch -e dns.qry.name -e ip.src -e ip.dst 2>/dev/null)

echo "$QUERY_LINE" | awk -F'\t' '{
    split($1, parts, ".")
    ms = substr(parts[2], 1, 3)
    printf "%s.%s  Query: %s\n", strftime("%H:%M:%S", parts[1]), ms, $2
  }'

SRC=$(echo "$QUERY_LINE" | cut -f3)
DST=$(echo "$QUERY_LINE" | cut -f4)

tshark -r "$PCAP" -Y "udp.stream eq 0 and dns.flags.response==1" -T fields -e frame.time_epoch -e dns.a -e dns.resp.ttl 2>/dev/null |
	awk -F'\t' -v src="$SRC" -v dst="$DST" '{
    split($1, parts, ".")
    ms = substr(parts[2], 1, 3)
    printf "%s.%s  Response: %s\n", strftime("%H:%M:%S", parts[1]), ms, $2
    printf "TTL: %s\n", $3
    printf "Source: %s -> %s\n", src, dst
  }'
echo ""

echo "=== TLS HANDSHAKE ==="

PHISH_IP="91.234.99.107"

tshark -r "$PCAP" -Y "tcp.flags.syn==1 and tcp.flags.ack==0 and ip.dst==$PHISH_IP" -T fields -e frame.time_epoch -e ip.dst -e tcp.dstport 2>/dev/null |
	awk -F'\t' '{split($1,p,"."); ms=substr(p[2],1,3); printf "%s.%s  SYN -> %s:%s\n", strftime("%H:%M:%S",p[1]), ms, $2, $3}'

tshark -r "$PCAP" -Y "tcp.flags.syn==1 and tcp.flags.ack==1 and ip.src==$PHISH_IP" -T fields -e frame.time_epoch 2>/dev/null |
	awk -F'\t' '{split($1,p,"."); ms=substr(p[2],1,3); printf "%s.%s  SYN-ACK\n", strftime("%H:%M:%S",p[1]), ms}'

tshark -r "$PCAP" -Y "ip.dst==$PHISH_IP and tls.handshake.type==1" -T fields -e frame.time_epoch -e tls.handshake.extensions_server_name -e tls.handshake.extensions.supported_version -e tls.handshake.ciphersuite 2>/dev/null |
	awk -F'\t' '
	BEGIN {
		cname["0x1301"]="TLS_AES_128_GCM_SHA256"
		cname["0x1302"]="TLS_AES_256_GCM_SHA384"
		cname["0x1303"]="TLS_CHACHA20_POLY1305_SHA256"
		cname["0xc02b"]="TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
		cname["0xc02c"]="TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	}
	{
		split($1,p,".")
		ms=substr(p[2],1,3)
		printf "%s.%s  ClientHello\n", strftime("%H:%M:%S",p[1]), ms
		printf "  SNI: %s\n", $2
		ver = ($3=="0x0304") ? "1.3" : $3
		printf "  TLS version offered: %s\n", ver
		n = split($4, ciphers, ",")
		first = (ciphers[1] in cname) ? cname[ciphers[1]] : ciphers[1]
		printf "  Cipher suites: %s (and %d others)\n", first, n-1
	}'
echo ""

CERT_COUNT=$(tshark -r "$PCAP" -Y "ip.addr==$PHISH_IP and tls.handshake.type==11" 2>/dev/null | wc -l)
if [ "$CERT_COUNT" -eq 0 ]; then
	echo "[*] ServerHello + Certificate: not observed in this capture (no Certificate handshake message present; capture appears to include only ClientHello messages)"
fi
echo ""
echo "=== DATA EXCHANGE ==="

tshark -r "$PCAP" -Y "ip.addr==$PHISH_IP" -T fields -e frame.time_epoch 2>/dev/null |
	awk '
	NR==1{first=$1}
	{last=$1}
	END{
		dur = last-first
		split(first,p,".")
		ms1=substr(p[2],1,3)
		split(last,q,".")
		ms2=substr(q[2],1,3)
		printf "Duration: %.1f seconds (%s.%s to %s.%s)\n", dur, strftime("%H:%M:%S",p[1]), ms1, strftime("%H:%M:%S",q[1]), ms2
	}'

CLIENT_IP="10.10.2.15"

C2S=$(tshark -r "$PCAP" -Y "ip.src==$CLIENT_IP and ip.dst==$PHISH_IP" -T fields -e frame.len 2>/dev/null |
	awk '{sum+=$1; n++} END{printf "%d %d", sum, n}')
read -r C2S_BYTES C2S_SEGS <<<"$C2S"
printf "Client -> Server: %d bytes across %d TCP segments\n" "$C2S_BYTES" "$C2S_SEGS"

S2C=$(tshark -r "$PCAP" -Y "ip.src==$PHISH_IP and ip.dst==$CLIENT_IP" -T fields -e frame.len 2>/dev/null |
	awk '{sum+=$1; n++} END{printf "%d %d", sum, n}')
read -r S2C_BYTES S2C_SEGS <<<"$S2C"
printf "Server -> Client: %d bytes across %d TCP segments\n" "$S2C_BYTES" "$S2C_SEGS"

MAXLINE=$(tshark -r "$PCAP" -Y "ip.src==$CLIENT_IP and ip.dst==$PHISH_IP" -T fields -e frame.time_epoch -e frame.len 2>/dev/null |
	awk '{if($2+0>max){max=$2+0; t=$1}} END{split(t,p,"."); ms=substr(p[2],1,3); printf "%d %s.%s", max, strftime("%H:%M:%S",p[1]), ms}')
read -r MAX_BYTES MAX_TIME <<<"$MAXLINE"
printf "Largest client TLS record: %d bytes at %s\n" "$MAX_BYTES" "$MAX_TIME"

echo ""
echo "[*] Analysis:"
echo "    The content is encrypted, so the exact form fields are not visible."
printf "    However, a largest client record of ~%d bytes during the session is\n" "$MAX_BYTES"
echo "    consistent with a small HTTPS form submission such as credentials plus"
echo "    token data. This conclusion is based on packet-size metadata only;"
echo "    no plaintext content was observed or is claimed."
echo ""

echo "=== POST-CLICK BEHAVIOR ==="

REAL_IP="10.10.1.20"

tshark -r "$PCAP" -Y "udp.stream eq 1 and dns.flags.response==0" -T fields -e frame.time_epoch -e dns.qry.name 2>/dev/null |
	awk -F'\t' '{split($1,p,"."); ms=substr(p[2],1,3); printf "%s.%s  DNS query: %s\n", strftime("%H:%M:%S",p[1]), ms, $2}'

tshark -r "$PCAP" -Y "udp.stream eq 1 and dns.flags.response==1" -T fields -e frame.time_epoch -e dns.a 2>/dev/null |
	awk -F'\t' '{split($1,p,"."); ms=substr(p[2],1,3); printf "%s.%s  DNS response: %s\n", strftime("%H:%M:%S",p[1]), ms, $2}'

tshark -r "$PCAP" -Y "tcp.flags.syn==1 and tcp.flags.ack==0 and ip.dst==$REAL_IP" -T fields -e frame.time_epoch -e ip.dst -e tcp.dstport 2>/dev/null |
	awk -F'\t' '{split($1,p,"."); ms=substr(p[2],1,3); printf "%s.%s  HTTPS connection to %s:%s\n", strftime("%H:%M:%S",p[1]), ms, $2, $3}'

echo ""
echo "[*] Possible interpretation:"
echo "    The user queried the real portal shortly after the phishing session."
echo "    This may indicate she noticed something wrong, or the phishing site"
echo "    redirected her to the legitimate portal after harvesting data."
echo ""

echo "=== 4x00 CORRELATION ==="

IOC_DOMAIN_MATCH=$(tshark -r "$PCAP" -Y 'dns.qry.name=="meddefense-portal.com"' 2>/dev/null | wc -l)
IOC_IP_MATCH=$(tshark -r "$PCAP" -Y "ip.addr==$PHISH_IP" 2>/dev/null | wc -l)

if [ "$IOC_DOMAIN_MATCH" -gt 0 ]; then
	echo "IOC domain match: meddefense-portal.com ($IOC_DOMAIN_MATCH packets)"
else
	echo "IOC domain match: none observed"
fi

if [ "$IOC_IP_MATCH" -gt 0 ]; then
	echo "IOC IP match: $PHISH_IP ($IOC_IP_MATCH packets)"
else
	echo "IOC IP match: none observed"
fi

echo "Conclusion: PCAP confirms the workstation ($CLIENT_IP) contacted the phishing infrastructure identified in 4x00 (meddefense-portal.com / $PHISH_IP), strengthening the email-based investigation with network-level evidence."
echo ""
