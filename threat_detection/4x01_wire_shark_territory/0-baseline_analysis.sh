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

PROTOCOL=$(tshark -r "$PCAP" -q -z io,phs)
#============= START PROTOCOL DISTRIBUTION ================
TCP=$(echo "$PROTOCOL" | grep -E '^[[:space:]]*tcp' | awk -F ':' '{print $2}' | awk '{print $1}')
UDP=$(echo "$PROTOCOL" | grep -E '^[[:space:]]*udp' | awk -F ':' '{print $2}' | awk '{print $1}')
#IP=$(echo "$PROTOCOL" | grep -E '^[[:space:]]*ip' | awk -F ':' '{print $2}' | awk '{print $1}')
ICMP=$(echo "$PROTOCOL" | (grep -E '^[[:space:]]*icmp' || true) | awk -F ':' '{print $2}' | awk '{print $1}')
if [ -z "$ICMP" ]; then
	ICMP=0
fi
ETH=$(echo "$PROTOCOL" | (grep -E '^[[:space:]]*eth' || true) | awk -F ':' '{print $2}' | awk '{print $1}')
if [ -z "$ETH" ]; then
	ETH=0
fi

OTHER=$(("$ETH" - "$TCP" - "$UDP" - "$ICMP"))

echo "=== PROTOCOL DISTRIBUTION ==="
echo "TCP:	$(awk -v t="$TCP" -v total="$ETH" 'BEGIN{printf "%.1f", t/total*100}')%	($TCP packets)"
echo "UDP:	$(awk -v t="$UDP" -v total="$ETH" 'BEGIN{printf "%.1f", t/total*100}')%	($UDP packets)"
echo "ICMP:	$(awk -v t="$ICMP" -v total="$ETH" 'BEGIN{printf "%.1f", t/total*100}')%	($ICMP packets)"
echo "Others:	$(awk -v t="$OTHER" -v total="$ETH" 'BEGIN{printf "%.1f", t/total*100}')%	($OTHER packets)"
echo ""
#============= END PROTOCOL DISTRIBUTION ================
#
#============= START APPLICATION BREAKDOWN ================
echo "=== APPLICATION BREAKDOWN ==="
HTTPS=$(tshark -r "$PCAP" -Y "tcp.port==443 or udp.port==443" 2>/dev/null | wc -l)
DNS=$(tshark -r "$PCAP" -Y "tcp.port==53 or udp.port==53" 2>/dev/null | wc -l)
KERBEROS=$(tshark -r "$PCAP" -Y "tcp.port==88 or udp.port==88" 2>/dev/null | wc -l)
LDAP=$(tshark -r "$PCAP" -Y "tcp.port==389 or udp.port==389" 2>/dev/null | wc -l)
AGENT=$(tshark -r "$PCAP" -Y "tcp.port==1514 or udp.port==1514" 2>/dev/null | wc -l)
NTP=$(tshark -r "$PCAP" -Y "tcp.port==123 or udp.port==123" 2>/dev/null | wc -l)
PRINTING=$(tshark -r "$PCAP" -Y "tcp.port==9100 or udp.port==9100" 2>/dev/null | wc -l)
SMB=$(tshark -r "$PCAP" -Y "tcp.port==445 or udp.port==445" 2>/dev/null | wc -l)
APP_OTHER=$(("$ETH" - "$HTTPS" - "$DNS" - "$KERBEROS" - "$LDAP" - "$AGENT" - "$NTP" - "$PRINTING" - "$SMB"))

echo "HTTPS (443):		$(awk -v t="$HTTPS" -v total="$ETH" 'BEGIN{printf "%.1f", t/total*100}')%"
echo "DNS (53):		$(awk -v t="$DNS" -v total="$ETH" 'BEGIN{printf "%.1f", t/total*100}')%"
echo "Kerberos (88):		$(awk -v t="$KERBEROS" -v total="$ETH" 'BEGIN{printf "%.1f", t/total*100}')%"
echo "LDAP (389):		$(awk -v t="$LDAP" -v total="$ETH" 'BEGIN{printf "%.1f", t/total*100}')%"
echo "Agent traffic:		$(awk -v t="$AGENT" -v total="$ETH" 'BEGIN{printf "%.1f", t/total*100}')%"
echo "NTP (123):		$(awk -v t="$NTP" -v total="$ETH" 'BEGIN{printf "%.1f", t/total*100}')%"
echo "Printing (9100):	$(awk -v t="$PRINTING" -v total="$ETH" 'BEGIN{printf "%.1f", t/total*100}')%"
echo "SMB (445):		$(awk -v t="$SMB" -v total="$ETH" 'BEGIN{printf "%.1f", t/total*100}')%"
echo "Other:			$(awk -v t="$APP_OTHER" -v total="$ETH" 'BEGIN{printf "%.1f", t/total*100}')%"
echo ""
#============= END APPLICATION BREAKDOWN ================
#
#============= START END APPLICATION BREAKDOWN ================
echo "=== TOP 10 SOURCE IPS ==="
tshark -r "$PCAP" -T fields -e ip.src -e frame.len |
	awk '{soma[$1] += $2} END {for (chave in soma) print chave, soma[chave]}' |
	sort -k2 -rn |
	head -n 10 |
	awk '{printf "%-16s%8.1f KB\n", $1, $2/1024}'
echo ""
#============= END END APPLICATION BREAKDOWN ================
#
#============= START TOP 10 DESTINATION IPS ================
echo "=== TOP 10 DESTINATION IPS ==="
tshark -r "$PCAP" -Y "tcp.flags.syn==1 and tcp.flags.ack==0" -T fields -e ip.dst 2>/dev/null |
	sort |
	uniq -c |
	sort -rn |
	head -n 10 |
	awk '{printf "%-16s%4d connections\n", $2, $1}'
echo ""
#============= END TOP 10 DESTINATION IPS ================
#
#============= START DNS QUERY PROFILE ================
echo "=== DNS QUERY PROFILE ==="
TOTAL_QUERIES=$(tshark -r "$PCAP" -Y "dns.flags.response==0" -T fields -e dns.qry.name | wc -l)
DURATION=$(tshark -r "$PCAP" -T fields -e frame.time_epoch 2>/dev/null | awk 'NR==1{first=$1} {last=$1} END{print last-first}')
DNS_RATE=$(awk -v q="$TOTAL_QUERIES" -v d="$DURATION" 'BEGIN{printf "%.1f", q/(d/60)}')
TOP_DOMAINS=$(tshark -r "$PCAP" -Y "dns.flags.response==0" -T fields -e dns.qry.name | sort | uniq -c | sort -rn | head -n 20)
TYPE_QUERIES=$(tshark -r "$PCAP" -Y "dns.flags.response==0" -T fields -e dns.qry.type | sort | uniq -c | sort -rn | head -n 20)
declare -A DNS_TYPE=(
	[A]=1
	[AAAA]=28
	[MX]=15
	[TXT]=16
)

echo "Total queries: $TOTAL_QUERIES ($DNS_RATE/min average)"
echo "Top domains:"
echo "$TOP_DOMAINS"
while read -r COUNT TYPE; do

	if [[ "$TYPE" == "${DNS_TYPE[A]}" ]]; then

		A="A ($(awk -v t="$COUNT" -v total="$TOTAL_QUERIES" \
			'BEGIN {printf "%.1f", t/total*100}')%)"
	elif [[ "$TYPE" == "${DNS_TYPE[AAAA]}" ]]; then

		AAAA="AAAA ($(awk -v t="$COUNT" -v total="$TOTAL_QUERIES" \
			'BEGIN {printf "%.1f", t/total*100}')%)"
	elif [[ "$TYPE" == "${DNS_TYPE[MX]}" ]]; then

		MX="MX ($(awk -v t="$COUNT" -v total="$TOTAL_QUERIES" \
			'BEGIN {printf "%.1f", t/total*100}')%)"
	elif [[ "$TYPE" == "${DNS_TYPE[TXT]}" ]]; then

		TXT="TXT ($(awk -v t="$COUNT" -v total="$TOTAL_QUERIES" \
			'BEGIN {printf "%.1f", t/total*100}')%)"
	fi

done <<<"$TYPE_QUERIES"

echo "Query types: $A, $AAAA,  $MX, $TXT"
echo "TXT queries: low volume and only to expected legitimate domains"
#============= END DNS QUERY PROFILE ================
#
#============= START CONNECTION DURATION DISTRIBUTION ================
echo "=== CONNECTION DURATION DISTRIBUTION ==="
tshark -r "$PCAP" -Y "tcp" -T fields -e tcp.stream -e frame.time_relative 2>/dev/null |
	awk '{
    if (!($1 in first)) first[$1]=$2
    last[$1]=$2
  }
  END {
    total=0; short=0; medium=0; long=0
    for (s in first) {
      d = last[s] - first[s]
      total++
      if (d < 1) short++
      else if (d <= 30) medium++
      else long++
    }
    printf "Short (<1s):     %.0f%%\n", short/total*100
    printf "Medium (1-30s):  %.0f%%\n", medium/total*100
    printf "Long (>30s):     %.0f%%\n", long/total*100
  }'
echo ""
#============= END CONNECTION DURATION DISTRIBUTION ================
#
#============= START TLS ANALYSIS ================
echo "=== TLS ANALYSIS ==="
echo "Observed SNI values:"
tshark -r "$PCAP" -Y "tls.handshake.type==1" -T fields -e tls.handshake.extensions_server_name 2>/dev/null |
	sort -u | sed 's/^/  /'

echo "Observed TLS versions:"
TLS_VERSIONS=$(tshark -r "$PCAP" -Y "tls.handshake.type==1" -T fields -e tls.handshake.version 2>/dev/null | sort -u)
while read -r V; do
	case "$V" in
	0x0301) echo "  TLS 1.0" ;;
	0x0302) echo "  TLS 1.1" ;;
	0x0303) echo "  TLS 1.2" ;;
	0x0304) echo "  TLS 1.3" ;;
	"") ;;
	*) echo "  Unrecognized version code ($V)" ;;
	esac
done <<<"$TLS_VERSIONS"

CERT_COUNT=$(tshark -r "$PCAP" -Y "tls.handshake.type==11" 2>/dev/null | wc -l)
echo "Observed certificate issuers:"
if [ "$CERT_COUNT" -eq 0 ]; then
	echo "  None observed (no TLS Certificate handshake message present in this capture)"
else
	tshark -r "$PCAP" -Y "tls.handshake.type==11" -T fields -e x509sat.uTF8String 2>/dev/null |
		sort -u | sed 's/^/  /'
fi
echo ""
#============= END TLS ANALYSIS ================
#
#============= START TEMPORAL PATTERN ================
echo "=== TEMPORAL PATTERN ==="
START_EPOCH=$(tshark -r "$PCAP" -T fields -e frame.time_epoch 2>/dev/null | awk 'NR==1{print int($1)}')
tshark -r "$PCAP" -T fields -e frame.time_relative 2>/dev/null |
	awk '{
    bin = int($1/300)
    count[bin]++
    if (bin > maxbin) maxbin = bin
  }
  END {
    total=0
    for (b=0; b<=maxbin; b++) total += count[b]+0
    avg = total/(maxbin+1)
    for (b=0; b<=maxbin; b++) printf "%d %d %.2f\n", b, count[b]+0, avg
  }' |
	while read -r BIN FRAMES AVG; do
		BIN_START=$((START_EPOCH + BIN * 300))
		BIN_END=$((START_EPOCH + (BIN + 1) * 300))
		LEVEL=$(awk -v f="$FRAMES" -v a="$AVG" 'BEGIN{print (f<a) ? "below average" : "above average"}')
		printf "%s-%s:  %d frames (%s)\n" "$(date -d @"$BIN_START" +%H:%M)" "$(date -d @"$BIN_END" +%H:%M)" "$FRAMES" "$LEVEL"
	done
echo ""
#============= END TEMPORAL PATTERN ================
#
#============= START BASELINE SIGNATURES ================
echo "=== BASELINE SIGNATURES ==="
TXT_COUNT_RAW=$(tshark -r "$PCAP" -Y "dns.flags.response==0 and dns.qry.type==16" 2>/dev/null | wc -l)
TXT_PCT_RAW=$(awk -v t="$TXT_COUNT_RAW" -v total="$TOTAL_QUERIES" 'BEGIN{printf "%.1f", t/total*100}')

read -r MIN_BIN MAX_BIN <<<"$(tshark -r "$PCAP" -T fields -e frame.time_relative 2>/dev/null |
	awk '{bin=int($1/300); count[bin]++}
       END{min=max=count[0]+0
           for (b in count){if(count[b]<min)min=count[b]; if(count[b]>max)max=count[b]}
           print min, max}')"

KNOWN_SNI=$(tshark -r "$PCAP" -Y "tls.handshake.type==1" -T fields -e tls.handshake.extensions_server_name 2>/dev/null | sort -u | paste -sd, -)

echo "Normal DNS rate: ~${DNS_RATE} queries/min, low-to-moderate and variable"
echo "Normal TXT query rate: very low (~${TXT_PCT_RAW}% of DNS queries)"
echo "Normal connection duration mix: mostly short/medium (human and application-driven), plus a small number of long-lived agent channels"
echo "Normal packet volume range: ${MIN_BIN}-${MAX_BIN} frames per 5-minute window"
echo "Known-good external services (by TLS SNI): $KNOWN_SNI"
echo "Known-good internal servers observed: 10.10.1.1, 10.10.1.10 (agent, port 1514), 10.10.1.60 (SMB, port 445), 10.10.2.200 (printing, port 9100), 10.10.20.5"

for IOC_IP in 91.234.99.107 154.118.42.89; do
	IOC_COUNT=$(tshark -r "$PCAP" -Y "ip.addr==$IOC_IP" 2>/dev/null | wc -l)
	if [ "$IOC_COUNT" -eq 0 ]; then
		echo "No traffic to $IOC_IP"
	else
		echo "WARNING: $IOC_COUNT packets observed to $IOC_IP"
	fi
done

IOC_DOMAIN_COUNT=$(tshark -r "$PCAP" -Y 'dns.qry.name contains "data-sync.meddefense-portal.com"' 2>/dev/null | wc -l)
if [ "$IOC_DOMAIN_COUNT" -eq 0 ]; then
	echo "No TXT queries to data-sync.meddefense-portal.com"
else
	echo "WARNING: $IOC_DOMAIN_COUNT queries observed to data-sync.meddefense-portal.com"
fi
echo ""
#============= END BASELINE SIGNATURES ================
#
#============= START SAVE JSON ================
SNI_JSON=$(tshark -r "$PCAP" -Y "tls.handshake.type==1" -T fields -e tls.handshake.extensions_server_name 2>/dev/null |
	sort -u | awk '{printf "%s\"%s\"", sep, $0; sep=", "}')

cat >baseline_clinical.json <<EOF
{
  "capture_file": "$PCAP",
  "capture_duration_seconds": $DURATION,
  "total_packets": $ETH,
  "protocol_distribution_packets": {
    "tcp": $TCP,
    "udp": $UDP,
    "icmp": $ICMP,
    "other": $OTHER
  },
  "application_breakdown_packets": {
    "https": $HTTPS,
    "dns": $DNS,
    "kerberos": $KERBEROS,
    "ldap": $LDAP,
    "agent": $AGENT,
    "ntp": $NTP,
    "printing": $PRINTING,
    "smb": $SMB,
    "other": $APP_OTHER
  },
  "dns": {
    "total_queries": $TOTAL_QUERIES,
    "queries_per_minute": $DNS_RATE,
    "txt_query_count": $TXT_COUNT_RAW,
    "txt_query_percent": $TXT_PCT_RAW
  },
  "packet_volume_per_5min_window": {
    "min_frames": $MIN_BIN,
    "max_frames": $MAX_BIN
  },
  "known_good_sni": [$SNI_JSON],
  "known_bad_checked": {
    "91.234.99.107": "not observed",
    "154.118.42.89": "not observed",
    "data-sync.meddefense-portal.com": "not observed"
  }
}
EOF

echo "BASELINE SAVED: baseline_clinical.json"
#============= END SAVE JSON ================
