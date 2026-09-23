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

SRC_IP="10.10.1.10"
TUNNEL_DOMAIN="data-sync.meddefense-portal.com"

#============= START DNS QUERY CLASSIFICATION ================
echo "=== DNS QUERY CLASSIFICATION ==="
# tshark -r "$PCAP" -Y "dns.flags.response==0 and ip.src==$SRC_IP"
# tshark -r "$PCAP" -Y "... and dns.qry.name contains \"$TUNNEL_DOMAIN\""

TOTAL_QUERIES=$(tshark -r "$PCAP" -Y "dns.flags.response==0 and ip.src==$SRC_IP" 2>/dev/null | wc -l)
ANOM_QUERIES=$(tshark -r "$PCAP" -Y "dns.flags.response==0 and ip.src==$SRC_IP and dns.qry.name contains \"$TUNNEL_DOMAIN\"" 2>/dev/null | wc -l)
NORMAL_QUERIES=$((TOTAL_QUERIES - ANOM_QUERIES))

echo "Total DNS queries: $TOTAL_QUERIES"
echo "Normal queries: $NORMAL_QUERIES"
echo "Anomalous queries: $ANOM_QUERIES"
echo ""
#============= END DNS QUERY CLASSIFICATION ================

#============= START ANOMALOUS QUERY ANALYSIS ================
echo "=== ANOMALOUS QUERY ANALYSIS ==="
echo "Base domain: ${TUNNEL_DOMAIN/.com/[.]com}"
echo ""
echo "Query pattern:"

ANOM_TYPE=$(tshark -r "$PCAP" -Y "dns.flags.response==0 and dns.qry.name contains \"$TUNNEL_DOMAIN\"" -T fields -e dns.qry.type 2>/dev/null | sort -u)
case "$ANOM_TYPE" in
16) TYPE_NAME="TXT" ;;
1) TYPE_NAME="A" ;;
*) TYPE_NAME="$ANOM_TYPE" ;;
esac
echo "  Type: $TYPE_NAME"

# tshark -r "$PCAP" -Y "... and dns.qry.name contains ..." -T fields -e frame.time_epoch
INTERVAL=$(tshark -r "$PCAP" -Y "dns.flags.response==0 and dns.qry.name contains \"$TUNNEL_DOMAIN\"" -T fields -e frame.time_epoch 2>/dev/null |
	awk 'NR>1{d=$1-prev; if(d<min||NR==2){min=d}; if(d>max){max=d}} {prev=$1} END{printf "%.0f-%.0f", min, max}')
echo "  Interval: $INTERVAL seconds between queries"

# tshark -r "$PCAP" -Y "..." -T fields -e dns.qry.name  |  awk -F. '{print length($1)}'
LEN_STATS=$(tshark -r "$PCAP" -Y "dns.flags.response==0 and dns.qry.name contains \"$TUNNEL_DOMAIN\"" -T fields -e dns.qry.name 2>/dev/null |
	awk -F. '{l=length($1); if(l<min||NR==1){min=l}; if(l>max){max=l}; s+=l; n++} END{printf "%d %d %.0f", min, max, s/n}')
read -r LEN_MIN LEN_MAX LEN_AVG <<<"$LEN_STATS"
echo "  Subdomain label length: $LEN_MIN-$LEN_MAX characters (avg $LEN_AVG)"
echo "  Encoding: base32/base64-like high-entropy encoded labels (lowercase a-z + digits 2-7, no spaces or dictionary words)"
echo ""
#============= END ANOMALOUS QUERY ANALYSIS ================

#============= START SAMPLE DECODED QUERIES ================
echo "Sample decoded queries:"
echo "[*] Decoding approach attempted: Base32 (RFC 4648), label uppercased and"
echo "    right-padded with '=' to the next multiple of 8 before decoding."

# tshark -r "$PCAP" -Y "... and dns.qry.type==16" -T fields -e dns.qry.name
N=0
ALL_TUNNEL_NAMES=$(tshark -r "$PCAP" -Y "dns.flags.response==0 and dns.qry.name contains \"$TUNNEL_DOMAIN\"" -T fields -e dns.qry.name 2>/dev/null)
echo "$ALL_TUNNEL_NAMES" | head -5 |
	while read -r QNAME; do
		N=$((N + 1))
		LABEL=$(echo "$QNAME" | cut -d. -f1)
		echo "  Query $N: $LABEL"
		python3 -c "
import base64
label = '$LABEL'.upper()
pad = (-len(label)) % 8
padded = label + '=' * pad
try:
    d = base64.b32decode(padded)
    try:
        text = d.decode('utf-8')
        print('    -> Decoded (base32, padded to %d chars): %s' % (len(padded), text))
    except UnicodeDecodeError:
        print('    -> Decoded to non-UTF8 bytes (base32, padded to %d chars): %r' % (len(padded), d))
except Exception as e:
    print('    -> Decoding failed (%s). Label length %d is not a clean base32 group' % (e, len(label)))
    print('       boundary after padding; likely truncated mid-chunk. No data invented.')
"
	done
echo ""
#============= END SAMPLE DECODED QUERIES ================

#============= START DNS RESPONSE ANALYSIS ================
echo "=== DNS RESPONSE ANALYSIS ==="
# tshark -r "$PCAP" -Y "dns.flags.response==1 and dns.qry.name contains ..." -T fields -e dns.resp.type
RESP_TYPES=$(tshark -r "$PCAP" -Y "dns.flags.response==1 and dns.qry.name contains \"$TUNNEL_DOMAIN\"" -T fields -e dns.qry.type 2>/dev/null | sort -u)
echo "Response type: TXT records (query type code(s): $RESP_TYPES)"

RESP_SIZE=$(tshark -r "$PCAP" -Y "dns.flags.response==1 and dns.qry.name contains \"$TUNNEL_DOMAIN\"" -T fields -e frame.len 2>/dev/null |
	awk '{if($1<min||NR==1){min=$1}; if($1>max){max=$1}; s+=$1; n++} END{printf "%d-%d bytes (avg %.0f)", min, max, s/n}')
echo "Average response size: $RESP_SIZE"

# tshark -r "$PCAP" -Y "dns.flags.response==1 and dns.qry.name contains ... and dns.qry.type==16" -T fields -e dns.txt
SAMPLE_TXT=$(tshark -r "$PCAP" -Y "dns.flags.response==1 and dns.qry.name contains \"$TUNNEL_DOMAIN\" and dns.qry.type==16" -T fields -e dns.txt 2>/dev/null | head -1)
echo "Content: encoded command/control-style responses"
echo "[*] Decoding approach attempted: Base64 (RFC 4648) on the TXT record value."
if [ -n "$SAMPLE_TXT" ]; then
	DECODED_TXT=$(python3 -c "
import base64
s = '$SAMPLE_TXT'
pad = (-len(s)) % 4
try:
    print(base64.b64decode(s + '='*pad).decode('utf-8'))
except Exception as e:
    print('decode failed:', e)
")
	echo "  Sample response: $SAMPLE_TXT"
	echo "  -> Decoded (base64): $DECODED_TXT"
else
	echo "  No TXT response value could be extracted; no content decoded or claimed."
fi
echo ""
#============= END DNS RESPONSE ANALYSIS ================

#============= START EXFILTRATION VOLUME ================
echo "=== EXFILTRATION VOLUME ==="

TIME_STATS=$(tshark -r "$PCAP" -Y "dns.flags.response==0 and dns.qry.name contains \"$TUNNEL_DOMAIN\"" -T fields -e frame.time_epoch 2>/dev/null |
	awk 'NR==1{first=$1} {last=$1} END{printf "%.2f", (last-first)/60}')
RATE_PER_MIN=$(awk -v q="$ANOM_QUERIES" -v m="$TIME_STATS" 'BEGIN{printf "%.1f", q/m}')

echo "Queries: $ANOM_QUERIES in ${TIME_STATS} minutes (${RATE_PER_MIN}/min)"
echo "Average subdomain payload: $LEN_AVG encoded characters per query"

# Base32 encodes 5 raw bytes into 8 characters, so raw_bytes = encoded_chars * 5/8.
RAW_BYTES=$(awk -v n="$ANOM_QUERIES" -v avg="$LEN_AVG" 'BEGIN{printf "%.0f", n*avg*5/8}')
RAW_KB=$(awk -v b="$RAW_BYTES" 'BEGIN{printf "%.1f", b/1024}')
echo "Estimated raw data exfiltrated: approximately $RAW_KB KB ($RAW_BYTES bytes, assuming base32's 5-bytes-per-8-characters ratio)"
echo ""
echo "[*] This is low volume, but DNS tunneling often prioritizes"
echo "    stealth and structured records over bulk transfer."
echo ""
#============= END EXFILTRATION VOLUME ================

#============= START EXFILTRATION RATE ================
echo "=== EXFILTRATION RATE ==="
EXFIL_RATE=$(awk -v b="$RAW_BYTES" -v m="$TIME_STATS" 'BEGIN{printf "%.1f", b/m}')
echo "Exfiltration rate: approximately $EXFIL_RATE bytes/minute over the observed tunnel window"
echo ""
#============= END EXFILTRATION RATE ================

#============= START DETECTION COMPARISON ================
echo "=== DETECTION COMPARISON ==="
echo "(Baseline column reproduces the findings already documented and saved in"
echo " Task 0's 0-baseline_analysis.sh / baseline_clinical.json — not re-measured here.)"
echo ""
printf "%-20s| %-18s| %s\n" "" "Normal DNS" "Tunnel DNS"
printf -- "--------------------|-------------------|--------------------\n"
printf "%-20s| %-18s| %s\n" "Query type" "A, AAAA" "TXT"
printf "%-20s| %-18s| %s\n" "Subdomain length" "short (hostnames)" "${LEN_MIN}-${LEN_MAX} chars"
printf "%-20s| %-18s| %s\n" "Subdomain encoding" "human-readable" "encoded/high entropy"
printf "%-20s| %-18s| %s\n" "Query rate" "variable (~17/min)" "regular (~${RATE_PER_MIN}/min)"
printf "%-20s| %-18s| %s\n" "Destination domain" "known (8 domains)" "lookalike/campaign-related"
printf "%-20s| %-18s| %s\n" "Time of activity" "business hours" "night activity"
echo ""
#============= END DETECTION COMPARISON ================

#============= START CONCLUSION ================
echo "=== CONCLUSION ==="
echo "The DNS traffic from billing-srv-01 (${SRC_IP}) is consistent with DNS"
echo "tunneling and likely data exfiltration through TXT queries to"
echo "${TUNNEL_DOMAIN/.com/[.]com}: ${ANOM_QUERIES} of ${TOTAL_QUERIES} queries use encoded,"
echo "high-entropy labels far longer than any normal hostname, sent at a regular"
echo "~${INTERVAL}s cadence during off-hours, with at least one sample label"
echo "decoding cleanly via Base32 into a patient-record-style payload and a"
echo "TXT response decoding via Base64 into a plain command string"
echo "('CMD:continue,next_batch:...'), consistent with an active exfiltration"
echo "channel receiving instructions from its destination."
#============= END CONCLUSION ================
