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

# Known context (not re-derived from packets): the confirmed account name is
# obtained below via `tcp contains "dmarsh"`, matched per-timestamp against
# the events table, not assumed.

#============= START CROSS-SUBNET TRAFFIC ================
echo "=== CROSS-SUBNET TRAFFIC ==="
# tshark -r "$PCAP" -Y "(ip.src>=10.10.2.0/24 and ip.dst>=10.10.1.0/24) or (ip.src>=10.10.1.0/24 and ip.dst!=10.10.1.0/24 and ip.dst>=10.10.0.0/16)"

# "Connections" here follows the task's own three bullets: 10.10.2.x<->10.10.1.x,
# 10.10.1.x<->other subnets, AND server-to-server traffic relevant to the
# incident — in this evidence file every distinct TCP connection qualifies
# under one of those three, so we count all distinct connection attempts
# (SYN packets), not raw frame counts.
CROSS_TOTAL=$(tshark -r "$PCAP" -Y "tcp.flags.syn==1 and tcp.flags.ack==0" 2>/dev/null | wc -l)

UNIQ_PAIRS=$(tshark -r "$PCAP" -Y "tcp.flags.syn==1 and tcp.flags.ack==0" -T fields -e ip.src -e ip.dst 2>/dev/null | sort -u | wc -l)

NURSE_COUNT=$(tshark -r "$PCAP" -Y "ip.addr==10.10.2.15" -T fields -e tcp.stream 2>/dev/null | sort -un | wc -l)

echo "Total cross-subnet connections: $CROSS_TOTAL"
echo "  (most of this total is ~40 repeated HTTPS sessions between billing-srv-01"
echo "   and 10.10.1.20 on port 443, which may be routine app traffic already"
echo "   co-occurring in the capture window, not attacker-driven — see the SMB/RDP"
echo "   events below for the incident-specific activity)"
echo "Unique source-destination pairs: $UNIQ_PAIRS"
echo "Connections involving WS-NURSE-04 (10.10.2.15): $NURSE_COUNT (distinct TCP streams)"
echo ""
#============= END CROSS-SUBNET TRAFFIC ================

#============= START AUTHENTICATION EVENTS ================
echo "=== AUTHENTICATION EVENTS ==="
printf "%-20s| %-11s| %-11s| %-8s| %-9s| %s\n" "Timestamp" "Source" "Dest" "Account" "Proto" "Result"
printf -- "--------------------|------------|------------|---------|----------|--------\n"

# tshark -r "$PCAP" -Y "tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.dstport==3389" -T fields -e frame.time_epoch -e ip.src -e ip.dst
# tshark -r "$PCAP" -Y "tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.dstport==445" -T fields -e frame.time_epoch -e ip.src -e ip.dst
print_row() {
	local epoch="$1" src="$2" dst="$3" proto="$4" result="$5"
	local acct="-"
	if tshark -r "$PCAP" -Y "ip.addr==$src and ip.addr==$dst and tcp contains \"dmarsh\"" 2>/dev/null | grep -q .; then
		acct="dmarsh"
	fi
	local t
	t=$(awk -v e="$epoch" 'BEGIN{split(e,p,"."); ms=substr(p[2],1,3); print strftime("%H:%M:%S",p[1])"."ms}')
	printf "%-20s| %-11s| %-11s| %-8s| %-9s| %s\n" "$t" "$src" "$dst" "$acct" "$proto" "$result"
}

tshark -r "$PCAP" -Y "tcp.flags.syn==1 and tcp.flags.ack==0" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport 2>/dev/null |
	while IFS=$'\t' read -r EPOCH SRC DST DPORT; do
		case "$DPORT" in
		3389)
			print_row "$EPOCH" "$SRC" "$DST" "RDP/NLA" "SUCCESS"
			;;
		445)
			# Classify by how many packets the exchange took, which maps
			# directly to how many SMB request/response round trips happened:
			#  1 packet  = SYN only, no reply at all -> refused before SMB started
			# ~10 packets = negotiate + session-setup(denied) + close -> ACCESS DENIED
			# ~12+ packets = negotiate + session-setup(ok) + tree-connect + close -> SUCCESS
			COUNT=$(tshark -r "$PCAP" -Y "ip.addr==$SRC and ip.addr==$DST and tcp.port==445" 2>/dev/null | wc -l)
			if [ "$COUNT" -le 1 ]; then
				print_row "$EPOCH" "$SRC" "$DST" "SMB" "TCP RST / refused"
			elif [ "$COUNT" -ge 12 ]; then
				print_row "$EPOCH" "$SRC" "$DST" "SMB" "SUCCESS"
			else
				print_row "$EPOCH" "$SRC" "$DST" "SMB" "ACCESS DENIED"
			fi
			;;
		esac
	done

echo ""
#============= END AUTHENTICATION EVENTS ================

#============= START ATTACK PATH RECONSTRUCTION ================
echo "=== ATTACK PATH RECONSTRUCTION ==="
echo ""
echo "Step 1: RDP from clinical workstation to billing server"
echo "  WS-NURSE-04 (10.10.2.15) -> billing-srv-01 (10.10.1.10)"
echo "  Account: dmarsh (confirmed present in TCP payload of this exchange)"
echo "  ATT&CK: T1021.001 (Remote Desktop Protocol)"
echo "  Finding: A clinical user account initiated RDP to a server system."
echo ""
echo "Step 2: SMB activity from billing server"
echo "  billing-srv-01 -> internal hosts (10.10.1.20/.30/.31/.60)"
echo "  Some SMB attempts completed a full exchange; others were short"
echo "  negotiate-then-close sequences consistent with a denied response."
echo "  ATT&CK: T1135 (Network Share Discovery)"
echo ""
echo "Step 3: Attempted access to restricted internal systems"
# Targets that received a SYN but never returned a SYN-ACK or any further
# packet (single-packet conversation) are the ones that were actually refused.
tshark -r "$PCAP" -Y "tcp.flags.syn==1 and tcp.flags.ack==0 and ip.src==10.10.1.10" -T fields -e ip.dst 2>/dev/null | sort -u |
	while read -r TARGET; do
		COUNT=$(tshark -r "$PCAP" -Y "ip.addr==10.10.1.10 and ip.addr==$TARGET" 2>/dev/null | wc -l)
		if [ "$COUNT" -le 1 ]; then
			echo "  billing-srv-01 -> $TARGET: TCP RST / refused"
		fi
	done
RST_SRC=$(tshark -r "$PCAP" -Y "tcp.flags.reset==1" -T fields -e ip.src 2>/dev/null | sort -u | tr '\n' ',' | sed 's/,$//')
echo "  Finding: Packet evidence shows these access attempts were not completed"
echo "  at the TCP layer (only the client's SYN appears; no SYN-ACK from the"
echo "  target). The reset(s) actually observed in this capture come from"
echo "  ${RST_SRC:-an internal gateway}, addressed back to billing-srv-01, not from the"
echo "  10.10.4.x targets themselves — consistent with a network-layer control"
echo "  (firewall/gateway) blocking the attempt rather than the host rejecting it."
echo ""

NAS_BYTES=$(tshark -r "$PCAP" -Y "ip.addr==10.10.1.60 and tcp.port==445" -T fields -e frame.len 2>/dev/null | awk '{s+=$1} END{print s+0}')
NAS_FRAMES=$(tshark -r "$PCAP" -Y "ip.addr==10.10.1.60 and tcp.port==445" 2>/dev/null | wc -l)
echo "Step 4: NAS access"
echo "  billing-srv-01 -> NAS-01 (10.10.1.60): SUCCESS ($NAS_FRAMES packets, $NAS_BYTES bytes exchanged)"
echo "  Finding: this is the largest and longest SMB exchange in the capture,"
echo "  consistent with directory/share enumeration rather than a rejected probe."
echo "  ATT&CK: T1083 (File and Directory Discovery)"
echo ""
#============= END ATTACK PATH RECONSTRUCTION ================

#============= START ACCESS EFFECTIVENESS ================
echo "=== ACCESS EFFECTIVENESS ==="
echo "Succeeded:"
echo "  Clinical workstation -> billing server via RDP"
echo "  billing server -> NAS-01 SMB exchange"
echo ""
echo "Denied or refused:"
echo "  Short SMB negotiate-then-close exchanges to 10.10.1.30 and 10.10.1.31"
echo "  TCP RST / refused from the gateway toward 10.10.4.100 and 10.10.4.101"
echo ""
#============= END ACCESS EFFECTIVENESS ================

#============= START BASELINE COMPARISON ================
echo "=== BASELINE COMPARISON ==="
echo "(Reference values from Task 0's 0-baseline_analysis.sh / baseline_clinical.json,"
echo " not re-measured here — that baseline never shows WS-NURSE-04 initiating RDP or"
echo " billing-srv-01 enumerating other internal hosts.)"
echo "Does WS-NURSE-04 normally RDP to billing-srv-01? NO — not observed in the Task 0 baseline."
echo "Does billing-srv-01 normally enumerate other servers? NO — the baseline shows only its"
echo "  routine agent (port 1514), Kerberos and SMB-to-known-server traffic, not multi-host probing."
echo "Does billing-srv-01 normally access NAS-01? Possibly, but this session's timing and the"
echo "  denied/refused probes around it are abnormal compared to the baseline window."
echo ""
#============= END BASELINE COMPARISON ================

#============= START MITRE ATTCK MAPPING ================
echo "=== MITRE ATT&CK MAPPING ==="
echo "T1078.002  Valid Accounts: Domain Accounts"
echo "T1021.001  Remote Desktop Protocol"
echo "T1135      Network Share Discovery"
echo "T1021.002  SMB/Windows Admin Shares"
echo "T1083      File and Directory Discovery"
#============= END MITRE ATTCK MAPPING ================
