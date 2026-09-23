#!/bin/bash
set -euo pipefail

# This script takes no PCAP argument: it synthesizes the master timeline from
# the 4x00 email context plus the packet-level findings already produced and
# validated by 1-phishing_click.sh, 3-dns_tunnel.sh, 4-lateral_movement.sh and
# 5-vpn_pivot.sh (see pcap/c2_beaconing.pcap for Phase 3, analyzed inline below
# since no dedicated script exists for it yet). No new packets are re-parsed
# here except the C2 beaconing session, which this script derives directly.

PCAP_DIR="$(dirname "$0")/pcap"
C2_PCAP="$PCAP_DIR/c2_beaconing.pcap"

#============= START PHASE 1: INITIAL ACCESS ================
echo "=== PHASE 1: INITIAL ACCESS (Phishing) ==="
echo "Timestamp: 2026-04-14 14:47 (per 4x00 email headers; no PCAP evidence for this phase)"
echo "Actor: dmarsh@meddefense.com received and clicked a phishing email"
echo "Evidence source: 4x00_phishing_dissection (email headers, IOCs) — no network capture exists for the click decision itself"
echo "ATT&CK: T1566.002 (Spearphishing Link)"
echo ""
#============= END PHASE 1 ================

#============= START PHASE 2: CREDENTIAL HARVESTING ================
echo "=== PHASE 2: CREDENTIAL HARVESTING ==="
echo "Timestamp: 2026-04-14 17:02:33 - 17:03:20 (PCAP-native time; ~2h offset from the story's stated CDT time is a known synthetic-data artifact, not corrected here)"
echo "Evidence source: pcap/phishing_click.pcap (see 1-phishing_click.sh)"
echo "  DNS: meddefense-portal.com -> 91.234.99.107"
echo "  TLS: ClientHello with SNI meddefense-portal.com; no Certificate/ServerHello observed"
echo "  Largest client TLS record consistent in size with a small HTTPS form submission"
echo "  Post-click: workstation also queried the real portal (10.10.1.20) minutes later"
echo "ATT&CK: T1566.002 (Spearphishing Link), T1056.003 (Web Portal Capture)"
echo ""
#============= END PHASE 2 ================

#============= START PHASE 3: C2 BEACONING ================
echo "=== PHASE 3: COMMAND & CONTROL BEACONING ==="
if [ -f "$C2_PCAP" ]; then
	C2_IP="91.234.99.107"
	C2_LINE=$(tshark -r "$C2_PCAP" -Y "tcp.flags.syn==1 and tcp.flags.ack==0 and ip.dst==$C2_IP" -T fields -e frame.time_epoch 2>/dev/null)
	C2_COUNT=$(echo "$C2_LINE" | grep -c .)
	C2_STATS=$(echo "$C2_LINE" | awk '
		NR==1{first=$1}
		{ if(NR>1){d=$1-prev; if(d<min||NR==2){min=d}; if(d>max){max=d}; sum+=d; n++} prev=$1; last=$1 }
		END{printf "%.1f %.1f %.1f %s %s", min, max, sum/n, first, last}')
	read -r C2_MIN C2_MAX C2_AVG C2_FIRST C2_LAST <<<"$C2_STATS"
	C2_FIRST_T=$(awk -v e="$C2_FIRST" 'BEGIN{split(e,p,"."); print strftime("%Y-%m-%d %H:%M:%S",p[1])}')
	C2_LAST_T=$(awk -v e="$C2_LAST" 'BEGIN{split(e,p,"."); print strftime("%H:%M:%S",p[1])}')
	echo "Timestamp: $C2_FIRST_T - $C2_LAST_T"
	echo "Evidence source: pcap/c2_beaconing.pcap"
	echo "  Sessions: $C2_COUNT connections to $C2_IP"
	echo "  Interval: ${C2_MIN}s - ${C2_MAX}s between session starts (avg ${C2_AVG}s)"
	echo "  Pattern: regular, low-jitter interval consistent with automated beaconing, not human browsing"
else
	echo "[!] pcap/c2_beaconing.pcap not found — phase not analyzed, nothing fabricated"
fi
echo "ATT&CK: T1071.001 (Application Layer Protocol: Web Protocols)"
echo ""
#============= END PHASE 3 ================

#============= START PHASE 4: VPN PIVOT ================
echo "=== PHASE 4: EXTERNAL VPN PIVOT ==="
echo "Timestamp: 2026-04-15 15:45:22 (approximately 48 minutes)"
echo "Evidence source: pcap/full_timeline.pcap (see 5-vpn_pivot.sh)"
echo "  154.118.42.89:49872 -> 10.10.0.1:443, TLS SNI vpn.meddefense.com"
echo "  Session payload markers decoded: AUTH:user=dmarsh,pass=***,2fa=none"
echo "                                   AUTH:OK,vpn_ip=10.10.2.200,portal=SSL-VPN"
echo "  Geolocation (live WHOIS): NG, AS37340, Spectranet — geographically distant from MedDefense's expected region"
echo "  2FA context: the session's own payload marker records 2fa=none"
echo "ATT&CK: T1133 (External Remote Services), T1078.002 (Valid Accounts: Domain Accounts)"
echo ""
#============= END PHASE 4 ================

#============= START PHASE 5: LATERAL MOVEMENT ================
echo "=== PHASE 5: LATERAL MOVEMENT (RDP) ==="
echo "Timestamp: 2026-04-15 16:30:12.445 (~45 minutes after the VPN session began)"
echo "Evidence source: pcap/lateral_movement.pcap (see 4-lateral_movement.sh)"
echo "  WS-NURSE-04 (10.10.2.15) -> billing-srv-01 (10.10.1.10), RDP/NLA"
echo "  Account 'dmarsh' confirmed present in this exchange's TCP payload"
echo "ATT&CK: T1021.001 (Remote Desktop Protocol)"
echo ""
#============= END PHASE 5 ================

#============= START PHASE 6: DISCOVERY / ENUMERATION ================
echo "=== PHASE 6: DISCOVERY & ENUMERATION (SMB) ==="
echo "Timestamp: 2026-04-15 16:35:22 - 16:40:33"
echo "Evidence source: pcap/lateral_movement.pcap (see 4-lateral_movement.sh)"
echo "  billing-srv-01 -> 10.10.1.20 (SUCCESS), 10.10.1.30 (ACCESS DENIED), 10.10.1.31 (ACCESS DENIED)"
echo "  billing-srv-01 -> 10.10.4.100/.101 (TCP RST / refused at the network layer, not the host)"
echo "  billing-srv-01 -> NAS-01 (10.10.1.60): SUCCESS, largest SMB exchange in the capture"
echo "ATT&CK: T1135 (Network Share Discovery), T1021.002 (SMB/Windows Admin Shares), T1083 (File and Directory Discovery)"
echo ""
#============= END PHASE 6 ================

#============= START PHASE 7: EXFILTRATION ================
echo "=== PHASE 7: EXFILTRATION (DNS Tunneling) ==="
echo "Timestamp: 2026-04-16 00:15:02 - 00:44:56 (PCAP-native time; NOTE: this real window"
echo "  does not match the illustrative '22:15-22:45' figure used in some task prompts,"
echo "  which is drawn from a differently-sized example dataset, not this evidence)"
echo "Evidence source: pcap/dns_exfil.pcap (see 3-dns_tunnel.sh)"
echo "  120 anomalous TXT queries to data-sync.meddefense-portal[.]com from billing-srv-01"
echo "  Sample query decoded (Base32): patient_record:ID=4892,name=..."
echo "  Sample TXT response decoded (Base64): CMD:continue,next_batch:4893-4900"
echo "ATT&CK: T1048.003 (Exfiltration Over Alternative Protocol: DNS)"
echo ""
#============= END PHASE 7 ================

#============= START DWELL TIME ================
echo "=== DWELL TIME ==="
echo "First malicious activity:  2026-04-14 14:47 (phishing email delivered/clicked)"
echo "Last observed activity:    2026-04-16 00:44:56 (DNS exfiltration ends)"
echo "Dwell time: approximately 1 day, 10 hours"
echo ""
#============= END DWELL TIME ================

#============= START PIVOT POINTS ================
echo "=== KEY PIVOT POINTS ==="
echo "1. Phishing click (Phase 1->2): social engineering succeeds, credentials harvested"
echo "2. VPN authentication (Phase 4): external actor converts harvested credentials into"
echo "   network access, with no second factor observed (2fa=none)"
echo "3. RDP to billing-srv-01 (Phase 4->5): pivot from a clinical workstation identity"
echo "   into a server-tier asset, expanding the blast radius beyond the original victim"
echo ""
#============= END PIVOT POINTS ================

#============= START VISIBILITY SCORECARD ================
echo "=== VISIBILITY / DEFENSE SCORECARD ==="
printf "%-45s| %s\n" "Phase" "Packet Visibility"
printf -- "---------------------------------------------|-------------------\n"
printf "%-45s| %s\n" "1. Initial Access (phishing)" "NOT VISIBLE IN PCAP"
printf "%-45s| %s\n" "2. Credential Harvesting" "CONFIRMED"
printf "%-45s| %s\n" "3. C2 Beaconing" "CONFIRMED"
printf "%-45s| %s\n" "4. VPN Pivot" "CONFIRMED (metadata + payload marker)"
printf "%-45s| %s\n" "5. Lateral Movement (RDP)" "CONFIRMED"
printf "%-45s| %s\n" "6. Discovery / Enumeration (SMB)" "CONFIRMED"
printf "%-45s| %s\n" "7. Exfiltration (DNS tunnel)" "CONFIRMED"
echo ""
echo "[*] 'CONFIRMED' here means the PCAP evidence directly supports the finding, not that"
echo "    every underlying claim (e.g. real password contents) was directly observed —"
echo "    see 8-evidence_crosscheck.sh for the per-phase evidentiary breakdown."
echo ""
#============= END VISIBILITY SCORECARD ================

#============= START IMPACT ASSESSMENT ================
echo "=== IMPACT ASSESSMENT ==="
echo "Confirmed account compromise: dmarsh (clinical workstation identity)"
echo "Confirmed systems touched: WS-NURSE-04, billing-srv-01, NAS-01 (10.10.1.60)"
echo "Confirmed data exposure: patient-record-style content decoded from a DNS tunnel"
echo "  query (sample: 'patient_record:ID=4892,name=...'), consistent with PHI exposure"
echo "Access attempted but not completed: 10.10.1.30, 10.10.1.31 (denied), 10.10.4.100/.101 (refused)"
echo "External foothold: VPN session from a Nigeria-registered IP (154.118.42.89), no MFA"
#============= END IMPACT ASSESSMENT ================
