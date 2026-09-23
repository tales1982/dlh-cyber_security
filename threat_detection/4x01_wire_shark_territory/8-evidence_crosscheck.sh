#!/bin/bash
set -euo pipefail

# This script takes no PCAP argument: it re-examines the 7 kill-chain phases
# from 6-kill_chain.sh under a stricter evidentiary standard, distinguishing
# what the packets themselves prove from what is inferred context. No new
# packets are parsed here; classifications are judgments over prior findings.

#============= START PHASE-BY-PHASE CLASSIFICATION ================
echo "=== EVIDENCE CROSS-CHECK: PHASE CLASSIFICATION ==="
echo ""

echo "Phase 1: Initial Access (Phishing)"
echo "  Classification: NOT VISIBLE IN PCAP"
echo "  Rationale: no capture exists covering the mail-delivery or click-decision moment;"
echo "  this phase rests entirely on 4x00's email headers and IOCs, not on network packets."
echo "  Additional evidence needed: mail gateway / MTA logs, EDR process-execution logs on"
echo "  the workstation, user interview confirming the click."
echo ""

echo "Phase 2: Credential Harvesting"
echo "  Classification: STRONG INFERENCE"
echo "  Rationale: DNS resolution and a full TLS ClientHello to meddefense-portal.com are"
echo "  CONFIRMED by packets, but the session is encrypted — no Certificate/ServerHello is"
echo "  even present, and no plaintext form data was or could be observed. The 'credentials"
echo "  were harvested' conclusion is inferred from record-size metadata and context, not proven."
echo "  Additional evidence needed: endpoint browser history/screenshot, the phishing site's"
echo "  own server-side logs, or a TLS-terminating proxy log with the decrypted form POST."
echo ""

echo "Phase 3: C2 Beaconing"
echo "  Classification: CONFIRMED"
echo "  Rationale: 24 distinct TCP sessions to a known-malicious IP at a regular ~300s"
echo "  interval are directly observed in pcap/c2_beaconing.pcap; the pattern itself (not"
echo "  its payload meaning) is packet-level fact."
echo "  Additional evidence needed: none to confirm beaconing occurred; endpoint process"
echo "  logs would help attribute which process on the host generated the traffic."
echo ""

echo "Phase 4: External VPN Pivot"
echo "  Classification: STRONG INFERENCE"
echo "  Rationale: the external connection, its timing, and a plaintext application-layer"
echo "  marker string ('AUTH:user=dmarsh,pass=***,2fa=none' / 'AUTH:OK,vpn_ip=...') are"
echo "  CONFIRMED present in this capture's payload. However, this is not a real, protocol-"
echo "  correct VPN handshake — in a genuine capture such an exchange would be TLS-encrypted"
echo "  and this marker would not be readable. The underlying claim (that dmarsh's actual"
echo "  credentials, without a second factor, were used) is evidenced by this dataset's"
echo "  marker, not independently proven the way a real captured handshake would allow."
echo "  Additional evidence needed: VPN concentrator authentication logs (RADIUS/AAA),"
echo "  which would independently confirm account, timestamp, source IP and MFA status."
echo ""

echo "Phase 5: Lateral Movement (RDP)"
echo "  Classification: CONFIRMED"
echo "  Rationale: the RDP/NLA connection from WS-NURSE-04 to billing-srv-01, its timestamp,"
echo "  and the literal string 'dmarsh' inside this exchange's TCP payload are all directly"
echo "  observed in pcap/lateral_movement.pcap."
echo "  Additional evidence needed: none to confirm the connection occurred; Windows Security"
echo "  Event Log (4624/4625) on billing-srv-01 would confirm logon success and session type."
echo ""

echo "Phase 6: Discovery / Enumeration (SMB)"
echo "  Classification: CONFIRMED"
echo "  Rationale: SMB connection attempts, their packet counts, and which targets returned"
echo "  a full exchange vs. a short denial vs. a network-layer reset are all directly"
echo "  observed in pcap/lateral_movement.pcap. The SUCCESS/DENIED/REFUSED classification"
echo "  itself is an inference from packet-count patterns, not from a decoded SMB status code."
echo "  Additional evidence needed: SMB/file-server audit logs to confirm exact share names"
echo "  and files accessed on NAS-01, which the encrypted/absent payload here does not show."
echo ""

echo "Phase 7: Exfiltration (DNS Tunneling)"
echo "  Classification: CONFIRMED"
echo "  Rationale: 120 anomalous TXT queries with encoded, high-entropy labels at a regular"
echo "  interval are directly observed in pcap/dns_exfil.pcap, and at least one query label"
echo "  and one TXT response decode cleanly (Base32/Base64) to plaintext content. This is"
echo "  the strongest-evidenced phase in the capture: both the channel and sample payload"
echo "  content are packet-proven, not inferred."
echo "  Additional evidence needed: full DNS query log at the authoritative resolver to"
echo "  determine the complete/total volume actually exfiltrated beyond the sampled queries."
echo ""
#============= END PHASE-BY-PHASE CLASSIFICATION ================

#============= START VISIBILITY SCORE ================
echo "=== PACKET-VISIBILITY SCORE ==="
CONFIRMED=4
STRONG=2
UNCONFIRMED=0
NOTVISIBLE=1
TOTAL=7
# Weighted: CONFIRMED=1.0, STRONG INFERENCE=0.5, UNCONFIRMED=0.25, NOT VISIBLE=0.0
SCORE=$(awk -v c="$CONFIRMED" -v s="$STRONG" -v u="$UNCONFIRMED" -v n="$NOTVISIBLE" -v t="$TOTAL" \
	'BEGIN{printf "%.0f", 100*(c*1.0 + s*0.5 + u*0.25 + n*0.0)/t}')
echo "Phases CONFIRMED by packets:       $CONFIRMED / $TOTAL"
echo "Phases STRONG INFERENCE:           $STRONG / $TOTAL"
echo "Phases UNCONFIRMED:                $UNCONFIRMED / $TOTAL"
echo "Phases NOT VISIBLE IN PCAP:        $NOTVISIBLE / $TOTAL"
echo "Overall packet-visibility score: ${SCORE}/100"
echo "(weighted: CONFIRMED counts fully, STRONG INFERENCE half, UNCONFIRMED a quarter,"
echo " NOT VISIBLE zero — this rewards direct packet proof over narrative plausibility)"
echo ""
#============= END VISIBILITY SCORE ================

#============= START CLOSING LESSON ================
echo "=== LESSON: PACKET EVIDENCE VS. LOG EVIDENCE ==="
echo "This capture proves that traffic matching each phase of the attack occurred, with"
echo "exact timestamps and, in three phases, literal payload content. What packets alone"
echo "cannot prove is intent, authentication outcome on the server side, or exactly what"
echo "data left the building beyond the samples this capture happened to contain — a TLS"
echo "session looks identical whether the login succeeded or failed, and a capture only"
echo "shows what passed the collection point during its window. Endpoint, authentication,"
echo "and application logs answer 'what did the system decide'; packet capture answers"
echo "'what was sent and when.' A complete investigation needs both: packets anchor the"
echo "timeline in unforgeable fact, and logs fill in the outcomes packets cannot see."
#============= END CLOSING LESSON ================
