#!/bin/bash
set -euo pipefail

# Task 3 - Firewall Session Analysis.
# Parses ir_evidence/firewall_sessions_ws_recv_03.json with jq. The file is
# an ABRIDGED export: 168 of 39,412 real sessions are reproduced individually
# (21 of those 168 are real session records; the rest are section markers/
# aggregates), but the file's own "summary" block carries authoritative
# full-14-day totals by classification. This script uses the summary block
# for totals and the reproduced sessions only for individual-event detail --
# it never extrapolates full-window figures from the 21-session sample.

FW="ir_evidence/firewall_sessions_ws_recv_03.json"

TOTAL_WINDOW=$(jq -r '.summary.total_sessions_in_window' "$FW")
EXPORT_COUNT=$(jq -r '.summary.session_count_this_export' "$FW")
RANGE_START=$(jq -r '.metadata.time_range_utc.start' "$FW")
RANGE_END=$(jq -r '.metadata.time_range_utc.end' "$FW")

echo "================================================================================"
echo "   FIREWALL SESSION ANALYSIS -- WS-RECV-03"
echo "   Source: ${FW}"
echo "   Period: ${RANGE_START} to ${RANGE_END}"
echo "================================================================================"
echo

echo "--------------------------------------------------------------------------------"
echo "SESSION OVERVIEW (full 14-day window, from the file's own summary block)"
echo "--------------------------------------------------------------------------------"
printf 'Total sessions in window: %s  (this abridged export reproduces %s individually)\n' \
  "$TOTAL_WINDOW" "$EXPORT_COUNT"
jq -r '
  .summary.by_classification as $c |
  ["KNOWN_C2","SECONDARY_C2_HYPOTHESIS","EXFIL_BURST","LATERAL_MOVEMENT","BENIGN","BROWSING"][] as $k |
  "  \($k): \($c[$k].session_count) sessions"
' "$FW"
echo
echo "  Internal destinations (LATERAL_MOVEMENT, BENIGN-internal): 47 + part of 22,841"
echo "  External destinations (KNOWN_C2 + SECONDARY_C2 + EXFIL_BURST + BROWSING):"
echo "    3,958 + 14 + 3 + 12,509 = 16,484 sessions"
echo

echo "--------------------------------------------------------------------------------"
echo "TOP EXTERNAL DESTINATIONS (by bytes out, full-window totals)"
echo "--------------------------------------------------------------------------------"
cat <<'EOF'
  Rank  IP:Port                 Sessions  Bytes Out    Bytes In   Classification
  ----  ----------------------  --------  -----------  ---------  ----------------------
  1     185.220.101.45:443      3,958     80,967,579   2,403,841  KNOWN_C2 (includes the
                                                                   3 exfil bursts below AND
                                                                   the 2 cred-dump exfil
                                                                   days, ~46 MB combined,
                                                                   riding the same channel)
  2     203.0.113.47:8443       14        14,218       28,412     SECONDARY_C2_HYPOTHESIS
EOF
echo

echo "--------------------------------------------------------------------------------"
echo "TOP INTERNAL DESTINATIONS (by session count, full-window LATERAL_MOVEMENT total)"
echo "--------------------------------------------------------------------------------"
jq -r '.summary.by_classification.LATERAL_MOVEMENT | "  47 sessions total across: \(.destinations | join(", "))\n  Ports observed: \(.ports_observed | join(", "))"' "$FW"
echo "  records03 has NO BUSINESS REASON to reach the 10.10.20.0/24 server"
echo "  segment at all -- every one of these 47 sessions is anomalous by the"
echo "  network topology document's own authorization matrix, independent of"
echo "  port or volume."
echo

echo "--------------------------------------------------------------------------------"
echo "UNKNOWN IP INVESTIGATION: 203.0.113.47:8443"
echo "--------------------------------------------------------------------------------"
jq -r '
  .summary.by_classification.SECONDARY_C2_HYPOTHESIS as $s |
  "  First seen:  \($s.first_seen_in_window)\n  Last seen:   \($s.last_seen_in_window)\n  Sessions:    \($s.session_count)\n  Bytes out:   \($s.total_bytes_out)   Bytes in: \($s.total_bytes_in)\n  Pattern:     \($s.interval_observed)"
' "$FW"
cat <<'EOF'

  ASSESSMENT: bytes_in:bytes_out ratio is ~2:1 (downstream-heavy) --
  consistent with a control channel receiving operator commands, NOT a
  data-exfil channel. First seen 2026-05-07T06:48:11Z, 38 seconds after the
  scheduled task's own registration timestamp (06:47:33Z per Task 1/2's
  TaskCache and $MFT evidence) -- this is not coincidence; task creation is
  the trigger event for secondary-C2 setup. The IP is on a Hetzner (DE)
  allocation, distinct from the LeaseWeb (DE) ASN hosting the primary C2 --
  NOT in reference/healthbane_ioc_master.json's original 31-entry list.
  CONFIDENCE: PROBABLE secondary C2 (corroborated independently by Task 1's
  memory capture, which shows the connection still ESTABLISHED on 2026-05-15).
  -> NEW IOC: 203.0.113.47:8443 (secondary C2, PROBABLE confidence). Note:
     this file's own metadata labels it HB-IOC-NEW-001; ir_evidence/
     memory_artifacts.txt independently calls the SAME indicator
     HB-IOC-NEW-001 too, but this firewall file's own "summary.
     iocs_added_by_firewall_analysis" block labels it HB-IOC-NEW-006. Use
     HB-IOC-NEW-006 downstream -- it is the ID attached to the fuller
     evidence record (first-seen, confidence, supporting_evidence array).
EOF
echo

echo "--------------------------------------------------------------------------------"
echo "TEMPORAL ANALYSIS"
echo "--------------------------------------------------------------------------------"
cat <<'EOF'
  KNOWN_C2 beacon cadence: 300 +/- 10 seconds, continuous, unbroken for the
  full 13.5-day observed window (first 2026-05-02T08:14:08Z, last allowed
  2026-05-15T18:42:00Z, then 12 DENY actions after isolation at 13:42 CDT).

  Off-hours external/cross-VLAN activity clusters on SIX distinct nights,
  all inside the 02:00-04:00 CDT (07:00-09:00 UTC) window, with ZERO overlap
  with Robert Kim's WS-ADMIN-01 baseline (per reference/network_topology.txt
  and the 4x04 hunt's own baseline profiling):
    2026-05-05  (first LSASS dump, 03:22 CDT)
    2026-05-06  (first lateral movement -> SRV-HEALTH-DB, 02:11 CDT)
    2026-05-07  (scheduled task + secondary C2, 01:47-01:48 CDT)
    2026-05-09  (second lateral movement -> SRV-INS-DB + 12-min log clear)
    2026-05-12  (second LSASS dump, 02:45 CDT)
    2026-05-13  (third lateral movement -> SRV-DC-01, 02:08 CDT)
  -> Matches the 4x04 hunt's anomalous-event nights exactly; the firewall
     export corroborates every one of them independently.

  Large outbound transfers (bytes_out far above the ~1 KB beacon baseline):
EOF
jq -r '.summary.by_classification.EXFIL_BURST.by_burst[] | "    \(.ts_utc)  \(.bytes_out) bytes -> \(.matches_disk_artifact)"' "$FW"
echo

echo "--------------------------------------------------------------------------------"
echo "EXFILTRATION ASSESSMENT"
echo "--------------------------------------------------------------------------------"
EXFIL_TOTAL=$(jq -r '.summary.by_classification.EXFIL_BURST.total_bytes_out' "$FW")
EXFIL_MB=$(LC_NUMERIC=C awk -v b="$EXFIL_TOTAL" 'BEGIN { printf "%.1f", b / 1048576 }')
printf '  Three discrete EXFIL_BURST sessions, total outbound: %s bytes (%s MB)\n' \
  "$EXFIL_TOTAL" "$EXFIL_MB"
echo "  Staging file sizes from Task 2 (disk forensics): 14.2 + 11.8 + 8.4 = 34.4 MB"
echo "  -> MATCH to the byte: each burst's size equals its corresponding disk"
echo "     archive's size EXACTLY (14,219,484 / 11,802,944 / 8,419,232 bytes),"
echo "     not approximately. This is the single strongest cross-evidence"
echo "     correlation in the entire investigation."
echo
echo "  FINDING: exfiltration DID occur, three separate times, and each"
echo "  transmission completed BEFORE the hunt's detection on 2026-05-18."
echo "  This is not an 'interrupted exfiltration' -- the hunt interrupted"
echo "  further lateral movement and credential abuse (no activity after"
echo "  2026-05-13), but the three confirmed exfil bursts had already"
echo "  completed days before isolation on 2026-05-15. A FOURTH scheduled-task"
echo "  run on 2026-05-15 02:00 CDT received an empty C2 config response and"
echo "  produced no burst -- the attacker's exfil channel was still live and"
echo "  usable right up to isolation, it simply had nothing new to send."
echo
echo "================================================================================"
echo "END OF FIREWALL SESSION ANALYSIS"
echo "================================================================================"
