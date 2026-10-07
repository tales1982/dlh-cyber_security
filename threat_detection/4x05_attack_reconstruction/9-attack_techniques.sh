#!/bin/bash
set -euo pipefail

# Task 9 - Final ATT&CK Technique Identification.
# Reads reference/attck_navigator_80pct.json as the baseline (29 techniques;
# per Task 0's live recount this is 22 OBSERVED / 3 INFERRED / 4 NOT
# COVERED -- NOT the file's own stored summary of 23/3/3, which does not
# match its own techniques[] array). Re-assesses every technique against
# the full IR evidence picture from Tasks 1-8.

BASELINE="reference/attck_navigator_80pct.json"

OBSERVED=$(jq '[.techniques[] | select(.score==3)] | length' "$BASELINE")
INFERRED=$(jq '[.techniques[] | select(.score==2)] | length' "$BASELINE")
NOT_COVERED=$(jq '[.techniques[] | select(.score==0)] | length' "$BASELINE")

echo "================================================================================"
echo "   HEALTHBANE ATT&CK TECHNIQUE INVENTORY (FINAL)"
echo "   Total techniques in original threat model: 29"
printf '   Baseline (recomputed, not copied from stored summary): %s OBSERVED / %s INFERRED / %s NOT COVERED\n' \
  "$OBSERVED" "$INFERRED" "$NOT_COVERED"
echo "================================================================================"
echo

echo "--------------------------------------------------------------------------------"
echo "UNCHANGED (already OBSERVED/CONFIRMED pre-4x05, re-verified against IR evidence,"
echo "no contradiction found -- 22 techniques)"
echo "--------------------------------------------------------------------------------"
jq -r '.techniques[] | select(.score==3) | "  \(.techniqueID)\t\(.tactic)"' "$BASELINE" | sort
echo

echo "--------------------------------------------------------------------------------"
echo "UPGRADED (INFERRED -> CONFIRMED by direct IR evidence)"
echo "--------------------------------------------------------------------------------"
cat <<'EOF'
  T1041      Exfiltration Over C2 Channel
             Tactic: exfiltration
             Was: INFERRED (4x03 -- exfiltrator has a C2-upload code path,
               not exercised at MedDefense per 4x04).
             Now: CONFIRMED. IR-firewall's 3 EXFIL_BURST sessions match
               IR-disk's 3 recovered staging archives byte-for-byte
               (Tasks 2, 3, 7). This is direct transmission evidence, not
               capability inference.
             Evidence: IR-firewall, IR-disk.

  T1005      Data from Local System
             Tactic: collection
             Was: INFERRED (4x04 -- database access confirmed, specific
               data READ not yet evidenced). Note: the generic Task 9
               template lists T1005 as a technique to "add" as NEW; it is
               actually already present in this baseline as INFERRED, not
               absent -- this is an upgrade, not a new addition.
             Now: CONFIRMED. IR-disk recovered the actual query-output CSVs
               (47,138-row patient table, 51,002-row insurance table,
               1,184-row AD export) -- proof of data READ, not just
               database reachability.
             Evidence: IR-disk.
EOF
echo

echo "--------------------------------------------------------------------------------"
echo "NEWLY CONFIRMED (was NOT COVERED in the baseline -- all 4 of the"
echo "baseline's own open_hypotheses_for_4x05 items, now resolved)"
echo "--------------------------------------------------------------------------------"
cat <<'EOF'
  T1053.005  Scheduled Task/Job (persistence)
             Evidence: IR-memory (TaskCache hive), IR-disk (on-disk XML,
               byte-identical to the memory capture).

  T1074.001  Local Data Staging (collection)
             Evidence: IR-disk (3 recovered staging archives in
               C:\Users\Public\Tmp\, each deleted within minutes of use).

  T1560.001  Archive via Utility / Archive Collected Data (collection)
             Evidence: IR-disk + IR-memory (recovered script body calls
               Compress-Archive explicitly before each exfil).

  T1070.001  Clear Windows Event Logs (defense-evasion)
             Evidence: IR-disk (12-minute Security.evtx gap, $MFT BORN-time
               confirmed) + IR-memory (recovered exfiltrator config
               fragment with clear_logs:true).
EOF
echo

echo "--------------------------------------------------------------------------------"
echo "UNCHANGED, DELIBERATELY NOT UPGRADED (no supporting evidence found)"
echo "--------------------------------------------------------------------------------"
cat <<'EOF'
  T1048.003  Exfiltration Over DNS (exfiltration)
             Remains INFERRED. 4x01 confirmed only 2 DNS TXT test-ping
               queries (reachability checks, not bulk exfil, per 4x03's own
               assessment). No IR evidence source (memory, disk, firewall)
               shows DNS-tunnel traffic during the actual exfil cycles --
               all three confirmed exfil bursts moved over the primary
               HTTPS C2 channel instead (Task 3/7). Capability exists in
               the exfiltrator's code (4x03); it was not the channel this
               attacker actually used at MedDefense. Upgrading this without
               transmission evidence would repeat exactly the overclaiming
               error the project's OBSERVED/INFERRED discipline exists to
               prevent.
EOF
echo

echo "--------------------------------------------------------------------------------"
echo "CORRECTED: none."
echo "--------------------------------------------------------------------------------"
echo "  No IR finding directly contradicts an earlier layer's technique"
echo "  mapping. The closest candidate -- the 4x03 capability matrix's"
echo "  \"PersistViaTask\" branch marked \"did not execute in sandbox\" -- is a"
echo "  scope correction (controlled test vs. real environment), not a wrong"
echo "  technique attribution; 4x03 correctly identified the capability."
echo

echo "--------------------------------------------------------------------------------"
echo "TECHNIQUES BEYOND THE ORIGINAL 29-TECHNIQUE THREAT MODEL"
echo "(genuinely new to the whole HEALTHBANE campaign model, not just to"
echo "MedDefense's coverage of it -- found only in IR evidence)"
echo "--------------------------------------------------------------------------------"
cat <<'EOF'
  T1562.001  Disable or Modify Tools (defense-evasion)
             Defender exclusion for C:\Windows\Temp, added under records03's
             token ~9h before the first LSASS dump. Evidence: IR-memory,
             IR-disk. Not attributed to HEALTHBANE in ANY prior layer
             (4x00-4x04) or in the original 29-technique threat model.

  T1070.004  File Deletion (defense-evasion)
             Every staging artifact (D1, D2, D3, D5) deleted within 2-3
             minutes of creation. Evidence: IR-disk ($MFT). Distinct from
             T1070.001 (log clearing), and also absent from the original
             29-technique model.

  T1571      Non-Standard Port (command-and-control) -- TENTATIVE
             The secondary C2 on 203.0.113.47:8443 uses a non-standard port
             for its protocol. Flagged tentative pending the final mapping
             review; Task 4 raised this same tentative classification.
EOF
echo

echo "--------------------------------------------------------------------------------"
echo "COVERAGE EVOLUTION"
echo "--------------------------------------------------------------------------------"
cat <<'EOF'
  Post-4x02 (intelligence):   28% (8/29 -- per Task 0's live recount of
                               previous_findings/4x02_attack_mapping.json;
                               NOT that file's own stored "38%," which does
                               not match its own techniques[] array)
  Post-4x04 (hunting):        76% (22/29 -- per this script's live recount
                               of reference/attck_navigator_80pct.json;
                               NOT that file's own stored "80%")
  Post-4x05 (reconstruction): 97% (28/29 -- within the original 29-technique
                               model: 22 unchanged + 2 upgraded + 4 newly
                               confirmed = 28 OBSERVED, 1 remains INFERRED)
                               Plus 3 techniques found that fall OUTSIDE the
                               original 29-technique threat model entirely
                               (T1562.001, T1070.004, tentative T1571).
EOF
echo

echo "--------------------------------------------------------------------------------"
echo "REMAINING GAP: 1/29 (within the original threat model)"
echo "--------------------------------------------------------------------------------"
echo "  T1048.003  Exfiltration Over DNS"
echo "  Assessment: NOT a collection limitation -- every evidence source"
echo "  that could show DNS-tunnel traffic (4x01 PCAP, IR-firewall) was"
echo "  available and showed only 2 reachability-test queries, never bulk"
echo "  transfer. This reads as TECHNIQUE NOT EMPLOYED by this attacker at"
echo "  MedDefense, not as a blind spot in the evidence."
echo
echo "================================================================================"
echo "END OF FINAL ATT&CK TECHNIQUE INVENTORY"
echo "================================================================================"
