#!/bin/bash
set -euo pipefail

# Task 12 - Data Exposure Assessment.
# Maps every compromised host to reference/meddefense_asset_inventory.txt's
# data-sensitivity classification, determines confirmed/potential/no access
# per host using Tasks 1-8's findings, and assesses HIPAA/regulatory
# implications. Every record count below is quoted directly from
# ir_evidence/disk_forensics_report.txt's recovered file contents.

echo "================================================================================"
echo "   DATA EXPOSURE ASSESSMENT"
echo "================================================================================"
echo

echo "--------------------------------------------------------------------------------"
echo "COMPROMISED SYSTEM MAPPING"
echo "--------------------------------------------------------------------------------"
cat <<'EOF'
  Host            Role                     Sensitivity        Access Level
  --------------  -----------------------  -----------------  ------------------
  WS-RECV-03      Records dept workstation LOW (local caches)  CONFIRMED (pivot
                                                                host for the full
                                                                intrusion)
  SRV-HEALTH-DB   Patient health records   CRITICAL (PHI)      CONFIRMED ACCESS --
                                                                query executed,
                                                                47,138-row result
                                                                recovered on disk,
                                                                transmitted (byte-
                                                                exact firewall match)
  SRV-INS-DB      Insurance claims DB      HIGH (PII+fin,      CONFIRMED ACCESS --
                                            partial PHI)        same pattern, 51,002
                                                                rows, transmitted
  SRV-DC-01       Domain controller        HIGH (auth          CONFIRMED ACCESS --
                                            material, NTDS.dit) Get-ADUser export
                                                                recovered (1,184
                                                                accounts), transmitted.
                                                                NTDS.dit extraction
                                                                itself NOT observed in
                                                                any evidence source --
                                                                this was read-level AD
                                                                enumeration, not a
                                                                DCSync/NTDS dump.
  SRV-FILE-01     Departmental file server MEDIUM (+ PHI in    NO ACCESS CONFIRMED --
                                            \shared\imaging)    not a lateral-movement
                                                                target in ANY evidence
                                                                source (4x04 hunt, IR
                                                                firewall, IR disk, IR
                                                                memory). It IS listed as
                                                                a watched "internal pivot
                                                                target" in the firewall
                                                                export's own metadata,
                                                                but the actual session
                                                                data never shows
                                                                malicious traffic to it
                                                                -- see Task 0's GAP 2.
                                                                Carried forward as an
                                                                explicit "not confirmed
                                                                exposed," not silently
                                                                omitted.
EOF
echo

echo "--------------------------------------------------------------------------------"
echo "EXFILTRATION STATUS"
echo "--------------------------------------------------------------------------------"
cat <<'EOF'
  Data staged on WS-RECV-03:    YES -- 34,441,660 bytes across 3 archives
                                 (IR-disk D1/D2/D3).
  Data transmitted externally:   YES, all three archives -- IR-firewall's 3
                                 EXFIL_BURST sessions match the 3 disk
                                 archives' byte counts EXACTLY (14,219,484 /
                                 11,802,944 / 8,419,232 bytes). This is not
                                 "probable," it is a direct byte-for-byte
                                 match between two independent collection
                                 points (Task 3/7).
  Exfiltration channel:          Primary HTTPS C2 (185.220.101.45:443),
                                 same channel as the beacon traffic -- NOT
                                 DNS tunneling (confirmed unused for bulk
                                 transfer, see Task 9) and NOT the secondary
                                 C2 (which carried only ~14 KB total, a
                                 control channel, not an exfil channel).
  Interruption:                  NONE of the three confirmed exfil cycles
                                 was interrupted -- each completed, start to
                                 delete, in under 3 minutes, days before the
                                 hunt's escalation. What the hunt interrupted
                                 was FURTHER activity: the last scheduled-
                                 task run (2026-05-15, empty config, no
                                 output) occurred AFTER the third and final
                                 confirmed exfil cycle, meaning the operator
                                 may simply have had nothing more to send
                                 that night, not that they were caught
                                 mid-transfer.

  CONCLUSION: data staging is CONFIRMED and exfiltration is CONFIRMED
  COMPLETED (not interrupted/partial) for all three recovered cycles. This
  is a materially more severe finding than "staging confirmed, exfiltration
  interrupted" -- the distinction matters directly for the HIPAA assessment
  below.
EOF
echo

echo "--------------------------------------------------------------------------------"
echo "DATA EXPOSURE BY TYPE"
echo "--------------------------------------------------------------------------------"
cat <<'EOF'
  Patient health records (PHI):
    Status:    EXFILTRATED (confirmed transmitted, not merely staged)
    Evidence:  IR-disk (staging_export_001.zip contents, CSV header
               patient_id,first_name,last_name,dob,ssn,diagnosis_codes),
               IR-firewall (byte-exact transmission match)
    Scope:     47,138 records -- matches reference/meddefense_asset_
               inventory.txt's own estimate of "~47,000 active patient
               records" within rounding distance.

  Insurance/claims data (PII + partial PHI):
    Status:    EXFILTRATED
    Evidence:  IR-disk (staging_export_002.zip, CSV header policy_id,
               member_id,first_name,last_name,ssn,plan_code,
               coverage_start,coverage_end), IR-firewall
    Scope:     51,002 records -- matches the asset inventory's "~51,000
               insurance member records" estimate.

  Active Directory account data (reconnaissance, not PHI/PII in the clinical
  sense, but sensitive auth-adjacent metadata):
    Status:    EXFILTRATED
    Evidence:  IR-disk (query_results.csv, Get-ADUser export), IR-firewall
    Scope:     1,184 domain accounts (includes service-account attributes,
               e.g. how the attacker could have learned svc_backup exists --
               no evidence svc_backup was itself abused).

  Imaging data (\shared\imaging on SRV-FILE-01, ~8,400 patients per the
  asset inventory):
    Status:    NOT EXPOSED in this evidence set (no lateral-movement
               evidence to SRV-FILE-01 in any source -- see Task 0 GAP 2
               and the host-mapping table above). Cannot be ruled out by
               absence of evidence given the firewall export's own flagged
               "watch" status for this host, but no source confirms access.

  Employee records (HR benefit forms on SRV-FILE-01, ~320 people):
    Status:    NOT EXPOSED -- same reasoning as imaging data above; no
               evidence of HR-system or SRV-FILE-01 access at all.
EOF
echo

echo "--------------------------------------------------------------------------------"
echo "REGULATORY ASSESSMENT"
echo "--------------------------------------------------------------------------------"
cat <<'EOF'
  HIPAA breach notification threshold: MET.
  Basis: confirmed exfiltration (not mere access, not mere staging) of
    47,138 patient records with direct PHI fields (name, DOB, SSN,
    diagnosis codes) and 51,002 insurance records with diagnosis-coded
    claims (PHI under HIPAA's broad definition per the asset inventory's
    own classification). Combined: 98,140 confirmed exfiltrated records,
    matching ir_team_notes.txt Entry #007's own stated HIPAA scoping figure
    exactly (independently re-derived here from the disk + firewall byte
    match, not copied from that entry).
  De-duplication note: ir_team_notes.txt Entry #009 (Sarah Park) notes
    overlap is expected between the patient and insurance cohorts (many
    patients are also insurance members) and gives a working estimate of
    78,000-82,000 UNIQUE individuals pending Legal's cross-database join --
    this evidence set does not contain the join itself, so this
    reconstruction reports both the raw combined count (98,140 records)
    and the pending de-duplicated estimate, and does not resolve between
    them.
  Mitigating factors:
    [*] NONE of the three exfil cycles was interrupted mid-transfer (this
        REMOVES "interruption" as a mitigating factor that a less rigorous
        reconstruction might have assumed).
    [*] SSN fields in SRV-HEALTH-DB are encrypted at rest per the asset
        inventory -- but the RECOVERED CSV in staging_export_001.zip has an
        ssn COLUMN in its header; whether the exfiltrated SSN values are
        still encrypted ciphertext or were decrypted by the SQL query
        before export is NOT determined by any evidence source here. This
        is a material open question for the regulatory assessment and
        should be resolved before finalizing breach severity -- flagging
        rather than assuming either answer.
    [*] Response time from detection to containment was reasonably fast
        once the hunt flagged the anomaly (escalation to isolation within
        the same day, per ir_team_notes.txt Entry #001), but this does not
        mitigate the already-completed exfiltration -- it only limited
        further loss.
  Recommended action: NOTIFY. HHS notification required within 60 days of
    discovery (legally defensible discovery date 2026-05-15 per Entry #007,
    deadline 2026-07-14); affected-individual notification on the same
    clock; state notification in TX/OK/AR per Entry #009. Resolve the SSN
    encryption-state question and the patient/insurance de-duplication
    before finalizing the exact notification count.
EOF
echo
echo "================================================================================"
echo "END OF DATA EXPOSURE ASSESSMENT"
echo "================================================================================"
