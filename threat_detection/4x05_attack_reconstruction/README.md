# 4x05 — Attack Reconstruction: HEALTHBANE End-to-End

Capstone reconstruction of the HEALTHBANE campaign against MedDefense
Health Systems, unifying five prior investigation modules (4x00 phishing,
4x01 network forensics, 4x02 intelligence, 4x03 malware, 4x04 threat
hunting) with new incident-response evidence (firewall export, memory
capture, disk forensics, IR team notes) gathered after WS-RECV-03 was
isolated on 2026-05-15.

**Bottom line: three production servers were breached and 98,140 patient
and insurance records were confirmed exfiltrated — not merely staged.**
See [15-reconstruction_report.md](15-reconstruction_report.md) for the
full synthesis.

## Deliverables

| # | File | Summary |
|---|---|---|
| 0 | [0-evidence_index.sh](0-evidence_index.sh) | Catalogs all 13 real evidence sources, builds a temporal coverage matrix, and lists 13 critical questions — including two verified discrepancies between each ATT&CK layer's stored technique-count summary and a direct recount of its own data, and a three-way IP-mapping conflict between the network reference docs and the firewall export |
| 1 | [1-memory_analysis.sh](1-memory_analysis.sh) | Parses the WS-RECV-03 memory capture: confirms the RAT, a live secondary-C2 connection, and the scheduled-task persistence mechanism; cross-references every finding against the 31-entry IOC master list (KNOWN/NEW/MODIFIED) |
| 2 | [2-disk_analysis.sh](2-disk_analysis.sh) | Parses the disk forensics report: recovers 3 deleted staging archives, the full scheduled-task XML, prefetch evidence of 6 anomalous tool executions, and a 12-minute event-log gap |
| 3 | [3-firewall_analysis.sh](3-firewall_analysis.sh) | Analyzes the 14-day firewall export via `jq`: confirms the secondary C2's first-seen timing, and proves — byte-for-byte — that all 3 staged archives were actually transmitted, not interrupted |
| 4 | [4-correlation_matrix.sh](4-correlation_matrix.sh) | Builds IOC/timeline/technique correlation matrices across all 13 sources; classifies every IOC CONVERGED/SINGLE-SOURCE/CONFLICTED and flags 2 genuine conflicts |
| 5 | [5-stages_1_2.sh](5-stages_1_2.sh) | Reconstructs Stage 1 (phishing) and Stage 2 (C2 establishment); corrects the assumption that the secondary C2 was part of initial C2 setup — it wasn't, by 23 days |
| 7 | [7-stage_4.sh](7-stage_4.sh) | Reconstructs Stage 4 (lateral movement, credential access, data staging, containment) in full, citing convergent evidence for every pivot |
| 8 | [8-unified_timeline.sh](8-unified_timeline.sh) | Merges Stages 1-4 into one 28-event chronology with temporal metrics (31-day dwell time, independently re-derived and matching the IR team's own figure) and explicitly distinguishes true evidence gaps from confirmed quiet periods |
| 9 | [9-attack_techniques.sh](9-attack_techniques.sh) | Final ATT&CK inventory: 28/29 techniques in the original threat model now CONFIRMED (97%), plus 3 techniques found outside that model entirely |
| 12 | [12-data_exposure.sh](12-data_exposure.sh) | Data exposure assessment: confirms HIPAA notification threshold is MET based on direct transmission evidence, not staging alone |
| 15 | [15-reconstruction_report.md](15-reconstruction_report.md) | Final synthesis report for SOC + board + Legal: executive summary, full stage-by-stage reconstruction, impact assessment, defensive posture evaluation and remediation plan |

Tasks 6, 10, 11, 13 and 14 were not part of the pasted exercise batch.
Where later deliverables explicitly depend on them (Task 8 merging a
"Stage 3," Task 15's report structure calling for Sections 7-8), the
needed content is pulled directly from `previous_findings/` and
`ir_evidence/` instead and each file/section says so explicitly.

## Materials

`ir_evidence/`, `previous_findings/` and `reference/` are the unmodified
lab materials. All 13 files inside them were read in full before any
script was written, so every catalog entry, coverage claim, correlation,
timeline event and impact figure is grounded in actual file content.

## Requirements checklist

- Every `.sh` file starts with `#!/bin/bash`, passes `shellcheck` cleanly,
  and ends with a trailing newline — verified for all 10 scripts.
- All scripts read only from `ir_evidence/`, `previous_findings/` and
  `reference/`; output is deterministic.
- `15-reconstruction_report.md` cites every numeric claim back to the
  script or evidence file that established it.

## Findings worth flagging (discovered while building this module)

- **Two ATT&CK Navigator layers don't match their own stored summaries.**
  `previous_findings/4x02_attack_mapping.json` claims "11/5/13" but a
  direct recount of its own `techniques[]` array gives 8/7/14.
  `reference/attck_navigator_80pct.json` claims "not_covered: 3" but a
  direct recount gives 4 — corroborated by that same file's own
  `open_hypotheses_for_4x05` list, which has exactly 4 entries. Every
  coverage percentage in this module (0, 9, 15) is computed live from the
  techniques array, never from either stored summary.
- **Three servers have conflicting IP addresses across reference
  material** (`meddefense_asset_inventory.txt` vs. the firewall export's
  own metadata) — SRV-DC-01 is the only one the two documents agree on.
- **The server-segment VLAN number disagrees** between
  `network_topology.txt` ("100") and `meddefense_asset_inventory.txt`
  ("VLAN-20").
- **The secondary C2 indicator has two different IOC IDs** minted
  independently by two IR sub-sources (`memory_artifacts.txt` calls it
  HB-IOC-NEW-001; the firewall export's own summary calls the same
  indicator HB-IOC-NEW-006).
- **`ir_team_notes.txt` contains an internal date inconsistency**
  (Entry #009 vs. Entry #001) about when the hunt was triggered relative
  to isolation — flagged in Task 0 and Task 8 rather than silently
  resolved.
- **Exfiltration was completed, not interrupted.** A less careful read of
  the disk evidence alone (staged files, immediately deleted) could
  suggest the hunt caught the attacker mid-transfer. The firewall export's
  byte-exact match to each archive proves all three transfers actually
  completed, days before the hunt even escalated — this materially changes
  the HIPAA impact assessment in Task 12.

All of these are listed as explicit findings or critical questions in the
relevant script's output rather than being resolved by silent assumption.
