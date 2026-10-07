# 4x05 — Attack Reconstruction: HEALTHBANE End-to-End

Capstone reconstruction of the HEALTHBANE campaign against MedDefense
Health Systems, unifying five prior investigation modules (4x00 phishing,
4x01 network forensics, 4x02 intelligence, 4x03 malware, 4x04 threat
hunting) with new incident-response evidence (firewall export, memory
capture, disk forensics, IR team notes) gathered after WS-RECV-03 was
isolated on 2026-05-15.

## Deliverables

| # | File | Summary |
|---|---|---|
| 0 | [0-evidence_index.sh](0-evidence_index.sh) | Catalogs all 13 real evidence sources (source, phase, type, temporal coverage, reliability, key findings), builds a temporal coverage matrix, and lists 13 critical questions the reconstruction must answer — including two independently-verified discrepancies between each ATT&CK layer's stored technique-count summary and a direct recount of its own data, and a three-way IP-mapping conflict between the network reference docs and the firewall export |

Tasks 1 through 15 (per the project's full exercise list) have not been
built yet — only Task 0 (Evidence Inventory) has been completed so far.

## Materials

`ir_evidence/`, `previous_findings/` and `reference/` are the unmodified
lab materials. All 13 files inside them were read in full before
`0-evidence_index.sh` was written, so every catalog entry, coverage claim
and critical question is grounded in actual file content rather than
assumed.

## Requirements checklist

- `0-evidence_index.sh` starts with `#!/bin/bash`, passes `shellcheck`,
  and ends with a trailing newline.
- Reads only from `ir_evidence/`, `previous_findings/` and `reference/`;
  produces deterministic output.

## Findings worth flagging (discovered while building Task 0)

- **Two ATT&CK Navigator layers don't match their own summaries.**
  `previous_findings/4x02_attack_mapping.json` stores "11 observed / 5
  inferred / 13 not covered," but a direct count of its own `techniques[]`
  array gives 8 / 7 / 14. `reference/attck_navigator_80pct.json` stores
  "not_covered: 3," but a direct count gives 4 — and the same file's own
  `open_hypotheses_for_4x05` list has exactly 4 entries, corroborating the
  recount over the stored field. `0-evidence_index.sh` recomputes both
  live with `jq` rather than trusting either stored summary.
- **Three servers have conflicting IP addresses across reference
  material.** `reference/meddefense_asset_inventory.txt` gives
  SRV-HEALTH-DB/SRV-INS-DB/SRV-FILE-01 as .15/.25/.30; the firewall
  export's own metadata gives the same three hosts as .30/.31/.40.
  SRV-DC-01 (.10) is the only one the two documents agree on — and
  asset_inventory's SRV-FILE-01 address (.30) is the exact address the
  firewall export assigns to SRV-HEALTH-DB. This has to be resolved
  before any lateral-movement target is attributed by IP alone.
- **The server-segment VLAN number disagrees between the two reference
  docs** (`network_topology.txt` says "100," `meddefense_asset_inventory.txt`
  says "VLAN-20" for every host on that same subnet).
- **`ir_team_notes.txt` contains an internal date inconsistency**: Entry
  #009 (Sarah Park) says the hunt was triggered "the day before isolation"
  on 2026-05-18, but Entry #001 (James Chen) dates isolation to
  2026-05-15 — three days earlier, not one day later. Flagged as Q13
  rather than silently resolved either way.

All four are listed as explicit critical questions in `0-evidence_index.sh`'s
output rather than being resolved by assumption.
