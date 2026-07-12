# Incident Classification — MedDefense Health Systems

## Methodology

Each incident from Marcus Webb's incident log was evaluated against the CIA Triad. The primary pillar reflects the direct impact described in the log entry. A secondary pillar is listed only when the log provides explicit textual support for it — speculative or hypothetical secondary impacts are deliberately excluded.

## Incident Classification Table

| ID | Date | Primary Pillar | Secondary Pillar |
|----|--------|-----------------|-------------------|
| A  | Jan 15 | Availability    | Integrity         |
| B  | Feb 2  | Confidentiality | None identified   |
| C  | Mar 18 | Integrity       | None identified   |
| D  | Apr 5  | Integrity       | None identified   |
| E  | May 22 | Availability    | None identified   |
| F  | Jun 10 | Confidentiality | None identified   |

## Justification by Incident

**A — Ransomware encrypted `billing-srv-01` (Jan 15)**
Primary — Availability: the server was inaccessible for 4 days, blocking insurance claims processing.
Secondary — Integrity: encryption is itself an unauthorized modification of the underlying data.

**B — Patient portal exposed other patients' lab results via URL manipulation (Feb 2)**
Primary — Confidentiality: a broken access control (IDOR) let an authenticated patient view another patient's lab results.
Secondary — None identified: no data was altered and no service became unavailable; this was exposure only.

**C — Database script overwrote medication dosage values (Mar 18)**
Primary — Integrity: an update script bug overwrote correct dosages with incorrect ones.
Secondary — None identified: the system stayed reachable throughout, and no unauthorized viewing is reported.

**D — Central's public website defaced (Apr 5)**
Primary — Integrity: homepage content was replaced with unauthorized content.
Secondary — None identified: the site holds no patient data, which rules out confidentiality, and it stayed reachable — only altered — until restored.

**E — EHR system down 9 hours during a database migration (May 22)**
Primary — Availability: the EHR was unreachable for 9 hours, forcing a fallback to paper records.
Secondary — None identified: no data alteration or unauthorized access is reported for this incident.

**F — Unmanaged personal laptop on the internal network for 3 weeks (Jun 10)**
Primary — Confidentiality: the laptop bypassed network segmentation and could reach the same segment as the HR file share.
Secondary — None identified: the torrent client is a policy/hygiene risk, but the log shows no evidence MedDefense data was altered or exfiltrated.
