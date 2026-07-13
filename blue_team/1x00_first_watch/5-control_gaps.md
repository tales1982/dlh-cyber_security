# Control Gap Analysis — MedDefense Health Systems

## Gaps

### G-001

- **Gap Description:** No compensating controls exist anywhere in the Technical category systems that can't be fully secured with standard preventive/detective controls have no documented fallback protection.
- **Category x Function Missing:** Technical Compensating
- **Affected Asset(s) or Zone:** Any legacy or unpatchable system (e.g., devices that can't be updated or isolated)
- **Risk if Unaddressed:** Integrity and Availability  a system that can't be secured normally and has no fallback protection is an open path for an attacker exploiting a known weakness.
- **Evidence:** Task 4 Control Summary Matrix the entire Technical/Compensating column is empty.

### G-002

- **Gap Description:** Detective logs exist (firewall traffic, SSH auth logs) but nothing actively reviews or alerts on them; logs are checked manually only "when something breaks."
- **Category x Function Missing:** Technical Detective (logging exists, alerting does not)
- **Affected Asset(s) or Zone:** Entire network firewall, Windows servers, Active Directory
- **Risk if Unaddressed:** Confidentiality and Integrity an attacker can operate undetected for a long time, since discovery depends on someone noticing a visible symptom rather than an automated alert (exactly what happened with the cryptominer in Task 2).
- **Evidence:** Artifact 8  "No automated alerting on security events"; "We check manually if something breaks."

### G-003

- **Gap Description:** A nightly backup exists, but a full disaster recovery test has never been performed; the one partial test took 6 hours to restore a single server.
- **Category x Function Missing:** Technical Corrective (control exists but is unverified)
- **Affected Asset(s) or Zone:** `ehr-srv-01`, `ehr-db-01`, `billing-srv-01`, `ad-dc-01`, `file-srv-01`, `web-srv-01`
- **Risk if Unaddressed:** Availability in a real disaster, there is no confidence the restore process works at scale or within an acceptable time, so clinical operations could be down far longer than expected.
- **Evidence:** Artifact 5 "Full DR test: Never performed"; James Chen: "we have a backup process but no tested recovery procedure."

### G-004

- **Gap Description:** Antivirus (Sophos) only covers Windows workstations; Windows servers and all Linux servers are explicitly excluded from coverage.
- **Category x Function Missing:** Technical Preventive (partial coverage critical servers excluded)
- **Affected Asset(s) or Zone:** `ehr-srv-01`, `ehr-db-01`, `billing-srv-01`, `ad-dc-01`, `ad-dc-02`, `file-srv-01`, `web-srv-01`, `backup-srv-01`
- **Risk if Unaddressed:** Confidentiality, Integrity and Availability the servers holding the most sensitive data have no active malware defense, which is exactly how the cryptominer went undetected on `billing-srv-01` in Task 2.
- **Evidence:** Artifact 4 "Windows servers: 15 (NOT covered)... Linux servers: 0 (NOT covered)."

### G-005

- **Gap Description:** Every Administrative control identified is Preventive (password policy, training); there is no documented process for detecting policy violations, no formal incident response plan, and no disciplinary/deterrent policy on record.
- **Category x Function Missing:** Administrative Detective, Corrective, Compensating, and Deterrent (all four)
- **Affected Asset(s) or Zone:** Organization-wide (people and process layer)
- **Risk if Unaddressed:** Integrity and Availability when an incident happens, there is no documented process to follow, so the response is improvised rather than structured, extending downtime and increasing the chance of mistakes.
- **Evidence:** Task 4 matrix the Administrative row is only populated in the Preventive column.

### G-006

- **Gap Description:** Cameras only cover building entrances and the parking garage; there is no coverage of the server room corridor, network closets, or administrative wing, and no documented corrective procedure after a physical breach is discovered.
- **Category x Function Missing:** Physical Detective (incomplete coverage) and Physical Corrective (entirely absent)
- **Affected Asset(s) or Zone:** Server room, network closet, administrative wing (Central)
- **Risk if Unaddressed:** Confidentiality and Integrity physical intrusions into these zones (see Task 3, Observations 1, 2 and 5) would go completely unnoticed and unaddressed.
- **Evidence:** Artifact 6 "No cameras in server room area, network closets or administrative wing"; Task 3 walk-through observations.

## Pattern Analysis

MedDefense's posture is heavily prevention-oriented: nearly every control identified in Task 4 blocks something before it happens, while detective coverage is thin and unmonitored, and corrective, compensating, and deterrent controls are almost entirely absent. This means that once an attacker gets past a preventive control which has already happened twice on `billing-srv-01` MedDefense has very little ability to notice, contain, or recover quickly; incidents are discovered by accident rather than by design, and the response is improvised instead of following a tested plan.
