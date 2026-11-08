# IR Activation: IR-2026-0420-01

- incident_id: IR-2026-0420-01
- declared_at: 2026-04-20T19:52Z
- declared_by: Tales Lima, on-call IR
- triggering_signal: phone call from Mike Torres (Network Engineer) at 2026-04-20T19:43:18Z, see `torres_call_transcript.md`
- initial_severity: SEV1
- decision_authority: Patricia Morales, CISO (Executive Sponsor). SEV1 is above the IR Commander authority ceiling (SEV2), so the CISO owns business-impacting decisions from the first minute.
- ir_commander: James Chen, SOC Lead
- scribe: Sarah Park, IT Director (backup Scribe; Mike Torres, primary Scribe, is reassigned to evidence acquisition)

## What was known at 19:52Z

Facts from the call, nothing else verified yet:

1. `CS-WS-101` (clinical coordinator station, ED charge desk, Site A / Main) is very slow and the on-call nurse reports that "the files on my desktop look different" (possible file renaming, an early sign of encryption).
2. SIEM rule `wz-edr-200214` (service installation) fired on `CS-WS-104`, `CS-WS-107`, `CS-WS-112`, three clinical workstations at Main, inside one 12-minute window this afternoon.
3. The installed service is `WinHealthSvc` with image path `C:\ProgramData\Microsoft\svchost32.exe`. That is not a Microsoft path or binary name: the same unsigned binary installed as a service on several hosts means remote service execution by an attacker.
4. `SCHED-SVR-01` (scheduling server, Main) has had CPU pinned and a very high disk queue for about 90 minutes (since about 18:13Z).
5. Torres captured memory of `CS-WS-101` with WinPmem at 19:38Z (file written 19:41Z, no hash recorded). No host is isolated. The file server and the other hosts are untouched.

## Severity reasoning

SEV1 is declared on the evidence above, using `severity_matrix.md`:

| Matrix dimension | Evidence at 19:52Z | Tier reached |
|---|---|---|
| Patient safety impact | ED charge desk workstation degraded during a live shift; scheduling server saturated; four clinical workstations under attacker control | high |
| Data exposure | Attacker has SYSTEM-level code execution on clinical workstations with EHR and file share access; exposure is suspected, not yet confirmed | suspected (SEV3 alone) |
| Service availability | One clinical workstation degraded, scheduling server degraded; possible encryption starting on CS-WS-101 | degraded, trending to outage |
| Scope | At least 4 workstations + 1 server at one clinical site; same service on all of them | multi-host |

- SEV2 conditions ("malware confirmed on a single workstation") are already exceeded: the same malicious service is on at least four hosts.
- The pattern (unsigned service binary pushed to several hosts, server disk saturation, users seeing renamed files) matches the SEV1 definition "ransomware affecting clinical systems". Ransomware is suspected, not confirmed. Under the matrix, severity is set by the worst credible case when patient care is involved, and the cost of being wrong is asymmetric: an over-declared SEV1 costs a few phone calls on a Sunday evening, an under-declared SEV2 could let encryption run across a clinical site while the people with authority to approve downtime are not on the call.
- Playbook PB-001 (as updated by PB-UPD-004) escalates to SEV1 when "attacker activity reaches clinical systems" with ePHI in the blast radius and when "more than one MedDefense account" or host is compromised.
- De-escalation rule: severity drops only after confirmed containment and IR Commander approval (severity_matrix.md, escalation rule).

## Playbook activated

- Primary: **PB-001 Credential Exposure via Phishing** (`5x00_incident_response/playbook_credential_exposure.yaml`) including the 5x03 updates PB-UPD-004 (`hipaa_assessment` decision node, Legal_Liaison within 1 hour when an ePHI system is in the blast radius) and PB-UPD-005 (workstation memory + persistence preservation before isolation).
  - Why: the lateral spread with one service name across hosts means the attacker holds reusable credentials; PB-001 owns credential revocation, Kerberos exposure and the HIPAA branch, which this case needs.
- Secondary: **PB-002 Clinical Service Degradation** (`playbook_clinical_degradation.yaml`) for the clinical-impact branch: call the on-call clinical lead first, confirm patient impact, trigger downtime procedures, use `comms_clinical_downtime.md`. Its indicators "unknown process on the server" and "mass file rename" are both present (SCHED-SVR-01, CS-WS-101).
- Gap recorded: MedDefense has no dedicated ransomware / multi-host intrusion playbook. PB-001 + PB-002 are combined for this incident. Logged for the post-incident review.

## Notifications (first 15 minutes, 19:52Z to 20:07Z)

Per `ir_team_structure.yaml` escalation SEV1 `on_detection`: IR_Commander, Technical_Lead, Executive_Sponsor, Scribe. Phone first, then the `#ir-2026-0420-01` channel.

- 19:52Z: James Chen, SOC Lead (IR Commander), phone. SEV1 declared, bridge opened, asked to take command of the bridge and the timeline.
- 19:54Z: Patricia Morales, CISO (Executive Sponsor, SEV1 decision authority), phone. Told that containment will need her approval because it takes clinical workstations and possibly the scheduling server offline.
- 19:56Z: Robert Kim, Infrastructure Lead (Technical Lead), phone. Asked to join the bridge, prepare EDR network containment for the affected hosts and the perimeter egress block, and execute nothing before evidence capture.
- 19:58Z: Sarah Park, IT Director (backup Scribe), phone. Asked to take over the timeline because Mike Torres becomes the evidence acquirer.
- 19:59Z: Mike Torres (already on the call), instruction: keep hands off all hosts, do not reboot or isolate anything, stand by to capture memory on CS-WS-104, CS-WS-107, CS-WS-112, SCHED-SVR-01 and FILE-SVR-01 from the IR jumpbox.
- 20:01Z: Main ED charge nurse (On-call Clinical Lead, PB-002 step 1), phone. Confirmed patient impact: one coordinator workstation degraded, ED and inpatient care continuing; asked to prepare paper downtime procedures for the ED charge desk and the scheduling desk.
- 20:05Z: executive status update sent to Dr. Patricia Morales (text below).

Within the first hour (SEV1 `on_confirmation`, and PB-UPD-004 "Legal_Liaison within 1 hour when an ePHI system enters the blast radius"):

- 20:12Z: Helena Reyes, General Counsel (Legal_Liaison). The compromised workstations have EHR and clinical file share access; HIPAA assessment clock may start. Litigation hold requested for all evidence under `LH-2026-0420-01`.
- 20:15Z: Marcus Webb, Communications Director (Communications_Lead). No external statement; prepare staff downtime notice for Main.

## First communication (verbatim)

- first_communication: executive_status_update sent to Dr. Morales at 20:05Z
- channel: phone call at 19:54Z followed by this written message by email and in `#ir-2026-0420-01`
- template: `comms_executive_update.md`

> **IR-2026-0420-01, SEV1, status update 1 (20:05Z):** At 19:52Z we declared a SEV1 security incident at the Main site. An unknown program has been installed as a service on at least four clinical workstations (CS-WS-101, CS-WS-104, CS-WS-107, CS-WS-112), and the scheduling server is under heavy unexplained load; one ED coordinator reports that files on her desktop look changed, which can be an early sign of ransomware, although no ransom note or encryption is confirmed yet. Patient care is continuing: one coordinator workstation is degraded and the ED charge nurse is preparing paper downtime procedures. We are capturing evidence now and will ask for your approval within 30 minutes to take the affected workstations, and possibly the scheduling server, off the network, which will move the ED charge desk and scheduling desk to downtime procedures. Patient data exposure is possible but not confirmed; Helena Reyes is being engaged. Next update at 20:35Z or sooner if anything changes.
