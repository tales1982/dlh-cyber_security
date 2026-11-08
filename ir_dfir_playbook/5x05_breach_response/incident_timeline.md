# Incident Timeline: IR-2026-0420-01

## Header

- incident_id: IR-2026-0420-01
- declared_at: 2026-04-20T19:52Z
- declared_by: Tales Lima, on-call IR
- initial_severity: SEV1
- current_severity: SEV1
- ir_commander: James Chen, SOC Lead
- decision_authority: Patricia Morales, CISO
- scribe: Sarah Park, IT Director (from 19:58Z; Mike Torres reassigned to evidence acquisition)
- litigation_hold: LH-2026-0420-01

## Rules

- Append-only. Entries are never edited or deleted. A correction is a new entry that names the entry it refines.
- Format: `timestamp | type | actor | description | source | certainty`
- Entries are written when the event happens. Attack events found later in the forensic phase are recorded at the time they were found, with the original event time in the description.

## Legend

- OBSERVATION: raw fact from a report, alert, log or artifact
- DECISION: a choice made by an authorized actor, with rationale
- ACTION: an operation executed against an asset, with owner
- COMMUNICATION: a message sent or received, with audience
- EVIDENCE: a preserved artifact with hash and storage path

## Entries

### Task 0: activation

- 2026-04-20T19:43:22Z | OBSERVATION | Mike Torres (relaying the on-call nurse, Main) | CS-WS-101 (clinical coordinator station, ED charge desk) is "crawling"; nurse reports "the files on my desktop look different", thinks some filenames changed; not verified by Torres. Separately, SCHED-SVR-01 has had CPU pinned and a saturated disk queue for ~90 min | source=torres_call_transcript.md 19:43:22-19:43:50 | certainty=probable (user report, not verified)
- 2026-04-20T19:44:20Z | OBSERVATION | SIEM rule wz-edr-200214 (reported by Mike Torres) | Service installation alert on CS-WS-104, CS-WS-107, CS-WS-112 (clinical workstations, Main) within one 12-minute window; service WinHealthSvc, image path C:\ProgramData\Microsoft\svchost32.exe (not a Microsoft path or name). Torres also reports a WinPmem memory capture of CS-WS-101 at 19:38Z, no hash, no host isolated | source=torres_call_transcript.md 19:44:20-19:45:12 + SIEM | certainty=confirmed (alert exists); alert time "this afternoon" not yet checked
- 2026-04-20T19:52:00Z | DECISION | Tales Lima | Incident IR-2026-0420-01 declared SEV1: same unsigned service on at least 4 clinical workstations + saturated scheduling server + user-visible file changes match "ransomware affecting clinical systems"; patient safety impact high; decision authority CISO; playbooks PB-001 (with PB-UPD-004/005) + PB-002 clinical branch | source=ir_activation.md, severity_matrix.md | certainty=high

### Task 0: notifications

- 2026-04-20T19:52:30Z | COMMUNICATION | Tales Lima | James Chen (IR Commander) called: SEV1 declared, bridge #ir-2026-0420-01 open | source=phone + incident channel | certainty=confirmed
- 2026-04-20T19:54:00Z | COMMUNICATION | Tales Lima | Patricia Morales (CISO, SEV1 decision authority) called: SEV1, containment approval needed within 30 min | source=phone | certainty=confirmed
- 2026-04-20T19:56:00Z | COMMUNICATION | Tales Lima | Robert Kim (Technical Lead) called: prepare EDR containment and perimeter block, execute nothing before evidence capture | source=phone | certainty=confirmed
- 2026-04-20T19:58:00Z | COMMUNICATION | Tales Lima | Sarah Park (backup Scribe) called and takes the timeline | source=phone | certainty=confirmed
- 2026-04-20T19:59:00Z | DECISION | Tales Lima | Mike Torres reassigned from Scribe to evidence acquirer; hands off all hosts until told; no reboot, no isolation | source=ir_activation.md | certainty=high
- 2026-04-20T20:01:00Z | COMMUNICATION | Tales Lima | Main ED charge nurse (On-call Clinical Lead, PB-002 step 1): care continuing, one coordinator workstation degraded; paper downtime prepared for ED charge desk and scheduling desk | source=phone | certainty=confirmed
- 2026-04-20T20:05:00Z | COMMUNICATION | Tales Lima | Executive status update 1 sent to Dr. Patricia Morales (email + channel), text in ir_activation.md; next update 20:35Z | source=comms_executive_update.md | certainty=confirmed

### Task 1: evidence preservation

- 2026-04-20T20:07:00Z | OBSERVATION | Tales Lima | SIEM query for svchost32.exe on all hosts returns a sixth host, SCHED-SVR-01: process started by services.exe at 18:02:18Z; matches Torres's "~90 min" of disk saturation. Scope expanded to six hosts | source=sysmon_multihost.jsonl (SIEM) | certainty=confirmed
- 2026-04-20T20:09:00Z | EVIDENCE | Tales Lima | ART-009 fileserver_access.evtx (FILE-SVR-01 Security log) exported first (rolling log, PHI record); sha256 d1704418690ebdd9f1b53f4d637f9317a3706a7b945f6f294ac4d8d4e95e5169, source = store | source=\\evidence\share\IR-2026-0420-01\ | certainty=confirmed
- 2026-04-20T20:10:00Z | EVIDENCE | Tales Lima | ART-001 cs-ws-101.mem (Torres, 19:38Z) hashed on the share: 565910b04b4521947aede9d48007520b369e09188783dcea3f3abf8d3006dc28, recorded as baseline (no acquisition hash exists); pre-custody gap 19:41Z-20:10Z | source=evidence_preservation.md ART-001 | certainty=confirmed
- 2026-04-20T20:11:00Z | EVIDENCE | Mike Torres | Signed statement for ART-001: acquired 19:38Z with WinPmem, written 19:41Z, file not opened since | source=evidence_preservation.md | certainty=confirmed
- 2026-04-20T20:12:00Z | COMMUNICATION | Tales Lima | Helena Reyes (General Counsel) informed: ePHI systems in blast radius, HIPAA assessment may be required; litigation hold LH-2026-0420-01 requested | source=PB-UPD-004 | certainty=confirmed
- 2026-04-20T20:12:30Z | ACTION | Mike Torres | Started WinPmem on SCHED-SVR-01 (priority 2, possible encryption in progress) via EDR live response | source=evidence_preservation.md ART-006 | certainty=confirmed
- 2026-04-20T20:14:00Z | ACTION | Robert Kim | Started FTK Imager disk image of CS-WS-101 over ir-jump01 (priority 1) | source=evidence_preservation.md ART-002 | certainty=confirmed
- 2026-04-20T20:14:30Z | ACTION | Mike Torres | Started WinPmem on CS-WS-104 | source=evidence_preservation.md ART-003 | certainty=confirmed
- 2026-04-20T20:15:00Z | COMMUNICATION | Tales Lima | Marcus Webb (Communications) informed: no external statement; prepare staff downtime notice for Main | source=phone | certainty=confirmed
- 2026-04-20T20:16:00Z | DECISION | Tales Lima | Containment strategy A (coordinated isolation in one window, SCHED-SVR-01 exception) presented on the bridge, see containment_decision.md | source=containment_decision.md | certainty=high
- 2026-04-20T20:18:00Z | DECISION | Patricia Morales | Strategy A approved (SEV1 authority); rollback trigger: clinical dependency broken beyond 15 min of downtime cover | source=containment_decision.md | certainty=confirmed
- 2026-04-20T20:20:00Z | EVIDENCE | Mike Torres | ART-003 cs-ws-104.mem, sha256 251a70a33d2c1ecb05b57ad884638c67178b11ab5900835c4d0b3c8fcbceeeb9 (source = store) | source=evidence store | certainty=confirmed
- 2026-04-20T20:21:00Z | EVIDENCE | Mike Torres | ART-006 sched-svr-01.mem, sha256 64aaa70726a272dbcb6001976020973099326dce77e36ba6e5cd9e1a08c9d8ae (source = store) | source=evidence store | certainty=confirmed
- 2026-04-20T20:24:00Z | EVIDENCE | Tales Lima | ART-010 proxy_72h.jsonl exported, sha256 c7b4ae53d3686338ae79b7efcc46fb952c2a1c33b317df60c1b530f27d8bba91 | source=SIEM | certainty=confirmed
- 2026-04-20T20:25:00Z | EVIDENCE | Mike Torres | ART-004 cs-ws-107.mem, sha256 5d56784e9cea089a758af2aabd3abebae461cc8008ce36f747f4619a34b0c208 | source=evidence store | certainty=confirmed
- 2026-04-20T20:26:00Z | EVIDENCE | Tales Lima | ART-011 sysmon_multihost.jsonl exported, sha256 1d949ecce295b2f579d8eb828b359277d540cad97bf64cc78a8bb1f3db9002d0 | source=SIEM | certainty=confirmed
- 2026-04-20T20:30:00Z | EVIDENCE | Mike Torres | ART-005 cs-ws-112.mem, sha256 d632fe64d3ffdc20df9c54515bece6ac4bca99abbae1e401375f10f2e5e9c064; last active-beacon host captured, perimeter block released | source=evidence store | certainty=confirmed
- 2026-04-20T20:35:00Z | COMMUNICATION | Tales Lima | Executive status update 2 to Dr. Morales: memory of all beacon hosts preserved, coordinated isolation under way, SCHED-SVR-01 added to scope | source=comms_executive_update.md | certainty=confirmed
- 2026-04-20T20:42:00Z | EVIDENCE | Mike Torres | ART-007 file-svr-01.mem, sha256 7aa955309bb9167af789a7c62a7c4190595eefba092bfbdcc8949dfd47042a3a | source=evidence store | certainty=confirmed
- 2026-04-20T20:58:00Z | EVIDENCE | Tales Lima | ART-008 file-svr-01_triage.zip (KAPE + ACLs + stager copy), sha256 ff0fc047bfea4b78f0f9107b52ac67ba0e5193daed64348254439fe117ab5205 | source=evidence store | certainty=confirmed
- 2026-04-20T21:38:00Z | EVIDENCE | Robert Kim | ART-002 cs-ws-101.dd finished, sha256 fca8e3094912e1cc28bbf609ab4c09bd78b78072ff1c68c827fc257f2c13da8a (FTK verify = store) | source=evidence store | certainty=confirmed
- 2026-04-20T21:40:00Z | ACTION | Tales Lima | sha256sum -c hashes.txt: 11/11 OK, manifest locked 0444 | source=evidence_preservation.md | certainty=confirmed

### Task 2: containment

- 2026-04-20T20:20:00Z | ACTION | Main scheduling desk | Moved to paper downtime before SCHED-SVR-01 isolation | source=containment_execution.md C-01 | certainty=confirmed
- 2026-04-20T20:21:30Z | ACTION | Robert Kim | C-01 SCHED-SVR-01 EDR network containment (planned exception, possible encryption) | source=containment_execution.md | certainty=confirmed
- 2026-04-20T20:31:05Z | ACTION | Robert Kim | C-02 perimeter deny 45.152.66.114 (rule IR-2026-0420-01-01) + proxy block *.office365-cdn.net | source=containment_execution.md | certainty=confirmed
- 2026-04-20T20:31:40Z | ACTION | Robert Kim | C-03 DNS sinkhole office365-cdn.net -> 10.30.250.53 | source=containment_execution.md | certainty=confirmed
- 2026-04-20T20:32:10Z | ACTION | Tales Lima | C-04 EDR containment CS-WS-104, CS-WS-107, CS-WS-112 (all contained by 20:32:58Z) | source=containment_execution.md | certainty=confirmed
- 2026-04-20T20:33:00Z | ACTION | Tales Lima | C-05 EDR containment CS-WS-101; FTK imaging continues through jumpbox | source=containment_execution.md | certainty=confirmed
- 2026-04-20T20:34:20Z | ACTION | Robert Kim | C-06 FILE-SVR-01 host firewall restriction (no internet, SMB only from clinical VLANs, compromised hosts denied) | source=containment_execution.md | certainty=confirmed
- 2026-04-20T20:37:10Z | ACTION | Tales Lima | C-07 fleet-wide EDR execution block for stager hash and encryption_staging.ps1 (1,214 agents by 20:41Z) | source=containment_execution.md | certainty=confirmed
- 2026-04-20T20:39:00Z | ACTION | Tales Lima | C-08 isolation verified from jumpbox and CS-WS-140 | source=containment_execution.md | certainty=confirmed
- 2026-04-20T20:44:00Z | ACTION | Robert Kim | C-09 passive DNS / proxy search: single C2 IP 45.152.66.114 | source=containment_execution.md | certainty=confirmed
- 2026-04-20T20:45:10Z | ACTION | Tales Lima | C-10 jdoe disabled, password reset, M365 sessions revoked | source=containment_execution.md | certainty=confirmed
- 2026-04-20T20:49:00Z | ACTION | Robert Kim | C-11 GPO deny network/RDP logon for local admin accounts on Workstations and Servers (1,180/1,214 by 21:05Z) | source=containment_execution.md | certainty=confirmed
- 2026-04-20T20:52:00Z | ACTION | Robert Kim | C-15 firewall log: last allowed C2 session 20:30:49Z, 17 denies until 20:32:58Z, none after | source=containment_execution.md | certainty=confirmed
- 2026-04-20T20:53:00Z | ACTION | Robert Kim | C-16 proxy: 0 allowed CONNECT to the C2 domain after 20:31:05Z | source=containment_execution.md | certainty=confirmed
- 2026-04-20T20:54:00Z | ACTION | Tales Lima | C-17 sinkhole: lookups only from the isolated hosts, none after 20:33:03Z, no seventh host | source=containment_execution.md | certainty=confirmed
- 2026-04-20T20:56:00Z | ACTION | Robert Kim | C-12 svc_sched reset | source=containment_execution.md | certainty=confirmed
- 2026-04-20T20:58:00Z | ACTION | Tales Lima | C-18 EDR: svchost32.exe on 6 hosts, all connections blocked, 0 bytes out. C2 severed (three sources) | source=containment_execution.md | certainty=confirmed
- 2026-04-20T21:02:00Z | ACTION | Tales Lima | C-13 forced reset + session revocation for 6 dwell-period users | source=containment_execution.md | certainty=confirmed
- 2026-04-20T21:06:00Z | ACTION | Tales Lima | C-14 no privileged logon on the six hosts during the dwell | source=containment_execution.md | certainty=confirmed
- 2026-04-20T21:10:00Z | DECISION | James Chen | Containment complete; SEV1 kept; forensic phase opens | source=containment_execution.md C-19 | certainty=confirmed
- 2026-04-20T21:15:00Z | COMMUNICATION | Tales Lima | Executive status update 3 to Dr. Morales: attackers cut off from all six computers, staged ransomware blocked, investigation started | source=comms_executive_update.md | certainty=confirmed

### Task 4: investigation

- 2026-04-20T21:45:00Z | ACTION | Tales Lima | Forensic session opened; sha256sum -c 11/11 OK | source=forensic_findings.md ART-001 verification | certainty=confirmed
- 2026-04-20T21:58:00Z | OBSERVATION | Tales Lima | Initial access reconstructed: Invoice_Q4_2025.docm from Outlook on the web (proxy download 2026-04-17T14:18:02Z; Word opened the Desktop copy at 14:17:52Z, 10 s earlier, discrepancy logged in PROXY-001) -> macro -> PowerShell 14:22:14Z -> downloader fetch 14:22:19Z -> first C2 14:23:07Z -> svchost32.exe process 14:23:14Z | source=forensic_findings.md MEM-001, MEM-002, PROXY-001, DISK-003 | certainty=confirmed
- 2026-04-20T22:05:00Z | OBSERVATION | Tales Lima | PHI access confirmed: 1,847 PDFs (1,104 lab results, 743 clinical notes) read on FILE-SVR-01 2026-04-19T02:14:01Z-02:41:12Z by svchost32.exe as MEDDEFENSE\jdoe | source=forensic_findings.md FS-001, FS-002, FS-003 | certainty=confirmed
- 2026-04-20T22:10:00Z | OBSERVATION | Tales Lima | 2,400,412 bytes sent from FILE-SVR-01 to the C2 at 2026-04-19T02:14:22Z during the reads; content unknown | source=forensic_findings.md PROXY-003 | certainty=probable
- 2026-04-20T22:12:00Z | COMMUNICATION | Tales Lima | Helena Reyes informed of FS-001/PROXY-003: HIPAA four-factor assessment starts at 23:00Z | source=PB-UPD-004 | certainty=confirmed
- 2026-04-20T22:20:00Z | OBSERVATION | Tales Lima | Lateral movement CS-WS-101 -> CS-WS-104/107/112 on 2026-04-19 00:03:44Z-00:17:35Z (SMB + remote service as jdoe); staging script dropped on the four workstations 2026-04-20 14:23:18Z-14:26:14Z, never executed | source=forensic_findings.md SYS-002, SYS-003 | certainty=confirmed
- 2026-04-20T22:30:00Z | OBSERVATION | Tales Lima | Refines entry 2026-04-20T19:44:20Z: service installed on six hosts; rule wz-edr-200214 missed CS-WS-101 and both servers (host group scope); alert timing still open | source=forensic_findings.md SYS-004 | certainty=probable
- 2026-04-20T22:40:00Z | ACTION | Tales Lima | Requested HIM mapping of the 1,847 files to patient MRNs (number of individuals) | source=forensic_findings.md open item 1 | certainty=confirmed
- 2026-04-20T22:55:00Z | ACTION | Tales Lima | Forensic session closed; sha256sum -c 11/11 OK | source=forensic_findings.md | certainty=confirmed

### Task 5: breach assessment and board brief

- 2026-04-20T23:00:00Z | ACTION | Tales Lima | HIPAA four-factor assessment started | source=hipaa_assessment.md | certainty=confirmed
- 2026-04-20T23:50:00Z | DECISION | Tales Lima | Assessment result: low probability of compromise NOT demonstrated; notification required; final determination by Helena Reyes before 07:00Z | source=hipaa_assessment.md | certainty=high
- 2026-04-20T23:50:30Z | COMMUNICATION | Tales Lima | Draft assessment reviewed with Helena Reyes on the bridge; written sign-off due 06:30Z | source=hipaa_assessment.md | certainty=confirmed
- 2026-04-21T06:30:00Z | COMMUNICATION | Tales Lima | executive_brief.md delivered to Dr. Morales for the 07:00Z board meeting | source=executive_brief.md | certainty=confirmed

### Task 7: eradication and recovery

- 2026-04-21T08:12:00Z | ACTION | Tales Lima | Eradication started after disk images ART-012..015 hashed; ERAD-001..006 beacon processes and stager removed on six hosts | source=eradication_checklist.yaml | certainty=confirmed
- 2026-04-21T08:40:00Z | ACTION | Tales Lima | ERAD-010..013 persistence removed and verified (service on 6 hosts, Run key on CS-WS-101, no scheduled task) | source=eradication_checklist.yaml | certainty=confirmed
- 2026-04-21T09:10:00Z | ACTION | Tales Lima | ERAD-020..022 staging scripts and klog.tmp removed and verified | source=eradication_checklist.yaml | certainty=confirmed
- 2026-04-21T09:40:00Z | ACTION | Robert Kim | ERAD-040 first krbtgt reset | source=eradication_checklist.yaml | certainty=confirmed
- 2026-04-21T15:30:00Z | ACTION | Robert Kim | ERAD-023 / ERAD-060 five hosts rebuilt from gold image, new computer accounts | source=eradication_checklist.yaml | certainty=confirmed
- 2026-04-21T20:05:00Z | ACTION | Robert Kim | ERAD-041 second krbtgt reset | source=eradication_checklist.yaml | certainty=confirmed
- 2026-04-22T16:05:00Z | ACTION | Tales Lima | recovery_validation.sh: ALL CHECKS PASSED (exit 0); hosts eligible for release from containment on CISO approval | source=recovery_validation.sh output | certainty=confirmed
