# Incident Timeline: IR-2026-0414-01

## Header

- incident_id: IR-2026-0414-01
- declared_at: 2026-04-14T02:51:04Z
- declared_by: Tales Lima, on-call SOC
- initial_severity: SEV2
- current_severity: SEV2
- ir_commander: James Chen, SOC Lead
- scribe: Tales Lima

## Legend

- OBSERVATION: raw fact from an alert, log, or artifact
- DECISION: a choice made by an authorized actor, with rationale
- ACTION: an operation executed against an asset, with owner
- COMMUNICATION: a message sent or received, with audience
- EVIDENCE: a preserved artifact with hash and storage path

## Entries

- 2026-04-14T02:47:11Z | OBSERVATION | SIEM rule wz-edr-100041 | powershell.exe (PID 7812, -ep bypass -w hidden -enc) parent of MSBuild.exe (PID 8104) running C:\Users\dmarsh\AppData\Local\Temp\update.xml as MEDDEFENSE\dmarsh on WST-WS-031, with outbound TCP 10.42.118.31:54917 -> 185.220.101.47:443 (Tor exit relay, VT 22/91) at 02:47:02Z | source=alert A-20260414-9841 | certainty=confirmed
- 2026-04-14T02:49:20Z | OBSERVATION | Tales Lima | Decoded PowerShell -enc argument (UTF-16LE base64) reads $s="https://ms0365-support[]login-verification[]click/auth"; the encoded command references the phishing domain | source=alert A-20260414-9841 process_tree.parent.cmdline | certainty=confirmed
- 2026-04-14T02:51:04Z | DECISION | Tales Lima | Incident declared: LOLBin execution (MSBuild, T1127.001) and active outbound session to Tor exit from a clinical workstation with LIS access; data exposure not confirmed yet | source=alert A-20260414-9841 + playbook PB-CRED-001 | certainty=confirmed
- 2026-04-14T02:51:40Z | DECISION | Tales Lima | Initial severity SEV2: matches severity matrix SEV2 "malware confirmed on a single workstation at a clinical site"; SEV1 not met (single host, no confirmed data exposure, no clinical outage, dmarsh is not a privileged account) | source=severity_matrix.md + alert A-20260414-9841 | certainty=high
- 2026-04-14T02:52:18Z | OBSERVATION | soc-evidence-collector v2.1 | 24h proxy export for dmarsh / 10.42.118.31 (window 2026-04-13T02:47:00Z to 2026-04-14T02:47:00Z) available for review | source=proxy_24h_dmarsh.log | certainty=confirmed
- 2026-04-14T02:54:05Z | OBSERVATION | Tales Lima | dmarsh opened Outlook message AAMkAG at 2026-04-13T18:13:44Z, then at 18:14:02Z requested https://ms0365-support[.]login-verification[.]click/auth (200) with that message as referer: phishing link click from email | source=proxy_24h_dmarsh.log | certainty=confirmed
- 2026-04-14T02:54:40Z | OBSERVATION | Tales Lima | dmarsh sent POST to https://ms0365-support[.]login-verification[.]click/auth/submit at 2026-04-13T18:14:41Z (302); credential submission is likely, POST body not available | source=proxy_24h_dmarsh.log | certainty=probable
- 2026-04-14T02:55:10Z | OBSERVATION | Tales Lima | dmarsh downloaded https://ms0365-support[.]login-verification[.]click/auth/drop/update.zip (200, 421004 bytes) at 2026-04-13T18:14:43Z; link between update.zip and Temp\update.xml not yet verified on disk | source=proxy_24h_dmarsh.log | certainty=probable
- 2026-04-14T02:55:45Z | OBSERVATION | Tales Lima | Proxy CONNECTs to 185.220.101.47:443 at 02:46:44Z, 02:47:02Z (4198 B) and 02:47:08Z (11203 B) match alert byte counts (sent 4198 / received 11203); C2 session corroborated by a second source | source=proxy_24h_dmarsh.log + alert A-20260414-9841 | certainty=confirmed
- 2026-04-14T02:56:30Z | DECISION | Tales Lima | Severity kept at SEV2 after proxy review (refines entry 2026-04-14T02:51:40Z): probable credential compromise of a clinical-access account plus malware on one host both map to SEV2; PB-CRED-001 applies; escalate to SEV1 if dmarsh holds privileged roles, other hosts are involved, or LIS/patient data exfiltration is confirmed | source=severity_matrix.md + playbook PB-CRED-001 + proxy_24h_dmarsh.log | certainty=high
- 2026-04-14T02:57:15Z | COMMUNICATION | Tales Lima | Notified James Chen (IR Commander) in #incident channel: IR-2026-0414-01 declared SEV2, WST-WS-031 / dmarsh, phishing at 2026-04-13T18:14Z -> MSBuild C2 to Tor exit, evidence preservation next, containment decision pending | source=incident channel | certainty=confirmed
