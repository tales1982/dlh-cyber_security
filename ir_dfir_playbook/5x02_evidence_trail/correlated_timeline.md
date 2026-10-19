# Correlated Incident Timeline: LH-2026-0414-01

- **Incident:** IR-2026-0414-01
- **Analyst:** Tales Lima
- **Sources:** ART-001 (disk WST-WS-031, see filesystem_analysis.md and persistence_analysis.md), ART-002 / ART-003 (memory, see memory_analysis.md), LOG-001 `proxy_log.jsonl`, LOG-002 `ad_auth_log.jsonl`, LOG-003 `siem_alert_export.json`
- **Line references** are 1-based line numbers in the JSONL files (LOG-001, LOG-002) or in the JSON file (LOG-003).
- **Certainty:** confirmed = directly recorded in at least one artifact (most events here are recorded in two or more independent sources); probable = strongly supported inference; possible = consistent with the evidence but not shown.
- All timestamps UTC, ISO 8601.

## Timeline

| Timestamp (UTC) | Source | Event | ATT&CK | Certainty | Evidence Ref |
|---|---|---|---|---|---|
| 2026-04-13T18:13:44Z | LOG-001 proxy | dmarsh opens Outlook message `AAMkAG` (phishing email, msg-AAMkAG-2026-04-13T18-13-00Z) | T1566.002 | confirmed | LOG-001 line 6 |
| 2026-04-13T18:14:02Z | LOG-001 proxy; ART-001 Chrome History | **Credential phishing link clicked**: GET `https://ms0365-support.login-verification.click/auth` with the Outlook message as referer (typosquat of Microsoft 365) | T1566.002 | confirmed | LOG-001 line 7; ART-001-F06; LOG-003 line 36 |
| 2026-04-13T18:14:41Z | LOG-001 proxy; LOG-002 azure_ad | **Credentials submitted to typosquat domain**: POST `/auth/submit` (form_submission, 302). In the **same second**, Azure AD sign-in as dmarsh from 45.63.9.88 (RU), MFA push approved, risk `impossibleTravel` not enforced | T1056.003, T1078.004, T1621 | confirmed | LOG-001 line 10; LOG-002 line 3 |
| 2026-04-13T18:14:43Z | LOG-001 proxy; ART-001 disk | `update.zip` (421004 bytes) downloaded from the phishing site to `C:\Users\dmarsh\Downloads\` with Mark of the Web pointing to the phishing URL | T1105, T1566.002 | confirmed | LOG-001 line 11; ART-001-F04; ART-001-F06 |
| 2026-04-13T18:14:58Z | ART-001 LNK | dmarsh opens update.zip in Explorer | T1204.002 | confirmed | ART-001-F05; ART-001-E04 |
| 2026-04-13T18:15:02Z | ART-001 MFT | **Malicious files dropped to AppData\Local\Temp**: `update.xml` (8412 B, sha256 a4f1e9b4...c2d3) created | T1204.002 | confirmed | ART-001-F01 |
| 2026-04-13T18:15:05Z | ART-001 MFT | **Malicious files dropped to AppData\Local\Temp**: `update.exe` (42816 B, sha256 5a4b3c2d...5a4b) created | T1204.002, T1036.005 | confirmed | ART-001-F02 |
| 2026-04-13T18:15:08Z | ART-001 UserAssist, Amcache, Prefetch | dmarsh double-clicks update.exe: first execution | T1204.002 | confirmed | ART-001-E01; ART-001-E02; ART-001-F07 |
| 2026-04-13T18:15:12Z | ART-001 NTUSER.DAT | **Run key persistence installed**: `HKCU\...\Run\WindowsUpdateSvc` = `C:\Users\dmarsh\AppData\Local\Temp\update.exe` | T1547.001 | confirmed | ART-001-R01 |
| 2026-04-13T18:15:14Z | ART-001 Tasks + TaskCache | **Scheduled task persistence installed**: `{7B4F2D81-19E2-4A8C-9E67-A1F0DE2C7B3A}`, LogonTrigger dmarsh, action update.exe, Hidden | T1053.005 | confirmed | ART-001-R02; ART-001-F03 |
| 2026-04-13T19:02:11Z | LOG-002 ad_dc01 | dmarsh logs off WST-WS-031; ShimCache flushed at shutdown 19:05:40Z | - | confirmed | LOG-002 line 4; ART-001-E03 |
| 2026-04-14T02:41:12Z | ART-002 memory | WST-WS-031 boots (System process create time) | - | confirmed | ART-002-M01 |
| 2026-04-14T02:44:02Z | LOG-002 ad_dc01 | Kerberos AS-REQ (TGT issued) for dmarsh from WST-WS-031, flagged `unusual_hour_for_user` | T1078.002 | confirmed | LOG-002 line 5 |
| 2026-04-14T02:44:03Z | LOG-002 ad_dc01; ART-002 memory | Interactive (type 2) logon of dmarsh on WST-WS-031, logon ID 0x3a71c2; explorer.exe PID 5920 starts. Who was at the console is not established by the evidence | T1078.002 | confirmed (logon); possible (attacker at console) | LOG-002 line 6; ART-002-M01; ART-002-M06 |
| 2026-04-14T02:44:05Z | ART-002 memory; ART-001 prefetch | update.exe PID 7204 starts with parent explorer.exe 5920 (Run-key launch pattern) | T1547.001 | confirmed (execution); probable (Run key, not task, as launcher) | ART-002-M01; ART-001-F07; ART-001-R01 |
| 2026-04-14T02:44:17Z | LOG-002 vpn | **Attacker VPN access using dmarsh credentials** from 45.63.9.88, the same RU IP that used the phished credentials on 2026-04-13; MFA push approved, conditional access passed | T1133, T1078.002 | confirmed | LOG-002 line 7; LOG-002 line 3 |
| 2026-04-14T02:46:41Z | ART-002 memory; LOG-003 SIEM | **powershell.exe execution with encoded payload**: PID 7812 (parent update.exe 7204) `-ep bypass -w hidden -enc`, decodes to the phishing domain | T1059.001, T1027 | confirmed | ART-002-M01; ART-002-M02; LOG-003 line 37 |
| 2026-04-14T02:46:51Z | ART-001 MFT | PowerShell rewrites `Temp\update.xml` (modified time) 6 s before MSBuild runs it | T1027 | confirmed | ART-001-F01 |
| 2026-04-14T02:46:57Z | ART-002 memory; ART-001 prefetch; LOG-003 SIEM | **msbuild.exe spawned by PowerShell**: PID 8104, parent 7812, `msbuild.exe ...\Temp\update.xml`; first MSBuild run ever on this host | T1127.001 | confirmed | ART-002-M01; ART-002-M02; ART-001-F07; LOG-003 line 38 |
| 2026-04-14T02:46:58Z | LOG-001 proxy | **C2 beacon starts**: MSBuild.exe PID 8104 first CONNECT to 185.220.101.47:443 (Tor exit relay) | T1071.001, T1090.003 | confirmed | LOG-001 line 12 |
| 2026-04-14T02:47:02Z | LOG-001 proxy; ART-002 memory | C2 session 10.42.118.31:54917 -> 185.220.101.47:443 ESTABLISHED (still open at memory capture) | T1071.001 | confirmed | LOG-001 line 13; ART-002-M03 |
| 2026-04-14T02:47:11Z | LOG-003 SIEM | SIEM alert A-20260414-9841 fires (rule wz-edr-100041, PowerShell -> MSBuild) | - | confirmed | LOG-003 line 9 |
| 2026-04-14T02:47:14Z | ART-002 memory | In-memory implant: 81920-byte RWX region with MZ header inside MSBuild 8104, unbacked by any file | T1055, T1620 | confirmed | ART-002-M05; ART-002-M04 |
| 2026-04-14T02:47:30Z | LOG-001 proxy; ART-002 memory | Second C2 session from PID 8104 to 185.220.101.47:443 | T1071.001 | confirmed | LOG-001 line 14; ART-002-M03 |
| 2026-04-14T03:02:00Z | ART-002 memory | **NTLM hash and Kerberos ticket material accessible in lsass.exe**: memory capture shows dmarsh TGT/tickets cached in lsass (session 0x3a71c2) and MSBuild 8104 connected to LSA (Kerberos ticket APIs in implant); local SAM hashes present. No lsass memory dump by the implant | T1558, T1003 | confirmed (material present); probable (tickets exported); possible (hashes obtained by attacker) | ART-002-M06; ART-002-M07; ART-002-M05 |
| 2026-04-14T03:22:47Z | LOG-002 ad_dc02 | **Kerberos TGS request for cifs/WST-WS-017** by dmarsh from WST-WS-031 (10.42.118.31); host/WST-WS-017 at 03:22:48Z | T1550.003, T1021.002 | confirmed | LOG-002 line 8; LOG-002 line 9 |
| 2026-04-14T03:23:01Z | LOG-002 ad_dc02; ART-003 memory | **Lateral movement logon to WST-WS-017**: network logon type 3, Kerberos, logon ID 0x7a2d18; inbound SMB from 10.42.118.31 seen on target | T1021.002 | confirmed | LOG-002 line 10; ART-003-M03; ART-003-M04 |
| 2026-04-14T03:23:44Z | ART-003 memory | powershell.exe PID 4402 started by services.exe on WST-WS-017 (remote service execution), encoded command decodes to `https://91.234.99.107/z` | T1569.002, T1059.001 | confirmed | ART-003-M01; ART-003-M02 |
| 2026-04-14T03:24:10Z | 5x01 incident_timeline.md | WST-WS-031 moved to quarantine VLAN 999; C2 to 185.220.101.47 severed (last flow 03:24:08Z) | - | confirmed | IR-2026-0414-01 incident_timeline entries 03:24:10Z, 03:28:05Z |
| 2026-04-14T03:24:12Z | ART-003 memory | MSBuild.exe PID 5108 (parent 4402) runs `Temp\update.xml` on WST-WS-017; RWX MZ region present | T1127.001, T1055 | confirmed | ART-003-M01; ART-003-M04 |
| 2026-04-14T03:27:13Z | LOG-001 proxy; ART-003 memory | **Second C2 beacon from WST-WS-017**: MSBuild PID 5108 -> 91.234.99.107:443 (c2_infrastructure), ESTABLISHED at capture; again 03:27:45Z | T1071.001 | confirmed | LOG-001 line 15; LOG-001 line 16; ART-003-M03 |
| 2026-04-14T03:38:00Z | acquisition_notes.md | Memory of WST-WS-017 captured (ART-003). Everything after this point on WST-WS-017 is outside the memory image | - | confirmed | chain_of_custody.md ART-003 |
| 2026-04-14T03:40:18Z | LOG-002 ad_dc02 | **Kerberos TGS request for cifs/LIS-WSIDE-01** by dmarsh from WST-WS-017 (10.42.118.17), where dmarsh has only a network session | T1550.003 | confirmed | LOG-002 line 11 |
| 2026-04-14T03:41:52Z | LOG-002 ad_dc02 | Second TGS request for cifs/LIS-WSIDE-01 flagged `second_request_with_ticket_reuse`: a dmarsh ticket brought from WST-WS-031 is replayed (Pass-the-Ticket) | T1550.003 | confirmed (request); probable (ticket exported on WST-WS-031) | LOG-002 line 12; ART-003-M04; ART-002-M06 |
| 2026-04-14T03:42:08Z | LOG-002 ad_dc02 | **Logon to LIS-WSIDE-01**: network logon type 3 by dmarsh from 10.42.118.17, Kerberos, logon ID 0x91f204 | T1021.002, T1078.002 | confirmed | LOG-002 line 13 |
| 2026-04-14T03:43:30Z | LOG-002 fileserver_audit | **14 patient lab report PDFs read on LIS-WSIDE-01**: event 4663, share `LIS_REPORTS$`, `C:\LIS\reports\daily\*.pdf`, access mask 0x1 (read), files_opened 14 | T1039, T1005 | confirmed | LOG-002 line 14 |
| 2026-04-14T03:43:30Z to 2026-04-14T07:42Z | LOG-001 proxy; network logs | No outbound transfer from LIS-WSIDE-01 or WST-WS-017 to 185.220.101.47 / 91.234.99.107 recorded after the PDF reads | T1041 (not observed) | possible (exfiltration not shown, not ruled out) | LOG-001 (no lines after line 16) |
| 2026-04-14T04:36:52Z | ART-001 $Volume, $UsnJrnl | Acquirer mounts WST-WS-031 disk read-write and browses Temp/Downloads (access times changed, no content written). Acquisition deviation, not attacker | - | confirmed | ART-001-F08; chain_of_custody.md gap 3 |
| 2026-04-14T04:51:00Z | acquisition_notes.md | Disk imaging of WST-WS-031 with FTK Imager starts (ends 06:14Z) | - | confirmed | chain_of_custody.md ART-001 |

## Kill chain

```text
Phishing email (18:13:44) -> fake M365 page (18:14:02) -> credentials stolen + used from RU (18:14:41)
 -> update.zip (18:14:43) -> user runs update.exe (18:15:08) -> Run key + scheduled task (18:15:12-14)
 -> next logon (02:44:03) -> update.exe -> encoded PowerShell -> MSBuild + in-memory implant (02:46:57)
 -> C2 #1 185.220.101.47 via Tor (02:46:58)       | VPN from 45.63.9.88 with dmarsh creds (02:44:17)
 -> Kerberos tickets of dmarsh available to implant (03:02 memory)
 -> TGS cifs/WST-WS-017 + remote service (03:22:47-03:24:12) -> C2 #2 91.234.99.107 (03:27:13)
 -> Pass-the-Ticket to cifs/LIS-WSIDE-01 (03:40:18-03:42:08) -> 14 patient PDFs read (03:43:30)
```

## Correlation notes

- **No single source shows the full chain.** The proxy shows the click and C2 but not execution; the disk shows delivery and persistence but not the in-memory implant; memory shows the implant and C2 but not the history before boot; the AD log shows the lateral movement and ePHI access but no processes.
- **SIEM indicators checked, not assumed.** Process tree (7812 -> 8104), command line and C2 IP in LOG-003 were all confirmed by memory (ART-002-M01/M02/M03). The SIEM did not know about update.exe, the two persistence mechanisms, the VPN session, the second host, the second C2 or the ePHI access. The EDR label "scheduled_task_logon" for update.exe is not supported by the process lineage (ART-001-R02).
- **Credential misuse started 8.5 hours before the alert** (18:14:41Z), and MFA did not stop it: the push was approved and the impossible-travel risk was not enforced.
- **Time correlation checks:** proxy CONNECT 02:46:58Z vs MSBuild start 02:46:57Z (1 s); netscan session created 02:47:02Z vs proxy 02:47:02Z (0 s); TGS for WST-WS-017 03:22:47Z vs inbound SMB on WST-WS-017 03:23:01Z. No clock skew above 1 s between sources was found.
- **Open questions (not asserted):** who performed the 02:44:03Z console logon; whether the PDFs left the network (no exfiltration evidence, but the PDF reads happened over SMB to WST-WS-017, whose C2 session was live, and no disk image of WST-WS-017 or LIS-WSIDE-01 exists); whether the VPN session (02:44:17Z) was used for any internal access (no VPN-sourced connections in the provided logs).
