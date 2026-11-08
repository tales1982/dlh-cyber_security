# Containment Execution: IR-2026-0420-01

- Strategy executed: A (coordinated isolation in one window) with the SCHED-SVR-01 exception, see `containment_decision.md`
- Approved by: Patricia Morales, CISO, 2026-04-20T20:18Z
- Run by: James Chen (IR Commander, bridge), executed by Tales Lima and Robert Kim from IR jumpbox `ir-jump01` (10.30.200.10)
- C2 indicators: domain `staging.office365-cdn.net` (squats Microsoft `office365` CDN naming), IP `45.152.66.114`, TCP 443
- Precondition per host: memory hash recorded in `hashes.txt` (evidence_preservation.md) before that host is isolated
- Append-only. Every completed step is also an ACTION entry in `incident_timeline.md`.

Format: step | UTC timestamp | actor | action | expected outcome | observed outcome | deviation notes

## 1. Host isolation sequence

- **C-01** | 2026-04-20T20:21:30Z | Robert Kim | WazuhEDR: network containment SET on SCHED-SVR-01 (policy `ir-isolate`: permit ir-jump01 + EDR manager only) | host unreachable except from jumpbox/EDR; attacker process loses C2 | console "Contained" 20:21:34Z; `svchost32.exe` still running (not killed, evidence), disk queue unchanged for 4 min then falling | Deviation (planned): isolated 10 min before the coordinated window because the disk activity may be encryption; ART-006 hash recorded 20:21Z first. Scheduling desk moved to paper at 20:20Z.

- **C-02** | 2026-04-20T20:31:05Z | Robert Kim | Perimeter firewall: rule `IR-2026-0420-01-01` deny ip any -> host 45.152.66.114 (outbound, all sources, logged); proxy category override "block" for `*.office365-cdn.net` | no MedDefense host can reach the C2 | rule committed 20:31:05Z; deny counter starts at 20:31:41Z (CS-WS-104 check-in denied) | no deviation. Applied after ART-005 (last active-beacon workstation) was hashed at 20:30Z.

- **C-03** | 2026-04-20T20:31:40Z | Robert Kim | Internal DNS: zone override for `office365-cdn.net` and `staging.office365-cdn.net` -> sinkhole 10.30.250.53 (logging) | any lookup resolves to the sinkhole, lookups are logged with source IP | sinkhole active 20:31:45Z; first lookup logged from 10.30.12.107 at 20:32:02Z | no deviation

- **C-04** | 2026-04-20T20:32:10Z | Tales Lima | WazuhEDR: network containment SET on CS-WS-104, CS-WS-107, CS-WS-112 in one batch job | all three "Contained" within 60 s | CS-WS-104 20:32:16Z, CS-WS-107 20:32:19Z, CS-WS-112 20:32:58Z (agent was mid-upload, retried once automatically) | minor: 40 s spread, inside the 5-minute window

- **C-05** | 2026-04-20T20:33:00Z | Tales Lima | WazuhEDR: network containment SET on CS-WS-101 | contained, FTK imaging over jumpbox continues | contained 20:33:03Z; FTK Imager progress on ir-jump01 continued without error (ART-002 at 41 %) | no deviation

- **C-06** | 2026-04-20T20:34:20Z | Robert Kim | FILE-SVR-01 host firewall (GPO `IR-FILESVR-RESTRICT`, applied with `gpupdate /force` via EDR): block all outbound to the internet; allow inbound SMB 445 only from clinical VLANs 10.30.20.0/22; deny inbound SMB/RPC/WinRM from 10.30.12.101/.104/.107/.112 and SCHED-SVR-01; allow ir-jump01 | clinicians keep read access to `\\FILE-SVR-01\clinical`; no path from compromised hosts or to the internet | GPO applied 20:35:02Z; test from clinical floor workstation CS-WS-140: lab PDF opens; test from ir-jump01: `Test-NetConnection 45.152.66.114 -Port 443` from FILE-SVR-01 = False | Deviation (planned): partial isolation only. Memory capture ART-007 was running and was not interrupted.

- **C-07** | 2026-04-20T20:37:10Z | Tales Lima | WazuhEDR fleet-wide IOC block (prevention policy): deny execution of sha256 `ff4c8a2d9e7b1a3c5d8f2e6b4a1d9c7f3e0b8a6d2c9e1f5a7b3d8c4e6f2a9b1d` (svchost32.exe), deny execution of any file named `encryption_staging.ps1`, deny `powershell.exe` with `-ep bypass` launched by services.exe or svchost32.exe | staged scripts cannot run even if triggered locally (scheduled task, service restart, reboot) | policy pushed to 1,214 agents by 20:41Z; test: `powershell -File C:\Windows\System32\encryption_staging.ps1` from live response on CS-WS-104 blocked, EDR event "prevented" | no deviation. Staged files are left in place for the disk images (removal is eradication).

- **C-08** | 2026-04-20T20:39:00Z | Tales Lima | Isolation check from ir-jump01 and from a non-compromised clinical workstation (CS-WS-140): ping + TCP 445/3389/5985 to the five isolated hosts | jumpbox OK, CS-WS-140 fails on every isolated host | jumpbox: ping 4/4 and 5985 open on all five; CS-WS-140: ping 0/4, 445 filtered on all five | no deviation

## 2. Firewall egress rule for the C2 domain

Covered by C-02 (IP deny), C-03 (DNS sinkhole) and the proxy block in C-02. Additional check:

- **C-09** | 2026-04-20T20:44:00Z | Robert Kim | Search for other resolutions of `staging.office365-cdn.net` in passive DNS / proxy (72 h) to catch a second C2 IP | single IP 45.152.66.114 | only 45.152.66.114 seen; no second IP, no other `*.office365-cdn.net` host contacted | no deviation

## 3. Credential revocation sequence

Accounts in scope are every account that authenticated on any of the six hosts between 2026-04-17T14:17Z (document opened) and isolation, from Security log 4624/4648 on the hosts plus the domain controllers. The attacker held an LSASS handle on CS-WS-101 (Sysmon 10, `0x1010`, 2026-04-17T14:25:02Z) and the SAM hashes (see forensic_findings.md MEM-005), so every credential on those hosts is treated as known to the attacker. Order: the account the attacker is actively using first, then the reused local administrator, then service accounts, then the other users.

- **C-10** | 2026-04-20T20:45:10Z | Tales Lima | `Disable-ADAccount -Identity jdoe`; `Set-ADAccountPassword -Identity jdoe -Reset` (random 32-char); `Revoke-MgUserSignInSession -UserId jdoe@meddefense.org` | account unusable on-prem and in M365; cloud refresh tokens revoked | DC01 event 4725 + 4724 at 20:45:12Z, replicated to DC02 20:45:30Z; Graph returned True | Deviation: Kerberos tickets already issued to jdoe stay valid until expiry (10 h TGT); covered by the krbtgt double reset in eradication. jdoe's manager informed at 20:47Z.

- **C-11** | 2026-04-20T20:49:00Z | Robert Kim | GPO `IR-DENY-LOCAL-NETWORK` on OU Workstations and OU Servers: "Deny access to this computer from the network" + "Deny log on through Remote Desktop" for `Local account and member of Administrators group` (S-1-5-114); `gpupdate /force` via EDR | the shared local admin `mdlocaladmin` hash (same NTLM on every clinical workstation, no LAPS) can no longer be used for pass-the-hash | GPO applied on 1,180 of 1,214 agents by 21:05Z; remaining 34 are powered off (laptops), flagged for next boot | Deviation: 34 hosts pending. The local password itself is rotated with LAPS in eradication.

- **C-12** | 2026-04-20T20:56:00Z | Robert Kim | Reset `svc_sched` (SCHED-SVR-01 service account) and update the scheduling service credential on the server through the jumpbox | service account hash obtained from SCHED-SVR-01 memory is useless | 4724 at 20:56:04Z; scheduling service stays stopped (host isolated) | no deviation

- **C-13** | 2026-04-20T21:02:00Z | Tales Lima | Force password reset at next logon + session revocation for the other 6 accounts with interactive logons on the six hosts during the dwell (ED on-call nurse account, 3 clinical staff on CS-WS-104/107/112, 2 scheduling clerks); list in `/evidence/IR-2026-0420-01/correlation/dwell_accounts.csv` | stolen passwords and sessions invalid | 6 x event 4724 + `ChangePasswordAtLogon` set 21:02-21:04Z; charge nurse informed staff by phone | no deviation

- **C-14** | 2026-04-20T21:06:00Z | Tales Lima | Check for privileged exposure: query 4624/4672 on the six hosts for Domain Admins, Epic admins, IT admins during the dwell | none, or immediate reset | no privileged logon (4672 with domain admin SID) on any of the six hosts during the dwell | no deviation. Machine accounts and krbtgt handled in eradication.

## 4. Proof that the C2 beacon is severed

- **C-15** | 2026-04-20T20:52:00Z | Robert Kim | Perimeter firewall log for 45.152.66.114, 20:00Z-20:52Z | allowed sessions stop at 20:31:05Z; only denies after | last allowed session CS-WS-112 -> 45.152.66.114:443 at 20:30:49Z; 17 denied attempts 20:31:41Z-20:32:58Z from 10.30.12.104, .107, .112, .101 (beacons still alive, retrying); 0 attempts after 20:33:03Z (hosts contained) | no deviation

- **C-16** | 2026-04-20T20:53:00Z | Robert Kim | Proxy log: CONNECT to `staging.office365-cdn.net` after 20:31:05Z | 0 allowed | 0 allowed, 9 blocked (category override) 20:31:12Z-20:32:50Z | no deviation

- **C-17** | 2026-04-20T20:54:00Z | Tales Lima | DNS sinkhole log 10.30.250.53 | lookups only from the isolated hosts before containment, none after | 6 lookups 20:32:02Z-20:32:57Z from .104/.107/.112/.101; none after 20:33:03Z; no lookup from any other MedDefense host | no deviation (confirms no seventh infected host querying the domain)

- **C-18** | 2026-04-20T20:58:00Z | Tales Lima | EDR network telemetry for process `svchost32.exe` on all agents, 20:33Z-20:58Z | only blocked connection attempts, zero bytes sent | 6 hosts show `svchost32.exe` still running with connect attempts every ~60 s, all `blocked by containment`, 0 bytes out | no deviation. **C2 severed on all six hosts, confirmed from three independent sources (firewall, proxy/DNS, EDR).**

- **C-19** | 2026-04-20T21:10:00Z | James Chen | Bridge decision: containment complete; severity stays SEV1 (PHI access confirmed on FILE-SVR-01, see forensic_findings.md FS-001); forensic phase opens | containment declared | declared at 21:10Z, executive update 2 sent to Dr. Morales at 21:15Z | no deviation
