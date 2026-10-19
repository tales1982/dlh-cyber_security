# Filesystem Analysis: ART-001 (wst-ws-031.dd)

- **Case:** LH-2026-0414-01 / IR-2026-0414-01
- **Analyst:** Tales Lima
- **Host:** WST-WS-031 (10.42.118.31), user MEDDEFENSE\dmarsh, Windows 10 Pro 22H2
- **Tools:** The Sleuth Kit 4.12.1 (mmls, fsstat, fls, mactime, istat, icat), sha256sum, sqlite3, LECmd, PECmd
- **Time zone:** all timestamps UTC (`mactime -z UTC`)

## Artifact verification

- Hash at analysis start: `a8f2c49d67d8e175e97d5639c9e6c3dfc0042c06e337efa6b3bb8e727a3e8b7a` (matches baseline in hashes.txt, `verify_artifacts.sh` [PASS] at 2026-04-14T08:20:05Z)
- Hash at analysis end: same value, [PASS] at 2026-04-14T09:01:15Z
- Mounted read-only: yes (`mount -o ro,loop,offset=$((2048*512)),noexec,show_sys_files,streams_interface=windows wst-ws-031.dd /mnt/art001`); TSK commands run directly against the image file, which TSK opens read-only
- CoC entry updated: yes, ART-001 access logged at 2026-04-14T08:20:05Z, 08:21:10Z, 08:24:00Z, 08:31:45Z, 08:52:20Z, 09:01:15Z
- Every exported file was hashed after `icat` and stored in `hashes_derived.txt`

### Evidence-quality caveat (pre-custody)

`acquisition_notes.md` states that the source disk was mounted **read-write** and browsed with Explorer before imaging, and that no hash was taken at acquisition. Consequences for this analysis:

- `$STANDARD_INFORMATION` **access** times for anything touched during that mount are not attributable to the attacker. The mount window is visible in the image (see "Acquirer activity" below): 2026-04-14T04:36:52Z to 04:43:58Z.
- Creation and modification times are used as primary evidence; access times are only used when they fall before the containment of the host (03:24Z).
- File **content** integrity of the attacker files is confirmed independently: the SHA-256 of each exported file equals the hash recorded by EDR at creation time (LOG-003 / EDR telemetry), so the read-write mount did not alter their content.

## Partition layout

```text
$ mmls wst-ws-031.dd
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0125827071   0125825024   NTFS / exFAT (0x07)
003:  -------   0125827072   0125829119   0000002048   Unallocated
```

Offset used for NTFS analysis: **2048** (byte offset 1,048,576). Single NTFS volume of 125,825,024 sectors (~60 GiB) holding C:\.

## Filesystem metadata

```text
$ fsstat -o 2048 wst-ws-031.dd
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: NTFS
Volume Serial Number: 6A3E4F1B3E4EE6D1
OEM Name: NTFS
Volume Name: Windows
Version: Windows XP

METADATA INFORMATION
--------------------------------------------
First Cluster of MFT: 786432
First Cluster of MFT Mirror: 2
Size of MFT Entries: 1024 bytes
Size of Index Records: 4096 bytes
Range: 0 - 412160
Root Directory: 5

CONTENT INFORMATION
--------------------------------------------
Sector Size: 512
Cluster Size: 4096
Total Cluster Range: 0 - 15728127
Total Sector Range: 0 - 125825023

$AttrDef Attribute Values:
$STANDARD_INFORMATION (16)   Size: 48-72   Flags: Resident
$FILE_NAME (48)   Size: 68-578   Flags: Resident,Index
...
```

- Volume serial number: **6A3E4F1B3E4EE6D1** (ties the image to WST-WS-031; same serial appears in the LNK files' volume info).
- "Version: Windows XP" is how TSK labels NTFS 3.1; it is the normal Windows 10 NTFS version.
- **Last mount time:** fsstat does not print a mount time for NTFS, so it was derived from the `$Volume` (inode 3) metadata and `$LogFile`:

```text
$ istat -o 2048 wst-ws-031.dd 3 | sed -n '/STANDARD_INFORMATION/,/FILE_NAME/p'
$STANDARD_INFORMATION Attribute Values:
Flags: Hidden, System
Created:        2026-01-09 11:02:41.000000000 (UTC)
File Modified:  2026-04-14 04:36:52.418220500 (UTC)
MFT Modified:   2026-04-14 04:36:52.418220500 (UTC)
Accessed:       2026-04-14 04:36:52.418220500 (UTC)
```

The last mount recorded on the volume is **2026-04-14T04:36:52Z**. That is after VLAN isolation (03:24Z) and before FTK started (04:51Z), which matches the acquirer's read-write mount, not attacker activity.

## File listing and MAC timeline

```bash
fls -r -m C: -o 2048 wst-ws-031.dd > fls_output.txt        # body format, 412,160 MFT entries
mactime -b fls_output.txt -d -z UTC > mac_timeline.csv       # sortable CSV timeline
mactime -b fls_output.txt -d -z UTC 2026-04-13T18:00:00..2026-04-14T07:00:00 > mac_window.csv
sha256sum fls_output.txt mac_timeline.csv mac_window.csv >> hashes_derived.txt
```

Note: `fls -r -o 2048 wst-ws-031.dd > fls_output.txt` produces a plain listing; `-m C:` was added so the output is in **body file** format that `mactime -b` can read.

Relevant slice of `mac_window.csv` (Date, Size, Type `macb`, Mode, UID, GID, Meta, File Name):

```text
Mon Apr 13 2026 18:14:43,421004,m.cb,r/rrwxrwxrwx,0,0,98871-128-4,"C:/Users/dmarsh/Downloads/update.zip"
Mon Apr 13 2026 18:14:58,1132,macb,r/rrwxrwxrwx,0,0,104230-128-1,"C:/Users/dmarsh/AppData/Roaming/Microsoft/Windows/Recent/update.zip.lnk"
Mon Apr 13 2026 18:15:02,8412,...b,r/rrwxrwxrwx,0,0,104233-128-1,"C:/Users/dmarsh/AppData/Local/Temp/update.xml"
Mon Apr 13 2026 18:15:05,42816,m.cb,r/rrwxrwxrwx,0,0,104234-128-1,"C:/Users/dmarsh/AppData/Local/Temp/update.exe"
Mon Apr 13 2026 18:15:14,3486,macb,r/rrwxrwxrwx,0,0,51207-128-1,"C:/Windows/System32/Tasks/{7B4F2D81-19E2-4A8C-9E67-A1F0DE2C7B3A}"
Mon Apr 13 2026 18:15:18,10342,macb,r/rrwxrwxrwx,0,0,112040-128-3,"C:/Windows/Prefetch/UPDATE.EXE-6A1D3C2F.pf"
Tue Apr 14 2026 02:44:15,10342,mac.,r/rrwxrwxrwx,0,0,112040-128-3,"C:/Windows/Prefetch/UPDATE.EXE-6A1D3C2F.pf"
Tue Apr 14 2026 02:46:51,8412,m.c.,r/rrwxrwxrwx,0,0,104233-128-1,"C:/Users/dmarsh/AppData/Local/Temp/update.xml"
Tue Apr 14 2026 02:46:51,33680,mac.,r/rrwxrwxrwx,0,0,33891-128-3,"C:/Windows/Prefetch/POWERSHELL.EXE-022A1004.pf"
Tue Apr 14 2026 02:47:07,15890,macb,r/rrwxrwxrwx,0,0,112052-128-3,"C:/Windows/Prefetch/MSBUILD.EXE-B5A2A1B9.pf"
Tue Apr 14 2026 04:38:27,8412,.a..,r/rrwxrwxrwx,0,0,104233-128-1,"C:/Users/dmarsh/AppData/Local/Temp/update.xml"
Tue Apr 14 2026 04:38:27,42816,.a..,r/rrwxrwxrwx,0,0,104234-128-1,"C:/Users/dmarsh/AppData/Local/Temp/update.exe"
Tue Apr 14 2026 04:38:27,421004,.a..,r/rrwxrwxrwx,0,0,98871-128-4,"C:/Users/dmarsh/Downloads/update.zip"
```

Reading the timeline:

- 18:14:43 to 18:15:18 on 2026-04-13: download, open, extraction, first execution and persistence install happen in **35 seconds**, right after the phishing credential POST (18:14:41Z in LOG-001).
- 02:44:15 to 02:47:07 on 2026-04-14: second execution of update.exe at logon, PowerShell rewrites `update.xml` (02:46:51), MSBuild runs for the first time on this host (prefetch created 02:47:07, about 10 s after process start at 02:46:57).
- 04:38:27: access-time updates on all three attacker files at the same second, inside the acquirer's mount window. **Not attacker activity.**

## Paths examined

| Path | Result |
|---|---|
| `C:\Users\dmarsh\AppData\Local\Temp\` | `update.xml` and `update.exe` present (F01, F02). No other executables or scripts created after 2026-04-13T00:00Z. |
| `C:\Windows\System32\Tasks\` | One task with a GUID name, `{7B4F2D81-19E2-4A8C-9E67-A1F0DE2C7B3A}` (F03). All other task files predate 2026-03-01 and are signed Microsoft/vendor tasks. |
| `C:\Users\dmarsh\AppData\Roaming\Microsoft\Windows\Recent\` | `update.zip.lnk` (F05); the rest are routine lab documents. No LNK created after 2026-04-13T19:02Z (dmarsh logoff). |
| `C:\Users\dmarsh\AppData\Local\Microsoft\Windows\History\` | Legacy IE/Edge history folder: only `desktop.ini` and empty `History.IE5` container; dmarsh browses with Chrome (proxy UA `Chrome/124.0.0.0`). Browser history was taken from Chrome's `History` SQLite database instead (F06). |

## Key findings

### ART-001-F01: Malicious MSBuild staging file

- Path: `C:\Users\dmarsh\AppData\Local\Temp\update.xml`
- MFT entry: 104233-128-1 (`icat -o 2048 wst-ws-031.dd 104233 > export/update.xml`)
- Created: 2026-04-13T18:15:02Z
- Modified: 2026-04-14T02:46:51Z
- Accessed: 2026-04-14T04:38:27Z (acquirer mount window, not attributable to attacker)
- MFT changed: 2026-04-14T02:46:51Z
- Size: 8412 bytes
- SHA-256: `a4f1e9b4fe7aa6d5d3f3e2b8c9a7d4e8f5b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3`
- `$STANDARD_INFORMATION` vs `$FILE_NAME` (istat): creation times agree to the second; no sign of timestomping.
- Significance: MSBuild project file with an inline task (`<UsingTask TaskFactory="CodeTaskFactory">`) holding Base64-encoded C# shellcode loader. Modified at 02:46:51Z, 6 s before `MSBuild.exe C:\Users\dmarsh\AppData\Local\Temp\update.xml` started at 02:46:57Z, so the payload executed is the version on disk. Hash equals the EDR hash at creation, so the acquirer mount did not alter the content. ATT&CK T1127.001.
- Certainty: confirmed

### ART-001-F02: Second-stage dropped payload

- Path: `C:\Users\dmarsh\AppData\Local\Temp\update.exe`
- MFT entry: 104234-128-1
- Created: 2026-04-13T18:15:05Z
- Modified: 2026-04-13T18:15:05Z
- Accessed: 2026-04-14T04:38:27Z (acquirer mount window)
- Size: 42816 bytes
- SHA-256: `5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b`
- Significance: Unsigned PE32+ extracted from `update.zip`. It is the target of both persistence mechanisms (F03 and ART-001-R01) and the parent of `powershell.exe` PID 7812 (see memory_analysis.md). Executable sitting in a user Temp folder, named like a Windows component. ATT&CK T1204.002, T1036.005.
- Certainty: confirmed

### ART-001-F03: Scheduled task persistence

- Path: `C:\Windows\System32\Tasks\{7B4F2D81-19E2-4A8C-9E67-A1F0DE2C7B3A}`
- MFT entry: 51207-128-1
- Created: 2026-04-13T18:15:14Z
- Modified: 2026-04-13T18:15:14Z
- Accessed: 2026-04-13T18:15:14Z
- Size: 3486 bytes
- SHA-256: `9059995d5c36dfab9c4db1e688a565f07e9e717a1fcbc23a4041b655fcbd7753`
- Significance: Task XML with a `LogonTrigger` for MEDDEFENSE\dmarsh and an `Exec` action `C:\Users\dmarsh\AppData\Local\Temp\update.exe`, created 9 s after update.exe was written. GUID-only names imitate legitimate component tasks. Full XML parsed in persistence_analysis.md (ART-001-R02). ATT&CK T1053.005.
- Certainty: confirmed

### ART-001-F04: Initial delivery archive

- Path: `C:\Users\dmarsh\Downloads\update.zip`
- MFT entry: 98871-128-4 (`Zone.Identifier` ADS at 98871-128-6)
- Created: 2026-04-13T18:14:43Z
- Modified: 2026-04-13T18:14:43Z
- Accessed: 2026-04-14T04:38:27Z (acquirer mount window)
- Size: 421004 bytes
- SHA-256: `3c2a1b9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a`
- `Zone.Identifier` (Mark of the Web): `ZoneId=3`, `ReferrerUrl=https://ms0365-support.login-verification.click/auth/submit`, `HostUrl=https://ms0365-support.login-verification.click/auth/drop/update.zip`
- Significance: Size and URL match the proxy record at 18:14:43Z (LOG-001, 421004 bytes). The Mark of the Web ties the file on disk to the phishing domain without relying on the proxy. Contains update.xml + update.exe. ATT&CK T1566.002, T1105.
- Certainty: confirmed

### ART-001-F05: LNK file showing the user opened the archive

- Path: `C:\Users\dmarsh\AppData\Roaming\Microsoft\Windows\Recent\update.zip.lnk`
- MFT entry: 104230-128-1
- Created: 2026-04-13T18:14:58Z
- Modified: 2026-04-13T18:14:58Z
- Accessed: 2026-04-13T18:14:58Z
- Size: 1132 bytes
- SHA-256: `cc0f6d9eb1fcc687d24ce16b81e3537f1a562167ce53202b5ec9eb9ccf45f97e`
- LECmd: target `C:\Users\dmarsh\Downloads\update.zip`, target size 421004, volume serial 6A3E4F1B3E4EE6D1, machine ID `wst-ws-031`
- Significance: Proves the archive was opened interactively through Explorer by the dmarsh profile 15 s after download, which supports user execution (T1204.002). No LNK files exist for the LIS reports: the patient PDFs were read over SMB from WST-WS-017, not opened in Explorer on this host.
- Certainty: confirmed

### ART-001-F06: Browser history of the phishing visit and download

- Path: `C:\Users\dmarsh\AppData\Local\Google\Chrome\User Data\Default\History` (SQLite, MFT entry 87612-128-1)
- Created: 2025-09-02T07:15:33Z
- Modified: 2026-04-13T19:01:48Z
- Accessed: 2026-04-14T04:38:31Z (acquirer mount window)
- Size: 1835008 bytes
- SHA-256: `65d898f3b5537b044889942aac512e313359709e8de1435f406b344f8e903498`
- Query (on the exported copy): `SELECT datetime(last_visit_time/1e6-11644473600,'unixepoch'), url FROM urls WHERE url LIKE '%login-verification%';` and the same on `downloads`
- Results: visit to `https://ms0365-support.login-verification.click/auth` at 2026-04-13T18:14:02Z (referrer `outlook.office.com/mail/id/AAMkAG`); download row `update.zip`, received_bytes 421004, target `C:\Users\dmarsh\Downloads\update.zip`, end_time 18:14:43Z
- Significance: Host-side confirmation of the phishing click and download recorded by the proxy. The POST body (the credentials) is not stored in history; the credential submission is confirmed by the Azure AD sign-in from 45.63.9.88 in the same second (LOG-002). The legacy `...\Microsoft\Windows\History\` folder is empty, which is expected for a Chrome user, not a sign of wiping.
- Certainty: confirmed

### ART-001-F07: Prefetch execution evidence

| Prefetch file | MFT entry | Created | Last run(s) | Run count | Size | SHA-256 |
|---|---|---|---|---|---|---|
| `C:\Windows\Prefetch\UPDATE.EXE-6A1D3C2F.pf` | 112040 | 2026-04-13T18:15:18Z | 2026-04-14T02:44:05Z, 2026-04-13T18:15:08Z | 2 | 10342 | `1d8459d26b3bd11065e17eeee64fce3ff4c68cb588d69006b7de0aab8482f1e4` |
| `C:\Windows\Prefetch\MSBUILD.EXE-B5A2A1B9.pf` | 112052 | 2026-04-14T02:47:07Z | 2026-04-14T02:46:57Z | 1 | 15890 | `b7c1e0a4d2f95c3e8a61d0b4f7e29c5a3d8b1e6f0a4c7d2e9b5f8a1c3e6d0b47` |
| `C:\Windows\Prefetch\POWERSHELL.EXE-022A1004.pf` | 33891 | 2025-09-02T07:20:10Z | 2026-04-14T02:46:41Z | 57 | 33680 | `e3a9d5c1b7f2048e6c9a1d3b5f7e0c2a4d6b8f1e3c5a7d9b0f2e4c6a8d1b3f5e` |

- Significance: Execution of update.exe twice (first by the user on 2026-04-13, then at logon on 2026-04-14) and **first-ever** execution of MSBuild.exe on a laboratory workstation. MSBuild prefetch "files loaded" list includes `\USERS\DMARSH\APPDATA\LOCAL\TEMP\UPDATE.XML` and `CLR.DLL`/`MICROSOFT.BUILD.TASKS.V4.0.DLL`, consistent with inline C# compilation. Prefetch proves execution and time without event logs.
- Certainty: confirmed

### ART-001-F08: Acquirer activity in the image (deviation, not attacker)

- Evidence: `$Volume` modified 2026-04-14T04:36:52Z; `$UsnJrnl:$J` (MFT entry 87412) holds 41 records between 04:36:52Z and 04:43:58Z, all `BASIC_INFO_CHANGE` / `CLOSE` on `Users\dmarsh\AppData\Local\Temp`, `Users\dmarsh\Downloads` and their files; **no** `DATA_OVERWRITE`, `DATA_EXTEND`, `FILE_DELETE` or `RENAME` reasons.
- Significance: Confirms the acquirer's statement that the volume was mounted read-write and browsed, and that no file content was written. Access times in that window are excluded from the attacker timeline. Recorded in chain_of_custody.md (pre-custody gap 3).
- Certainty: confirmed

## What the filesystem does NOT show (bounded conclusions)

- No evidence of data staging on WST-WS-031 (no archives, `.7z`/`.rar`, or large files created in user-writable paths after 2026-04-13T18:15:18Z).
- No patient PDFs or LIS paths on this disk: the ePHI access happened on LIS-WSIDE-01 from WST-WS-017 (LOG-002), which is outside this image.
- No evidence of anti-forensics (no deleted attacker files recovered with `fls -d`, no `$SI`/`$FN` mismatch, no event log clearing in `Security.evtx` MFT activity).
- The in-memory payload loaded by MSBuild is not on disk; see memory_analysis.md (ART-002-M03).

## SIEM indicators checked against disk

| SIEM indicator (LOG-003) | Disk result |
|---|---|
| `MSBuild.exe C:\Users\dmarsh\AppData\Local\Temp\update.xml` | Confirmed: update.xml present (F01), MSBuild prefetch (F07) |
| Parent `powershell.exe -ep bypass -w hidden -enc ...` | Confirmed: PowerShell prefetch last run 02:46:41Z, update.xml rewritten 02:46:51Z (F01, F07) |
| Typosquat visit 18:14:02Z | Confirmed: Chrome History (F06), Mark of the Web (F04) |
| SIEM does not mention update.exe, the Run key or the scheduled task | Added by disk analysis: F02, F03 and persistence_analysis.md |
