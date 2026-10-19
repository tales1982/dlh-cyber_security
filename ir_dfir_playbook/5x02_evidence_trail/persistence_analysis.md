# Persistence Artifact Analysis: ART-001 (wst-ws-031.dd)

- **Case:** LH-2026-0414-01 / IR-2026-0414-01
- **Analyst:** Tales Lima
- **Host / profile:** WST-WS-031, MEDDEFENSE\dmarsh (SID S-1-5-21-3141592653-589793238-462643383-1187)
- **Tools:** TSK `icat` (extraction), RegRipper 3.0 `rip.pl`, regipy 4.x, AppCompatCacheParser, AmcacheParser, LECmd, xmllint
- **Time zone:** UTC

## Artifact verification

- Hash at analysis start: `a8f2c49d67d8e175e97d5639c9e6c3dfc0042c06e337efa6b3bb8e727a3e8b7a` (matches baseline, `verify_artifacts.sh` [PASS])
- CoC entry updated: yes, ART-001 access logged at 2026-04-14T09:05Z (hash_verify), 09:06:30Z (export_section), 09:10Z (registry_parse), 09:48:40Z (hash_verify, end of session)
- Hives were **extracted** from the image with `icat` and parsed as copies; the image was never mounted read-write. Each exported hive was hashed into `hashes_derived.txt`. Transaction logs (`.LOG1`/`.LOG2`) were exported with each hive and replayed on the copy (regipy) so recent writes are not missed.

### Extraction

```bash
OFF=2048; IMG=wst-ws-031.dd; OUT=/cases/LH-2026-0414-01/export/registry
ifind -o $OFF -n "Users/dmarsh/NTUSER.DAT" $IMG                           # -> 61544
icat  -o $OFF $IMG 61544 > $OUT/NTUSER.DAT
icat  -o $OFF $IMG $(ifind -o $OFF -n "Windows/System32/config/SYSTEM"   $IMG) > $OUT/SYSTEM
icat  -o $OFF $IMG $(ifind -o $OFF -n "Windows/System32/config/SOFTWARE" $IMG) > $OUT/SOFTWARE
icat  -o $OFF $IMG $(ifind -o $OFF -n "Windows/AppCompat/Programs/Amcache.hve" $IMG) > $OUT/Amcache.hve
icat  -o $OFF $IMG 51207 > $OUT/task_7B4F2D81.xml
sha256sum $OUT/* >> hashes_derived.txt
```

## Registry persistence

### ART-001-R01: Run key

- Key: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (NTUSER.DAT of dmarsh)
- Value name: `WindowsUpdateSvc`
- Value type: REG_SZ
- Value data: `C:\Users\dmarsh\AppData\Local\Temp\update.exe`
- Last write: 2026-04-13T18:15:12Z
- Command: `rip.pl -r NTUSER.DAT -p run`
- Significance: Starts update.exe every time dmarsh logs on. Name imitates Windows Update; real Windows components never live in a user Temp folder. Written 7 s after update.exe was created (ART-001-F02) and 2 s before the scheduled task (R02). The process lineage in memory (update.exe PID 7204 with parent explorer.exe PID 5920, ART-002-M01) is the pattern of a Run-key launch, because Explorer runs the Run key at logon. ATT&CK T1547.001.
- Certainty: confirmed

### ART-001-R02: Scheduled task

- File: `C:\Windows\System32\Tasks\{7B4F2D81-19E2-4A8C-9E67-A1F0DE2C7B3A}` (ART-001-F03)
- Registry: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\{7B4F2D81-19E2-4A8C-9E67-A1F0DE2C7B3A}` (`Id` = `{C9E1F0A2-5B3D-4E77-8A21-6D4F9B0C3E15}`, `SD` present, so the task is not hidden by SD deletion) and `...\TaskCache\Tasks\{C9E1F0A2-...}`
- Last write (Tree key): 2026-04-13T18:15:14Z
- Parsed XML (`xmllint --xpath`):

```xml
<RegistrationInfo>
  <Date>2026-04-13T18:15:14</Date>
  <Author>MEDDEFENSE\dmarsh</Author>
  <URI>\{7B4F2D81-19E2-4A8C-9E67-A1F0DE2C7B3A}</URI>
</RegistrationInfo>
<Triggers>
  <LogonTrigger>
    <Enabled>true</Enabled>
    <UserId>MEDDEFENSE\dmarsh</UserId>
  </LogonTrigger>
</Triggers>
<Principals>
  <Principal id="Author">
    <UserId>S-1-5-21-3141592653-589793238-462643383-1187</UserId>
    <LogonType>InteractiveToken</LogonType>
    <RunLevel>LeastPrivilege</RunLevel>
  </Principal>
</Principals>
<Settings>
  <Hidden>true</Hidden>
  <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
  <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
</Settings>
<Actions Context="Author">
  <Exec>
    <Command>C:\Users\dmarsh\AppData\Local\Temp\update.exe</Command>
  </Exec>
</Actions>
```

- Trigger: at logon of dmarsh. Action: run update.exe. Principal: dmarsh, interactive token, least privilege (no admin rights were needed to install it). `Hidden=true` hides it from the default Task Scheduler view; `ExecutionTimeLimit=PT0S` means no time limit (a long-running implant).
- Significance: Second, redundant persistence for the same payload. The SIEM/EDR label `trigger=scheduled_task_logon` on PID 7204 is **not supported** by the lineage: a task would start under `svchost.exe -k netsvcs -s Schedule`/`taskhostw.exe`, not `explorer.exe`, and prefetch shows only one update.exe launch on 2026-04-14 (ART-001-F07). So the launcher on 2026-04-14 was most likely R01; the task remains a live persistence mechanism either way and must be removed. ATT&CK T1053.005.
- Certainty: confirmed (task exists and is configured as above); probable (that R01, not R02, launched PID 7204)

### ART-001-R03: RunOnce and other autostart locations (negative results)

| Location | Result | Last write |
|---|---|---|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce` | empty | 2026-01-09T11:31:07Z (profile creation) |
| `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` / `RunOnce` | only signed vendor entries (SecurityHealth, WazuhAgent tray) | 2026-02-17T08:12:44Z |
| `HKLM\SYSTEM\CurrentControlSet\Services` | no service created after 2026-03-01 | n/a |
| `HKLM\...\Winlogon` Shell / Userinit | default values (`explorer.exe`, `userinit.exe,`) | 2026-01-09T11:02:41Z |
| WMI (`\Windows\System32\wbem\Repository\OBJECTS.DATA`) | no `__EventFilter` / `CommandLineEventConsumer` bindings besides the default SCM filter | n/a |
| Startup folder `...\Start Menu\Programs\Startup\` | `desktop.ini` only | n/a |

- Significance: Bounds the eradication scope on WST-WS-031 to exactly two persistence mechanisms (R01, R02). Negative results are recorded because "not found" must be shown, not assumed.
- Certainty: confirmed (for the locations listed)

## Execution evidence

### ART-001-E01: UserAssist - update.exe launched by the user, no entry for MSBuild.exe

- Key: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count`
- Command: `rip.pl -r NTUSER.DAT -p userassist`
- Value (ROT13): `P:\Hfref\qznefu\NccQngn\Ybpny\Grzc\hcqngr.rkr`
- Value (decoded): `C:\Users\dmarsh\AppData\Local\Temp\update.exe`
- Run count: 1
- Last executed: 2026-04-13T18:15:08Z
- Key last write: 2026-04-13T18:15:08Z
- MSBuild.exe: **no UserAssist value**. powershell.exe: last UserAssist entry 2026-03-30 (routine).
- Significance: UserAssist only records programs started through the Explorer shell (double-click, Start menu). It proves dmarsh **double-clicked update.exe** on 2026-04-13 at 18:15:08Z, which is the moment the Run key and task were installed (T1204.002 User Execution). The absence of MSBuild.exe is expected and does not refute its execution: MSBuild was started by powershell.exe (not by the shell) and its execution is proven by prefetch (ART-001-F07) and memory (ART-002-M01).
- Certainty: confirmed

### ART-001-E02: Amcache first execution

- File: `C:\Windows\AppCompat\Programs\Amcache.hve`
- Key: `Root\InventoryApplicationFile\update.exe|5d1c3a7f0b2e9c84`
- Values: `LowerCaseLongPath` = `c:\users\dmarsh\appdata\local\temp\update.exe`; `FileId` = `0000ae8f0e6170cd6b45d0cc212ac0c66e0e8d722f2b` (SHA-1, Amcache prefix `0000`); `Size` = 42816; `Publisher` = (empty); `IsOsComponent` = 0; `LinkDate` = 2026-04-02 21:17:44
- Last write (first execution): 2026-04-13T18:15:08Z
- SHA-1 check: `icat -o 2048 wst-ws-031.dd 104234 | sha1sum` = `ae8f0e6170cd6b45d0cc212ac0c66e0e8d722f2b`, same as the Amcache FileId
- Second entry: `Root\InventoryApplicationFile\msbuild.exe|...` for `c:\windows\microsoft.net\framework64\v4.0.30319\msbuild.exe`, Microsoft-signed, last write 2026-04-14T02:47:03Z, the first MSBuild entry for this host
- Significance: Independent source confirming the first execution of update.exe at 18:15:08Z and the identity of the binary (SHA-1 matches the file on disk). The binary has no publisher and was compiled 11 days before the phishing campaign. MSBuild.exe appearing in Amcache for the first time on 2026-04-14 supports the first-ever MSBuild run seen in prefetch.
- Certainty: confirmed

### ART-001-E03: AppCompatCache / ShimCache

- Key: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache` (ControlSet001)
- Command: `AppCompatCacheParser.exe -f SYSTEM --csv out/` (and `rip.pl -r SYSTEM -p appcompatcache`)
- Key last write: 2026-04-13T19:05:40Z (cache flushed to the registry at shutdown after dmarsh logged off at 19:02:11Z)
- Relevant entries (most recent first):

| Position | Path | File last modified |
|---|---|---|
| 0 | `C:\Users\dmarsh\AppData\Local\Temp\update.exe` | 2026-04-13T18:15:05Z |
| 1 | `C:\Windows\System32\schtasks.exe` | 2025-11-12T04:21:10Z |
| 2 | `C:\Program Files\Google\Chrome\Application\chrome.exe` | 2026-04-02T09:14:51Z |

- Significance: Confirms update.exe existed and was processed by the shim engine on 2026-04-13, right after schtasks.exe (consistent with the task creation at 18:15:14Z). On Windows 10, ShimCache alone does not prove execution (no execution flag) and the timestamp is the file's modified time, not the run time; here execution is proven by E01, E02 and prefetch. **MSBuild.exe and the 2026-04-14 activity are not in the registry ShimCache** because the host was not shut down between the 02:4xZ boot and imaging; that cache was only in memory (ART-002).
- Certainty: confirmed (presence); execution confirmed only in combination with E01/E02/F07

### ART-001-E04: LNK targets in Recent

- Path: `C:\Users\dmarsh\AppData\Roaming\Microsoft\Windows\Recent\`
- Command: `LECmd.exe -d Recent\ --csv out/`

| LNK file | Target | Created | Target opened (last) |
|---|---|---|---|
| `QC_reagent_lot_2026-04.xlsx.lnk` | `\\fs01\labops\QC\QC_reagent_lot_2026-04.xlsx` | 2026-04-13T14:41:02Z | 2026-04-13T14:41:02Z |
| `LIS_daily_worklist.pdf.lnk` | `C:\Users\dmarsh\Documents\LIS_daily_worklist.pdf` | 2026-04-08T07:02:19Z | 2026-04-13T10:01:55Z |
| `Downloads.lnk` | `C:\Users\dmarsh\Downloads` | 2026-02-11T15:20:07Z | 2026-04-13T18:14:58Z |
| `update.zip.lnk` | `C:\Users\dmarsh\Downloads\update.zip` (size 421004, vol. serial 6A3E4F1B3E4EE6D1) | 2026-04-13T18:14:58Z | 2026-04-13T18:14:58Z |

- Significance: Before the compromise dmarsh opened only normal lab documents. The last user-opened item is update.zip at 18:14:58Z. **No LNK file is created after dmarsh's logoff at 19:02:11Z on 2026-04-13**, so nothing was opened through Explorer on WST-WS-031 during the 2026-04-14 session: the activity of 2026-04-14 is process-based (PowerShell/MSBuild/C2), not a person browsing files. No LNK points to LIS patient reports.
- Certainty: confirmed

## Summary for eradication

| ID | Mechanism | Location | Removal / verification |
|---|---|---|---|
| ART-001-R01 | Run key `WindowsUpdateSvc` | HKCU\...\Run (dmarsh) | `reg delete ... /v WindowsUpdateSvc`; verify with `reg query` |
| ART-001-R02 | Scheduled task `{7B4F2D81-19E2-4A8C-9E67-A1F0DE2C7B3A}` | System32\Tasks + TaskCache | `schtasks /delete /tn ...`; verify Tree and Tasks keys gone |
| ART-001-F01/F02 | Payload files | `Temp\update.xml`, `Temp\update.exe`, `Downloads\update.zip` | delete after evidence capture; sweep by SHA-256 |

No other persistence (services, WMI, Winlogon, Startup folder, HKLM Run) was found on WST-WS-031 (R03). Persistence on WST-WS-017 (remote service created through ADMIN$) is outside this image and needs its own disk analysis.
