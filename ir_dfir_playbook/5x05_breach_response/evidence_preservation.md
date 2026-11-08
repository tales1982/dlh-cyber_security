# Evidence Preservation: IR-2026-0420-01

- Case / litigation hold: `LH-2026-0420-01` (requested from Helena Reyes, General Counsel, at 20:12Z)
- Evidence lead: Tales Lima, on-call IR
- Acquirer: Mike Torres, Network Engineer (memory captures), Robert Kim, Infrastructure Lead (disk imaging)
- Evidence store: `\\evidence\share\IR-2026-0420-01\` (SMB, IR-team-only ACL), analysis copy `/evidence/IR-2026-0420-01/`
- Hash algorithm: SHA-256. Every artifact is hashed twice: at the source (`certutil -hashfile <file> SHA256` on the host, or `sha256sum` on the jumpbox) and on arrival in the store (`sha256sum`). Both values go into `hashes.txt` and the chain of custody table.
- Acquisition path: IR jumpbox `ir-jump01` (10.30.200.10) through WazuhEDR live response. No USB, no personal device, no RDP session as a user (an interactive logon would put new credentials in LSASS on a compromised host).

## Scope

| Host | Role | Why it is in scope | Volatile state now |
|---|---|---|---|
| CS-WS-101 | ED charge desk clinical coordinator station (user MEDDEFENSE\jdoe) | Initial compromise (phishing macro, Thursday 2026-04-17) | Beacon `svchost32.exe` live, last C2 check-in 19:32:04Z; memory already captured 19:38Z (ART-001) |
| CS-WS-104 | Clinical workstation, Main | SIEM `wz-edr-200214`, service WinHealthSvc, beacon since 2026-04-19T00:04Z, staging script dropped 2026-04-20T14:25Z | Beacon live |
| CS-WS-107 | Clinical workstation, Main | Same service, beacon since 2026-04-19T00:12Z, staging script 14:25Z | Beacon live |
| CS-WS-112 | Clinical workstation, Main | Same service, beacon since 2026-04-19T00:18Z, staging script 14:26Z | Beacon live |
| FILE-SVR-01 | Clinical documentation file server (D:\clinical\labs, D:\clinical\notes) | 1,847 patient PDF reads on 2026-04-19 02:14-02:41Z by `svchost32.exe` | No beacon since the attacker session ended at 2026-04-19T02:41:18Z (event 4634) |
| SCHED-SVR-01 | Scheduling server, Main | **Scope expansion.** Not in the original host list. Sysmon shows `svchost32.exe` started by services.exe at 2026-04-20T18:02:18Z; Torres reports CPU pinned and disk queue saturated for ~90 min | Attacker process live, heavy disk activity (possible encryption in progress) |

SCHED-SVR-01 was added at 20:07Z after the Sysmon query for `svchost32.exe` across all hosts returned a sixth host. It is treated with the same rules as the five named hosts.

## Priority order rationale

Preservation is a parallel operation. Two acquirers work at the same time: Robert Kim images the CS-WS-101 disk (long, runs in the background) while Mike Torres captures memory on the other hosts one after another through EDR live response. The order is driven by three questions per host: what evidence disappears first, what the attacker can still do on that host, and where credential material sits.

0. **FILE-SVR-01 Security event log export first (minutes, not a host image).** The PHI access record (1,847 events 4663) is in a rolling Security log. Every hour of normal file server activity pushes it closer to being overwritten. Export takes about 2 minutes, does not touch the attacker, and protects the single most important record for the HIPAA decision.
1. **CS-WS-101 disk image (start immediately, runs in parallel).** Memory already exists (ART-001). The disk holds the phishing document, the PowerShell downloader, the beacon binary, the staging script and the persistence. The nurse reports changed file names, so something may already be modifying the disk: the image must start before any containment step and before anyone else touches the console.
2. **SCHED-SVR-01 memory.** It has an attacker process running right now with saturated disk I/O. If this is encryption in progress, the key material and the ransomware configuration exist only in RAM, and the server is minutes away from containment. Highest volatility and highest current damage, so it is captured first among the memory images.
3. **CS-WS-104 memory.** First laterally compromised host (`sc create WinHealthSvc` at 2026-04-19T00:03:44Z), active beacon, staged `encryption_staging.ps1`. Memory holds the injected beacon, its C2 configuration, and the credential material used for the next hops. Network isolation will close the C2 sockets, so memory comes before isolation.
4. **CS-WS-107 memory.** Active beacon and staging script, same reasoning as WS-104. Second in time of the lateral hops (00:12:44Z).
5. **CS-WS-112 memory.** Active beacon and staging script; last lateral hop (00:18:02Z). Same value as WS-104/107; ordered last of the three only because it was compromised last and shows the same pattern.
6. **FILE-SVR-01 memory + triage collection.** No attacker process since 2026-04-19T02:41Z, so its memory holds little attacker state (the attacker logon session is closed). The evidence that matters is on disk and in logs: Security.evtx (already exported in step 0), $MFT, ACLs on D:\clinical, and the `svchost32.exe` binary in ProgramData. A full disk image of the clinical data volume is impractical tonight (multi-TB) and would take the server out of clinical use; a targeted triage collection is taken instead.

Containment rule: no host is isolated until its memory hash is recorded in `hashes.txt`. The perimeter egress block is applied only after the last active-beacon memory image (CS-WS-112) is hashed, because it closes the C2 sockets on every host at once. This holds the C2 channel open for about 40 minutes after declaration; the accepted risk and its limit are documented in `containment_decision.md`.

Disk images of CS-WS-104, CS-WS-107, CS-WS-112 and SCHED-SVR-01 are taken after isolation (EDR containment still allows the jumpbox) and before any reimage. They are numbered ART-012 to ART-015 when acquired and are not part of tonight's 11-artifact baseline.

## ART-001: cs-ws-101.mem (Torres acquisition)

- artifact_id: ART-001
- host: CS-WS-101 (10.30.12.101)
- acquired_by: Mike Torres, Network Engineer
- acquired_at: 2026-04-20T19:38Z (start), file written to the share 2026-04-20T19:41Z
- tool: WinPmem (winpmem_mini_x64), run before the call to IR
- storage: `\\evidence\share\IR-2026-0420-01\cs-ws-101.mem`
- sha256_at_acquisition: NOT RECORDED. Torres flagged this himself; it repeats the IR-2026-0414-01 finding (no hash at acquisition).
- sha256_verified_by_analyst: computed at 2026-04-20T20:10Z on the evidence share, `sha256sum cs-ws-101.mem` = `565910b04b4521947aede9d48007520b369e09188783dcea3f3abf8d3006dc28`. Recorded as the **baseline**, not as a match: no earlier hash exists to compare with.
- integrity_note: integrity is provable from 20:10Z forward only. Between 19:41Z and 20:10Z it rests on Torres's statement that nobody opened the file. Torres signed the statement at 20:11Z. Every finding from ART-001 carries this qualification.
- gap_note: memory captured at **19:38Z**, file written at **19:41Z** (3-minute write window, the image reflects the state at 19:38Z and the host kept running during the write), Torres called IR at **19:43:18Z** (5 minutes after capture), incident declared at **19:52Z** (14 minutes after capture). The host stayed online and unisolated through the whole gap, so anything the attacker did on CS-WS-101 after 19:38Z is not in ART-001. The last C2 check-in before capture (19:32:04Z, proxy and Sysmon) is inside the image window; check-ins after 19:38Z must come from proxy logs, not memory.
- operator_footprint: WinPmem runs in the image as a process started by Torres. It is an acquisition tool, not attacker activity.
- next action: `sha256sum -c hashes.txt` at the start of every analysis session (see forensic_findings.md).

## ART-009: fileserver_access.evtx (FILE-SVR-01 Security log)

- priority: 0 (before every host image)
- acquired_by: Tales Lima
- acquired_at: 2026-04-20T20:09Z
- method: EDR live response on FILE-SVR-01: `wevtutil epl Security C:\IR\fileserver_access.evtx` then copy to the store; plus `wevtutil gli Security` saved to record oldest record number and log size
- why first: rolling log, PHI access record, the HIPAA assessment depends on it
- sha256: source `certutil -hashfile C:\IR\fileserver_access.evtx SHA256` = store `sha256sum` = `d1704418690ebdd9f1b53f4d637f9317a3706a7b945f6f294ac4d8d4e95e5169`
- note: the export file on C:\IR is deleted from the server after the store hash matches; the deletion is logged.

## ART-002: cs-ws-101.dd

- priority: 1
- host: CS-WS-101
- acquired_by: Robert Kim
- acquired_before: any containment action on CS-WS-101 (started 20:14Z; EDR isolation of CS-WS-101 at 20:33Z keeps the jumpbox path open, so imaging continues during isolation)
- tool: FTK Imager CLI over the IR jumpbox, raw/dd output, physical disk
- command: `ftkimager.exe \\.\PhysicalDrive0 \\evidence\share\IR-2026-0420-01\cs-ws-101 --verify` (raw output renamed `cs-ws-101.dd`)
- volatile extras captured at 20:12Z before imaging (EDR live response, outputs hashed into `hashes_derived.txt`): `tasklist /v`, `netstat -anob`, `ipconfig /displaydns`, `sc qc WinHealthSvc`, `schtasks /query /fo csv /v`, `reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run`, directory listing of `C:\Users\*\Desktop` (to record the "files look different" report before anything changes)
- duration: 2026-04-20T20:14Z to 21:38Z
- sha256: FTK verify hash = store `sha256sum` = `fca8e3094912e1cc28bbf609ab4c09bd78b78072ff1c68c827fc257f2c13da8a`
- on-console instruction: the nurse stopped using CS-WS-101 at 19:52Z (transcript handoff notes); nobody logs on interactively

## ART-006: sched-svr-01.mem

- priority: 2
- host: SCHED-SVR-01
- acquired_by: Mike Torres
- tool: WinPmem via EDR live response, output straight to the evidence share
- command: `winpmem_mini_x64.exe \\evidence\share\IR-2026-0420-01\sched-svr-01.mem`
- volatile extras: `tasklist /v`, `netstat -anob`, `Get-CimInstance Win32_Service -Filter "Name='WinHealthSvc'"`, `Get-Process svchost32 | fl *`, open handles of the svchost32 PID (`handle.exe -p <pid>`), list of most recently modified files on data volumes (to tell encryption from load)
- duration: 2026-04-20T20:12Z to 20:20Z (32 GB RAM)
- sha256: source `certutil` = store `sha256sum` = `64aaa70726a272dbcb6001976020973099326dce77e36ba6e5cd9e1a08c9d8ae`
- isolation: right after the hash is recorded (see containment_execution.md)

## ART-003: cs-ws-104.mem

- priority: 3
- host: CS-WS-104 (10.30.12.104)
- acquired_by: Mike Torres
- tool / command: `winpmem_mini_x64.exe \\evidence\share\IR-2026-0420-01\cs-ws-104.mem` (EDR live response)
- volatile extras: `tasklist /v`, `netstat -anob` (expect ESTABLISHED to 45.152.66.114:443 from svchost32.exe), `ipconfig /displaydns` (expect `staging.office365-cdn.net`), `sc qc WinHealthSvc`, `klist sessions`
- duration: 2026-04-20T20:14Z to 20:19Z
- sha256: source = store = `251a70a33d2c1ecb05b57ad884638c67178b11ab5900835c4d0b3c8fcbceeeb9`

## ART-004: cs-ws-107.mem

- priority: 4
- host: CS-WS-107 (10.30.12.107)
- acquired_by: Mike Torres
- tool / command: `winpmem_mini_x64.exe \\evidence\share\IR-2026-0420-01\cs-ws-107.mem` (EDR live response), same volatile extras as ART-003
- duration: 2026-04-20T20:19Z to 20:24Z
- sha256: source = store = `5d56784e9cea089a758af2aabd3abebae461cc8008ce36f747f4619a34b0c208`

## ART-005: cs-ws-112.mem

- priority: 5
- host: CS-WS-112 (10.30.12.112)
- acquired_by: Mike Torres
- tool / command: `winpmem_mini_x64.exe \\evidence\share\IR-2026-0420-01\cs-ws-112.mem` (EDR live response), same volatile extras as ART-003
- duration: 2026-04-20T20:24Z to 20:29Z
- sha256: source = store = `d632fe64d3ffdc20df9c54515bece6ac4bca99abbae1e401375f10f2e5e9c064`

## ART-007 and ART-008: FILE-SVR-01 memory and triage collection

- priority: 6
- host: FILE-SVR-01 (10.30.10.20)
- acquired_by: Mike Torres (memory), Tales Lima (triage)
- ART-007 command: `winpmem_mini_x64.exe \\evidence\share\IR-2026-0420-01\file-svr-01.mem`, 2026-04-20T20:29Z to 20:41Z (64 GB RAM), sha256 `7aa955309bb9167af789a7c62a7c4190595eefba092bfbdcc8949dfd47042a3a`
- ART-008 command: `kape.exe --tsource C: --tdest \\evidence\share\IR-2026-0420-01\file-svr-01_triage --target !SANS_Triage,EventLogs,RegistryHives,FileSystem --zip file-svr-01_triage` plus `icacls D:\clinical /t /c > acl_clinical.txt` and `C:\ProgramData\Microsoft\svchost32.exe` copied as a file; 2026-04-20T20:42Z to 20:58Z, sha256 `ff0fc047bfea4b78f0f9107b52ac67ba0e5193daed64348254439fe117ab5205`
- why no full disk image tonight: the clinical data volume is multi-TB and imaging it would take the server out of clinical use for hours; the triage set preserves the attacker's binary, the logs, the MFT and the ACLs. A full image of the system volume (C:) is scheduled before eradication.

## ART-010 and ART-011: log exports

- ART-010 `proxy_72h.jsonl`: proxy log for all MedDefense hosts, 2026-04-17T14:00Z to 2026-04-20T20:00Z, exported from the SIEM by Tales Lima at 20:24Z, sha256 `c7b4ae53d3686338ae79b7efcc46fb952c2a1c33b317df60c1b530f27d8bba91`
- ART-011 `sysmon_multihost.jsonl`: Sysmon events (1, 3, 10, 11, 13) for CS-WS-101/104/107/112, FILE-SVR-01, SCHED-SVR-01, same window, exported at 20:26Z, sha256 `1d949ecce295b2f579d8eb828b359277d540cad97bf64cc78a8bb1f3db9002d0`
- Schema references used during analysis (not evidence): `proxy_72h.sample.jsonl`, `sysmon_multihost.sample.jsonl`, `fileserver_access.sample.json`.

## Verification step

At 21:40Z, after ART-002 finished, the full store was re-hashed:

```bash
cd /evidence/IR-2026-0420-01
sha256sum -c hashes.txt
# cs-ws-101.mem: OK ... sysmon_multihost.jsonl: OK   (11/11 OK)
chmod 0444 * && chmod 0444 hashes.txt
sha256sum hashes.txt > hashes.txt.sha256
```

Result: 11/11 OK, no DEVIATION. `hashes.txt` locked read-only.

## Chain of custody

| Artifact ID | Host | Artifact | Acquired by | Acquired at (UTC) | Tool | SHA-256 at acquisition | SHA-256 verified by analyst | Storage | Custody notes |
|---|---|---|---|---|---|---|---|---|---|
| ART-001 | CS-WS-101 | cs-ws-101.mem | Mike Torres | 2026-04-20T19:38Z (written 19:41Z) | WinPmem | NOT RECORDED | 565910b04b4521947aede9d48007520b369e09188783dcea3f3abf8d3006dc28 (baseline set 20:10Z by Tales Lima) | \\evidence\share\IR-2026-0420-01\ | Pre-custody gap 19:41Z-20:10Z, Torres statement signed 20:11Z; acquired before IR engagement |
| ART-002 | CS-WS-101 | cs-ws-101.dd | Robert Kim | 2026-04-20T20:14Z-21:38Z | FTK Imager CLI (raw) | fca8e3094912e1cc28bbf609ab4c09bd78b78072ff1c68c827fc257f2c13da8a | match at 21:40Z | same | Imaging continued after EDR isolation at 20:33Z through jumpbox path |
| ART-003 | CS-WS-104 | cs-ws-104.mem | Mike Torres | 2026-04-20T20:14Z-20:19Z | WinPmem via EDR live response | 251a70a33d2c1ecb05b57ad884638c67178b11ab5900835c4d0b3c8fcbceeeb9 | match at 20:20Z and 21:40Z | same | Captured before isolation, C2 socket present |
| ART-004 | CS-WS-107 | cs-ws-107.mem | Mike Torres | 2026-04-20T20:19Z-20:24Z | WinPmem via EDR live response | 5d56784e9cea089a758af2aabd3abebae461cc8008ce36f747f4619a34b0c208 | match at 20:25Z and 21:40Z | same | Captured before isolation |
| ART-005 | CS-WS-112 | cs-ws-112.mem | Mike Torres | 2026-04-20T20:24Z-20:29Z | WinPmem via EDR live response | d632fe64d3ffdc20df9c54515bece6ac4bca99abbae1e401375f10f2e5e9c064 | match at 20:30Z and 21:40Z | same | Captured before isolation |
| ART-006 | SCHED-SVR-01 | sched-svr-01.mem | Mike Torres | 2026-04-20T20:12Z-20:20Z | WinPmem via EDR live response | 64aaa70726a272dbcb6001976020973099326dce77e36ba6e5cd9e1a08c9d8ae | match at 20:21Z and 21:40Z | same | Scope expansion host; captured while attacker process active |
| ART-007 | FILE-SVR-01 | file-svr-01.mem | Mike Torres | 2026-04-20T20:29Z-20:41Z | WinPmem via EDR live response | 7aa955309bb9167af789a7c62a7c4190595eefba092bfbdcc8949dfd47042a3a | match at 20:42Z and 21:40Z | same | No attacker session active at capture |
| ART-008 | FILE-SVR-01 | file-svr-01_triage.zip | Tales Lima | 2026-04-20T20:42Z-20:58Z | KAPE + icacls | ff0fc047bfea4b78f0f9107b52ac67ba0e5193daed64348254439fe117ab5205 | match at 21:40Z | same | Targeted collection instead of full data volume image |
| ART-009 | FILE-SVR-01 | fileserver_access.evtx | Tales Lima | 2026-04-20T20:09Z | wevtutil epl | d1704418690ebdd9f1b53f4d637f9317a3706a7b945f6f294ac4d8d4e95e5169 | match at 20:10Z and 21:40Z | same | Priority 0 (rolling log); temp copy on server deleted after match |
| ART-010 | all hosts | proxy_72h.jsonl | Tales Lima | 2026-04-20T20:24Z | SIEM export | c7b4ae53d3686338ae79b7efcc46fb952c2a1c33b317df60c1b530f27d8bba91 | match at 21:40Z | same | Window 2026-04-17T14:00Z to 2026-04-20T20:00Z |
| ART-011 | all hosts | sysmon_multihost.jsonl | Tales Lima | 2026-04-20T20:26Z | SIEM export | 1d949ecce295b2f579d8eb828b359277d540cad97bf64cc78a8bb1f3db9002d0 | match at 21:40Z | same | Same window; includes SCHED-SVR-01 |

All artifacts: read-only (0444), IR-team-only ACL, litigation hold `LH-2026-0420-01`. Access after this table is logged in the forensic session records (`forensic_findings.md`, ART verification sections).
