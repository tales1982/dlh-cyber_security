# Chain of Custody: `LH-2026-0414-01`

> Append-only for the duration of the investigation. Rows are never edited or deleted; corrections are new rows that reference the row they correct. Any hash deviation is appended immediately as a **DEVIATION** note.

## Case Header

- **Case number:** `LH-2026-0414-01`
- **Incident ID:** `IR-2026-0414-01`
- **Lead investigator:** `Tales Lima`
- **Date opened:** `2026-04-14`
- **Litigation hold reference:** `Memo from Helena Reyes, 2026-04-14T07:30Z`
- **Forensic phase authorized by:** James Chen (SOC Lead / IR Commander)
- **Evidence received from:** Mike Torres (Network Engineer, acquirer) at 2026-04-14T07:42Z, with `acquisition_notes.md`
- **Hash algorithm:** SHA-256 (`sha256sum`), baseline manifest `hashes.txt`, verification log `verification_log.txt` (written by `verify_artifacts.sh`)

## Artifact Registry

| Artifact ID | Artifact Name | Format | Acquired By | Acquisition Timestamp (UTC) | Acquisition Tool | SHA-256 at Acquisition | Storage Path | Access Controls |
|---|---|---|---|---|---|---|---|---|
| ART-001 | wst-ws-031.dd | RAW (dd), disk image of WST-WS-031 | Mike Torres | 2026-04-14T04:51Z (start) to 2026-04-14T06:14Z (end) | FTK Imager (raw/dd) | NOT RECORDED at acquisition (see acquisition_notes.md). Baseline set at first analyst access 2026-04-14T08:05:12Z: `a8f2c49d67d8e175e97d5639c9e6c3dfc0042c06e337efa6b3bb8e727a3e8b7a` | `\\evidence\share\IR-2026-0414-01\wst-ws-031.dd` (analysis copy `/evidence/IR-2026-0414-01/disk/wst-ws-031.dd`) | read-only (0444), IR team only, litigation hold LH-2026-0414-01 |
| ART-002 | wst-ws-031.mem | RAW memory image of WST-WS-031 | Mike Torres | 2026-04-14T03:02Z | WinPmem v3.3-rc3 (run from USB) | NOT RECORDED at acquisition. Baseline set at first analyst access 2026-04-14T08:05:12Z: `3bc19f7eb5def64684c6dac931163dd517c1a3292d5a29c115ed146c3f8f6ddc` | `\\evidence\share\IR-2026-0414-01\wst-ws-031.mem` (analysis copy `/evidence/IR-2026-0414-01/memory/wst-ws-031.mem`) | read-only (0444), IR team only, litigation hold LH-2026-0414-01 |
| ART-003 | wst-ws-017.mem | RAW memory image of WST-WS-017 | Mike Torres | 2026-04-14T03:38Z | WinPmem (run from console, West Campus) | NOT RECORDED at acquisition. Baseline set at first analyst access 2026-04-14T08:05:12Z: `90e7d14ca77bfc4b93825e7850669d395791c06a604532bbcb633d3e8f7a067f` | `\\evidence\share\IR-2026-0414-01\wst-ws-017.mem` (analysis copy `/evidence/IR-2026-0414-01/memory/wst-ws-017.mem`) | read-only (0444), IR team only, litigation hold LH-2026-0414-01 |

### Supplementary evidence (logs, not forensic images)

| Artifact ID | Artifact Name | Format | Source | Received (UTC) | SHA-256 at receipt | Storage Path | Access Controls |
|---|---|---|---|---|---|---|---|
| LOG-001 | proxy_log.jsonl | JSON Lines | web proxy export | 2026-04-14T07:42Z | `340c4a575bf6dc0104e4a21c7c8219a1406615d8e3ffd08b66c2d9dcb73a68e9` | `/evidence/IR-2026-0414-01/logs/proxy_log.jsonl` | read-only, IR team only |
| LOG-002 | ad_auth_log.jsonl | JSON Lines | ad_dc01, ad_dc02, azure_ad, vpn, fileserver_audit | 2026-04-14T07:42Z | `0596d6b2de97fe3bd6ccd7a65cb4e3eb3b2a5094c8d96787eaf38c30de25fbed` | `/evidence/IR-2026-0414-01/logs/ad_auth_log.jsonl` | read-only, IR team only |
| LOG-003 | siem_alert_export.json | JSON (MedDefense-SIEM-Alert-v1.2) | soc-evidence-collector, exported 2026-04-14T02:58:04Z | 2026-04-14T07:42Z | `d270a87e00d33f6f9f7261fd18b40db76a64bb4be53b08bf9c29f4f1b420f63d` | `/evidence/IR-2026-0414-01/logs/siem_alert_export.json` | read-only, IR team only; SOC detection context only |
| DOC-001 | acquisition_notes.md | Markdown | Mike Torres, signed 2026-04-14T07:42Z | 2026-04-14T07:42Z | `457c32001b98aa89234bb3c4e76d6b3585f41ab32ff4cc457cf26fcc92c2a649` | `/evidence/IR-2026-0414-01/logs/acquisition_notes.md` | read-only, IR team only |

### Pre-custody gaps (from acquisition_notes.md, recorded before first access)

These gaps happened before the investigator received the evidence. They are recorded, not hidden, and every finding that depends on them is qualified.

1. **No SHA-256 at acquisition** for ART-001, ART-002, ART-003. Integrity can only be proven from the first analyst access (2026-04-14T08:05:12Z) forward. Between acquisition and that moment, integrity rests on the acquirer's statement only.
2. **No chain-of-custody form at acquisition.** Custody between 03:02Z / 03:38Z / 06:14Z and the hand-off at 07:42Z is undocumented (who had physical or network access to the USB stick, the NVMe enclosure, the acquirer workstation and the evidence share is unknown).
3. **ART-001 source disk mounted read-write before imaging.** The acquirer opened Explorer on the mount to check `update.xml`. NTFS access times (and possibly `$MFT`/`$LogFile`/`$UsnJrnl` records) for the browsed folders can reflect the acquirer, not the attacker. Every access timestamp after the containment window (after ~03:24Z) is treated as unreliable in `filesystem_analysis.md`.
4. **Copy path** for the memory images went through a personal workstation and an external NVMe enclosure before reaching the evidence share.
5. Litigation hold issued about 07:30Z; evidence handed over at 07:42Z.

## Access Log

| Timestamp (UTC) | Actor | Artifact ID | Action | Tool Used | Hash Verified | Notes |
|---|---|---|---|---|---|---|
| 2026-04-14T07:42:00Z | Mike Torres -> Tales Lima | ART-001, ART-002, ART-003 | custody_transfer | n/a (evidence share) | no | Received with acquisition_notes.md; no acquisition hashes, no prior CoC; pre-custody gaps 1-5 recorded above |
| 2026-04-14T07:55:30Z | Tales Lima | ART-001, ART-002, ART-003 | set_read_only | chmod 0444, share ACL IR-team-only | no | Write permissions removed before any read; litigation hold LH-2026-0414-01 applied to the share |
| 2026-04-14T08:05:12Z | Tales Lima | ART-001 | hash_verify (baseline) | verify_artifacts.sh (sha256sum) | yes | Baseline established; hash stored in hashes.txt: a8f2c49d67d8e175e97d5639c9e6c3dfc0042c06e337efa6b3bb8e727a3e8b7a. Status BASELINE_SET |
| 2026-04-14T08:05:12Z | Tales Lima | ART-002 | hash_verify (baseline) | verify_artifacts.sh (sha256sum) | yes | Baseline established; hash stored in hashes.txt: 3bc19f7eb5def64684c6dac931163dd517c1a3292d5a29c115ed146c3f8f6ddc. Status BASELINE_SET |
| 2026-04-14T08:05:12Z | Tales Lima | ART-003 | hash_verify (baseline) | verify_artifacts.sh (sha256sum) | yes | Baseline established; hash stored in hashes.txt: 90e7d14ca77bfc4b93825e7850669d395791c06a604532bbcb633d3e8f7a067f. Status BASELINE_SET |
| 2026-04-14T08:06:40Z | Tales Lima | hashes.txt | hash_manifest_lock | sha256sum, chmod 0444 | yes | Manifest locked; its own hash stored in hashes.txt.sha256 |
| 2026-04-14T08:20:05Z | Tales Lima | ART-001 | hash_verify | verify_artifacts.sh | yes | [PASS] start of filesystem session (Task 3) |
| 2026-04-14T08:21:10Z | Tales Lima | ART-001 | read_only_mount | `mount -o ro,loop,offset=1048576,noexec,show_sys_files,streams_interface=windows` | yes | Loop device read-only; TSK commands also run directly against the image file |
| 2026-04-14T08:24:00Z | Tales Lima | ART-001 | partition_and_fs_metadata | mmls, fsstat (TSK 4.12) | yes | NTFS volume at sector offset 2048 |
| 2026-04-14T08:31:45Z | Tales Lima | ART-001 | file_listing_timeline | fls -r -m, mactime -b -d | yes | Output fls_output.txt, mac_timeline.csv (derived files, hashed in hashes_derived.txt) |
| 2026-04-14T08:52:20Z | Tales Lima | ART-001 | export_section | icat (TSK) | yes | Exported update.xml, update.exe, update.zip, task XML, prefetch, LNK, Chrome History to /cases/LH-2026-0414-01/export/; each export hashed |
| 2026-04-14T09:01:15Z | Tales Lima | ART-001 | hash_verify | verify_artifacts.sh | yes | [PASS] end of filesystem session; image unchanged |
| 2026-04-14T09:05:02Z | Tales Lima | ART-001 | hash_verify | verify_artifacts.sh | yes | [PASS] start of registry/persistence session (Task 4) |
| 2026-04-14T09:06:30Z | Tales Lima | ART-001 | export_section | icat (TSK) | yes | Exported NTUSER.DAT (dmarsh), SYSTEM, SOFTWARE, Amcache.hve, System32\Tasks\{7B4F2D81-...}, Recent\*.lnk |
| 2026-04-14T09:10:00Z | Tales Lima | ART-001 (exports) | registry_parse | RegRipper 3.0 (rip.pl), regipy, LECmd, AppCompatCacheParser, AmcacheParser | yes | Parsed exported copies only; original image not opened for write |
| 2026-04-14T09:48:40Z | Tales Lima | ART-001 | hash_verify | verify_artifacts.sh | yes | [PASS] end of registry session |
| 2026-04-14T10:02:10Z | Tales Lima | ART-002 | hash_verify | verify_artifacts.sh | yes | [PASS] start of memory session (Task 5) |
| 2026-04-14T10:03:00Z | Tales Lima | ART-002 | memory_analysis | Volatility 3 (2.7.0): pslist, pstree, cmdline, netscan, dlllist, malfind, handles, hashdump | yes | Volatility reads the image; outputs written to /cases/LH-2026-0414-01/vol/ |
| 2026-04-14T10:41:30Z | Tales Lima | ART-002 | export_section | Volatility 3 windows.malfind --dump | yes | Injected region of PID 8104 dumped (pid.8104.vad.0x1f0000-0x203fff.dmp), hashed |
| 2026-04-14T10:55:00Z | Tales Lima | ART-003 | hash_verify | verify_artifacts.sh | yes | [PASS] |
| 2026-04-14T10:56:00Z | Tales Lima | ART-003 | memory_analysis | Volatility 3 (2.7.0): pslist, pstree, cmdline, netscan, malfind | yes | Outputs written to /cases/LH-2026-0414-01/vol/ |
| 2026-04-14T11:20:30Z | Tales Lima | ART-002, ART-003 | hash_verify | verify_artifacts.sh | yes | [PASS] end of memory session; ALL ARTIFACTS VERIFIED |
| 2026-04-14T11:30:00Z | Tales Lima | LOG-001, LOG-002, LOG-003 | read_for_correlation | jq, sha256sum | yes | Correlation for correlated_timeline.md (Task 6); log hashes recorded in hashes_derived.txt |
| 2026-04-14T12:15:00Z | Tales Lima | ART-001, ART-002, ART-003 | hash_verify | verify_artifacts.sh | yes | [PASS] close of analysis day; no DEVIATION recorded |
