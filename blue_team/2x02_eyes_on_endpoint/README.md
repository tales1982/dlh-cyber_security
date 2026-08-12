# 2x02 - Eyes on the Endpoint

Telemetry engineering for MedDefense Health Systems. Where
[2x00_locking_the_gates](../2x00_locking_the_gates) and
[2x01_windows_fortress](../2x01_windows_fortress) reduced what an attacker
*can* do, this project proves what the resulting instrumentation actually
*sees*. The Crimson Tide advisory attacker lived inside MedDefense's network
for 4-7 days undetected - hardening alone does not fix that; visibility
does. This project validates Sysmon and PowerShell logging on Windows and
refines auditd on Linux, runs controlled attacker-like actions against the
project's own hardened endpoints, measures how much of that activity is
actually captured, and exports the result as a structured, analyst-ready
handoff package for Module 3.

## Lab environment

| Parameter | Value |
|---|---|
| Linux host | billing-srv-01 (hardened in [2x00](../2x00_locking_the_gates), auditd configured with `meddefense.rules`) |
| Windows host | DC01 (hardened in [2x01](../2x01_windows_fortress), Sysmon deployed with `sysmonconfig.xml`, audit policies active, PowerShell logging enabled) |

## Scripts

| Script | Task | Purpose |
|---|---|---|
| [0-sysmon_validation.ps1](0-sysmon_validation.ps1) | 0 | Triggers 5 controlled actions (process creation, network connection, file creation, registry write, DNS query) and verifies each produces the matching Sysmon Event ID. Read-only against telemetry; cleans up its own test artifacts. |
| [1-sysmon_coverage_matrix.ps1](1-sysmon_coverage_matrix.ps1) | 1 | Parses [2x01's sysmonconfig.xml](../2x01_windows_fortress/sysmonconfig.xml), maps 7 MITRE ATT&CK techniques to the Sysmon Event IDs required to see them, and evaluates each as covered/partial/blind based on the config's actual include/exclude filter scope - not just whether the Event ID exists. Produces `sysmon_coverage_matrix.json`. |
| [2-powershell_logging_validation.ps1](2-powershell_logging_validation.ps1) | 2 | Proves Script Block Logging (EID 4104, including decoded `-EncodedCommand` content), Module Logging (EID 4103) and Transcription all work against the PowerShell patterns Crimson Tide actually used. |
| [3-windows_telemetry_export.ps1](3-windows_telemetry_export.ps1) | 3 | Exports Security, Sysmon and PowerShell Operational events from a configurable time window (default 24h) into `windows_events_export.json`, with normalized common fields plus event-specific enrichment (logon fields, process command lines, decoded script blocks, network/file/registry/DNS details) extracted from each event's structured XML, not regex-scraped from the message text. |
| [4-windows_telemetry_quality.ps1](4-windows_telemetry_quality.ps1) | 4 | Reads `windows_events_export.json` and produces `windows_telemetry_quality.json`: event/channel distribution, hour-by-hour time coverage, gap detection (>30 min silent), field completeness (command line, source IP, script block), and a weighted 0-100 quality score with a good/acceptable/poor verdict. |
| [5-auditd_refine.sh](5-auditd_refine.sh) | 5 | Extends [2x00 Task 10's](../2x00_locking_the_gates/10-auditd_config.sh) `meddefense.rules` with 5 detection-focused rules Sysmon has an equivalent of but auditd didn't yet cover: execve tracking, socket/connect tracking, SSH key file access, cron persistence, sudoers.d access. Reloads auditd and validates each rule fires with `ausearch`. Idempotent. |
| [6-log_source_map.sh](6-log_source_map.sh) | 6 | Inventories every active Linux log source (auth.log, audit.log, syslog, kern.log, apache2 access/error, dpkg.log, plus anything else security-relevant it finds, e.g. ufw.log) - real path, format, rotation policy read from `/etc/logrotate.d/`, current size, an estimated event rate and a relevance rating. Flags any expected source that's missing. Produces `log_source_map.json`. |
| [7-linux_export.sh](7-linux_export.sh) | 7 | The Linux counterpart to Task 3: parses auth.log (SSH/sudo/su/PAM), audit.log (execve/file access/network via SYSCALL, PATH and SOCKADDR records) and syslog (service lifecycle, errors) into one normalized `linux_events_export.json`. Single `awk` pass per file plus one batched `jq` timestamp-normalization pass - a naive per-line `grep`/`date` loop measured minutes against a real 26k-line audit.log; this measures under a second. |
| [8-linux_telemetry_quality.sh](8-linux_telemetry_quality.sh) | 8 | Applies the same quality bar as Task 4, in bash/`jq`, to `linux_events_export.json`: event/source-type distribution, hour-by-hour time coverage, gap detection (>30 min silent), field completeness (execve command line, SSH source IP/user, auditd file path), and a weighted 0-100 quality score. Produces `linux_telemetry_quality.json`. |
| [9-windows_attack_sim.ps1](9-windows_attack_sim.ps1) | 9 | Runs the Crimson Tide playbook against the project's own hardened endpoint: create a local user, add it to Administrators, run encoded PowerShell, create a persistence scheduled task, beacon outbound, drop a Startup-folder file. Every action is timestamped and mapped to its expected Sysmon/Security Event ID and MITRE ATT&CK technique in `windows_attack_log.json` (the ground truth), then every artifact is removed. |
| [10-windows_detection_proof.ps1](10-windows_detection_proof.ps1) | 10 | Reads `windows_attack_log.json` and, for each action, searches Security/Sysmon/PowerShell within a 30-second window for the expected Event ID, scoring the result full/partial/missed based on whether that event's key fields are actually populated. Produces the detection matrix (`windows_detection_matrix.json`) that proves - not claims - the instrumentation works end to end. |

## Requirements

- `README.md` at the project root (this file).
- All files end with a newline.
- Bash scripts start with `#!/bin/bash` and pass `shellcheck`.
- PowerShell scripts use the `.ps1` extension and
  `Set-StrictMode -Version Latest`.
- Every script has a comment header with name, purpose and author.

## Usage

```powershell
.\0-sysmon_validation.ps1               # triggers 5 actions, verifies each Sysmon Event ID fires
.\1-sysmon_coverage_matrix.ps1          # reads sysmonconfig.xml, writes sysmon_coverage_matrix.json
.\2-powershell_logging_validation.ps1   # verifies Script Block/Module Logging + Transcription
.\3-windows_telemetry_export.ps1        # [-StartTime <dt>] [-EndTime <dt>], writes windows_events_export.json
.\4-windows_telemetry_quality.ps1       # reads windows_events_export.json, writes windows_telemetry_quality.json
.\9-windows_attack_sim.ps1              # runs + cleans up the 6-action attack sequence, writes windows_attack_log.json
.\10-windows_detection_proof.ps1        # reads windows_attack_log.json, writes windows_detection_matrix.json
```

```bash
sudo ./5-auditd_refine.sh               # extends meddefense.rules, reloads auditd, validates each rule
./6-log_source_map.sh                   # inventories Linux log sources, writes log_source_map.json
./7-linux_export.sh [output.json]       # parses auth.log/audit.log/syslog, writes linux_events_export.json
./8-linux_telemetry_quality.sh [in] [out]  # reads linux_events_export.json, writes linux_telemetry_quality.json
```

Run 0-4 and 9-10 directly on `DC01` as `analyst`. 0, 2 and 9 are the only
ones that execute real commands (harmless, cleaned-up triggers purely to
generate the telemetry being verified/proven); 9 additionally creates -
and always removes - a local user, an Administrators membership, a
scheduled task and a Startup-folder file. Run 5-8 on `billing-srv-01`.
5 makes a real, idempotent change to `/etc/audit/rules.d/meddefense.rules`
and reloads the live auditd ruleset via `augenrules --load`; 6, 7 and 8
are read-only.

Tasks 1, 3, 4, 5, 7, 8, 9 and 10 accept path/time overrides
(`-SysmonConfigPath`, `-StartTime`/`-EndTime`, `-InputPath`, `RULES_FILE=`,
positional input/output paths, `-GroundTruthPath`, `-WindowSeconds`) so
their logic can be exercised against scratch paths without touching the
real Sysmon config, event logs or auditd rules - see each script's
parameter block.
