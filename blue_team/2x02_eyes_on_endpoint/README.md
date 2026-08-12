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
```

```bash
sudo ./5-auditd_refine.sh               # extends meddefense.rules, reloads auditd, validates each rule
```

Run 0-4 directly on `DC01` as `analyst`; all five are read-only against
system configuration (0, 2 and the encoded-command test in 2 execute
harmless, cleaned-up commands purely to generate the telemetry being
verified). Run 5 on `billing-srv-01` as root; it makes a real, idempotent
change to `/etc/audit/rules.d/meddefense.rules` and reloads the live
auditd ruleset via `augenrules --load`.

Tasks 1, 3, 4 and 5 accept path/time overrides (`-SysmonConfigPath`,
`-StartTime`/`-EndTime`, `-InputPath`, `RULES_FILE=`) so their logic can be
exercised against scratch paths without touching the real Sysmon config,
event logs or auditd rules - see each script's parameter block.
