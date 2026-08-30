# 2x05 – Defensible Endpoint

## Task - 0-environment_intake.sh

What it does: Collects a complete snapshot of the Linux host (hawthorne-app-01) for the capstone intake — hostname, kernel, distro, patch level, package count, listening sockets, active systemd services, effective sshd configuration, security-related sysctl parameters, SUID/SGID and world-writable file counts, the size of the loaded nftables ruleset, and auditd/rsyslog/Sysmon status — all into a single JSON.
How to use it: `./0-environment_intake.sh` (writes to `artifacts/<hostname>-capstone-environment_intake.json`)
Commands:

- `hostname` — identifies the host in the intake report.
- `uname -r` — the running kernel version.
- `grep '^PRETTY_NAME=' /etc/os-release` — extracts the OS distribution/version.
- `apt list --upgradable` — counts how many updates are pending, used as the patch level.
- `dpkg-query -W` — counts the total number of installed packages.
- `ss -tulnpH` — lists listening TCP/UDP sockets with their owning process.
- `systemctl list-units --type=service --state=active --no-legend --no-pager` — lists the systemd services currently active.
- `sudo sshd -T` — dumps the effective sshd configuration (every directive already resolved, not just what's written in the file).
- `sysctl <param> [<param> ...]` — reads several security-related kernel parameters at once (ip_forward, ASLR, redirects, syncookies, etc.).
- `sudo find / -perm /6000 -type f` — counts binaries with the SUID or SGID bit set.
- `sudo find / -path /proc -prune -o -path /sys -prune -o -perm -0002 -type f -print` — counts world-writable files, excluding /proc and /sys.
- `sudo nft list ruleset` — measures the size in bytes of the currently loaded nftables ruleset.
- `systemctl is-active auditd` / `systemctl is-active rsyslog` — status of the two telemetry services.
- `command -v sysmon` — checks whether Sysmon for Linux is installed and returns the executable path.

## Task - 0-environment_intake.ps1

What it does: Windows counterpart of the intake — hostname, OS build, patch level (UBR), installed-feature count, running services, local user accounts, per-profile firewall status, the full audit policy, Sysmon presence/version with its log channel size, Script Block Logging state, and account policy — serialized into a single JSON.
How to use it: `.\0-environment_intake.ps1` (PowerShell as Administrator; writes to `artifacts\<hostname>-capstone-environment_intake.json`)
Commands:

- `hostname` — identifies the host in the intake report.
- `Get-ComputerInfo` — used here only for its OsBuildNumber field, the OS build.
- `Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'` — reads the UBR (Update Build Revision), Windows's fine-grained patch level.
- `Get-CimInstance Win32_OperatingSystem` — determines the ProductType (workstation vs. server/DC) to decide which feature-count command to use next.
- `Get-WindowsOptionalFeature -Online` / `Get-WindowsFeature` — count installed features; the first on a workstation, the second on a server/DC.
- `Get-Service` — lists services and filters down to the ones currently running.
- `Get-LocalUser` — lists local user accounts.
- `Get-NetFirewallProfile` — enabled/disabled status of each Windows Firewall profile.
- `auditpol /get /category:*` — dumps the full audit policy, every category.
- `Get-Service -Name "Sysmon*"` — checks whether the Sysmon service is installed.
- `Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\<service>"` — reads the Sysmon service's ImagePath to locate the executable and extract its version.
- `Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational"` — the Sysmon log channel's size, without reading the events themselves.
- `Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'` — the Script Block Logging policy state.
- `net accounts` — account policy (lockout, minimum password length, expiration).
- `ConvertTo-Json -Depth N | Set-Content -Path <file> -Encoding UTF8` — serializes the resulting PowerShell object into JSON and writes the intake file to disk.

## Task - 1-baseline_snapshot.sh

What it does: Runs Lynis in quick mode against the Linux host, extracts the Hardening Index, warnings count and suggestions count from the raw report, and writes it all — together with the full Lynis log — as the "before hardening" baseline, to be compared later against Task 3's result.
How to use it: `sudo ./1-baseline_snapshot.sh` (writes to `capstone/baseline/baseline_linux.json` and `capstone/baseline/lynis_baseline.log`)
Commands:

- `lynis audit system --quick --no-colors` — runs the full Lynis audit with no interactive prompts and no color codes, so the log comes out clean.
- `grep -m1 '^hardening_index=' /var/log/lynis-report.dat` — extracts the first occurrence of the Hardening Index from Lynis's raw report.
- `grep -c '^warning\[\]='` / `grep -c '^suggestion\[\]='` — count how many findings of each type (warning/suggestion) Lynis recorded in the report.
- `lynis --version` — the installed Lynis version, recorded in the baseline for traceability.

## Task - 1-baseline_snapshot.ps1

What it does: Runs the lab-provided audit helper (win_audit.ps1) and module 2x01's CIS Level 1 scoring script (15-master_validation.ps1) against the Windows host, computes the pass rate (pass_rate_percent), and writes the "before hardening" baseline.
How to use it: `.\1-baseline_snapshot.ps1` (PowerShell as Administrator; writes to `capstone\baseline\baseline_windows.json` and `capstone\baseline\windows_baseline.log`)
Commands:

- (no new command — directly invokes the existing `win_audit.ps1` and `15-master_validation.ps1` scripts from module 2x01, and uses `Get-Content -Raw | ConvertFrom-Json` to read back the JSON report they produce)

## Task - 2-target_state.sh

What it does: Declares the capstone's target-state "contract" — 29 controls covering hardening, telemetry, patching, network and handoff across both platforms — each with id, platform, family, description, check type (file_exists/json_field_equals/json_field_gte/command_exit_zero/grep_match), check target and expected value. Inspects nothing on the system — it only materializes the JSON that Task 8 will use as the source of truth to validate everything. Refuses to overwrite an existing target_state.json unless `--force` is passed.
How to use it: `./2-target_state.sh [--force]` (writes to `capstone/target_state.json`)
Commands: no system command — the script is pure jq, it assembles the controls list straight into JSON.

## Task - 3-linux_harden.sh

What it does: Orchestrates the full Linux hardening pass in deterministic order — SSH, sysctl, permissions (SUID/world-writable), service minimization, PAM, AppArmor and auditd — reusing module 2x00's scripts (with local overrides wherever one needs a Hawthorne-specific adjustment, e.g. the service whitelist and the allowed SSH user). Captures each step's stdout and exit code into a log, re-runs Lynis at the end, and only exits 0 if every step passed and the new Hardening Index meets the target defined in target_state.json.
How to use it: `sudo ./3-linux_harden.sh`
Commands: no new command — reuses `lynis audit system --quick --no-colors` and `grep -m1 '^hardening_index='`, already seen in Task 1; what's new here is orchestrating module 2x00's seven hardening scripts in sequence, not a new system command.

## Task - 4-windows_harden.ps1

What it does: Orchestrates the full Windows hardening pass in order — account policy, audit policy, Windows Firewall, Sysmon deployment, Script Block Logging, AppLocker and service minimization — reusing module 2x01's scripts (with local overrides, e.g. the correct subnet on the management firewall rules). Captures each step's stdout and exit code, re-runs win_audit.ps1 and the CIS Level 1 scoring at the end, and emits the same JSON schema as its Linux sibling (Task 3) so Task 8 can read both platforms without branching logic.
How to use it: `.\4-windows_harden.ps1` (PowerShell as Administrator)
Commands: no new command — reuses `Get-Content -Raw | ConvertFrom-Json`, already seen in Task 1, to read target_state.json and the validation reports; what's new here is orchestrating module 2x01's seven hardening scripts in sequence, not a new system command.

## Task - 5-telemetry_deploy.sh

What it does: Ensures auditd is active with the meddefense rules file loaded, runs a controlled test sequence (create/remove a user, restart a service, add/remove a cron job, run find as root) and confirms via ausearch that each one produced the expected event under the right key. Exports the last 30 minutes of auditd and syslog events.
How to use it: `sudo ./5-telemetry_deploy.sh` (writes to `capstone/telemetry/linux_events.json`)
Commands:

- `ausearch -ts recent -k <key>` — searches recent audit records tagged with a specific key, used to confirm that each test action actually produced the expected record.
- `augenrules --load` — reloads the audit rule set from /etc/audit/rules.d/, ensuring the meddefense.rules rule is actually in effect.
- `useradd -M -N -s /usr/sbin/nologin <user>` / `userdel <user>` — trigger: creates and then removes a test user to fire identity events.
- `systemctl restart cron` (or `rsyslog` as a fallback) — trigger: restarts a service to fire a process-execution event.
- `crontab -l` / `crontab -` — trigger: schedules and then removes a test cron job to fire a cron-persistence event.
- `find /tmp -maxdepth 1 -name "<pattern>"` — trigger: an authorized run as root, to test process tracking.
- `journalctl --since "30 minutes ago" --no-pager` (or `tail -n 500 /var/log/syslog` as a fallback) — exports the recent system-log window alongside the auditd events.

## Task - 5-telemetry_deploy.ps1

What it does: Confirms Sysmon and Script Block Logging are actually active, runs a controlled test sequence (create a local user, a scheduled task, restart a service, an authorized PowerShell command) and checks each relevant event channel (Security, System, PowerShell Operational) for the expected Event ID within 10 minutes. Exports the last 30 minutes of Sysmon and PowerShell events.
How to use it: `.\5-telemetry_deploy.ps1` (PowerShell as Administrator; writes to `capstone\telemetry\windows_events.json` and `windows_coverage.json`)
Commands:

- `Get-WinEvent -FilterHashtable @{ LogName=...; Id=...; StartTime=... }` — queries an event log filtered by ID and time window, used both to confirm each individual trigger and to export the 30-minute Sysmon/PowerShell window.
- `New-LocalUser` / `Remove-LocalUser` — trigger: creates and removes a test local user to fire Security EID 4720.
- `Register-ScheduledTask` / `Start-ScheduledTask` / `Unregister-ScheduledTask` — trigger: creates, runs and removes a test scheduled task to fire Security EID 4698.
- `Restart-Service -Name "Spooler" -Force` — trigger: restarts a service to fire System EID 7036.

## Task - 6-patch_pipeline.sh

What it does: Orchestrates module 2x03's patch pipeline (13-patch_pipeline.sh) end to end against the host, redirecting every sub-step's artifacts into the capstone package via the CAPSTONE_ARTIFACTS_DIR environment variable, consuming the lab-provided CVE feed and mandated blacklist, and configuring unattended-upgrades with that blacklist. Only exits 0 if the pipeline exited 0 and no entry in the execution log ended up in "failed" status.
How to use it: `sudo ./6-patch_pipeline.sh` (consumes `/home/analyst/MedDefense_Lab/capstone/cve_feed.json` and `blacklist.json`; writes to `capstone/patch/`)
Commands: no new command — what's new is the orchestration (`export CAPSTONE_ARTIFACTS_DIR=...` and `sudo -E bash <script>`, the latter needed to propagate the environment variables into the sub-process instead of losing them to plain `sudo`) over module 2x03's existing scripts; the failure check reuses `jq` on the execution log they already produce.

## Task - 7-network_deploy.sh

What it does: Orchestrates the network defense stack against the host — copies the Hawthorne-specific segmentation_rules.json (does not regenerate MedDefense's main topology), validates and optionally applies module 2x04's nftables config, runs the functional test against the live ruleset, brings up Suricata and replays every provided PCAP, runs the custom rule validation against the labeled PCAPs, and configures the local DNS filter. By default runs nftables in `--render-only` mode (validates syntax only, doesn't load it live, to avoid risking the management session itself); `--apply-live` is required to actually apply the ruleset and to run the functional test against it.
How to use it: `sudo ./7-network_deploy.sh [--apply-live]` (writes to `capstone/network/`)
Commands: no new command directly — orchestrates `4-nftables_config.sh`, `8-suricata_setup.sh`, `9-suricata_analysis.sh` and the `10-rule_validation.sh`/`13-dns_filtering.sh` overrides from module 2x04, plus `5-firewall_test.sh` (a new script, written for this module because 2x04's own Task 5 had never actually been implemented), which reuses `nft list ruleset`, already seen in module 2x04, to check that every flow declared in segmentation_rules.json has a matching live rule loaded.

## Task - 8-validate_all.sh

What it does: Reads target_state.json, evaluates each of the 29 controls dispatching on check_type (file_exists, json_field_equals, json_field_gte, command_exit_zero, grep_match), skips controls whose platform doesn't match the current host, and aggregates results by control family (hardening/telemetry/patching/network/handoff) into a machine-readable report. Must run as root, since several checks require it (aa-status, auditctl, nft list ruleset). Only exits 0 if no evaluated control came back fail or error.
How to use it: `sudo ./8-validate_all.sh [target_state.json]` (writes to `capstone/validation.json`)
Commands:

- `eval "$command"` — command_exit_zero check: dynamically runs the command string defined in a control's check_target field and evaluates only its exit code.
- `grep -Eq -- "$pattern" <file>` — grep_match check: searches for the expected_value (extended regex) in the target file, quietly (no output, just the exit code).
- `jq -c "$field" <file>` — json_field_equals/json_field_gte checks: extracts a field's value from the target JSON preserving its original type (string, number, bool) for comparison, unlike `jq -r`, which always returns plain text and would break the numeric/boolean comparison.
- `awk -v p="$total_pass" -v t="$total_evaluated" 'BEGIN { printf "%.1f", (p / t) * 100 }'` — computes the pass percentage to one decimal place.
