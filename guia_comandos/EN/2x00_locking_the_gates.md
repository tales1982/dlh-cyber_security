# 2x00 – Locking the Gates

## Task - 0-baseline_snapshot.sh
What it does: Captures a complete, read-only security baseline snapshot of the host before any hardening happens — services, ports, SUID/SGID binaries, world-writable files, sysctl parameters and SSH config — so later work can be measured against it.
How to use: `sudo ./0-baseline_snapshot.sh [output.json]`
Commands:
- `hostname` — shows the host's name, used to identify the system in the baseline report.
- `cat /etc/os-release` — shows the OS distribution/version, needed to know which security benchmark applies.
- `uname -r` — shows the running kernel version, used to cross-reference known kernel CVEs.
- `uptime -p` — shows how long the system has been up without a reboot, a patch/reboot discipline indicator.
- `systemctl list-units --type=service --state=running` — lists every service currently running, the baseline attack-surface inventory.
- `ss -tulnH` — lists listening TCP/UDP sockets, showing which ports are actually reachable on the host.
- `find / -xdev -type f -perm -4000` — finds binaries with the SUID bit set, the classic local-privilege-escalation vector.
- `find / -xdev -type f -perm -2000` — finds binaries with the SGID bit set, the same escalation risk at the group level.
- `find / -xdev -type f -perm -0002` — finds world-writable files, files an attacker could tamper with so a privileged process later executes them.
- `cat /proc/sys/<parameter>` — reads the current value of a kernel sysctl parameter straight from the running kernel.
- `grep -iE '^\s*<Directive>\s+' /etc/ssh/sshd_config` — checks the current value of a specific sshd_config directive.
- `awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd` — lists "regular" (non-system) user accounts from the password database.
- `getent group sudo` — lists members of the sudo group, i.e. who has administrative privilege escalation.

## Task - 1-cis_profile.sh
What it does: Generates the threat-prioritized CIS control catalog (MD-CIS-001 through 015) the company decided to implement, mapping each control to its remediation script and verification method.
How to use: `./1-cis_profile.sh`
Commands:
- No system commands — the script only generates a static JSON catalog via jq, without inspecting the host.

## Task - 2-lynis_parse.sh
What it does: Converts the raw Lynis report (lynis-report.dat) into a structured JSON with the hardening index and every finding (warning/suggestion/manual_check), for consumption by the other tasks.
How to use: `./2-lynis_parse.sh /var/log/lynis-report.dat`
Commands:
- `grep '^hardening_index=' <report.dat>` — extracts the Lynis hardening index (score) from the report file.

## Task - 3-remediation_queue.sh
What it does: Cross-references the CIS profile (Task 1) and Lynis findings (Task 2) against the live system state to classify every control (compliant/non_compliant/etc.) and produces a priority-ordered remediation queue.
How to use: `./3-remediation_queue.sh [cis_profile.json] [lynis_findings.json]`
Commands:
- `id -u` — checks whether the script is running as root (needed for full system visibility).
- `grep 'minlen' /etc/security/pwquality.conf` — checks the configured minimum password length policy.
- `findmnt -no OPTIONS /tmp` — shows the current mount options (e.g. noexec, nosuid) applied to a filesystem.
- `systemctl list-unit-files --type=service --state=enabled` — lists services configured to start at boot (attack surface that persists across reboots).
- `grep 'deny' /etc/security/faillock.conf` — checks the configured account lockout threshold.
- `aa-status --enforced` — lists AppArmor profiles currently running in enforce (blocking) mode.
- `grep 'identity' /etc/audit/rules.d/meddefense.rules` — checks whether a specific audit watch rule is present in the rules file.
- `grep 'ENABLED=' /etc/ufw/ufw.conf` — checks whether the UFW firewall is configured to be enabled.
- `find /etc/rsyslog.d -iname '*meddefense*'` — checks whether a custom log-routing policy has already been deployed.

## Task - 4-ssh_hardening.sh
What it does: Applies SSH hardening (no password auth, no root login, MaxAuthTries, session idle timeout, warning banner, etc.) by editing sshd_config idempotently and restarting the service.
How to use: `sudo ./4-ssh_hardening.sh [path-to-sshd_config]`
Commands:
- `cp -p /etc/ssh/sshd_config /etc/ssh/sshd_config.bak` — backs up a config file before modifying it, preserving permissions and timestamps.
- `sed -i -E 's|...|...|' /etc/ssh/sshd_config` — idempotently replaces/edits a config directive in place.
- `sshd -t -f /etc/ssh/sshd_config` — validates sshd configuration syntax before applying/restarting the service.
- `systemctl restart ssh.service` — restarts a service to apply the new configuration.
- `systemctl is-active ssh.service` — checks whether a service is currently active/running.

## Task - 5-sysctl_hardening.sh
What it does: Hardens network and kernel parameters via sysctl (disables IP forwarding, ICMP redirects, enables full ASLR, SYN cookies, etc.) to block pivoting and reduce the reliability of memory-corruption exploits.
How to use: `sudo ./5-sysctl_hardening.sh [path-to-sysctl.conf]`
Commands:
- `sysctl -p /etc/sysctl.conf` — applies the parameters from a sysctl file directly to the running kernel.

## Task - 6-filesystem_hardening.sh
What it does: Sweeps the system for SUID/SGID binaries outside the whitelist and world-writable files, strips the dangerous bits/permissions, applies noexec/nosuid/nodev to /tmp, /var/tmp and /dev/shm, and restricts cron access.
How to use: `sudo ./6-filesystem_hardening.sh [SCAN_ROOT]`
Commands:
- `chmod u-s <file>` — removes the SUID bit from a binary, eliminating a privilege-escalation path.
- `chmod g-s <file>` — removes the SGID bit from a binary.
- `chmod o-w <file>` — removes the "other" write permission from a file.
- `chmod <numeric mode> <file>` — sets explicit numeric permissions (e.g. 600 on cron.allow, restricting who can schedule cron jobs).
- `stat -c '%a' <file>` — shows a file's permission bits, used to record the before/after state.
- `mount -o remount,<options> <mountpoint>` — reapplies mount options (e.g. noexec,nosuid,nodev) to an already-mounted filesystem without unmounting it.

## Task - 7-service_minimization.sh
What it does: Compares enabled services against a required-services whitelist and stops/disables everything not on the list, reducing exposed attack surface.
How to use: `sudo ./7-service_minimization.sh` (or `DRY_RUN=1 ./7-service_minimization.sh` to report only)
Commands:
- `systemctl start <unit>` — starts a required service that should be running but isn't.
- `systemctl stop <unit>` — stops a running service that is not on the whitelist.
- `systemctl disable <unit>` — prevents a service from starting automatically at boot.

## Task - 8-pam_hardening.sh
What it does: Installs and configures libpam-pwquality and pam_faillock to enforce password complexity policy, account lockout after failed attempts, and password history, editing the PAM stack with safety backups.
How to use: `sudo ./8-pam_hardening.sh`
Commands:
- `dpkg -s <package>` — checks whether a package is installed and its version.
- `apt-get install -y <package>` — installs a package non-interactively.

## Task - 9-apparmor_config.sh
What it does: Checks and forces enforce mode for the Apache/MySQL AppArmor profiles and deploys a custom profile for the billing application, confining the process even if it is compromised.
How to use: `sudo ./9-apparmor_config.sh`
Commands:
- `grep 'Y' /sys/module/apparmor/parameters/enabled` — checks whether the AppArmor kernel module is loaded/enabled.
- `aa-status --complaining` — lists AppArmor profiles running in complain mode (log-only, non-blocking).
- `aa-enforce <binary/profile>` — switches an AppArmor profile from complain to enforce (blocking) mode.
- `apparmor_parser -r <profile>` — reloads/compiles an AppArmor profile into the kernel.
- `diff -q <file1> <file2>` — compares two files to determine whether content actually changed (decides whether a rewrite/reload is needed).

## Task - 10-auditd_config.sh
What it does: Installs/enables auditd and deploys a set of kernel-level audit rules (identity files, SSH/PAM config, privilege escalation, suspicious tooling, persistence), validating with a controlled functional test.
How to use: `sudo ./10-auditd_config.sh`
Commands:
- `systemctl enable --now <service>` — enables a service to start at boot AND starts it immediately, in one command.
- `augenrules --load` — compiles and loads every rule file in rules.d into the kernel audit subsystem.
- `auditctl -R <rules_file>` — loads a specific rules file directly into the kernel (fallback when augenrules is unavailable).
- `auditctl -l` — lists the audit rules currently active in the kernel.
- `useradd -M -N -s /usr/sbin/nologin <user>` — creates a throwaway test account (no home dir, no private group, no shell) for a controlled test.
- `userdel <user>` — removes a user account, cleaning up test artifacts.
- `ausearch --input-logs -ts recent -k <key>` — searches the audit log for events tagged with a specific rule key.

## Task - 11-audit_coverage_test.sh
What it does: Fires six controlled, reversible triggers (sudo, user creation, curl, sshd_config change, writes to init.d/cron.d) and confirms via ausearch that each Task 10 audit rule actually captures the event.
How to use: `sudo ./11-audit_coverage_test.sh`
Commands:
- `sudo -n true` — tests whether cached/passwordless sudo credentials are available (non-interactive privilege check); also used here to generate a controlled privilege-escalation audit event.
- `curl --version` — harmless command run to generate a controlled "suspicious tool execution" event and test audit coverage.
- `touch <file>` — updates only a file's modification time (used here to trigger an attribute-change audit rule without altering the content).

## Task - 12-log_config.sh
What it does: Configures rsyslog routing (auth/authpriv to auth.log, everything else to syslog), sets logrotate retention policies, and fixes log file permissions/ownership, verifying it all with a test marker via logger.
How to use: `sudo ./12-log_config.sh`
Commands:
- `logger -p <facility.priority> <message>` — injects a test message into the system log at a specific facility/priority, used to verify log routing.
- `chown <user>:<group> <file>` — changes a file's owner and group.

## Task - 13-firewall_baseline.sh
What it does: Configures UFW with a default-deny inbound policy, allows only SSH (management network), HTTP/HTTPS and MySQL (application network), turns on logging, and enables the firewall.
How to use: `sudo ./13-firewall_baseline.sh`
Commands:
- `ufw default deny incoming` — sets the firewall's default policy to deny inbound traffic not explicitly allowed.
- `ufw default allow outgoing` — sets the firewall's default policy to allow outbound traffic.
- `ufw allow from <network> to any port <port> proto tcp` — allows a port only from a specific source network (segmented ACL).
- `ufw allow <port>/tcp` — allows a port from any source (open rule).
- `ufw logging low` — sets the firewall's log verbosity level.
- `ufw status verbose` — shows the firewall's current status, default policies and rule set.
- `ufw --force enable` — activates the firewall without an interactive confirmation prompt.

## Task - 14-hardening_orchestrator.sh
What it does: Orchestrates running Tasks 0, 2, 4-13 and 15 in order, halts the pipeline on the first failed step, and produces the before/after Lynis score delta proving the hardening worked.
How to use: `sudo ./14-hardening_orchestrator.sh` (or `DRY_RUN=1 ./14-hardening_orchestrator.sh` to test only the control flow)
Commands:
- `lynis audit system --quick --no-colors` — runs a full Lynis security scan and writes a report file.

## Task - 15-validation.sh
What it does: Runs an independent battery of post-hardening checks (SSH, sysctl, SUID, mount options, PAM, services, auditd, AppArmor, logs, UFW) and produces a PASS/FAIL report per CIS control.
How to use: `sudo ./15-validation.sh` (works without root, but with partial checks on items that require privilege, such as UFW)
Commands:
- No new commands — reapplies the verification patterns already listed (config greps, `cat /proc/sys`, SUID/SGID `find`, `systemctl is-active`/`list-unit-files`, `ufw status verbose`, rsyslog policy `find`) to validate the post-hardening state.

## Task - 16-lynis_diff.sh
What it does: Compares Lynis findings before and after hardening (by test_id) to classify each as resolved, remaining, or new, and calculates the hardening index delta.
How to use: `./16-lynis_diff.sh [before_findings.json] [after_findings.json]`
Commands:
- No new commands — reruns `lynis audit system --quick --no-colors` (already listed in Task 14) to generate the post-hardening comparison scan when one doesn't already exist.

## Task - 17-compliance_bundle.sh
What it does: Consolidates the six evidence artifacts produced by the earlier tasks into a single audit-ready compliance bundle, with remediated/verified controls, documented deviations, and residual findings.
How to use: `./17-compliance_bundle.sh`
Commands:
- No new system commands — aggregates the JSON files produced by earlier tasks via jq; reuses `hostname`, `cat /etc/os-release` and `uname -r` already listed in Task 0.
