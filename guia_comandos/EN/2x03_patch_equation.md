# 2x03 – Patch Equation

## Task - 0-vuln_inventory.sh
What it does: Enumerates installed packages and identifies which ones have upgrades available from the "security" pocket, extracting CVEs from the changelog (or a local USN mapping as fallback) and cross-referencing them against CVSS scores and CISA KEV status. Produces a vulnerability inventory that can be prioritized by severity.
How to use it: `./0-vuln_inventory.sh` (reads cve_feed.json and cisa_kev.json from the same directory; writes vulnerability_inventory.json).
Commands:
- `apt-cache policy <package>` — shows the candidate version and which repository/pocket (security, updates, backports) it would come from, used to prioritize security-only updates.
- `apt-get changelog <package>` — downloads the package changelog (with a 60s timeout) to extract CVEs fixed in versions above the installed one.
- `dpkg --compare-versions <v1> gt <v2>` — compares two package versions to determine whether a changelog entry is newer than the installed version.
- `dpkg-query -W -f='${binary:Package} ${Version} ${Status}\n'` — lists every installed package with name, version and status in a controlled format.
- `apt list --upgradable` — lists packages that have a newer version available in the configured repositories.

## Task - 1-service_deps.sh
What it does: Maps every active systemd service to the package that installed it and to the shared libraries it loads, cross-referencing all of this with a criticality file to decide whether the service needs a restart when its package is patched.
How to use it: `./1-service_deps.sh [service_criticality.json] [service_dependency_map.json]` (root recommended, to read /proc for every PID).
Commands:
- `systemctl list-units --type=service --state=active --no-legend --plain` — lists every systemd service currently active.
- `systemctl show <service> --property=MainPID --value` — retrieves a service's main PID, used to locate its executable under /proc.
- `systemctl show <service> --property=ExecStart --value` — retrieves the ExecStart path defined on the unit, used as a fallback when there is no valid MainPID (e.g. oneshot services).
- `dpkg -S <path>` — finds which Debian package owns a given file/executable.
- `readlink -f <path>` — resolves the canonical path (follows symlinks), needed because of merged-/usr.
- `sudo -n readlink -f /proc/<pid>/exe` — attempts to resolve a process's executable via non-interactive sudo, when the current user lacks direct read permission.
- `ldd <executable>` — lists the shared libraries a binary depends on, to map additional packages affected by an update.

## Task - 2-pre_patch_snapshot.sh
What it does: Takes the complete "before" snapshot of the system prior to any patch: versions of every package, state of every active service, listening sockets, and a SHA-256 hash of every conffile tracked by dpkg. This is the baseline every later validation and rollback is measured against.
How to use it: `sudo ./2-pre_patch_snapshot.sh [output.json]`
Commands:
- `dpkg-query -W -f='${Conffiles}\n' '*'` — lists every configuration file (conffile) tracked by dpkg across all installed packages.
- `ss -tulnp` — lists every listening TCP/UDP socket along with its owning process, recording the network exposure surface before the patch.
- `sha256sum -- <files>` — computes the SHA-256 hash of each conffile, used as a fingerprint to detect drift later.

## Task - 3-patch_plan.sh
What it does: Joins the vulnerability inventory (T0) with the service dependency map (T1) and computes a per-package priority score (CVSS + CISA KEV presence + criticality of affected services + exposure), sorting each package into emergency/urgent/scheduled.
How to use it: `./3-patch_plan.sh [vulnerability_inventory.json] [service_dependency_map.json] [output.json]`
Commands: no system commands — this script is pure jq over artifacts already produced by T0 and T1, never touching the live system.

## Task - 4-patch_execute.sh
What it does: Applies each patch from the plan (T3) in order, with an exclusive lock against concurrent runs, exponential-backoff retries if dpkg is busy, and automatic restart of affected services; logs the "before/after" state of every package and service.
How to use it: `sudo ./4-patch_execute.sh [patch_plan.json] [output.json]` (PIPELINE_TEST=1 runs a dry-run; LOCK_FILE overrides the lock path).
Commands:
- `apt-get install --only-upgrade -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold <package>` — upgrades a single already-installed package (never installs a new one), auto-resolving modified-conffile prompts so it never hangs on stdin.
- `flock -n <fd>` — attempts to acquire an exclusive lock without blocking, guaranteeing two runs of this script never execute at the same time.
- `systemctl show <service> -p ActiveState --value` — queries a service's current active state (active/inactive/failed), before and after the patch.
- `systemctl try-restart <service>` — restarts a service only if it is already running, applied to every service affected by the just-patched package.
- `dpkg-query -W -f='${Version}' <package>` — quickly looks up the installed version of a single package.

## Task - 5-post_patch_validate.sh
What it does: Compares the current system state against the pre-patch snapshot (T2) — services, listening sockets — and runs liveness probes (HTTP/TCP/command) against every service flagged as critical, so "the patch ran" and "the patch is safe" stop being the same claim.
How to use it: `sudo ./5-post_patch_validate.sh [pre_patch_state.json] [output.json]`
Commands:
- `curl -fsS --max-time 5 -o /dev/null <url>` — HTTP liveness probe: fails silently on error, discards the response body, 5s timeout.
- `bash -c 'exec 3<>/dev/tcp/HOST/PORT'` — TCP liveness probe using bash's /dev/tcp pseudo-device to test whether a port accepts a connection (wrapped externally in timeout).

## Task - 6-config_drift.sh
What it does: Detects configuration files (conffiles) that changed since the pre-patch snapshot, separating "expected" drift (caused by the package that was just patched) from "unexpected" drift, producing a unified diff whenever a cached reference copy exists.
How to use it: `sudo ./6-config_drift.sh [pre_patch_state.json] [patch_execution_log.json] [output.json]`
Commands:
- `diff -u <baseline> <current>` — generates a unified diff between the last known-good cached copy of a conffile and the current file, showing exactly what changed.
- `cat /var/lib/dpkg/info/*.conffiles` — reads dpkg's own internal files listing which paths each package registers as a conffile.

## Task - 7-apt_recovery.sh
What it does: Diagnoses and repairs a stuck apt/dpkg system (a held lock, a half-configured package) in the one strictly safe order: removes orphaned locks, runs dpkg --configure -a, then apt-get --fix-broken install, and restarts the services owned by packages that were broken.
How to use it: `sudo ./7-apt_recovery.sh [output.json]`
Commands:
- `pgrep -fa '(dpkg|apt-get|apt)'` — lists live processes whose command line matches the pattern, used to confirm whether dpkg/apt is genuinely still running before touching any lock.
- `fuser <lock_file>` — shows which process, if any, currently has a lock file open; distinguishes a "stuck" lock (no owner) from one legitimately in use.
- `dpkg --audit` — reports packages left in an inconsistent state (half-installed, half-configured, etc).
- `dpkg -l` — lists installed packages with their status flags; used to find anything outside ii/rc/un (broken).
- `df -k /` — shows free disk space (in KB) for a filesystem, used here to diagnose dpkg failures caused by lack of space.
- `rm -f <lock_file>` — removes a dpkg/apt lock file confirmed to be orphaned (no live process holding it).
- `dpkg --configure -a` — finishes configuring every package left "unpacked but not configured", the mandatory first repair step.
- `apt-get --fix-broken install -y` — resolves broken dependencies, completing what dpkg --configure -a could not fix on its own.

## Task - 8-unattended_config.sh
What it does: Installs and configures unattended-upgrades to apply only security patches automatically, with critical packages (kernel, mysql, apache2) blacklisted and automatic reboot disabled; finishes with a dry-run to confirm what would actually be upgraded.
How to use it: `sudo ./8-unattended_config.sh [output.json]`
Commands:
- `dpkg -s <package>` — checks whether a package is installed and shows its status details.
- `apt-get install -y unattended-upgrades -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold` — installs the unattended-upgrades package non-interactively, if not already present.
- `systemctl enable --now apt-daily.timer apt-daily-upgrade.timer` — enables and immediately starts the systemd timers that trigger apt's daily update-check and upgrade.
- `systemctl is-active apt-daily.timer apt-daily-upgrade.timer` — confirms whether the configured timers are actually active.
- `unattended-upgrades --dry-run --debug` — simulates an unattended-upgrades run with verbose logging, without installing anything for real.
- `apt-mark showhold` — lists every package currently marked "hold" (blocked from upgrades).

## Task - 9-rollback.sh
What it does: Rolls a specific package back to the exact version recorded in the pre-patch snapshot (T2), confirms that version is still obtainable from the cache/repository before acting, applies a hold to stop unattended-upgrades from undoing the rollback, and re-runs the probes for affected services.
How to use it: `sudo ./9-rollback.sh <package> [pre_patch_state.json]`
Commands:
- `apt-cache madison <package>` — lists every version of a package available in the configured cache/repositories, used to confirm the rollback target version can actually be obtained.
- `apt-get install -y --allow-downgrades <package>=<version> -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold` — explicitly installs an older version of a package, permitting a downgrade.
- `apt-mark hold <package>` — pins a package at its current version, stopping unattended-upgrades from undoing the rollback on its next run.

## Task - 10-version_hold.sh
What it does: The only script authorized to change apt-mark holds and the pin file /etc/apt/preferences.d/meddefense-pins: applies every hold listed in hold_registry.json (with an owner and review date) and releases any hold no longer present in the registry.
How to use it: `sudo ./10-version_hold.sh [hold_registry.json] [output.json]`
Commands:
- `apt-mark unhold <package>` — releases the hold on a package that is no longer listed in the registry, letting it be upgraded normally again.

## Task - 11-maintenance_window.sh
What it does: Purely decides, without touching packages, whether the current moment (or a past timestamp passed via AS_OF) falls inside a configured maintenance window, including support for an always-on emergency window that requires an explicit override.
How to use it: `./11-maintenance_window.sh [--check|--report|--wait <seconds>] [maintenance_windows.json]` (MEDDEFENSE_EMERGENCY=1 accepts the emergency window as a green light).
Commands: no system commands — pure date/time logic (date) and jq over maintenance_windows.json.

## Task - 12-change_log.sh
What it does: Reconstructs the change history from /var/log/apt/history.log (and its .gz rotations), groups nearby transactions into "change events", classifies each event as inside/outside the maintenance window, and links CVEs resolved per event.
How to use it: `sudo ./12-change_log.sh [output.json]`
Commands:
- `zcat <log.N.gz>` — decompresses old rotated apt log files (/var/log/apt/history.log.N.gz) to include them when reconstructing the history.

## Task - 13-patch_pipeline.sh
What it does: Orchestrates the full pipeline — inventory, dependency map, snapshot, plan, maintenance-window check, execute, validate, drift, and change log — as one run with an aggregated status.
How to use it: `sudo ./13-patch_pipeline.sh [output.json]` (PIPELINE_TEST=1 propagates dry-run to execution; MEDDEFENSE_EMERGENCY=1 accepts the emergency window).
Commands: no new system commands — calls each of scripts 0, 1, 2, 3, 11, 4, 5, 6 and 12 in sequence via bash, propagating status and artifacts.

## Task - 14-pipeline_test.sh
What it does: Tests the pipeline against a hypothetical scenario: temporarily swaps the real CVE feed for a simulated one, runs the whole pipeline in dry-run mode, and compares the resulting patch plan against a frozen expected baseline.
How to use it: `sudo ./14-pipeline_test.sh [output.json]`
Commands: no new system commands — reruns 13-patch_pipeline.sh (PIPELINE_TEST=1) and compares patch_plan.json to the baseline via diff (already introduced in T6).

## Task - 15-compliance_report.sh
What it does: Consolidates every artifact the pipeline has already produced (vulnerability inventory, change log, holds, pipeline execution) into a single per-CVE compliance report — resolved, open, deferred by hold, or deferred by window — with a compliance score over critical/high CVEs.
How to use it: `sudo ./15-compliance_report.sh [output.json]`
Commands: no new system commands — aggregates, via jq, the artifacts already produced by earlier stages.
