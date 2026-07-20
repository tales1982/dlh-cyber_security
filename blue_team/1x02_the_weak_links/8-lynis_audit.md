# 8. The Self-Audit — Lynis Security Audit

**Analyst:** Threat Intelligence Analyst
**Date:** Current
**Audited system:** Personal Linux machine, Ubuntu 24.04.4 LTS, kernel 6.8.0-134-generic, Lynis 3.0.9

## A Note on How This Audit Was Run

The task instructions call for `sudo lynis audit system`. On this machine, `sudo` requires an interactive password prompt that could not be supplied in this session, so the audit was run as `lynis audit system` **without root privileges** instead. This is a real, supported Lynis mode — not a failure — but it comes with a direct, honest consequence: Lynis's own summary reports it ran in **non-privileged mode** and explicitly lists which tests it skipped as a result (16 tests, covering boot-loader detail, several authentication file-permission checks, iptables ruleset inspection, and disk-encryption detection — the exact categories root access unlocks). Every number below is real output from this run, not a projection — but it is a **partial** picture for exactly the same reason the MedDefense scan's own unauthenticated medical-device findings were a partial picture in Task 0: reduced access produces reduced visibility, and that limitation deserves to be stated up front rather than discovered later.

## Hardening Index

**61 / 100**, from **254 tests performed**, with 1 plugin enabled. Lynis buckets this in the "needs improvement" range typical of a general-purpose desktop/dev machine that has never been deliberately hardened — not alarming, but not defensible as a production posture either.

## Top Warnings

Running non-privileged produced exactly **one** formal Warning:

1. **KRNL-5830 — "Reboot of system is most likely needed."**
   - **What it checks:** Whether the currently running kernel matches the most recently installed kernel package (a mismatch means a kernel update was installed but the system hasn't rebooted to load it).
   - **Why it matters:** Security patches in a newer kernel package provide zero protection until the system actually boots into them — a "patched" package sitting unused is functionally identical to not having patched at all.
   - **Remediation:** Reboot during a scheduled maintenance window and confirm `uname -r` matches the latest installed kernel package.

**Why there's only one:** the majority of Lynis's Warning-level findings live in root-only checks — sudo configuration file permissions (AUTH-9252), iptables ruleset content (FIRE-4508/4512/4513), full LUKS disk-encryption detection (CRYP-7930), and password-hashing method verification (AUTH-9229) were all explicitly skipped in this run for lack of privilege. A privileged run would very likely surface additional Warnings from exactly those checks — which is the same authenticated-vs-unauthenticated distinction the MedDefense scan report itself flagged for its medical-device findings.

## Top 5 Suggestions

1. **PKGS-7398 — Install a package audit tool to determine vulnerable packages.** No tool (like `debsecan` or a Ubuntu Pro subscription check) currently cross-references installed package versions against known CVEs on this machine — meaning outdated, vulnerable packages could sit unnoticed indefinitely, the same blind spot Findings 011/026 describe for `billing-srv-01`.
2. **HRDN-7230 — Install at least one malware scanner (e.g., rkhunter, chkrootkit, OSSEC) for periodic file-system scans.** There is currently no on-demand or scheduled malware detection running on this machine at all.
3. **PKGS-7410 — Remove unneeded kernel packages (55 found).** More than 50 old kernel packages have accumulated from routine updates without cleanup — not a direct vulnerability, but it bloats the attack surface of `/boot` and makes patch-status auditing harder to reason about.
4. **LOGG-2154 — Enable logging to an external logging host for archiving and additional protection.** All logs currently live only on the local disk; if the machine were compromised, an attacker with root could alter or delete the only copy of its own audit trail.
5. **AUTH-9328 — Default umask in `/etc/login.defs` could be more strict (e.g., 027 instead of the current default).** New files created by users inherit a looser default permission mask than necessary, a small but real over-permissioning default.

## Category Breakdown

Lynis's console output does not print a literal numeric score per category — only the single overall Hardening Index — so "highest/lowest" is measured here as **tests executed per category** (breadth of coverage) cross-referenced against **suggestion density** (how many of those tests produced an actionable finding), which is a fair proxy for where a category stands.

**Most-covered categories:** Authentication (23 tests), File permissions (18), Logging (16), Networking (14), Name resolution/DNS (13). These are also Lynis's traditional core strengths — most of a general Linux hardening posture lives in these five buckets.

**Highest finding-density categories (most suggestions relative to tests run):** Debian/Ubuntu package-management checks (5 suggestions out of only 6 tests run — fail2ban, apt-listbugs, apt-listchanges and needrestart are all absent) and Package management broadly (5 suggestions out of 8 tests — no vulnerable-package auditing tool, no patch-tracking tool installed). **Lowest finding-density:** Networking (4 suggestions out of 14 tests) and File permissions (4 out of 18) — the bulk of those categories' checks passed cleanly.

**What this says about this machine's posture:** the pattern mirrors MedDefense's own profile from Task 7 almost exactly — the gaps are concentrated in **tooling and process** (no malware scanner, no vulnerable-package auditor, no remote log shipping), not in fundamentally broken configuration. This is a personal workstation that has been reasonably maintained by default OS behavior but never deliberately hardened past that baseline — the same "prevention exists, detection and process discipline are thin" pattern identified in the 1x00 Gap Analysis for MedDefense itself.

## Part 3: MedDefense Projection — `billing-srv-01`

Without access to the actual server, here are 5 specific Lynis findings I would expect on `billing-srv-01` (Ubuntu 18.04, Apache 2.4.29, MySQL, prior cryptominer compromise, SSH password auth enabled), reasoning from what the scan report and 1x00 already establish about this host:

1. **SSH-7408 / SSH hardening: "PasswordAuthentication yes" flagged as a suggestion/warning.** Lynis's SSH module directly inspects `sshd_config` for exactly this directive. This is not a prediction requiring inference — Finding 009 already confirms password authentication is enabled on this host, so Lynis would flag it with certainty.
2. **HRDN-7230 — No malware scanner installed, at Warning-level severity rather than Suggestion-level, given the history.** The 1x00 Gap Analysis (GAP-005) already establishes that Sophos AV explicitly excludes all Linux servers, including `billing-srv-01` — and this is the exact server that hosted an undetected cryptominer for two weeks (1x00 Task 2). Lynis would flag the absence of any malware-scanning tool, and I'd weight this one higher than a typical Suggestion given the server's own incident history.
3. **PKGS-7392 / PKGS-7394 — Security updates unavailable or unresolved, Ubuntu 18.04 past standard support.** Finding 011 already confirms ESM was never enrolled; a privileged Lynis run specifically checks `apt-show-versions`/`unattended-upgrades` status and would very likely report that no security-patch channel is currently active for this OS release at all — not just "some patches missing," but "no patch channel exists."
4. **FIRE-4508/4512 — No effective host-based firewall ruleset, or an overly permissive one.** Given that MySQL is confirmed bound to `0.0.0.0` (Finding 006) with no compensating network ACL, a privileged Lynis run inspecting `iptables`/`nftables` on this host would very likely find either no host firewall active at all, or a default-accept posture — since a host firewall correctly configured to restrict 3306 would have made Finding 006 far less exploitable in practice.
5. **LOGG-2154 — No remote/central logging configured.** This lines up directly with GAP-002 from the 1x00 Gap Analysis: logs exist on this host but nothing centrally aggregates or actively reviews them. A Lynis run would flag the same local-only logging gap already identified as the root cause of both prior incidents (ransomware and cryptominer) going unnoticed until symptoms became visible.

## Repo

- **GitHub repository:** `dlh-cyber_security`
- **Directory:** `blue_team/1x02_the_weak_links`
- **File:** `8-lynis_audit.md`
