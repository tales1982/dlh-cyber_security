#!/bin/bash
#
# 1-cis_profile.sh
#
# MedDefense Health Systems - Locking the Gates (2x00)
#
# Builds a threat-driven CIS control profile for billing-srv-01, web-srv-01
# and log-srv-01. The CIS Benchmark for Ubuntu 22.04 is ~800 pages; Sarah
# Park's instruction was explicit: "do not implement all of it. Pick the
# controls that matter for our threat model." This script is that decision,
# expressed as data so Tasks 3, 15, 16 and 17 can consume it programmatically
# instead of re-deriving it from a PDF.
#
# control_id values defined here (MD-CIS-001 .. MD-CIS-015) are the anchor
# identifiers for the rest of the project: Task 3 (gap_analysis.json /
# remediation_queue.json), Task 15 (validation_results.json) and Task 17
# (compliance_report.json) all reference these exact IDs. Do not renumber.
#
# Read-only / generator script - produces cis_profile.json, makes no system
# changes.

set -euo pipefail

OUT_JSON="cis_profile.json"

CONTROLS_JSON=$(cat <<'EOF'
[
  {
    "control_id": "MD-CIS-001",
    "title": "SSH Password Authentication Disabled",
    "cis_section": "5 - Access, Authentication and Authorization",
    "severity": "critical",
    "asset_scope": ["billing-srv-01", "web-srv-01", "log-srv-01"],
    "threat_mapping": "1x02 Finding 009 (SSH password auth permits brute force); Crimson Tide Phase 3 (SSH lateral movement via harvested credentials)",
    "implementation_task": "4-ssh_hardening.sh",
    "verification_method": "sshd -T | grep passwordauthentication -> no; MD-CIS-001 check in 15-validation.sh",
    "justification": "3 of 5 hospital breaches in the Crimson Tide advisory used SSH with password auth for lateral movement. Key-only auth removes the credential-stuffing/brute-force path entirely."
  },
  {
    "control_id": "MD-CIS-002",
    "title": "SSH Root Login Prohibited",
    "cis_section": "5 - Access, Authentication and Authorization",
    "severity": "critical",
    "asset_scope": ["billing-srv-01", "web-srv-01", "log-srv-01"],
    "threat_mapping": "1x02 Finding 009; Crimson Tide Phase 3 (SSH lateral movement)",
    "implementation_task": "4-ssh_hardening.sh",
    "verification_method": "sshd -T | grep permitrootlogin -> no; MD-CIS-002 check in 15-validation.sh",
    "justification": "Direct root SSH login removes the audit trail of which named account was used and is unnecessary when sudo is available to authorized admins."
  },
  {
    "control_id": "MD-CIS-003",
    "title": "Kernel Network Stack Hardened Against Pivoting",
    "cis_section": "3 - Network Configuration",
    "severity": "critical",
    "asset_scope": ["billing-srv-01", "web-srv-01", "log-srv-01"],
    "threat_mapping": "Crimson Tide Phase 3 (lateral movement across a flat network via IP forwarding / ICMP redirects)",
    "implementation_task": "5-sysctl_hardening.sh",
    "verification_method": "sysctl net.ipv4.ip_forward, accept_redirects, tcp_syncookies read back from /proc/sys; MD-CIS-003 check in 15-validation.sh",
    "justification": "A compromised host with IP forwarding enabled becomes a router for the attacker; ICMP redirects allow traffic rerouting. Both are default-off requirements for any production Linux server."
  },
  {
    "control_id": "MD-CIS-004",
    "title": "SUID/SGID Binary Whitelist Enforced",
    "cis_section": "1 - Initial Setup",
    "severity": "critical",
    "asset_scope": ["billing-srv-01", "web-srv-01", "log-srv-01"],
    "threat_mapping": "Crimson Tide Phase 3 (local privilege escalation after initial low-privilege access)",
    "implementation_task": "6-filesystem_hardening.sh",
    "verification_method": "find / -xdev -perm -4000/-2000 compared to whitelist; MD-CIS-004 check in 15-validation.sh",
    "justification": "SUID/SGID binaries outside the known-safe Ubuntu 22.04 set are the most common local privilege-escalation vector once an attacker has any shell."
  },
  {
    "control_id": "MD-CIS-005",
    "title": "PAM Password Quality Policy Enforced",
    "cis_section": "5 - Access, Authentication and Authorization",
    "severity": "critical",
    "asset_scope": ["billing-srv-01", "web-srv-01", "log-srv-01"],
    "threat_mapping": "Crimson Tide Phase 2 (harvested/weak credentials) and Phase 3 (Kerberoasting-style credential reuse)",
    "implementation_task": "8-pam_hardening.sh",
    "verification_method": "grep minlen/dcredit/ucredit/reject_username /etc/security/pwquality.conf; MD-CIS-005 check in 15-validation.sh",
    "justification": "MedDefense currently enforces no password complexity on Linux hosts. A 14-character complexity policy directly raises the cost of the credential-based attacks documented in 3 of 5 Crimson Tide breaches."
  },
  {
    "control_id": "MD-CIS-006",
    "title": "Kernel Memory and Pointer Exposure Protections",
    "cis_section": "1 - Initial Setup",
    "severity": "high",
    "asset_scope": ["billing-srv-01", "web-srv-01", "log-srv-01"],
    "threat_mapping": "Finding 026 (outdated kernel, 47 known CVEs) - ASLR/kptr_restrict reduce exploit reliability even against unpatched kernel bugs",
    "implementation_task": "5-sysctl_hardening.sh",
    "verification_method": "sysctl kernel.randomize_va_space=2, kernel.kptr_restrict=2, kernel.dmesg_restrict=1, fs.suid_dumpable=0; MD-CIS-006 check in 15-validation.sh",
    "justification": "With 47 known CVEs outstanding against the kernel (Finding 026), memory-corruption exploit reliability must be reduced independently of patching timelines."
  },
  {
    "control_id": "MD-CIS-007",
    "title": "World-Writable Files Remediated and Hardened Mount Options",
    "cis_section": "1 - Initial Setup",
    "severity": "high",
    "asset_scope": ["billing-srv-01", "web-srv-01", "log-srv-01"],
    "threat_mapping": "Crimson Tide Phase 3 (privilege escalation via modification of root-executed files); 1x00 incident (crypto-miner persistence in writable web directories)",
    "implementation_task": "6-filesystem_hardening.sh",
    "verification_method": "find / -xdev -perm -0002 -type f; findmnt -no OPTIONS for /tmp,/var/tmp,/dev/shm; MD-CIS-007 check in 15-validation.sh",
    "justification": "World-writable files let a low-privilege attacker tamper with content a privileged process later executes; noexec/nosuid/nodev on temp filesystems removes /tmp as a binary-drop staging area."
  },
  {
    "control_id": "MD-CIS-008",
    "title": "Unnecessary Services Disabled (Attack Surface Reduction)",
    "cis_section": "2 - Services",
    "severity": "high",
    "asset_scope": ["billing-srv-01", "web-srv-01", "log-srv-01"],
    "threat_mapping": "1x02 Finding 006 (MySQL bound to 0.0.0.0); Crimson Tide advisory (every breach started with a misconfigured, reachable service)",
    "implementation_task": "7-service_minimization.sh",
    "verification_method": "systemctl list-unit-files --state=enabled compared to MedDefense whitelist; MD-CIS-008 check in 15-validation.sh",
    "justification": "Baseline found 24 enabled services on billing-srv-01. A billing server does not need avahi-daemon, cups or rpcbind - each is an unused, unmonitored entry point."
  },
  {
    "control_id": "MD-CIS-009",
    "title": "Account Lockout on Repeated Failed Authentication",
    "cis_section": "5 - Access, Authentication and Authorization",
    "severity": "high",
    "asset_scope": ["billing-srv-01", "web-srv-01", "log-srv-01"],
    "threat_mapping": "Crimson Tide Phase 2/3 (credential brute force and reuse)",
    "implementation_task": "8-pam_hardening.sh",
    "verification_method": "grep deny/unlock_time/fail_interval /etc/security/faillock.conf; MD-CIS-009 check in 15-validation.sh",
    "justification": "Without pam_faillock, an attacker with a credential list has unlimited authentication attempts. 5 attempts / 900s lockout directly closes the brute-force window Finding 009 identified."
  },
  {
    "control_id": "MD-CIS-010",
    "title": "AppArmor Mandatory Access Control Enforced",
    "cis_section": "1 - Initial Setup",
    "severity": "high",
    "asset_scope": ["billing-srv-01", "web-srv-01"],
    "threat_mapping": "1x00 incident (crypto-miner compromised Apache and had full www-data filesystem access)",
    "implementation_task": "9-apparmor_config.sh",
    "verification_method": "aa-status --enforced listing apache2/mysqld profiles; MD-CIS-010 check in 15-validation.sh",
    "justification": "Confinement is the difference between 'the attacker got a shell on the web server' and 'the attacker got a shell that can only touch /var/www'. Directly addresses the root cause of the 1x00 incident."
  },
  {
    "control_id": "MD-CIS-011",
    "title": "Audit Trail for Identity Files and Configuration Integrity",
    "cis_section": "4 - Logging and Auditing",
    "severity": "high",
    "asset_scope": ["billing-srv-01", "web-srv-01", "log-srv-01"],
    "threat_mapping": "Marcus Webb's 1x00 notes: 'No SIEM or IDS was deployed. Attacker moved undetected for 5 days.'",
    "implementation_task": "10-auditd_config.sh",
    "verification_method": "auditctl -l shows -w rules for /etc/passwd, /etc/shadow, /etc/group, sshd_config, pam.d; MD-CIS-011 check in 15-validation.sh",
    "justification": "Kernel-level watch rules on identity and auth configuration files are the minimum telemetry needed to detect the credential-harvesting phase of a Crimson Tide-style intrusion in real time instead of 5 days later."
  },
  {
    "control_id": "MD-CIS-012",
    "title": "Host Firewall Default-Deny Inbound Policy",
    "cis_section": "3 - Network Configuration",
    "severity": "high",
    "asset_scope": ["billing-srv-01", "web-srv-01", "log-srv-01"],
    "threat_mapping": "1x02 scan (billing-srv-01 had 11 open ports); Crimson Tide advisory (every breach started on a reachable, misconfigured service)",
    "implementation_task": "13-firewall_baseline.sh",
    "verification_method": "ufw status verbose shows default deny (incoming) / allow (outgoing) with an explicit allow list; MD-CIS-012 check in 15-validation.sh",
    "justification": "Service minimization (MD-CIS-008) reduces what listens; the firewall independently enforces what is reachable from the network, so a re-enabled service by mistake is still blocked at the network layer."
  },
  {
    "control_id": "MD-CIS-013",
    "title": "Audit Trail for Privilege Escalation and Suspicious Tooling",
    "cis_section": "4 - Logging and Auditing",
    "severity": "medium",
    "asset_scope": ["billing-srv-01", "web-srv-01", "log-srv-01"],
    "threat_mapping": "Crimson Tide Phase 3 (sudo/su abuse, use of wget/curl/nc to stage second-stage payloads, as seen in the 1x00 crypto-miner delivery)",
    "implementation_task": "10-auditd_config.sh",
    "verification_method": "auditctl -l shows -x execve watches on sudo, su, wget, curl, nc keyed priv_esc/suspicious_download/suspicious_netcat; MD-CIS-013 check in 15-validation.sh",
    "justification": "Rated medium rather than critical because this is detective, not preventive, control - it does not stop the action, it guarantees it is not silent. Preventive controls (MD-CIS-001/002/005) carry the higher severity."
  },
  {
    "control_id": "MD-CIS-014",
    "title": "Audit Telemetry Coverage Validated",
    "cis_section": "4 - Logging and Auditing",
    "severity": "medium",
    "asset_scope": ["billing-srv-01", "web-srv-01", "log-srv-01"],
    "threat_mapping": "Marcus Webb's 1x00 notes (undetected dwell time) - a rule that is deployed but never proven to fire is a false sense of security",
    "implementation_task": "11-audit_coverage_test.sh",
    "verification_method": "audit_validation.json shows 6/6 controlled test events captured via ausearch; MD-CIS-014 check in 15-validation.sh",
    "justification": "Medium severity: this control validates MD-CIS-011/013 rather than independently blocking or detecting a threat. Without it, a silently-broken auditd rule set would go unnoticed until an actual incident."
  },
  {
    "control_id": "MD-CIS-015",
    "title": "Structured Log Routing and Retention",
    "cis_section": "4 - Logging and Auditing",
    "severity": "medium",
    "asset_scope": ["billing-srv-01", "web-srv-01", "log-srv-01"],
    "threat_mapping": "Attacker log erasure risk on log-srv-01 (README: 'if the log server is compromised, the attacker can erase the evidence'); supports Module 3 telemetry export",
    "implementation_task": "12-log_config.sh",
    "verification_method": "rsyslog rules route auth/authpriv to auth.log; logrotate policy retains auth.log 90d / syslog 60d; MD-CIS-015 check in 15-validation.sh",
    "justification": "Medium severity because default rsyslog routing already captures most events on a stock Ubuntu install; the gap is retention/rotation discipline, not total log loss - a compensating control already partially exists."
  }
]
EOF
)

jq -n --argjson controls "$CONTROLS_JSON" \
  --arg generated "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{
    profile_name: "MedDefense CIS Control Profile",
    generated: $generated,
    target_assets: ["billing-srv-01", "web-srv-01", "log-srv-01"],
    controls: $controls
  }' > "$OUT_JSON"

CONTROL_COUNT=$(jq '.controls | length' "$OUT_JSON")
CRITICAL=$(jq '[.controls[] | select(.severity=="critical")] | length' "$OUT_JSON")
HIGH=$(jq '[.controls[] | select(.severity=="high")] | length' "$OUT_JSON")
MEDIUM=$(jq '[.controls[] | select(.severity=="medium")] | length' "$OUT_JSON")
SECTIONS=$(jq '[.controls[].cis_section] | unique | length' "$OUT_JSON")
MAPPED_TASKS=$(jq '[.controls[].implementation_task] | unique | length' "$OUT_JSON")

echo "Controls selected: $CONTROL_COUNT"
echo "Critical: $CRITICAL"
echo "High: $HIGH"
echo "Medium: $MEDIUM"
echo "CIS sections covered: $SECTIONS"
echo "Mapped implementation tasks: $MAPPED_TASKS"
echo "Report saved to: $OUT_JSON"
