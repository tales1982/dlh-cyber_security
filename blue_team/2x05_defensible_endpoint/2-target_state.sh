#!/bin/bash

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAPSTONE_DIR="${SCRIPT_DIR}/capstone"
TARGET_STATE_FILE="${CAPSTONE_DIR}/target_state.json"
FORCE=0

for arg in "$@"; do
    if [[ "$arg" == "--force" ]]; then
        FORCE=1
    fi
done

if ! command -v jq >/dev/null 2>&1; then
    echo "Error: required command 'jq' not found." >&2
    exit 2
fi

if [[ -f "$TARGET_STATE_FILE" && "$FORCE" -ne 1 ]]; then
    echo "Error: '$TARGET_STATE_FILE' already exists. Use --force to overwrite." >&2
    exit 1
fi

mkdir -p "$CAPSTONE_DIR" || {
    echo "Error: unable to create output directory '$CAPSTONE_DIR'." >&2
    exit 2
}

GENERATED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

if ! OUTPUT_JSON=$(jq -n \
    --arg schema_version "1.0.0" \
    --arg generated_at "$GENERATED_AT" \
    '{
        schema_version: $schema_version,
        generated_at: $generated_at,
        controls: [
            {
                id: "LNX-SSH-01",
                platform: "linux",
                family: "hardening",
                description: "SSH must refuse direct root login",
                check_type: "grep_match",
                check_target: "/etc/ssh/sshd_config",
                expected_value: "^PermitRootLogin\\s+no",
                source_project: "2x00_locking_the_gates",
                severity: "critical"
            },
            {
                id: "LNX-SSH-02",
                platform: "linux",
                family: "hardening",
                description: "SSH must refuse password authentication",
                check_type: "grep_match",
                check_target: "/etc/ssh/sshd_config",
                expected_value: "^PasswordAuthentication\\s+no",
                source_project: "2x00_locking_the_gates",
                severity: "critical"
            },
            {
                id: "LNX-SYSCTL-01",
                platform: "linux",
                family: "hardening",
                description: "IP forwarding must be disabled",
                check_type: "json_field_equals",
                check_target: "capstone/baseline/baseline_linux.json#sysctl_security.\"net.ipv4.ip_forward\"",
                expected_value: "0",
                source_project: "2x00_locking_the_gates",
                severity: "high"
            },
            {
                id: "LNX-SYSCTL-02",
                platform: "linux",
                family: "hardening",
                description: "ASLR must be fully enabled",
                check_type: "json_field_equals",
                check_target: "capstone/baseline/baseline_linux.json#sysctl_security.\"kernel.randomize_va_space\"",
                expected_value: "2",
                source_project: "2x00_locking_the_gates",
                severity: "high"
            },
            {
                id: "LNX-AUDITD-01",
                platform: "linux",
                family: "telemetry",
                description: "auditd service must be active",
                check_type: "command_exit_zero",
                check_target: "systemctl is-active --quiet auditd",
                expected_value: null,
                source_project: "2x00_locking_the_gates",
                severity: "critical"
            },
            {
                id: "LNX-APPARMOR-01",
                platform: "linux",
                family: "hardening",
                description: "AppArmor must be running in enforce mode",
                check_type: "command_exit_zero",
                check_target: "aa-status --enforced | grep -q .",
                expected_value: null,
                source_project: "2x00_locking_the_gates",
                severity: "high"
            },
            {
                id: "LNX-LYNIS-01",
                platform: "linux",
                family: "hardening",
                description: "Lynis hardening index must be at least 80",
                check_type: "json_field_gte",
                check_target: "capstone/baseline/baseline_linux.json#hardening_index",
                expected_value: 80,
                source_project: "2x05_defensible_endpoint",
                severity: "critical"
            },
            {
                id: "WIN-FW-01",
                platform: "windows",
                family: "hardening",
                description: "Windows Firewall must default-deny inbound on every profile",
                check_type: "json_field_equals",
                check_target: "capstone/baseline/baseline_windows.json#firewall_status",
                expected_value: "deny",
                source_project: "2x01_windows_fortress",
                severity: "critical"
            },
            {
                id: "WIN-PSLOG-01",
                platform: "windows",
                family: "telemetry",
                description: "PowerShell Script Block Logging must be enabled",
                check_type: "json_field_equals",
                check_target: "capstone/telemetry/windows_coverage.json#script_block_logging_enabled",
                expected_value: true,
                source_project: "2x01_windows_fortress",
                severity: "high"
            },
            {
                id: "WIN-SYSMON-01",
                platform: "windows",
                family: "telemetry",
                description: "Sysmon service must be installed and running",
                check_type: "command_exit_zero",
                check_target: "Get-Service Sysmon* | Where-Object Status -eq Running",
                expected_value: null,
                source_project: "2x01_windows_fortress",
                severity: "critical"
            },
            {
                id: "WIN-AUDIT-01",
                platform: "windows",
                family: "telemetry",
                description: "Audit policy must cover Account Logon, Logon, Object Access and Privilege Use subcategories",
                check_type: "grep_match",
                check_target: "capstone/baseline/windows_baseline.log",
                expected_value: "(Account Logon|Logon|Object Access|Privilege Use)",
                source_project: "2x01_windows_fortress",
                severity: "high"
            },
            {
                id: "WIN-CIS-01",
                platform: "windows",
                family: "hardening",
                description: "CIS Level 1 pass rate must be at least 85 percent",
                check_type: "json_field_gte",
                check_target: "capstone/baseline/baseline_windows.json#pass_rate_percent",
                expected_value: 85,
                source_project: "2x05_defensible_endpoint",
                severity: "critical"
            },
            {
                id: "TEL-LNX-01",
                platform: "linux",
                family: "telemetry",
                description: "Linux auditd rules file must be present and loaded",
                check_type: "command_exit_zero",
                check_target: "test -f /etc/audit/rules.d/meddefense.rules && auditctl -l | grep -q meddefense",
                expected_value: null,
                source_project: "2x02_eyes_on_endpoint",
                severity: "high"
            },
            {
                id: "TEL-EXPORT-01",
                platform: "both",
                family: "telemetry",
                description: "Structured telemetry JSON export path must exist",
                check_type: "file_exists",
                check_target: "capstone/telemetry",
                expected_value: null,
                source_project: "2x02_eyes_on_endpoint",
                severity: "medium"
            },
            {
                id: "TEL-WIN-01",
                platform: "windows",
                family: "telemetry",
                description: "Windows Sysmon event count must be greater than zero in the last 10 minutes",
                check_type: "json_field_gte",
                check_target: "capstone/telemetry/windows_coverage.json#sysmon_event_count_last_10m",
                expected_value: 1,
                source_project: "2x02_eyes_on_endpoint",
                severity: "high"
            },
            {
                id: "TEL-WIN-02",
                platform: "windows",
                family: "telemetry",
                description: "PowerShell Script Block Logging event channel size must be greater than zero",
                check_type: "json_field_gte",
                check_target: "capstone/baseline/baseline_windows.json#script_block_logging_channel_size",
                expected_value: 1,
                source_project: "2x02_eyes_on_endpoint",
                severity: "medium"
            },
            {
                id: "PATCH-01",
                platform: "both",
                family: "patching",
                description: "Vulnerability inventory artifact must be present",
                check_type: "file_exists",
                check_target: "capstone/patch/vulnerability_inventory.json",
                expected_value: null,
                source_project: "2x03_patch_equation",
                severity: "medium"
            },
            {
                id: "PATCH-02",
                platform: "both",
                family: "patching",
                description: "Patch plan artifact must be present",
                check_type: "file_exists",
                check_target: "capstone/patch/patch_plan.json",
                expected_value: null,
                source_project: "2x03_patch_equation",
                severity: "medium"
            },
            {
                id: "PATCH-03",
                platform: "both",
                family: "patching",
                description: "Patch execution log must be present with zero entries in failed state",
                check_type: "json_field_equals",
                check_target: "capstone/patch/patch_execution_log.json#failed_count",
                expected_value: 0,
                source_project: "2x03_patch_equation",
                severity: "high"
            },
            {
                id: "PATCH-04",
                platform: "linux",
                family: "patching",
                description: "unattended-upgrades must be configured with the mandated blacklist",
                check_type: "grep_match",
                check_target: "/etc/apt/apt.conf.d/50unattended-upgrades",
                expected_value: "Unattended-Upgrade::Package-Blacklist",
                source_project: "2x03_patch_equation",
                severity: "medium"
            },
            {
                id: "NET-NFT-01",
                platform: "network",
                family: "network",
                description: "nftables input chain must default to drop",
                check_type: "command_exit_zero",
                check_target: "nft list ruleset | grep -q \"hook input.*policy drop\"",
                expected_value: null,
                source_project: "2x04_perimeter_defense",
                severity: "critical"
            },
            {
                id: "NET-SEG-01",
                platform: "network",
                family: "network",
                description: "Segmentation rules artifact must be present",
                check_type: "file_exists",
                check_target: "capstone/network/segmentation_rules.json",
                expected_value: null,
                source_project: "2x04_perimeter_defense",
                severity: "medium"
            },
            {
                id: "NET-SURICATA-01",
                platform: "network",
                family: "network",
                description: "Suricata custom rule file must be loaded with at least six rules",
                check_type: "json_field_gte",
                check_target: "capstone/network/rule_validation.json#rules_loaded",
                expected_value: 6,
                source_project: "2x04_perimeter_defense",
                severity: "high"
            },
            {
                id: "NET-SURICATA-02",
                platform: "network",
                family: "network",
                description: "Suricata rule validation report must show every rule fired against its target PCAP",
                check_type: "json_field_equals",
                check_target: "capstone/network/rule_validation.json#all_rules_fired",
                expected_value: true,
                source_project: "2x04_perimeter_defense",
                severity: "high"
            },
            {
                id: "NET-DNS-01",
                platform: "network",
                family: "network",
                description: "DNS filter must be active",
                check_type: "json_field_equals",
                check_target: "capstone/network/dns_filtering_result.json#active",
                expected_value: true,
                source_project: "2x04_perimeter_defense",
                severity: "medium"
            },
            {
                id: "HANDOFF-01",
                platform: "both",
                family: "handoff",
                description: "Compliance report artifact must be present",
                check_type: "file_exists",
                check_target: "capstone/handoff/compliance.json",
                expected_value: null,
                source_project: "2x05_defensible_endpoint",
                severity: "medium"
            },
            {
                id: "HANDOFF-02",
                platform: "both",
                family: "handoff",
                description: "Manifest must be present with a SHA-256 hash per file",
                check_type: "file_exists",
                check_target: "capstone/handoff/manifest.json",
                expected_value: null,
                source_project: "2x05_defensible_endpoint",
                severity: "high"
            },
            {
                id: "HANDOFF-03",
                platform: "both",
                family: "handoff",
                description: "Telemetry export package must exist and be tarballed",
                check_type: "file_exists",
                check_target: "capstone/handoff/telemetry_export.tar.gz",
                expected_value: null,
                source_project: "2x05_defensible_endpoint",
                severity: "medium"
            },
            {
                id: "HANDOFF-04",
                platform: "both",
                family: "handoff",
                description: "Runbook script must be present and executable",
                check_type: "command_exit_zero",
                check_target: "test -x capstone/handoff/runbook.sh",
                expected_value: null,
                source_project: "2x05_defensible_endpoint",
                severity: "high"
            }
        ]
    }'); then
    echo "Error: failed to build target_state.json (jq filter error)." >&2
    exit 2
fi

echo "$OUTPUT_JSON" > "$TARGET_STATE_FILE" || {
    echo "Error: unable to write '$TARGET_STATE_FILE'." >&2
    exit 2
}

echo "Target state written to $TARGET_STATE_FILE"

exit 0
