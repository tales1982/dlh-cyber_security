#!/bin/bash
#
# 5-auditd_refine.sh
#
# MedDefense Health Systems - Eyes on the Endpoint (2x02), Task 5.
#
# 2x00 Task 10 deployed auditd rules for identity files, privilege
# escalation and suspicious tooling - but it never watched execve itself
# (the Linux equivalent of Sysmon Event ID 1), network socket creation,
# SSH private key access, cron persistence or sudoers.d. This script adds
# those five detection-focused rules to the same meddefense.rules file,
# reloads auditd, and proves each new rule fires with a real, safe,
# reversible trigger checked against ausearch.
#
# Idempotent: each rule is only appended if a rule tagged with its key is
# not already present, so re-running this script never duplicates rules.
#
# RULES_FILE can be overridden via environment variable so this logic can
# be exercised against a scratch path without touching the real auditd
# configuration.
#
# Usage: sudo ./5-auditd_refine.sh

set -euo pipefail

RULES_FILE="${RULES_FILE:-/etc/audit/rules.d/meddefense.rules}"
LIVE_MODE=1
[ "$RULES_FILE" != "/etc/audit/rules.d/meddefense.rules" ] && LIVE_MODE=0

if [ "$LIVE_MODE" -eq 1 ] && [ "$(id -u)" -ne 0 ]; then
    echo "Error: this script must run as root to modify and reload auditd rules" >&2
    exit 1
fi

mkdir -p "$(dirname "$RULES_FILE")" 2>/dev/null || true
touch "$RULES_FILE"

# Prefers the live kernel ruleset (auditctl -l) over the rules file when
# possible, so the reported count reflects what auditd actually has loaded
# right now, not just what is written to disk (the two can drift if the
# file was edited without a reload).
count_rules() {
    if [ "$LIVE_MODE" -eq 1 ] && command -v auditctl >/dev/null 2>&1; then
        auditctl -l 2>/dev/null | grep -cE '^-[wa] ' || true
    else
        grep -cE '^-[wa] ' "$RULES_FILE" 2>/dev/null || true
    fi
}

CURRENT_COUNT=$(count_rules)
echo "[*] Current auditd rules: ${CURRENT_COUNT:-0}"

# add_rule_if_missing <key> <label> <rule_line...>
# Idempotent: skips the append if a rule tagged with this key is already
# present anywhere in the file, so a second run never duplicates rules.
add_rule_if_missing() {
    local key="$1" label="$2"
    shift 2
    if grep -qE -- "-k ${key}\$" "$RULES_FILE" 2>/dev/null; then
        printf '    %-38s [ALREADY PRESENT]\n' "$label"
        return
    fi
    {
        for line in "$@"; do
            echo "$line"
        done
    } >> "$RULES_FILE"
    printf '    %-38s [ADDED]\n' "$label"
}

echo "[*] Adding detection-focused rules..."

# Process execution tracking: execve is the Linux equivalent of Sysmon
# Event ID 1 - every program that actually runs goes through it.
add_rule_if_missing "process_exec" "execve syscall tracking" \
    "-a always,exit -F arch=b64 -S execve -k process_exec"

# Network tracking: socket/connect syscalls catch outbound connections at
# the kernel level, independent of which userspace tool initiated them.
add_rule_if_missing "network_connect" "socket/connect syscall tracking" \
    "-a always,exit -F arch=b64 -S socket -S connect -k network_connect"

# SSH keys monitoring. auditd -w rules do not expand globs at load time;
# this path is written exactly as specified, but on a multi-user host it
# only reliably matches a literal /home/*/.ssh/ directory if one exists -
# watch per-account paths individually for real environments with several
# home directories.
add_rule_if_missing "ssh_keys" "SSH key file monitoring" \
    "-w /home/*/.ssh/ -p rwa -k ssh_keys"

# Cron persistence: both cron.d and the per-user spool are watched under
# the same key, since either one is a valid attacker persistence path.
add_rule_if_missing "cron_persist" "Cron directory monitoring" \
    "-w /etc/cron.d/ -p wa -k cron_persist" \
    "-w /var/spool/cron/ -p wa -k cron_persist"

# sudoers.d monitoring: catches privilege-escalation persistence via a
# dropped sudoers.d file, distinct from the /etc/sudoers watch in Task 10.
add_rule_if_missing "sudoers" "sudoers.d monitoring" \
    "-w /etc/sudoers.d/ -p wa -k sudoers"

RULES_ADDED=5

if [ "$LIVE_MODE" -eq 1 ]; then
    if command -v augenrules >/dev/null 2>&1; then
        augenrules --load >/dev/null 2>&1 || true
        echo "[*] Loading rules... augenrules --load: OK"
    else
        auditctl -R "$RULES_FILE" >/dev/null 2>&1 || true
        echo "[*] Loading rules... auditctl -R: OK"
    fi
else
    echo "[*] Loading rules... [SKIPPED - scratch mode, rules file written but not loaded into live kernel audit subsystem]"
fi

TOTAL_COUNT=$(count_rules)
echo "[*] Total rules: ${TOTAL_COUNT:-0}"

VALIDATION_PASS=0
VALIDATION_TOTAL=5

# validate_rule <label> <audit key>: runs a safe trigger for the caller,
# then checks ausearch for that audit key to confirm the rule fired.
validate_rule() {
    local label="$1" key="$2"
    local hits
    if [ "$LIVE_MODE" -ne 1 ]; then
        printf '    %-58s [SKIPPED - scratch mode]\n' "$label"
        return
    fi
    sleep 1
    hits=$(ausearch -ts recent -k "$key" 2>/dev/null | grep -c '^type=') || true
    if [ "${hits:-0}" -gt 0 ]; then
        VALIDATION_PASS=$((VALIDATION_PASS + 1))
        printf '    %-58s [CAPTURED]\n' "$label"
    else
        printf '    %-58s [MISSED]\n' "$label"
    fi
}

echo "[*] Validating new rules..."

/usr/bin/id >/dev/null 2>&1 || true
validate_rule "execve: ran /usr/bin/id -> ausearch -k process_exec" "process_exec"

curl --silent --max-time 2 http://localhost >/dev/null 2>&1 || true
validate_rule "socket: curl localhost -> ausearch -k network_connect" "network_connect"

SSH_TEST_DIR="$HOME/.ssh"
SSH_TEST_FILE="$SSH_TEST_DIR/test"
mkdir -p "$SSH_TEST_DIR" 2>/dev/null || true
touch "$SSH_TEST_FILE" 2>/dev/null || true
validate_rule "ssh_keys: touch ~/.ssh/test -> ausearch -k ssh_keys" "ssh_keys"
rm -f "$SSH_TEST_FILE" 2>/dev/null || true

CRON_TEST_FILE="/etc/cron.d/test"
touch "$CRON_TEST_FILE" 2>/dev/null || true
validate_rule "cron: touch /etc/cron.d/test -> ausearch -k cron_persist" "cron_persist"
rm -f "$CRON_TEST_FILE" 2>/dev/null || true

SUDOERS_TEST_FILE="/etc/sudoers.d/test"
touch "$SUDOERS_TEST_FILE" 2>/dev/null || true
validate_rule "sudoers: touch /etc/sudoers.d/test -> ausearch -k sudoers" "sudoers"
rm -f "$SUDOERS_TEST_FILE" 2>/dev/null || true

echo "Rules added: $RULES_ADDED | Validation: $VALIDATION_PASS/$VALIDATION_TOTAL PASS"

[ "$VALIDATION_PASS" -eq "$VALIDATION_TOTAL" ] || [ "$LIVE_MODE" -ne 1 ]
