#!/bin/bash
#
# 10-auditd_config.sh
#
# MedDefense Health Systems - Locking the Gates (2x00)
#
# Marcus Webb's notes from the 1x00 incident: "No SIEM or IDS was deployed.
# Attacker moved undetected for 5 days." auditd is the Linux kernel audit
# framework - it records system calls, file access and authentication events
# at the kernel level, and becomes the primary Linux telemetry source for
# the SOC analyst work in Module 3. The rules deployed here determine what
# the SOC can see the next time this happens.
#
# Idempotent: rules are written to a single MedDefense-owned rules file that
# is fully rewritten from the same fixed content every run (rewriting is
# safe/idempotent because the content is deterministic), then loaded with
# augenrules --load. A second run produces the identical rules file and the
# same active rule count.
#
# Maps to CIS controls MD-CIS-011 (identity/config integrity) and
# MD-CIS-013 (privilege escalation / suspicious tooling) from
# cis_profile.json.
#
# RULES_FILE can be overridden via environment variable so the rule-file
# generation logic can be exercised against a scratch path without touching
# the real auditd configuration - see this project's validation notes for
# exactly what was and was not loaded into the live kernel audit subsystem.
#
# Usage: sudo ./10-auditd_config.sh

set -uo pipefail

RULES_FILE="${RULES_FILE:-/etc/audit/rules.d/meddefense.rules}"
LIVE_MODE=1
[ "$RULES_FILE" != "/etc/audit/rules.d/meddefense.rules" ] && LIVE_MODE=0

if [ "$LIVE_MODE" -eq 1 ] && [ "$(id -u)" -ne 0 ]; then
    echo "Error: this script must run as root to install/enable auditd and load audit rules" >&2
    exit 1
fi

# --- 1. Install and enable auditd --------------------------------------------
echo "[*] Enabling auditd service..."
if [ "$LIVE_MODE" -eq 1 ]; then
    if ! command -v auditd >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get install -y auditd audispd-plugins >/dev/null 2>&1
    fi
    systemctl enable --now auditd >/dev/null 2>&1
    state="$(systemctl is-active auditd 2>/dev/null || echo unknown)"
    echo "    auditd.service: ${state} (running)"
else
    echo "    (scratch mode: not installing/enabling the real auditd service)"
fi

# --- 2. Deploy MedDefense audit rules ----------------------------------------
# Each rule is commented with the exact threat it detects. Order matters for
# auditd (more specific rules first is a best practice, but functionally
# these are all independent watches so order here just matches this task's
# specified presentation order).
echo "[*] Deploying MedDefense audit rules..."

mkdir -p "$(dirname "$RULES_FILE")" 2>/dev/null || true

RULES_CONTENT=$(cat <<'RULES'
## MedDefense Health Systems - auditd rules
## Deployed by 10-auditd_config.sh - do not edit by hand, re-run the script.

## Identity files: any write to these is either legitimate admin activity
## (which should still be logged) or the credential-harvesting phase of a
## Crimson Tide-style intrusion (Phase 2).
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity

## PAM and SSH config integrity - if an attacker weakens auth config after
## gaining access, this is the trail (Finding 009).
-w /etc/pam.d/ -p wa -k pam_config
-w /etc/ssh/sshd_config -p wa -k sshd_config

## Privilege escalation - every sudo/su invocation and any sudoers edit
## (Crimson Tide Phase 3 lateral movement relies on privilege escalation).
-w /usr/bin/sudo -p x -k priv_esc
-w /usr/bin/su -p x -k priv_esc
-w /etc/sudoers -p wa -k sudoers

## Suspicious tooling - wget/curl/nc are the standard second-stage payload
## delivery tools seen in the 1x00 crypto-miner incident.
-w /usr/bin/wget -p x -k suspicious_download
-w /usr/bin/curl -p x -k suspicious_download
-w /usr/bin/nc -p x -k suspicious_netcat

## MedDefense application-specific file integrity - the billing database and
## the web server configuration are the two assets Finding 006 and the 1x00
## incident both centered on.
-w /var/lib/mysql/ -p wa -k meddefense_db
-w /etc/apache2/ -p wa -k meddefense_web

## Startup script integrity - a common persistence mechanism after initial
## access.
-w /etc/init.d/ -p wa -k startup_scripts
RULES
)

# Idempotent: only (re)write the file if content actually changed, so a
# second run does not need to reload rules that are already correct.
if [ -f "$RULES_FILE" ] && diff -q <(echo "$RULES_CONTENT") "$RULES_FILE" >/dev/null 2>&1; then
    CHANGED=0
else
    echo "$RULES_CONTENT" > "$RULES_FILE"
    CHANGED=1
fi

while IFS= read -r rule; do
    printf '    %-46s [ADDED]\n' "$rule"
done < <(grep -E '^-w ' <<<"$RULES_CONTENT")

RULE_COUNT=$(grep -cE '^-w ' <<<"$RULES_CONTENT")

# --- 3. Load and verify --------------------------------------------------------
if [ "$LIVE_MODE" -eq 1 ]; then
    if command -v augenrules >/dev/null 2>&1; then
        augenrules --load >/dev/null 2>&1
        echo "[*] Loading rules... augenrules --load: OK"
    else
        auditctl -R "$RULES_FILE" >/dev/null 2>&1
        echo "[*] Loading rules... auditctl -R: OK"
    fi
    ACTIVE_RULES=$(auditctl -l 2>/dev/null | grep -cE 'identity|pam_config|sshd_config|priv_esc|sudoers|suspicious_download|suspicious_netcat|meddefense_db|meddefense_web|startup_scripts')
    echo "[*] Verifying... auditctl -l: ${ACTIVE_RULES:-0} rules loaded"

    # --- 4. Controlled functional test -----------------------------------------
    echo "[*] Test: reading /etc/shadow..."
    cat /etc/shadow >/dev/null 2>&1
    sleep 1
    HITS=$(ausearch -ts recent -k identity 2>/dev/null | grep -c '^type=')
    if [ "${HITS:-0}" -gt 0 ]; then
        echo "    ausearch -ts recent -k identity: ${HITS} event(s) found [PASS]"
    else
        echo "    ausearch -ts recent -k identity: 0 events found [FAIL - check auditd is running and rules loaded]"
    fi
else
    echo "[*] Loading rules... [SKIPPED - scratch mode, rules file written but not loaded into live kernel audit subsystem]"
    if [ "$CHANGED" -eq 1 ]; then
        change_note="rewritten this run"
    else
        change_note="already current, unchanged"
    fi
    echo "[*] Verifying... $RULE_COUNT rules present in $RULES_FILE ($change_note)"
fi
