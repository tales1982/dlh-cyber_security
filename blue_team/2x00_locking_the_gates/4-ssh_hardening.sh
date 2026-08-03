#!/bin/bash
#
# 4-ssh_hardening.sh
#
# MedDefense Health Systems - Locking the Gates (2x00)
#
# Addresses 1x02 Finding 009 directly: "SSH on billing-srv-01 allows
# password-based authentication. Combined with no account lockout policy,
# this permits brute-force attacks." The Crimson Tide advisory confirmed 3 of
# 5 hospital breaches used harvested credentials for SSH lateral movement
# (Phase 3). This script closes that door: key-only auth, no root login, a
# hard cap on auth attempts, and an idle session timeout.
#
# Idempotent: every directive is added if missing or replaced in place if
# present with a different value - running this twice produces an identical
# sshd_config (verified by diffing two consecutive runs against a scratch
# copy during development).
#
# Maps to CIS control MD-CIS-001 (PasswordAuthentication) and MD-CIS-002
# (PermitRootLogin) from cis_profile.json.
#
# Usage: sudo ./4-ssh_hardening.sh [path-to-sshd_config]  (defaults to
#        /etc/ssh/sshd_config; the override exists so this logic can be
#        exercised safely against a scratch copy without touching the real
#        file - see the validation notes in this project's final report)

set -uo pipefail

SSHD_CONFIG="${1:-/etc/ssh/sshd_config}"
BACKUP="${SSHD_CONFIG}.bak"
# ISSUE_NET_OVERRIDE exists only so this script's logic can be exercised
# against a scratch path during isolated testing without touching the real
# system banner file. Production runs never set it, so the default below
# (the literal path this task requires) is what actually applies.
ISSUE_NET="${ISSUE_NET_OVERRIDE:-/etc/issue.net}"

if [ "$(id -u)" -ne 0 ] && [ "${1:-}" = "" ]; then
    echo "Error: this script must run as root to modify $SSHD_CONFIG" >&2
    exit 1
fi

if [ ! -f "$SSHD_CONFIG" ]; then
    echo "Error: $SSHD_CONFIG not found" >&2
    exit 1
fi

echo "[*] Backing up $SSHD_CONFIG"
# Preserve the very first backup taken (do not overwrite an existing backup
# on a re-run, so the true pre-hardening state is never lost).
if [ ! -f "$BACKUP" ]; then
    cp -p "$SSHD_CONFIG" "$BACKUP"
fi

# set_directive <key> <value> <comment>
# Idempotently sets a single "Key Value" directive: replaces the line if the
# key already exists (commented or not), appends it otherwise. This is the
# core idempotency mechanism for the whole script.
set_directive() {
    local key="$1" value="$2" comment="$3"
    # Both branches must write the exact same line format ("KEY VALUE  #
    # comment") so a first-time append and a subsequent in-place replace are
    # byte-for-byte identical - this is what makes two consecutive runs of
    # this script produce an identical file (true idempotency), not just an
    # identical effective configuration.
    if grep -qiE "^[[:space:]]*#?[[:space:]]*${key}[[:space:]]+" "$SSHD_CONFIG"; then
        sed -i -E "s|^[[:space:]]*#?[[:space:]]*${key}[[:space:]]+.*|${key} ${value}  # ${comment}|I" "$SSHD_CONFIG"
    else
        echo "${key} ${value}  # ${comment}" >> "$SSHD_CONFIG"
    fi
    echo "    ${key} ${value}"
}

echo "[*] Applying SSH hardening settings..."

# Finding 009 / Crimson Tide Phase 3 (SSH lateral movement): remove direct
# root shell access over the network entirely.
set_directive "PermitRootLogin" "no" \
    "MedDefense: no direct root SSH login (Finding 009, Crimson Tide Phase 3)"

# Finding 009 / Crimson Tide Phase 3: this is THE fix - password auth is the
# credential-stuffing / brute-force attack surface.
set_directive "PasswordAuthentication" "no" \
    "MedDefense: key-only auth, closes brute-force path (Finding 009)"

# Belt-and-suspenders for PasswordAuthentication - explicitly deny blank
# passwords even if some PAM stack misconfiguration would otherwise allow it.
set_directive "PermitEmptyPasswords" "no" \
    "MedDefense: defense in depth alongside PasswordAuthentication no"

# X11 forwarding is unused on headless production servers and is a known
# tunneling / pivot vector once a session is established (Crimson Tide Phase 3).
set_directive "X11Forwarding" "no" \
    "MedDefense: no GUI forwarding need on billing/web/log servers, reduces pivot surface"

# Caps brute-force attempts per connection - closes the gap Finding 009
# explicitly called out ("no account lockout policy").
set_directive "MaxAuthTries" "3" \
    "MedDefense: limits brute-force attempts per connection (Finding 009)"

# Idle session timeout: 300s * 2 = 10 minutes before an unattended,
# authenticated session is dropped - reduces the window a hijacked or
# abandoned session is usable by an attacker who gained host access.
set_directive "ClientAliveInterval" "300" \
    "MedDefense: idle timeout part 1/2 (10 min total, Crimson Tide Phase 3 session hijack mitigation)"
set_directive "ClientAliveCountMax" "2" \
    "MedDefense: idle timeout part 2/2 (10 min total)"

# Only named, authorized MedDefense admin accounts may reach SSH at all -
# removes the generic-account / service-account SSH exposure.
set_directive "AllowUsers" "medadmin sysadmin" \
    "MedDefense: SSH restricted to named authorized admins only"

# Protocol 1 is deprecated/removed from modern OpenSSH, but the directive is
# still explicitly pinned so no downgrade is possible if an old config or
# package ever reintroduces it.
set_directive "Protocol" "2" \
    "MedDefense: pin SSHv2 only, SSHv1 is cryptographically broken"

# Shortens the window an unauthenticated connection can hold a slot open -
# reduces exposure to slow-auth / connection-exhaustion abuse.
set_directive "LoginGraceTime" "60" \
    "MedDefense: reduces unauthenticated connection hold time"

# Legal/warning banner shown pre-authentication - required for MedDefense
# compliance posture and gives explicit notice to anyone probing SSH.
set_directive "Banner" "$ISSUE_NET" \
    "MedDefense: pre-auth warning banner for compliance"

SETTINGS_APPLIED=11

echo "[*] Creating warning banner at $ISSUE_NET"
cat > "$ISSUE_NET" <<'BANNER'
***************************************************************************
                       AUTHORIZED ACCESS ONLY

This system is the property of MedDefense Health Systems. Unauthorized
access, use, or modification is prohibited and may be subject to criminal
and civil penalties. All activity is logged and monitored.
***************************************************************************
BANNER

echo "[*] Validating SSH configuration..."
if command -v sshd >/dev/null 2>&1; then
    if sshd -t -f "$SSHD_CONFIG" 2>/tmp/sshd_hardening_test_err; then
        echo "    sshd -t: OK"
        VALID=1
    else
        echo "    sshd -t: FAILED"
        cat /tmp/sshd_hardening_test_err >&2
        VALID=0
    fi
    rm -f /tmp/sshd_hardening_test_err
else
    echo "    sshd binary not found - skipping syntax validation"
    VALID=1
fi

if [ "$VALID" -eq 1 ]; then
    echo "[*] Restarting SSH service..."
    if [ "$(id -u)" -eq 0 ] && command -v systemctl >/dev/null 2>&1 && [ "$SSHD_CONFIG" = "/etc/ssh/sshd_config" ]; then
        systemctl restart ssh.service 2>/dev/null || systemctl restart sshd.service 2>/dev/null
        state="$(systemctl is-active ssh.service 2>/dev/null || systemctl is-active sshd.service 2>/dev/null)"
        echo "    ssh.service: ${state:-unknown}"
    else
        echo "    (skipped actual service restart - not running as root against the live config)"
    fi
    echo "Settings applied: $SETTINGS_APPLIED"
else
    echo "[*] Validation failed - restoring backup"
    cp -p "$BACKUP" "$SSHD_CONFIG"
    exit 1
fi
