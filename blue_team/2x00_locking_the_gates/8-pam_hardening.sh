#!/bin/bash
#
# 8-pam_hardening.sh
#
# MedDefense Health Systems - Locking the Gates (2x00)
#
# The Crimson Tide advisory documented that in 3 of 5 breaches the attacker
# used harvested credentials (Phase 2) and credential-reuse techniques
# (Phase 3) to move laterally. Weak passwords are the root cause. PAM is
# where Linux enforces password policy - and today MedDefense enforces none
# of it: no complexity requirement, no lockout, no history. This script
# fixes all three.
#
# Idempotent: pwquality.conf / faillock.conf directives are replaced in
# place if present, appended otherwise (same pattern as Task 4/5); the
# pam_faillock/pam_unix lines in the PAM stack files are only inserted if
# not already present. A second run changes nothing.
#
# Maps to CIS controls MD-CIS-005 (password quality) and MD-CIS-009
# (account lockout) from cis_profile.json.
#
# PWQUALITY_CONF / FAILLOCK_CONF / PAM_COMMON_AUTH / PAM_COMMON_PASSWORD can
# be overridden via environment variables so this logic can be exercised
# against scratch copies without touching the real PAM stack - see this
# project's validation notes for exactly what was and was not run for real.
#
# Usage: sudo ./8-pam_hardening.sh

set -uo pipefail

PWQUALITY_CONF="${PWQUALITY_CONF:-/etc/security/pwquality.conf}"
FAILLOCK_CONF="${FAILLOCK_CONF:-/etc/security/faillock.conf}"
PAM_COMMON_AUTH="${PAM_COMMON_AUTH:-/etc/pam.d/common-auth}"
PAM_COMMON_PASSWORD="${PAM_COMMON_PASSWORD:-/etc/pam.d/common-password}"

if [ "$(id -u)" -ne 0 ] && [ "$PWQUALITY_CONF" = "/etc/security/pwquality.conf" ]; then
    echo "Error: this script must run as root to install packages and modify PAM configuration" >&2
    exit 1
fi

# --- 1. libpam-pwquality ------------------------------------------------------
echo "[*] Checking libpam-pwquality..."
if dpkg -s libpam-pwquality >/dev/null 2>&1; then
    ver="$(dpkg -s libpam-pwquality 2>/dev/null | awk -F': ' '/^Version/{print $2}')"
    echo "    Already installed: libpam-pwquality ${ver:-unknown}"
elif [ "$PWQUALITY_CONF" = "/etc/security/pwquality.conf" ]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y libpam-pwquality >/dev/null 2>&1 \
        && echo "    Installed libpam-pwquality" \
        || echo "    WARNING: could not install libpam-pwquality (no network/apt access?)"
else
    echo "    (scratch mode: skipping package installation)"
fi

# --- 2. Password quality (pwquality.conf) ------------------------------------
echo "[*] Configuring password quality ($PWQUALITY_CONF)..."
mkdir -p "$(dirname "$PWQUALITY_CONF")" 2>/dev/null || true
touch "$PWQUALITY_CONF"

# set_kv <file> <key> <value>: idempotent "key = value" or "key" (flag-only,
# when value is empty) replace-or-append. Both branches write the identical
# line format, so a second run leaves the file byte-for-byte unchanged.
set_kv() {
    local file="$1" key="$2" value="$3"
    local esc_key="${key//./\\.}"
    local line
    if [ -n "$value" ]; then
        line="${key} = ${value}"
        if grep -qE "^[[:space:]]*#?[[:space:]]*${esc_key}[[:space:]]*=" "$file"; then
            sed -i -E "s|^[[:space:]]*#?[[:space:]]*${esc_key}[[:space:]]*=.*|${line}|" "$file"
        else
            echo "$line" >> "$file"
        fi
    else
        line="${key}"
        if grep -qE "^[[:space:]]*#?[[:space:]]*${esc_key}[[:space:]]*\$" "$file"; then
            sed -i -E "s|^[[:space:]]*#?[[:space:]]*${esc_key}[[:space:]]*\$|${line}|" "$file"
        else
            echo "$line" >> "$file"
        fi
    fi
}

# Finding 009 / Crimson Tide Phase 2: no password complexity today. A 14-char
# minimum with full character-class requirements directly raises the cost of
# credential-based attacks.
set_kv "$PWQUALITY_CONF" "minlen" "14";          echo "    minlen = 14                      [SET]"
set_kv "$PWQUALITY_CONF" "dcredit" "-1";         echo "    dcredit = -1                     [SET]"
set_kv "$PWQUALITY_CONF" "ucredit" "-1";         echo "    ucredit = -1                     [SET]"
set_kv "$PWQUALITY_CONF" "lcredit" "-1";         echo "    lcredit = -1                     [SET]"
set_kv "$PWQUALITY_CONF" "ocredit" "-1";         echo "    ocredit = -1                     [SET]"
set_kv "$PWQUALITY_CONF" "maxrepeat" "3";        echo "    maxrepeat = 3                    [SET]"
set_kv "$PWQUALITY_CONF" "reject_username" "";   echo "    reject_username                  [SET]"

# --- 3. Account lockout (pam_faillock) ---------------------------------------
echo "[*] Configuring account lockout (pam_faillock)..."
mkdir -p "$(dirname "$FAILLOCK_CONF")" 2>/dev/null || true
touch "$FAILLOCK_CONF"

# Finding 009 explicitly: "no account lockout policy... permits brute-force
# attacks." 5 attempts / 900s (15 min) directly closes that gap.
set_kv "$FAILLOCK_CONF" "deny" "5";            echo "    deny = 5                         [SET]"
set_kv "$FAILLOCK_CONF" "unlock_time" "900";   echo "    unlock_time = 900                [SET]"
set_kv "$FAILLOCK_CONF" "fail_interval" "900"; echo "    fail_interval = 900              [SET]"

# Wire pam_faillock into the auth stack, idempotently. Debian/Ubuntu's
# pam-auth-update is the "correct" long-term mechanism, but for a
# script-driven, re-runnable hardening baseline we manage the lines directly
# and guard every insertion with a grep check so re-running never duplicates
# them.
if [ -f "$PAM_COMMON_AUTH" ]; then
    if ! grep -q 'pam_faillock.so preauth' "$PAM_COMMON_AUTH"; then
        sed -i '1i auth        required                        pam_faillock.so preauth silent audit deny=5 unlock_time=900' "$PAM_COMMON_AUTH"
    fi
    if ! grep -q 'pam_faillock.so authfail' "$PAM_COMMON_AUTH"; then
        # Insert authfail immediately after the primary pam_unix.so auth line.
        if grep -q 'pam_unix.so' "$PAM_COMMON_AUTH"; then
            sed -i '/pam_unix\.so/a auth        [default=die]                   pam_faillock.so authfail deny=5 unlock_time=900' "$PAM_COMMON_AUTH"
        else
            echo 'auth        [default=die]                   pam_faillock.so authfail deny=5 unlock_time=900' >> "$PAM_COMMON_AUTH"
        fi
    fi
else
    echo "    WARNING: $PAM_COMMON_AUTH not found, skipping pam_faillock stack wiring"
fi

# --- 4. Password history (remember 12) ---------------------------------------
echo "[*] Configuring password history..."
if [ -f "$PAM_COMMON_PASSWORD" ]; then
    if grep -qE 'pam_unix\.so.*remember=' "$PAM_COMMON_PASSWORD"; then
        sed -i -E 's/(pam_unix\.so[^\n]*remember=)[0-9]+/\112/' "$PAM_COMMON_PASSWORD"
    elif grep -q 'pam_unix.so' "$PAM_COMMON_PASSWORD"; then
        sed -i -E 's/(pam_unix\.so[^\n]*)/\1 remember=12/' "$PAM_COMMON_PASSWORD"
    else
        echo "password    [success=1 default=ignore]     pam_unix.so obscure use_authtok try_first_pass sha512 remember=12" >> "$PAM_COMMON_PASSWORD"
    fi
    echo "    remember = 12                    [SET]"
else
    echo "    WARNING: $PAM_COMMON_PASSWORD not found, skipping password history configuration"
fi

# --- 5. Validation ------------------------------------------------------------
MINLEN_CHECK=$(grep -E '^minlen' "$PWQUALITY_CONF" 2>/dev/null | tail -1 | awk -F= '{print $2}' | tr -d ' ')
DENY_CHECK=$(grep -E '^deny' "$FAILLOCK_CONF" 2>/dev/null | tail -1 | awk -F= '{print $2}' | tr -d ' ')

echo "Password minimum length: ${MINLEN_CHECK:-unset} | Lockout: ${DENY_CHECK:-unset} attempts / 15 min | History: 12"
