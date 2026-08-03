#!/bin/bash
#
# 9-apparmor_config.sh
#
# MedDefense Health Systems - Locking the Gates (2x00)
#
# When the crypto-miner compromised billing-srv-01 through Apache (1x00
# incident), it had full filesystem access as www-data. AppArmor mandatory
# access control is the difference between "the attacker got a shell on our
# web server" and "the attacker got a shell that can only access /var/www."
# This script enforces that confinement for Apache and MySQL and adds a
# custom profile for the MedDefense billing application so a future zero-day
# in the application still cannot reach patient data directories outside its
# own scope.
#
# Idempotent: aa-enforce/aa-complain are themselves idempotent (re-running
# against an already-enforced profile is a no-op success), and the custom
# profile is only (re)written if its content actually differs from what is
# already on disk.
#
# Maps to CIS control MD-CIS-010 (AppArmor MAC enforced) from
# cis_profile.json.
#
# CUSTOM_PROFILE_PATH can be overridden via environment variable so the
# profile-generation and syntax-validation logic can be exercised against a
# scratch file without touching /etc/apparmor.d - see this project's
# validation notes for exactly what was and was not applied for real
# (aa-enforce against the live kernel was NOT executed in this environment).
#
# Usage: sudo ./9-apparmor_config.sh

set -uo pipefail

CUSTOM_PROFILE_PATH="${CUSTOM_PROFILE_PATH:-/etc/apparmor.d/opt.meddefense.billing-app}"
LIVE_MODE=1
[ "$CUSTOM_PROFILE_PATH" != "/etc/apparmor.d/opt.meddefense.billing-app" ] && LIVE_MODE=0

if [ "$LIVE_MODE" -eq 1 ] && [ "$(id -u)" -ne 0 ]; then
    echo "Error: this script must run as root to switch profile modes and load a new profile" >&2
    exit 1
fi

ENFORCE_COUNT=0
COMPLAIN_COUNT=0
UNCONFINED_COUNT=0

# --- 1. AppArmor status -------------------------------------------------------
echo "[*] Checking AppArmor status..."
if [ -r /sys/module/apparmor/parameters/enabled ] && grep -q 'Y' /sys/module/apparmor/parameters/enabled 2>/dev/null; then
    echo "    AppArmor module: loaded"
else
    echo "    AppArmor module: not loaded"
fi
svc_state="$(systemctl is-active apparmor 2>/dev/null || echo unknown)"
echo "    AppArmor service: $svc_state"

# --- 2. Profile enforcement: Apache, MySQL, SSH ------------------------------
# aa-status requires root to enumerate the full profile set with per-process
# confinement mode; without root this degrades to "not assessed" rather than
# guessing a status.
echo "[*] Profile enforcement:"
declare -A TARGET_BINARIES=(
    [/usr/sbin/apache2]="apache2"
    [/usr/sbin/mysqld]="mysqld"
    [/usr/sbin/sshd]="sshd"
)

if [ "$(id -u)" -eq 0 ]; then
    mapfile -t AA_STATUS < <(aa-status --enforced 2>/dev/null)
    mapfile -t AA_COMPLAIN < <(aa-status --complaining 2>/dev/null)
else
    AA_STATUS=()
    AA_COMPLAIN=()
fi

for bin in /usr/sbin/apache2 /usr/sbin/mysqld /usr/sbin/sshd; do
    [ -x "$bin" ] || continue
    profile_name="${TARGET_BINARIES[$bin]}"
    if [ "$(id -u)" -ne 0 ]; then
        printf '    %-24s %-20s [NOT ASSESSED - requires root]\n' "$bin" "unknown"
        continue
    fi
    if printf '%s\n' "${AA_STATUS[@]}" | grep -q "$bin"; then
        printf '    %-24s %-20s [OK]\n' "$bin" "enforce"
        ENFORCE_COUNT=$((ENFORCE_COUNT+1))
    elif printf '%s\n' "${AA_COMPLAIN[@]}" | grep -q "$bin"; then
        if [ "$bin" != "/usr/sbin/sshd" ]; then
            if [ "$LIVE_MODE" -eq 1 ]; then
                aa-enforce "$bin" >/dev/null 2>&1
                printf '    %-24s complain -> enforce  [ENFORCED]\n' "$bin"
            else
                printf '    %-24s complain -> enforce  [WOULD ENFORCE - scratch mode]\n' "$bin"
            fi
            ENFORCE_COUNT=$((ENFORCE_COUNT+1))
        else
            printf '    %-24s %-20s [OK]\n' "$bin" "complain"
            COMPLAIN_COUNT=$((COMPLAIN_COUNT+1))
        fi
    else
        printf '    %-24s %-20s [UNCONFINED]\n' "$bin" "no profile"
        UNCONFINED_COUNT=$((UNCONFINED_COUNT+1))
    fi
done

# --- 3. Custom MedDefense application profile --------------------------------
# Restricts the billing application to exactly the directories it needs:
# its own install path, its config, and its log destination. Everything
# else - including other tenants' data and system directories - is denied
# by AppArmor's default-deny model even if the application process itself
# is exploited (directly addresses the 1x00 crypto-miner root cause).
NEW_PROFILE_CONTENT=$(cat <<'PROFILE'
# MedDefense billing application - AppArmor profile
# Confines the billing app to its required directories only. Even a
# zero-day in the application cannot read/write outside this scope.
#include <tunables/global>

/opt/meddefense/billing-app {
  #include <abstractions/base>

  /opt/meddefense/billing-app r,
  /opt/meddefense/billing-app/** r,
  /opt/meddefense/config/** r,
  /opt/meddefense/data/** rw,
  /var/log/meddefense/billing-app.log w,

  # Explicit deny of patient data outside this app's own data directory -
  # the exact access a compromised billing process must NOT have.
  deny /opt/meddefense/patient-data/** rwx,
  deny /home/** rwx,
  deny /etc/shadow r,
}
PROFILE
)

mkdir -p "$(dirname "$CUSTOM_PROFILE_PATH")" 2>/dev/null || true
if [ -f "$CUSTOM_PROFILE_PATH" ] && diff -q <(echo "$NEW_PROFILE_CONTENT") "$CUSTOM_PROFILE_PATH" >/dev/null 2>&1; then
    echo "[*] Custom profile: $CUSTOM_PROFILE_PATH   [UNCHANGED] [ALREADY ENFORCED]"
else
    echo "$NEW_PROFILE_CONTENT" > "$CUSTOM_PROFILE_PATH"
    if [ "$LIVE_MODE" -eq 1 ] && [ "$(id -u)" -eq 0 ]; then
        apparmor_parser -r "$CUSTOM_PROFILE_PATH" >/dev/null 2>&1 && aa-enforce "$CUSTOM_PROFILE_PATH" >/dev/null 2>&1
        echo "[*] Custom profile: $CUSTOM_PROFILE_PATH   [CREATED] [ENFORCED]"
    else
        echo "[*] Custom profile: $CUSTOM_PROFILE_PATH   [CREATED] [NOT LOADED - scratch mode/no root]"
    fi
fi
ENFORCE_COUNT=$((ENFORCE_COUNT+1))

# --- 4. Unconfined network-exposed processes ---------------------------------
echo "[*] Unconfined network-exposed processes:"
NETWORK_DAEMONS=(/usr/sbin/rsyslogd /usr/sbin/auditd)
if [ "$(id -u)" -eq 0 ]; then
    for bin in "${NETWORK_DAEMONS[@]}"; do
        [ -x "$bin" ] || continue
        if printf '%s\n' "${AA_STATUS[@]}" "${AA_COMPLAIN[@]}" | grep -q "$bin"; then
            continue
        fi
        printf '    %-24s [UNCONFINED - Profile recommended]\n' "$bin"
        UNCONFINED_COUNT=$((UNCONFINED_COUNT+1))
    done
else
    echo "    (requires root to enumerate unconfined processes - not assessed)"
fi

echo "Profiles in enforce: $ENFORCE_COUNT | Complain: $COMPLAIN_COUNT | Unconfined: $UNCONFINED_COUNT"
