#!/bin/bash
#
# 6-filesystem_hardening.sh
#
# MedDefense Health Systems - Locking the Gates (2x00)
#
# SUID binaries are how an attacker with a low-privilege shell escalates to
# root. World-writable files are how an attacker modifies a script or binary
# that later runs as root. Both are the classic Crimson Tide Phase 3
# privilege-escalation vectors used after initial access. The baseline
# snapshot (Task 0) found 23 SUID binaries and 7 world-writable files on
# billing-srv-01 - not all of them are necessary, and this script proves,
# one binary at a time, which ones are.
#
# Idempotent: every remediation (SUID/SGID strip, world-writable chmod,
# mount option, cron.allow) first checks current state and only acts if a
# change is actually needed, so a second run reports 0 additional changes.
#
# Maps to CIS control MD-CIS-004 (SUID/SGID whitelist) and MD-CIS-007
# (world-writable files + mount options) from cis_profile.json.
#
# SCAN_ROOT overrides the filesystem root walked by find (default "/"). This
# exists purely so the whitelist/removal logic can be exercised against a
# scratch directory tree in isolated testing without touching real system
# binaries - see this project's validation notes for exactly what was run
# for real versus tested in isolation.
#
# Usage: sudo ./6-filesystem_hardening.sh [SCAN_ROOT]

set -uo pipefail

SCAN_ROOT="${1:-/}"
LIVE_MODE=1
[ "${1:-}" != "" ] && LIVE_MODE=0

if [ "$LIVE_MODE" -eq 1 ] && [ "$(id -u)" -ne 0 ]; then
    echo "Error: this script must run as root to strip SUID/SGID bits and remediate world-writable files" >&2
    exit 1
fi

REMEDIATION_LOG="filesystem_hardening_remediation.log"
: > "$REMEDIATION_LOG"

# --- Known-safe SUID/SGID binaries for stock Ubuntu 22.04/24.04 ------------
# Anything with the SUID/SGID bit set OUTSIDE this list is either unexpected
# software (Finding-worthy on its own) or a legacy/leftover tool - the
# subject's example calls out /usr/local/bin/oldtool and
# /opt/legacy/setuid-app as exactly this kind of finding.
SUID_WHITELIST_REGEX='^(/usr)?/bin/(su|mount|umount|ping|fusermount3?|su|passwd)$|^/usr/bin/(sudo|passwd|su|chsh|chfn|chage|expiry|gpasswd|newgrp|mount|umount|ping|fusermount3?|pkexec|crontab)$|^/usr/lib/(openssh/ssh-keysign|dbus-1\.0/dbus-daemon-launch-helper|policykit-1/polkit-agent-helper-1|xorg/Xorg\.wrap)$|^/usr/sbin/(pppd|mount\.nfs)$'

SGID_WHITELIST_REGEX='^/usr/bin/(wall|write|bsd-write|crontab|ssh-agent|chage|expiry)$|^(/usr)?/sbin/unix_chkpwd$|^/usr/libexec/.*$'

# --- SUID sweep --------------------------------------------------------------
mapfile -t SUID_FOUND < <(find "$SCAN_ROOT" -xdev -type f -perm -4000 2>/dev/null | sort)
SUID_TOTAL="${#SUID_FOUND[@]}"
SUID_WHITELISTED=0
SUID_REMEDIATED=0
declare -a SUID_STRIPPED_LIST=()

echo "Found $SUID_TOTAL SUID binaries"
for f in "${SUID_FOUND[@]}"; do
    [ -z "$f" ] && continue
    if echo "$f" | grep -qE "$SUID_WHITELIST_REGEX"; then
        SUID_WHITELISTED=$((SUID_WHITELISTED+1))
        continue
    fi
    # Non-whitelisted: strip the SUID bit. Idempotent - if the bit is already
    # gone (e.g. a re-run), skip silently rather than re-logging it.
    if [ -u "$f" ]; then
        perm_before="$(stat -c '%a' "$f" 2>/dev/null)"
        chmod u-s "$f" 2>/dev/null && {
            SUID_REMEDIATED=$((SUID_REMEDIATED+1))
            SUID_STRIPPED_LIST+=("$f")
            echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) SUID_REMOVED $f (was $perm_before)" >> "$REMEDIATION_LOG"
        }
    fi
done
echo "Whitelisted: $SUID_WHITELISTED"
echo "Non-whitelisted: $((SUID_TOTAL - SUID_WHITELISTED))"
for f in "${SUID_STRIPPED_LIST[@]}"; do
    printf '  %-30s [SUID REMOVED]\n' "$f"
done

# --- SGID sweep --------------------------------------------------------------
mapfile -t SGID_FOUND < <(find "$SCAN_ROOT" -xdev -type f -perm -2000 2>/dev/null | sort)
SGID_TOTAL="${#SGID_FOUND[@]}"
SGID_WHITELISTED=0
SGID_REMEDIATED=0
declare -a SGID_STRIPPED_LIST=()

echo "Found $SGID_TOTAL SGID binaries"
for f in "${SGID_FOUND[@]}"; do
    [ -z "$f" ] && continue
    if echo "$f" | grep -qE "$SGID_WHITELIST_REGEX"; then
        SGID_WHITELISTED=$((SGID_WHITELISTED+1))
        continue
    fi
    if [ -g "$f" ]; then
        perm_before="$(stat -c '%a' "$f" 2>/dev/null)"
        chmod g-s "$f" 2>/dev/null && {
            SGID_REMEDIATED=$((SGID_REMEDIATED+1))
            SGID_STRIPPED_LIST+=("$f")
            echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) SGID_REMOVED $f (was $perm_before)" >> "$REMEDIATION_LOG"
        }
    fi
done
echo "Whitelisted: $SGID_WHITELISTED"
echo "Non-whitelisted: $((SGID_TOTAL - SGID_WHITELISTED))"
for f in "${SGID_STRIPPED_LIST[@]}"; do
    printf '  %-30s [SGID REMOVED]\n' "$f"
done

# --- World-writable files -----------------------------------------------------
# Excludes /proc, /sys, /dev (pseudo-filesystems, not real writable content)
# per the task's explicit instruction.
mapfile -t WW_FOUND < <(find "$SCAN_ROOT" -xdev -type f -perm -0002 \
    -not -path '/proc/*' -not -path '/sys/*' -not -path '/dev/*' 2>/dev/null | sort)
WW_TOTAL="${#WW_FOUND[@]}"
WW_FIXED=0

echo "Found $WW_TOTAL world-writable files"
for f in "${WW_FOUND[@]}"; do
    [ -z "$f" ] && continue
    perm_before="$(stat -c '%a' "$f" 2>/dev/null)"
    if chmod o-w "$f" 2>/dev/null; then
        WW_FIXED=$((WW_FIXED+1))
        echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) WORLD_WRITABLE_FIXED $f (was $perm_before)" >> "$REMEDIATION_LOG"
        printf '  %-30s [FIXED]\n' "$f"
    fi
done

# --- Mount options: /tmp, /var/tmp, /dev/shm --------------------------------
# noexec/nosuid/nodev on temp filesystems removes /tmp as a binary-drop
# staging area - the standard next step after a Crimson Tide-style initial
# foothold (attacker writes a payload to /tmp and executes it there).
declare -A DESIRED_MOUNT_OPTS=( [/tmp]="noexec,nosuid,nodev" [/var/tmp]="noexec,nosuid,nodev" [/dev/shm]="noexec,nosuid,nodev" )
FSTAB="${FSTAB_OVERRIDE:-/etc/fstab}"

check_and_apply_mount() {
    local mnt="$1" desired="$2"
    if [ "$LIVE_MODE" -eq 0 ]; then
        printf '%-9s %-22s [SKIPPED - scratch mode, no real mount/remount performed]\n' "${mnt}:" "$desired"
        return
    fi
    local current
    current="$(findmnt -no OPTIONS "$mnt" 2>/dev/null)"
    local missing=""
    IFS=',' read -ra want <<<"$desired"
    for opt in "${want[@]}"; do
        [[ ",${current}," == *",${opt},"* ]] || missing="${missing}${opt},"
    done
    if [ -z "$missing" ]; then
        printf '%-9s %-22s [OK]\n' "${mnt}:" "$desired"
        return
    fi
    # Idempotently ensure /etc/fstab carries the desired options for this
    # mount point (replace its options field if the mount is listed,
    # otherwise leave fstab untouched and rely on a live remount only - most
    # production hosts already have /tmp et al. in fstab or as tmpfs units).
    if grep -qE "^[^#[:space:]]+[[:space:]]+${mnt//\//\\/}[[:space:]]" "$FSTAB" 2>/dev/null; then
        sed -i -E "s#(^[^#[:space:]]+[[:space:]]+${mnt//\//\\/}[[:space:]]+[^[:space:]]+[[:space:]]+)[^[:space:]]+#\1${desired}#" "$FSTAB"
    fi
    if mount -o remount,"$desired" "$mnt" 2>/dev/null; then
        printf '%-9s %-22s [APPLIED]\n' "${mnt}:" "$desired"
    else
        printf '%-9s %-22s [FAILED - remount not possible, check fstab/systemd mount unit]\n' "${mnt}:" "$desired"
    fi
}

for mnt in /tmp /var/tmp /dev/shm; do
    check_and_apply_mount "$mnt" "${DESIRED_MOUNT_OPTS[$mnt]}"
done

# --- Cron access restriction --------------------------------------------------
# Only named MedDefense admins (and root) may schedule cron jobs - an
# unrestricted cron is a persistence mechanism an attacker uses after initial
# access (Crimson Tide Phase 3).
CRON_ALLOW="${CRON_ALLOW_OVERRIDE:-/etc/cron.allow}"
CRON_DENY="${CRON_DENY_OVERRIDE:-/etc/cron.deny}"
if [ "$LIVE_MODE" -eq 1 ]; then
    {
        echo "root"
        echo "medadmin"
        echo "sysadmin"
    } > "$CRON_ALLOW"
    chmod 600 "$CRON_ALLOW"
    # cron.allow takes precedence over cron.deny on Debian/Ubuntu; remove the
    # deny list so there is a single, unambiguous source of truth.
    [ -f "$CRON_DENY" ] && rm -f "$CRON_DENY"
    echo "Cron access restricted to: root medadmin sysadmin"
else
    echo "Cron access restriction: [SKIPPED - scratch mode]"
fi

echo "SUID remediated: $SUID_REMEDIATED | SGID remediated: $SGID_REMEDIATED | World-writable fixed: $WW_FIXED"
