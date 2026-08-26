#!/bin/bash
#
# 7-service_minimization.sh
#
# MedDefense Health Systems - Locking the Gates (2x00)
#
# CIS Benchmark Section 2 (Services): every running service is a potential
# entry point. The 1x02 scan found billing-srv-01 with unnecessary services
# exposed network-wide (Finding 006: MySQL on 0.0.0.0) alongside services
# that have no business purpose at all (avahi-daemon, cups, rpcbind). The
# baseline snapshot (Task 0) counted 24 enabled services; a production
# billing server needs fewer than 10.
#
# Idempotent: before stopping/disabling anything, the script checks the
# service's current active/enabled state and only acts if a change is
# actually required - a second run reports the same before/after counts
# with zero additional stop/disable actions.
#
# Maps to CIS control MD-CIS-008 (unnecessary services disabled) from
# cis_profile.json.
#
# DRY_RUN=1 exists purely so the whitelist-diff logic can be exercised
# safely against this host's real (but untouched) service list without
# stopping/disabling anything for real - see this project's validation
# notes for exactly what was and was not executed for real.
#
# Usage: sudo ./7-service_minimization.sh
#        DRY_RUN=1 ./7-service_minimization.sh   (report-only, no changes)

set -euo pipefail

DRY_RUN="${DRY_RUN:-0}"

if [ "$DRY_RUN" -ne 1 ] && [ "$(id -u)" -ne 0 ]; then
    echo "Error: this script must run as root to stop/disable services (or set DRY_RUN=1 to report only)" >&2
    exit 1
fi

# --- Hawthorne-required service whitelist ------------------------------------
# Adapted from 2x00's billing-srv-01/web-srv-01/log-srv-01 whitelist for the
# hawthorne-app-01 clinical intake host (2x05 capstone). apache2/mysql were
# dropped (no evidence this host runs them); unattended-upgrades was added
# because the capstone's own target_state.json (PATCH-04) requires it to
# stay active, and getty@ was added so console access via the hypervisor
# survives this pass even if SSH ever breaks.
declare -A REQUIRED_SERVICES=(
    [ssh]="Remote administration - the only intentional remote-shell path, and it is now hardened (Task 4)"
    [ufw]="Host firewall - default-deny enforcement (Task 13)"
    [auditd]="Kernel-level security event logging (Task 10) - the telemetry Marcus Webb's notes said was completely absent"
    [apparmor]="Mandatory access control confinement (Task 9)"
    [cron]="Scheduled maintenance/backup jobs - access restricted to authorized admins only (Task 6)"
    [rsyslog]="Central syslog/auth.log collection (Task 12) - required for the telemetry pipeline"
    [systemd-timesyncd]="Accurate system clock - required for valid audit log timestamps and Kerberos/TLS operation"
    [systemd-networkd]="Network interface configuration on netplan/networkd-managed hosts (the Ubuntu Server default) - disabling it drops the host's own network configuration, which is a self-inflicted outage, not a hardening win"
    [systemd-resolved]="DNS resolution - required for the host to resolve names at all, including its own management/monitoring traffic"
    [unattended-upgrades]="Automated security patching - required by target_state.json control PATCH-04"
    [getty@]="Console login - keeps hypervisor console access available if SSH ever breaks"
)
REQUIRED_COUNT="${#REQUIRED_SERVICES[@]}"

echo "[*] Scanning enabled services..."
mapfile -t ENABLED_UNITS < <(systemctl list-unit-files --type=service --state=enabled --no-legend --no-pager 2>/dev/null | awk '{print $1}' | sed 's/\.service$//' | sort -u)
BEFORE_COUNT="${#ENABLED_UNITS[@]}"
echo "    Enabled services found: $BEFORE_COUNT"

echo "[*] Comparing against MedDefense whitelist ($REQUIRED_COUNT required services)..."

DISABLED_COUNT=0
ACTIVE_COUNT=0

for svc in "${ENABLED_UNITS[@]}"; do
    [ -z "$svc" ] && continue
    unit="${svc}.service"
    if [ -n "${REQUIRED_SERVICES[$svc]:-}" ]; then
        # Required: verify it is actually running, do not touch it.
        if [ "$DRY_RUN" -eq 1 ]; then
            state="$(systemctl is-active "$unit" 2>/dev/null || echo unknown)"
            printf '  %-25s [%s]\n' "$unit" "${state^^}"
        else
            systemctl is-active --quiet "$unit" 2>/dev/null || systemctl start "$unit" 2>/dev/null || true
            state="$(systemctl is-active "$unit" 2>/dev/null || echo unknown)"
            printf '  %-25s [%s]\n' "$unit" "${state^^}"
        fi
        ACTIVE_COUNT=$((ACTIVE_COUNT+1))
        continue
    fi

    # Not on the whitelist: stop and disable, but only if it is not already
    # stopped/disabled (idempotency - a second run should report [STOPPED]
    # for a unit this script already stopped, without erroring).
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '  %-25s [WOULD STOP] [WOULD DISABLE]\n' "$unit"
    else
        is_active="$(systemctl is-active "$unit" 2>/dev/null || echo inactive)"
        if [ "$is_active" = "active" ]; then
            systemctl stop "$unit" 2>/dev/null || true
        fi
        systemctl disable "$unit" 2>/dev/null || true
        printf '  %-25s [STOPPED] [DISABLED]\n' "$unit"
    fi
    DISABLED_COUNT=$((DISABLED_COUNT+1))
done

if [ "$DRY_RUN" -eq 1 ]; then
    echo "Before: $BEFORE_COUNT | After (projected): $((BEFORE_COUNT - DISABLED_COUNT)) | Would disable: $DISABLED_COUNT"
else
    mapfile -t AFTER_UNITS < <(systemctl list-unit-files --type=service --state=enabled --no-legend --no-pager 2>/dev/null | awk '{print $1}')
    AFTER_COUNT="${#AFTER_UNITS[@]}"
    echo "Before: $BEFORE_COUNT | After: $AFTER_COUNT | Disabled: $DISABLED_COUNT"
fi
