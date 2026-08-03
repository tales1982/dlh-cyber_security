#!/bin/bash
#
# 0-baseline_snapshot.sh
#
# MedDefense Health Systems - Locking the Gates (2x00)
#
# Captures the complete, unhardened security baseline of a Linux host before
# any CIS remediation work begins. Every number recorded here is the number
# every later task (4-13, 15, 16) is measured against. Without this snapshot
# there is no way to prove the hardening work in this project actually did
# anything - "we hardened the server" is a claim, this file is the evidence.
#
# Read-only. This script makes no configuration changes to the system.
#
# Usage: sudo ./0-baseline_snapshot.sh [output.json]

set -uo pipefail

OUT_JSON="${1:-baseline_snapshot.json}"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- System identification ------------------------------------------------
HOSTNAME_VAL="$(hostname)"
if [ -r /etc/os-release ]; then
    OS_VAL="$(. /etc/os-release; echo "${PRETTY_NAME:-unknown}")"
else
    OS_VAL="unknown"
fi
KERNEL_VAL="$(uname -r)"
UPTIME_VAL="$(uptime -p 2>/dev/null || uptime)"

# --- Running services -------------------------------------------------------
# CIS Section 2 concern: every running service is a candidate attack surface
# (Finding 006 - MySQL bound to 0.0.0.0 on billing-srv-01 was found this way).
mapfile -t RUNNING_SERVICES < <(systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null | awk '{print $1}')
RUNNING_COUNT="${#RUNNING_SERVICES[@]}"

# --- Open ports / listening sockets -----------------------------------------
# Reachable listeners are what an external attacker actually sees (1x02 scan
# found billing-srv-01 with 11 open ports).
mapfile -t OPEN_PORTS < <(ss -tulnH 2>/dev/null | awk '{print $1, $5}' | sort -u)
PORTS_COUNT="${#OPEN_PORTS[@]}"

# --- SUID / SGID binaries ----------------------------------------------------
# SUID/SGID binaries are the classic local privilege-escalation vector a
# Crimson Tide affiliate uses after gaining a low-privilege shell (Phase 3).
# -xdev restricts each find to the filesystem it starts on so the scan does
# not wander into mounted network shares, container overlays or removable
# media - only the host's own root filesystem is assessed.
mapfile -t SUID_BINARIES < <(find / -xdev -type f -perm -4000 2>/dev/null | sort)
SUID_COUNT="${#SUID_BINARIES[@]}"

mapfile -t SGID_BINARIES < <(find / -xdev -type f -perm -2000 2>/dev/null | sort)
SGID_COUNT="${#SGID_BINARIES[@]}"

# --- World-writable files ----------------------------------------------------
# A world-writable file that a root-owned process reads/executes is a direct
# path to privilege escalation (attacker modifies it, root executes it).
mapfile -t WORLD_WRITABLE < <(find / -xdev -type f -perm -0002 \
    -not -path '/proc/*' -not -path '/sys/*' -not -path '/dev/*' 2>/dev/null | sort)
WW_COUNT="${#WORLD_WRITABLE[@]}"

# --- sysctl security-relevant parameters ------------------------------------
# These are the exact parameters 5-sysctl_hardening.sh will change. Capturing
# them now is what lets 15-validation.sh and 16-lynis_diff.sh prove a delta.
SYSCTL_KEYS=(
    net.ipv4.ip_forward
    net.ipv4.conf.all.accept_redirects
    net.ipv4.conf.default.accept_redirects
    net.ipv4.conf.all.send_redirects
    net.ipv4.conf.all.accept_source_route
    net.ipv4.conf.all.log_martians
    net.ipv4.tcp_syncookies
    net.ipv4.icmp_echo_ignore_broadcasts
    net.ipv6.conf.all.disable_ipv6
    net.ipv6.conf.default.disable_ipv6
    kernel.randomize_va_space
    fs.suid_dumpable
    kernel.dmesg_restrict
    kernel.kptr_restrict
)
SYSCTL_JSON="{}"
for key in "${SYSCTL_KEYS[@]}"; do
    path="/proc/sys/${key//.//}"
    if [ -r "$path" ]; then
        val="$(cat "$path" 2>/dev/null)"
    else
        val="unavailable"
    fi
    SYSCTL_JSON="$(jq --arg k "$key" --arg v "$val" '. + {($k): $v}' <<<"$SYSCTL_JSON")"
done

# --- SSH configuration -------------------------------------------------------
# Finding 009: SSH allows password authentication. This is the exact
# configuration 4-ssh_hardening.sh will lock down.
SSHD_CONFIG="/etc/ssh/sshd_config"
SSH_KEYS=(PermitRootLogin PasswordAuthentication PermitEmptyPasswords X11Forwarding \
          MaxAuthTries ClientAliveInterval ClientAliveCountMax AllowUsers Protocol \
          LoginGraceTime Banner)
SSH_JSON="{}"
if [ -r "$SSHD_CONFIG" ]; then
    for key in "${SSH_KEYS[@]}"; do
        val="$(grep -iE "^\s*${key}\s+" "$SSHD_CONFIG" 2>/dev/null | tail -1 | awk '{ $1=""; sub(/^ /,""); print }')"
        [ -z "$val" ] && val="not_set"
        SSH_JSON="$(jq --arg k "$key" --arg v "$val" '. + {($k): $v}' <<<"$SSH_JSON")"
    done
else
    SSH_JSON='{"error":"sshd_config not readable"}'
fi

# --- User accounts and sudo group membership --------------------------------
mapfile -t USER_ACCOUNTS < <(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd | sort)
USER_COUNT="${#USER_ACCOUNTS[@]}"
mapfile -t SUDO_MEMBERS < <(getent group sudo 2>/dev/null | awk -F: '{print $4}' | tr ',' '\n' | sed '/^$/d' | sort)

# --- Build JSON --------------------------------------------------------------
jq -n \
  --arg ts "$TS" \
  --arg hostname "$HOSTNAME_VAL" \
  --arg os "$OS_VAL" \
  --arg kernel "$KERNEL_VAL" \
  --arg uptime "$UPTIME_VAL" \
  --argjson running_count "$RUNNING_COUNT" \
  --argjson ports_count "$PORTS_COUNT" \
  --argjson suid_count "$SUID_COUNT" \
  --argjson sgid_count "$SGID_COUNT" \
  --argjson ww_count "$WW_COUNT" \
  --argjson sysctl "$SYSCTL_JSON" \
  --argjson ssh "$SSH_JSON" \
  --argjson user_count "$USER_COUNT" \
  --arg services "$(printf '%s\n' "${RUNNING_SERVICES[@]:-}")" \
  --arg ports "$(printf '%s\n' "${OPEN_PORTS[@]:-}")" \
  --arg suid "$(printf '%s\n' "${SUID_BINARIES[@]:-}")" \
  --arg sgid "$(printf '%s\n' "${SGID_BINARIES[@]:-}")" \
  --arg ww "$(printf '%s\n' "${WORLD_WRITABLE[@]:-}")" \
  --arg users "$(printf '%s\n' "${USER_ACCOUNTS[@]:-}")" \
  --arg sudoers "$(printf '%s\n' "${SUDO_MEMBERS[@]:-}")" \
  '{
    timestamp: $ts,
    hostname: $hostname,
    os: $os,
    kernel: $kernel,
    uptime: $uptime,
    services: { running_count: $running_count, list: ($services | split("\n") | map(select(length > 0))) },
    open_ports: { count: $ports_count, list: ($ports | split("\n") | map(select(length > 0))) },
    suid_binaries: { count: $suid_count, list: ($suid | split("\n") | map(select(length > 0))) },
    sgid_binaries: { count: $sgid_count, list: ($sgid | split("\n") | map(select(length > 0))) },
    world_writable_files: { count: $ww_count, list: ($ww | split("\n") | map(select(length > 0))) },
    sysctl_parameters: $sysctl,
    ssh_config: $ssh,
    user_accounts: { count: $user_count, list: ($users | split("\n") | map(select(length > 0))) },
    sudo_group_members: ($sudoers | split("\n") | map(select(length > 0)))
  }' > "$OUT_JSON"

# --- Human-readable summary --------------------------------------------------
echo "Hostname: $HOSTNAME_VAL"
echo "OS: $OS_VAL"
echo "Running services: $RUNNING_COUNT"
echo "Open ports: $PORTS_COUNT"
echo "SUID binaries: $SUID_COUNT"
echo "SGID binaries: $SGID_COUNT"
echo "World-writable files: $WW_COUNT"
echo "Baseline saved to: $OUT_JSON"
