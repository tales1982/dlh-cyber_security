#!/bin/bash
#
# 5-sysctl_hardening.sh
#
# MedDefense Health Systems - Locking the Gates (2x00)
#
# Crimson Tide Phase 3: the attacker moved laterally across a flat network.
# A compromised Linux host with IP forwarding enabled becomes a router FOR
# the attacker. Accepted ICMP redirects let the attacker reroute traffic.
# Disabled ASLR turns memory-corruption bugs (Finding 026: 47 known kernel
# CVEs) into reliable exploits instead of coin-flip crashes. None of these
# settings have any legitimate reason to be on for billing-srv-01, web-srv-01
# or log-srv-01 - they are default-off requirements for any production host.
#
# Idempotent: every parameter is written via a key=value replace-or-append
# directly into sysctl.conf, then applied with sysctl -p and verified by
# reading back from /proc/sys. Running this twice yields the same file
# content and the same live values both times.
#
# Maps to CIS controls MD-CIS-003 (network stack) and MD-CIS-006 (memory/
# pointer exposure protections) from cis_profile.json.
#
# Usage: sudo ./5-sysctl_hardening.sh [path-to-sysctl.conf]  (defaults to
#        /etc/sysctl.conf; the override exists only so this logic can be
#        exercised safely against a scratch copy - see this project's
#        validation notes for what was and was not run against the real file)

set -uo pipefail

SYSCTL_CONF="${1:-/etc/sysctl.conf}"
BACKUP="${SYSCTL_CONF}.bak"

if [ "${1:-}" = "" ] && [ "$(id -u)" -ne 0 ]; then
    echo "Error: this script must run as root to modify $SYSCTL_CONF and apply live sysctl values" >&2
    exit 1
fi

echo "[*] Backing up $SYSCTL_CONF"
touch "$SYSCTL_CONF"
if [ ! -f "$BACKUP" ]; then
    cp -p "$SYSCTL_CONF" "$BACKUP"
fi

# Parallel arrays (not an associative array) so the PASS/FAIL report below
# prints in the exact, deliberate order the subject's expected output uses.
PARAM_KEYS=(
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
PARAM_VALUES=(
    0   # ip_forward=0 - Crimson Tide Phase 3: a compromised host must not become a router/pivot
    0   # accept_redirects=0 (all) - prevents ICMP-redirect traffic rerouting
    0   # accept_redirects=0 (default) - same, applied to future interfaces
    0   # send_redirects=0 - this host is not a router, never emit redirects
    0   # accept_source_route=0 - source-routed packets are a classic spoofing/pivot technique
    1   # log_martians=1 - log impossible/spoofed source addresses for SOC visibility (Marcus Webb: "no SIEM/IDS")
    1   # tcp_syncookies=1 - SYN flood protection
    1   # icmp_echo_ignore_broadcasts=1 - Smurf-attack mitigation
    1   # disable_ipv6 (all) - MedDefense does not route IPv6; unmonitored dual-stack is an unused attack surface
    1   # disable_ipv6 (default) - same, applied to future interfaces
    2   # randomize_va_space=2 - full ASLR, raises exploit reliability cost against Finding 026's 47 outstanding CVEs
    0   # suid_dumpable=0 - SUID process core dumps must never leak sensitive memory to disk
    1   # dmesg_restrict=1 - unprivileged users cannot read the kernel ring buffer (info leak / recon hardening)
    2   # kptr_restrict=2 - kernel pointers hidden from all unprivileged users, hardens against KASLR-defeat techniques
)

echo "[*] Applying kernel hardening parameters..."

# Idempotently write "key = value": replace the line if the key already
# exists (commented or not), append a fresh line otherwise. Both branches
# produce byte-identical output for the same key/value, so two consecutive
# runs leave the file unchanged after the first application.
set_param() {
    local key="$1" value="$2"
    local esc_key="${key//./\\.}"
    if grep -qE "^[[:space:]]*#?[[:space:]]*${esc_key}[[:space:]]*=" "$SYSCTL_CONF"; then
        sed -i -E "s|^[[:space:]]*#?[[:space:]]*${esc_key}[[:space:]]*=.*|${key} = ${value}|" "$SYSCTL_CONF"
    else
        echo "${key} = ${value}" >> "$SYSCTL_CONF"
    fi
}

for i in "${!PARAM_KEYS[@]}"; do
    set_param "${PARAM_KEYS[$i]}" "${PARAM_VALUES[$i]}"
done

# Apply immediately against the live kernel. Only done when operating on the
# real, default path - a scratch-file test must never touch the running
# kernel's actual parameters.
LIVE_MODE=0
if [ "${1:-}" = "" ]; then
    LIVE_MODE=1
    sysctl -p "$SYSCTL_CONF" >/dev/null 2>&1 || true
else
    echo "    (scratch mode: not calling sysctl -p against the live kernel)"
fi

# Verify by reading back from /proc/sys directly - the only authoritative
# source for what the running kernel actually has in effect right now. In
# scratch mode (no real sysctl -p was run) we verify the file content
# instead, since /proc/sys was intentionally left untouched.
PASS_COUNT=0
FAIL_COUNT=0
for i in "${!PARAM_KEYS[@]}"; do
    key="${PARAM_KEYS[$i]}"
    expected="${PARAM_VALUES[$i]}"
    if [ "$LIVE_MODE" -eq 1 ]; then
        path="/proc/sys/${key//.//}"
        actual="$(cat "$path" 2>/dev/null || echo "unreadable")"
    else
        actual="$(grep -E "^${key//./\\.}[[:space:]]*=" "$SYSCTL_CONF" | tail -1 | awk -F= '{gsub(/ /,"",$2); print $2}')"
    fi
    if [ "$actual" = "$expected" ]; then
        result="PASS"; PASS_COUNT=$((PASS_COUNT+1))
    else
        result="FAIL"; FAIL_COUNT=$((FAIL_COUNT+1))
    fi
    printf '%-42s = %-4s [%s]\n' "$key" "$actual" "$result"
done

echo "Parameters applied: ${#PARAM_KEYS[@]}"
echo "Verified PASS: $PASS_COUNT"
echo "Verified FAIL: $FAIL_COUNT"

[ "$FAIL_COUNT" -eq 0 ]
