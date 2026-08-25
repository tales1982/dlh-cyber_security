#!/bin/bash

set -uo pipefail


# ==================================================
# 1. SYSTEM INFORMATION
# ==================================================

# Hostname
HOSTNAME=$(hostname)

# Kernel release
KERNEL=$(uname -r)

# Linux distribution
DISTRIBUTION=$(grep '^PRETTY_NAME=' /etc/os-release | cut -d= -f2 | tr -d '"')

# Patch level - number of pending package updates
PATCH_LEVEL=$(apt list --upgradable 2>/dev/null | tail -n +2 | wc -l)


# ==================================================
# 2. INSTALLED PACKAGES
# ==================================================

# Number of installed packages
PACKAGE_COUNT=$(dpkg-query -W | wc -l)


# ==================================================
# 3. LISTENING SOCKETS
# ==================================================

# TCP and UDP listening sockets
LISTENING_SOCKETS=$(ss -tulnpH)


# ==================================================
# 4. ACTIVE SYSTEMD SERVICES
# ==================================================

# Currently active systemd services
ACTIVE_SERVICES=$(systemctl list-units \
    --type=service \
    --state=active \
    --no-legend \
    --no-pager)


# ==================================================
# 5. SSH CONFIGURATION
# ==================================================

# Effective SSH daemon configuration
SSHD_CONFIG=$(sudo sshd -T)


# ==================================================
# 6. SYSCTL SECURITY PARAMETERS
# ==================================================

# Current security-related kernel parameters
SYSCTL_SECURITY=$(sysctl \
    net.ipv4.ip_forward \
    net.ipv4.conf.all.accept_redirects \
    net.ipv4.conf.default.accept_redirects \
    net.ipv4.conf.all.send_redirects \
    net.ipv4.conf.all.accept_source_route \
    net.ipv4.conf.all.log_martians \
    net.ipv4.tcp_syncookies \
    net.ipv4.icmp_echo_ignore_broadcasts \
    net.ipv6.conf.all.disable_ipv6 \
    net.ipv6.conf.default.disable_ipv6 \
    kernel.randomize_va_space \
    fs.suid_dumpable \
    kernel.dmesg_restrict \
    kernel.kptr_restrict)


# ==================================================
# 7. SUID / SGID BINARIES
# ==================================================

# Number of files with SUID or SGID permissions
SUID_SGID_COUNT=$(sudo find / -perm /6000 -type f 2>/dev/null | wc -l)


# ==================================================
# 8. WORLD-WRITABLE FILES
# ==================================================

# Number of world-writable files, excluding /proc and /sys
WORLD_WRITABLE_COUNT=$(sudo find / \
    -path /proc -prune -o \
    -path /sys -prune -o \
    -perm -0002 -type f -print 2>/dev/null | wc -l)


# ==================================================
# 9. FIREWALL STATUS
# ==================================================

# Size in bytes of the current nftables ruleset
NFT_RULESET_SIZE=$(sudo nft list ruleset 2>/dev/null | wc -c)


# ==================================================
# 10. TELEMETRY
# ==================================================

# auditd service status
AUDITD_STATUS=$(systemctl is-active auditd 2>/dev/null || true)

# rsyslog service status
RSYSLOG_STATUS=$(systemctl is-active rsyslog 2>/dev/null || true)

# Sysmon for Linux executable path (empty if not installed)
SYSMON_PATH=$(command -v sysmon 2>/dev/null || true)

jq -n \
    --arg hostname "$HOSTNAME" \
    --arg kernel "$KERNEL" \
    --arg distribution "$DISTRIBUTION" \
    --argjson patch_level "$PATCH_LEVEL" \
    --argjson package_count "$PACKAGE_COUNT" \
    --arg listening_sockets "$LISTENING_SOCKETS" \
    --arg active_services "$ACTIVE_SERVICES" \
    --arg sshd_config "$SSHD_CONFIG" \
    --arg sysctl_security "$SYSCTL_SECURITY" \
    --argjson suid_sgid_count "$SUID_SGID_COUNT" \
    --argjson world_writable_count "$WORLD_WRITABLE_COUNT" \
    --argjson nft_ruleset_size "$NFT_RULESET_SIZE" \
    --arg auditd_status "$AUDITD_STATUS" \
    --arg rsyslog_status "$RSYSLOG_STATUS" \
    --arg sysmon_path "$SYSMON_PATH" \
    '{
        hostname: $hostname,
        kernel: $kernel,
        distribution: $distribution,
        patch_level: $patch_level,
        package_count: $package_count,
        listening_sockets: ($listening_sockets | split("\n") | map(select(length > 0))),
        active_services: ($active_services | split("\n") | map(select(length > 0))),
        sshd_config: ($sshd_config | split("\n") | map(select(length > 0)) | map(split(" ")) | map({(.[0]): (.[1:] | join(" "))}) | add),
        sysctl_security: ($sysctl_security | split("\n") | map(select(length > 0)) | map(split(" = ")) | map({(.[0]): .[1]}) | add),
        suid_sgid_count: $suid_sgid_count,
        world_writable_count: $world_writable_count,
        firewall: {
            nft_ruleset_size: $nft_ruleset_size
        },
        telemetry: {
            auditd_running: ($auditd_status == "active"),
            rsyslog_running: ($rsyslog_status == "active"),
            sysmon_present: ($sysmon_path != ""),
            sysmon_path: (if $sysmon_path == "" then null else $sysmon_path end)
        }
    }'





# ==================================================
# TEST
# ==================================================

#echo "$HOSTNAME"
#echo "$KERNEL"
#echo "$DISTRIBUTION"
#echo "$PACKAGE_COUNT"
#echo "$LISTENING_SOCKETS"
#echo "$ACTIVE_SERVICES"
#echo "$SSHD_CONFIG"
#echo "$SYSCTL_SECURITY"
#echo "$SUID_SGID_COUNT"
#echo "$WORLD_WRITABLE_COUNT"
#echo "$NFT_RULESET_SIZE"
#echo "$AUDITD_STATUS"
#echo "$RSYSLOG_STATUS"
#echo "$SYSMON_PATH"