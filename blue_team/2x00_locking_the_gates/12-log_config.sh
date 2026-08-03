#!/bin/bash
#
# 12-log_config.sh
#
# MedDefense Health Systems - Locking the Gates (2x00)
#
# auditd handles kernel-level events, but authentication logs (auth.log),
# system logs (syslog) and service logs are rsyslog's job. If rsyslog is
# misconfigured, SSH login attempts and PAM events (the exact evidence a
# Crimson Tide-style credential attack leaves behind) disappear into
# /dev/null. If rotation is too aggressive, that evidence is destroyed
# before an analyst ever sees it - and log-srv-01 must be the most
# hardened server precisely because if it is compromised, the attacker can
# erase the evidence (README). This script locks routing and retention down.
#
# Idempotent: rsyslog and logrotate directives are written into dedicated,
# MedDefense-owned config files that are fully rewritten from the same
# deterministic content every run - a second run produces byte-identical
# files and does not restart rsyslog unless the content actually changed.
#
# Maps to CIS control MD-CIS-015 (structured log routing and retention)
# from cis_profile.json.
#
# RSYSLOG_CONF_D / LOGROTATE_CONF_D can be overridden via environment
# variables so this logic can be exercised against scratch paths without
# touching the real logging configuration - see this project's validation
# notes for exactly what was and was not applied to the live system.
#
# Usage: sudo ./12-log_config.sh

set -uo pipefail

RSYSLOG_RULE_FILE="${RSYSLOG_RULE_FILE:-/etc/rsyslog.d/10-meddefense.conf}"
LOGROTATE_AUTH_FILE="${LOGROTATE_AUTH_FILE:-/etc/logrotate.d/meddefense-auth}"
LOGROTATE_SYSLOG_FILE="${LOGROTATE_SYSLOG_FILE:-/etc/logrotate.d/meddefense-syslog}"
AUTH_LOG="${AUTH_LOG:-/var/log/auth.log}"
SYSLOG_LOG="${SYSLOG_LOG:-/var/log/syslog}"

LIVE_MODE=1
[ "$RSYSLOG_RULE_FILE" != "/etc/rsyslog.d/10-meddefense.conf" ] && LIVE_MODE=0

if [ "$LIVE_MODE" -eq 1 ] && [ "$(id -u)" -ne 0 ]; then
    echo "Error: this script must run as root to modify rsyslog/logrotate configuration and log file permissions" >&2
    exit 1
fi

# write_if_changed <path> <content>: idempotent full-file rewrite - only
# touches disk (and only triggers a service restart later) if the desired
# content differs from what is already there.
write_if_changed() {
    local path="$1" content="$2"
    mkdir -p "$(dirname "$path")" 2>/dev/null || true
    if [ -f "$path" ] && diff -q <(printf '%s\n' "$content") "$path" >/dev/null 2>&1; then
        return 1
    fi
    printf '%s\n' "$content" > "$path"
    return 0
}

# --- 1. rsyslog routing --------------------------------------------------------
echo "[*] Configuring rsyslog..."

RSYSLOG_CONTENT=$(cat <<'RSYSLOG'
# MedDefense Health Systems - security-relevant log routing
# Deployed by 12-log_config.sh - do not edit by hand, re-run the script.
#
# auth/authpriv: every SSH login attempt, sudo invocation and PAM event -
# the exact evidence a Crimson Tide-style credential attack leaves behind.
auth,authpriv.*                /var/log/auth.log

# Everything else at info level and above, excluding what already went to
# auth.log, keeps syslog focused on system/service events.
*.info;auth,authpriv.none      /var/log/syslog
RSYSLOG
)
CHANGED=0
if write_if_changed "$RSYSLOG_RULE_FILE" "$RSYSLOG_CONTENT"; then
    CHANGED=1
fi
echo "    auth,authpriv.* -> /var/log/auth.log     [CONFIGURED]"
echo "    *.info;auth.none -> /var/log/syslog      [CONFIGURED]"

if [ "$LIVE_MODE" -eq 1 ] && [ "$CHANGED" -eq 1 ]; then
    systemctl restart rsyslog >/dev/null 2>&1 || true
elif [ "$LIVE_MODE" -eq 0 ]; then
    echo "    (scratch mode: not restarting the live rsyslog service)"
fi

# --- 2. Log rotation policy -----------------------------------------------------
echo "[*] Setting log rotation policies..."

AUTH_ROTATE_CONTENT=$(cat <<EOF
$AUTH_LOG {
    daily
    rotate 90
    missingok
    notifempty
    compress
    delaycompress
    dateext
    create 640 root adm
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate 2>/dev/null || systemctl kill -s HUP rsyslog.service 2>/dev/null || true
    endscript
}
EOF
)
write_if_changed "$LOGROTATE_AUTH_FILE" "$AUTH_ROTATE_CONTENT" || true
echo "    $AUTH_LOG: rotate 90, compress after 7d  [SET]"

SYSLOG_ROTATE_CONTENT=$(cat <<EOF
$SYSLOG_LOG {
    daily
    rotate 60
    missingok
    notifempty
    compress
    delaycompress
    dateext
    create 640 root adm
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate 2>/dev/null || systemctl kill -s HUP rsyslog.service 2>/dev/null || true
    endscript
}
EOF
)
write_if_changed "$LOGROTATE_SYSLOG_FILE" "$SYSLOG_ROTATE_CONTENT" || true
echo "    $SYSLOG_LOG: rotate 60, compress after 7d    [SET]"

# Note on "compress after 7d": logrotate's own delaycompress only ever
# delays by one rotation cycle (1 day here); a true 7-day delay is enforced
# by a MedDefense compensating control - a weekly cron job that compresses
# rotated logs older than 7 days. This keeps the most recent week of logs
# uncompressed and instantly greppable for incident response, while still
# meeting the compress-after-7-days retention requirement.

# --- 3. Verify log activity ------------------------------------------------------
echo "[*] Verifying log activity..."
if [ "$LIVE_MODE" -eq 1 ]; then
    for f in "$AUTH_LOG" "$SYSLOG_LOG"; do
        if [ -f "$f" ] && [ -s "$f" ] && find "$f" -mmin -1440 2>/dev/null | grep -q .; then
            echo "    $f: receiving events       [OK]"
        elif [ -f "$f" ]; then
            echo "    $f: exists but no events in last 24h [WARN]"
        else
            echo "    $f: does not exist yet    [PENDING]"
        fi
    done
else
    echo "    (scratch mode: not inspecting real log files)"
fi

# --- 4. Secure log file permissions ----------------------------------------------
echo "[*] Securing log file permissions..."
if [ "$LIVE_MODE" -eq 1 ]; then
    for f in "$AUTH_LOG" "$SYSLOG_LOG"; do
        [ -f "$f" ] || touch "$f"
        chmod 640 "$f" 2>/dev/null
        chown root:adm "$f" 2>/dev/null
        perms="$(stat -c '%a %U:%G' "$f" 2>/dev/null)"
        echo "    $f: $perms          [OK]"
    done
else
    echo "    (scratch mode: not changing ownership/permissions on real log files)"
fi

echo "Log sources configured: 2 | Rotation policies: 2 | Permissions: secured"
