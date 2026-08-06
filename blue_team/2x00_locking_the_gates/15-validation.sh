#!/bin/bash
set -euo pipefail

OUT_JSON="validation_report.json"

IS_ROOT=0
[ "$(id -u)" -eq 0 ] && IS_ROOT=1

CHECKS_JSONL=""
PASS_COUNT=0
FAIL_COUNT=0

record() {
    local cid="$1"
    local label="$2"
    local expected="$3"
    local actual="$4"
    local ok="$5"
    local obj

    if [ "$ok" -eq 1 ]; then
        echo "[PASS] ${label} = ${actual}"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "[FAIL] ${label} = ${actual} (expected: ${expected})"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi

    obj=$(
        jq -n \
            --arg cid "$cid" \
            --arg label "$label" \
            --arg expected "$expected" \
            --arg actual "$actual" \
            --argjson ok "$(
                [ "$ok" -eq 1 ] && echo true || echo false
            )" \
            '{
                control_id: $cid,
                check: $label,
                expected: $expected,
                actual: $actual,
                status: (if $ok then "PASS" else "FAIL" end)
            }'
    )

    CHECKS_JSONL="${CHECKS_JSONL}${obj}"$'\n'
}

sysctl_val() {
    cat "/proc/sys/${1//.//}" 2>/dev/null || echo "unreadable"
}

check_cfg() {
    local cid="$1"
    local file="$2"
    local key="$3"
    local label="$4"
    local expected="$5"
    local val

    val=$(
        grep -iE "^[[:space:]]*${key}[[:space:]]*[= ]" "$file" 2>/dev/null |
            tail -1 |
            awk -F'[= ]+' '{print tolower($2)}'
    ) || true

    [ -z "$val" ] && val="not_set"

    record \
        "$cid" \
        "$label" \
        "$expected" \
        "$val" \
        "$([ "$val" = "$expected" ] && echo 1 || echo 0)"
}

check_sysctl() {
    local cid="$1"
    local key="$2"
    local expected="$3"
    local val

    val=$(sysctl_val "$key")

    record \
        "$cid" \
        "$key" \
        "$expected" \
        "$val" \
        "$([ "$val" = "$expected" ] && echo 1 || echo 0)"
}

check_cfg \
    MD-CIS-002 \
    /etc/ssh/sshd_config \
    PermitRootLogin \
    PermitRootLogin \
    no

check_cfg \
    MD-CIS-001 \
    /etc/ssh/sshd_config \
    PasswordAuthentication \
    PasswordAuthentication \
    no

check_cfg \
    MD-CIS-001 \
    /etc/ssh/sshd_config \
    MaxAuthTries \
    MaxAuthTries \
    3

check_sysctl MD-CIS-003 net.ipv4.ip_forward 0
check_sysctl MD-CIS-003 net.ipv4.tcp_syncookies 1
check_sysctl MD-CIS-006 kernel.randomize_va_space 2
check_sysctl MD-CIS-003 net.ipv4.conf.all.log_martians 1

whitelist_regex='^(/usr)?/bin/(su|mount|umount|ping|fusermount3?|passwd)$|^/usr/bin/(sudo|passwd|su|chsh|chfn|chage|expiry|gpasswd|newgrp|mount|umount|ping|fusermount3?|pkexec|crontab)$|^/usr/lib/(openssh/ssh-keysign|dbus-1\.0/dbus-daemon-launch-helper|policykit-1/polkit-agent-helper-1|xorg/Xorg\.wrap)$|^/usr/sbin/(pppd|mount\.nfs)$'

mapfile -t suid_bins < <(
    find / -xdev -type f -perm -4000 2>/dev/null
)

unexpected=0

for file_path in "${suid_bins[@]}"; do
    echo "$file_path" | grep -qE "$whitelist_regex" ||
        unexpected=$((unexpected + 1))
done

record \
    "MD-CIS-004" \
    "unexpected_suid_binaries" \
    "0" \
    "$unexpected" \
    "$([ "$unexpected" -eq 0 ] && echo 1 || echo 0)"

tmp_opts=$(findmnt -no OPTIONS /tmp 2>/dev/null) || true
tmp_ok=0

if [[ "$tmp_opts" == *noexec* &&
      "$tmp_opts" == *nosuid* &&
      "$tmp_opts" == *nodev* ]]; then
    tmp_ok=1
fi

record \
    "MD-CIS-007" \
    "/tmp mount options" \
    "noexec,nosuid,nodev" \
    "${tmp_opts:-none}" \
    "$tmp_ok"

check_cfg \
    MD-CIS-005 \
    /etc/security/pwquality.conf \
    minlen \
    pwquality.minlen \
    14

check_cfg \
    MD-CIS-009 \
    /etc/security/faillock.conf \
    deny \
    faillock.deny \
    5

required_services='ssh|sshd|apache2|mysql|ufw|auditd|apparmor|cron|rsyslog|systemd-timesyncd'

mapfile -t enabled_units < <(
    systemctl list-unit-files \
        --type=service \
        --state=enabled \
        --no-legend \
        --no-pager 2>/dev/null |
        awk '{print $1}'
)

extra=0

for unit in "${enabled_units[@]}"; do
    echo "$unit" | grep -qiE "$required_services" ||
        extra=$((extra + 1))
done

record \
    "MD-CIS-008" \
    "unwhitelisted_enabled_services" \
    "0" \
    "$extra" \
    "$([ "$extra" -eq 0 ] && echo 1 || echo 0)"

val=$(systemctl is-active auditd 2>/dev/null || echo unknown)

record \
    "MD-CIS-011" \
    "auditd.service" \
    "active" \
    "$val" \
    "$([ "$val" = "active" ] && echo 1 || echo 0)"

rule_count=0

if [ -r /etc/audit/rules.d/meddefense.rules ]; then
    rule_count=$(
        grep -cE '^-w ' \
            /etc/audit/rules.d/meddefense.rules 2>/dev/null ||
            true
    )
fi

record \
    "MD-CIS-011" \
    "meddefense_audit_rules_present" \
    ">0" \
    "$rule_count" \
    "$([ "${rule_count:-0}" -gt 0 ] && echo 1 || echo 0)"

priv_esc_present=0

if [ -r /etc/audit/rules.d/meddefense.rules ] &&
   grep -q 'priv_esc' \
       /etc/audit/rules.d/meddefense.rules 2>/dev/null; then
    priv_esc_present=1
fi

record \
    "MD-CIS-013" \
    "priv_esc_audit_rules_present" \
    "yes" \
    "$([ "$priv_esc_present" -eq 1 ] && echo yes || echo no)" \
    "$priv_esc_present"

val=$(systemctl is-active apparmor 2>/dev/null || echo unknown)

record \
    "MD-CIS-010" \
    "apparmor.service" \
    "active" \
    "$val" \
    "$([ "$val" = "active" ] && echo 1 || echo 0)"

audit_validation_file=""

for candidate in \
    "./audit_validation.json" \
    "../11-the_audit_telemetry_coverage_test/audit_validation.json"
do
    if [ -r "$candidate" ]; then
        audit_validation_file="$candidate"
        break
    fi
done

if [ -n "$audit_validation_file" ]; then
    executed=$(
        jq -r \
            '.summary.tests_executed // 0' \
            "$audit_validation_file" 2>/dev/null
    )

    captured=$(
        jq -r \
            '.summary.captured // 0' \
            "$audit_validation_file" 2>/dev/null
    )

    coverage_ok=$(
        [ "${executed:-0}" -gt 0 ] &&
        [ "$captured" = "$executed" ] &&
        echo 1 || echo 0
    )

    coverage_actual="${captured:-0}/${executed:-0} captured"
else
    coverage_ok=0
    coverage_actual="audit_validation.json not found"
fi

record \
    "MD-CIS-014" \
    "audit_telemetry_coverage" \
    "all captured" \
    "$coverage_actual" \
    "$coverage_ok"

val="not_configured"

if find /etc/rsyslog.d \
    -maxdepth 1 \
    -iname '*meddefense*' \
    2>/dev/null |
    grep -q .
then
    val="configured"
fi

record \
    "MD-CIS-015" \
    "meddefense_rsyslog_policy" \
    "configured" \
    "$val" \
    "$([ "$val" = "configured" ] && echo 1 || echo 0)"

ufw_state="requires_root"
default_in="requires_root"

if [ "$IS_ROOT" -eq 1 ] &&
   command -v ufw >/dev/null 2>&1; then

    ufw_out="$(ufw status verbose 2>/dev/null)" || true

    ufw_state=$(
        grep -m1 '^Status:' <<<"$ufw_out" |
            awk '{print $2}'
    ) || true

    default_in=$(
        grep -m1 '^Default:' <<<"$ufw_out" |
            grep -oE 'deny \(incoming\)' |
            awk '{print $1}'
    ) || true

    [ -z "$ufw_state" ] && ufw_state="unknown"
    [ -z "$default_in" ] && default_in="unknown"
fi

record \
    "MD-CIS-012" \
    "UFW status" \
    "active" \
    "$ufw_state" \
    "$([ "$ufw_state" = "active" ] && echo 1 || echo 0)"

record \
    "MD-CIS-012" \
    "Default incoming" \
    "deny" \
    "$default_in" \
    "$([ "$default_in" = "deny" ] && echo 1 || echo 0)"

CHECKS_JSON=$(jq -s '.' <<<"$CHECKS_JSONL")

jq -n \
    --argjson checks "$CHECKS_JSON" \
    --arg generated "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson pass "$PASS_COUNT" \
    --argjson fail "$FAIL_COUNT" \
    --argjson is_root "$(
        [ "$IS_ROOT" -eq 1 ] && echo true || echo false
    )" \
    '{
        generated: $generated,
        executed_as_root: $is_root,
        summary: {
            total: ($checks | length),
            passed: $pass,
            failed: $fail
        },
        checks: $checks
    }' > "$OUT_JSON"

[ "$FAIL_COUNT" -eq 0 ]