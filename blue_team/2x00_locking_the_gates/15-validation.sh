#!/bin/bash
#
# 15-validation.sh
#
# MedDefense Health Systems - Locking the Gates (2x00)
#
# Hardening is not a one-time event. Configuration drift happens: an admin
# changes a sysctl setting for debugging and forgets to revert; a package
# update overwrites sshd_config. This is the script James Chen runs every
# Monday morning. It makes NO changes to the system - it only reads and
# reports, checking every control from Tasks 4-13 against its expected
# value.
#
# Read-only. Exits 0 if every check passes, 1 if any check fails - this
# exit code is what a cron job or CI pipeline would gate on.
#
# control_id values match cis_profile.json (Task 1) / gap_analysis.json and
# remediation_queue.json (Task 3) exactly, so Task 17's compliance bundle
# can join validation results back to the original control profile.
#
# Usage: sudo ./15-validation.sh

set -uo pipefail

OUT_JSON="validation_results.json"
IS_ROOT=0
[ "$(id -u)" -eq 0 ] && IS_ROOT=1

RESULTS_JSONL=""
PASS_COUNT=0
FAIL_COUNT=0

# record <control_id> <check_label> <expected> <actual> <pass:0/1>
record() {
    local cid="$1" label="$2" expected="$3" actual="$4" ok="$5"
    if [ "$ok" -eq 1 ]; then
        echo "[PASS] ${label} = ${actual}"
        PASS_COUNT=$((PASS_COUNT+1))
    else
        echo "[FAIL] ${label} = ${actual} (expected: ${expected})"
        FAIL_COUNT=$((FAIL_COUNT+1))
    fi
    obj=$(jq -n --arg cid "$cid" --arg label "$label" --arg expected "$expected" \
        --arg actual "$actual" --argjson ok "$([ "$ok" -eq 1 ] && echo true || echo false)" \
        '{control_id: $cid, check: $label, expected: $expected, actual: $actual,
          status: (if $ok then "PASS" else "FAIL" end)}')
    RESULTS_JSONL="${RESULTS_JSONL}${obj}"$'\n'
}

sysctl_val() { cat "/proc/sys/${1//.//}" 2>/dev/null || echo "unreadable"; }

# --- SSH (Task 4 / MD-CIS-001, MD-CIS-002) -----------------------------------
val=$(grep -iE '^\s*PermitRootLogin\s+' /etc/ssh/sshd_config 2>/dev/null | tail -1 | awk '{print tolower($2)}')
[ -z "$val" ] && val="not_set"
record "MD-CIS-002" "PermitRootLogin" "no" "$val" "$([ "$val" = "no" ] && echo 1 || echo 0)"

val=$(grep -iE '^\s*PasswordAuthentication\s+' /etc/ssh/sshd_config 2>/dev/null | tail -1 | awk '{print tolower($2)}')
[ -z "$val" ] && val="not_set"
record "MD-CIS-001" "PasswordAuthentication" "no" "$val" "$([ "$val" = "no" ] && echo 1 || echo 0)"

val=$(grep -iE '^\s*MaxAuthTries\s+' /etc/ssh/sshd_config 2>/dev/null | tail -1 | awk '{print $2}')
[ -z "$val" ] && val="not_set"
record "MD-CIS-001" "MaxAuthTries" "3" "$val" "$([ "$val" = "3" ] && echo 1 || echo 0)"

# --- Kernel / sysctl (Task 5 / MD-CIS-003, MD-CIS-006) -----------------------
val=$(sysctl_val net.ipv4.ip_forward)
record "MD-CIS-003" "net.ipv4.ip_forward" "0" "$val" "$([ "$val" = "0" ] && echo 1 || echo 0)"

val=$(sysctl_val net.ipv4.tcp_syncookies)
record "MD-CIS-003" "net.ipv4.tcp_syncookies" "1" "$val" "$([ "$val" = "1" ] && echo 1 || echo 0)"

val=$(sysctl_val net.ipv4.conf.all.log_martians)
record "MD-CIS-003" "net.ipv4.conf.all.log_martians" "1" "$val" "$([ "$val" = "1" ] && echo 1 || echo 0)"

val=$(sysctl_val kernel.randomize_va_space)
record "MD-CIS-006" "kernel.randomize_va_space" "2" "$val" "$([ "$val" = "2" ] && echo 1 || echo 0)"

# --- Filesystem (Task 6 / MD-CIS-004) -----------------------------------------
whitelist_regex='^(/usr)?/bin/(su|mount|umount|ping|fusermount3?|passwd)$|^/usr/bin/(sudo|passwd|su|chsh|chfn|chage|expiry|gpasswd|newgrp|mount|umount|ping|fusermount3?|pkexec|crontab)$|^/usr/lib/(openssh/ssh-keysign|dbus-1\.0/dbus-daemon-launch-helper|policykit-1/polkit-agent-helper-1|xorg/Xorg\.wrap)$|^/usr/sbin/(pppd|mount\.nfs)$'
mapfile -t suid_bins < <(find / -xdev -type f -perm -4000 2>/dev/null)
unexpected=0
for f in "${suid_bins[@]}"; do
    echo "$f" | grep -qE "$whitelist_regex" || unexpected=$((unexpected+1))
done
record "MD-CIS-004" "unexpected_suid_binaries" "0" "$unexpected" "$([ "$unexpected" -eq 0 ] && echo 1 || echo 0)"

# --- Mount options / world-writable (Task 6 / MD-CIS-007) --------------------
tmp_opts=$(findmnt -no OPTIONS /tmp 2>/dev/null)
if [[ "$tmp_opts" == *noexec* && "$tmp_opts" == *nosuid* && "$tmp_opts" == *nodev* ]]; then
    tmp_ok=1
else
    tmp_ok=0
fi
record "MD-CIS-007" "/tmp mount options" "noexec,nosuid,nodev" "${tmp_opts:-none}" "$tmp_ok"

# --- PAM (Task 8 / MD-CIS-005, MD-CIS-009) -----------------------------------
val=$(grep -E '^\s*minlen\s*=' /etc/security/pwquality.conf 2>/dev/null | tail -1 | awk -F= '{gsub(/ /,"",$2); print $2}')
[ -z "$val" ] && val="not_set"
record "MD-CIS-005" "pwquality.minlen" "14" "$val" "$([ "$val" = "14" ] && echo 1 || echo 0)"

val=$(grep -E '^\s*deny\s*=' /etc/security/faillock.conf 2>/dev/null | tail -1 | awk -F= '{gsub(/ /,"",$2); print $2}')
[ -z "$val" ] && val="not_set"
record "MD-CIS-009" "faillock.deny" "5" "$val" "$([ "$val" = "5" ] && echo 1 || echo 0)"

# --- Service minimization (Task 7 / MD-CIS-008) ------------------------------
required_services='ssh|sshd|apache2|mysql|ufw|auditd|apparmor|cron|rsyslog|systemd-timesyncd'
mapfile -t enabled_units < <(systemctl list-unit-files --type=service --state=enabled --no-legend --no-pager 2>/dev/null | awk '{print $1}')
extra=0
for u in "${enabled_units[@]}"; do
    echo "$u" | grep -qiE "$required_services" || extra=$((extra+1))
done
record "MD-CIS-008" "unwhitelisted_enabled_services" "0" "$extra" "$([ "$extra" -eq 0 ] && echo 1 || echo 0)"

# --- AppArmor (Task 9 / MD-CIS-010) ------------------------------------------
val=$(systemctl is-active apparmor 2>/dev/null || echo unknown)
record "MD-CIS-010" "apparmor.service" "active" "$val" "$([ "$val" = "active" ] && echo 1 || echo 0)"

# --- Audit engine (Task 10 / MD-CIS-011) -------------------------------------
val=$(systemctl is-active auditd 2>/dev/null || echo unknown)
record "MD-CIS-011" "auditd.service" "active" "$val" "$([ "$val" = "active" ] && echo 1 || echo 0)"

if [ -r /etc/audit/rules.d/meddefense.rules ]; then
    rule_count=$(grep -cE '^-w ' /etc/audit/rules.d/meddefense.rules 2>/dev/null)
else
    rule_count=0
fi
record "MD-CIS-011" "meddefense_audit_rules_present" ">0" "$rule_count" "$([ "${rule_count:-0}" -gt 0 ] && echo 1 || echo 0)"

# --- Privilege escalation audit rules (Task 10 / MD-CIS-013) -----------------
if [ -r /etc/audit/rules.d/meddefense.rules ] && grep -q 'priv_esc' /etc/audit/rules.d/meddefense.rules 2>/dev/null; then
    priv_esc_present=1
else
    priv_esc_present=0
fi
record "MD-CIS-013" "priv_esc_audit_rules_present" "yes" "$([ "$priv_esc_present" -eq 1 ] && echo yes || echo no)" "$priv_esc_present"

# --- Audit telemetry coverage (Task 11 / MD-CIS-014) -------------------------
audit_validation_file=""
for c in "./audit_validation.json" "../11-the_audit_telemetry_coverage_test/audit_validation.json"; do
    [ -r "$c" ] && { audit_validation_file="$c"; break; }
done
if [ -n "$audit_validation_file" ]; then
    executed=$(jq -r '.summary.tests_executed // 0' "$audit_validation_file" 2>/dev/null)
    captured=$(jq -r '.summary.captured // 0' "$audit_validation_file" 2>/dev/null)
    coverage_ok=$([ "${executed:-0}" -gt 0 ] && [ "$captured" = "$executed" ] && echo 1 || echo 0)
    coverage_actual="${captured:-0}/${executed:-0} captured"
else
    coverage_ok=0
    coverage_actual="audit_validation.json not found"
fi
record "MD-CIS-014" "audit_telemetry_coverage" "all captured" "$coverage_actual" "$coverage_ok"

# --- Logging (Task 12 / MD-CIS-015) ------------------------------------------
if find /etc/rsyslog.d -maxdepth 1 -iname '*meddefense*' 2>/dev/null | grep -q .; then
    val="configured"
else
    val="not_configured"
fi
record "MD-CIS-015" "meddefense_rsyslog_policy" "configured" "$val" "$([ "$val" = "configured" ] && echo 1 || echo 0)"

# --- Firewall (Task 13 / MD-CIS-012) -----------------------------------------
if [ "$IS_ROOT" -eq 1 ] && command -v ufw >/dev/null 2>&1; then
    ufw_out="$(ufw status verbose 2>/dev/null)"
    ufw_state=$(grep -m1 '^Status:' <<<"$ufw_out" | awk '{print $2}')
    default_in=$(grep -m1 '^Default:' <<<"$ufw_out" | grep -oE 'deny \(incoming\)' | awk '{print $1}')
    [ -z "$ufw_state" ] && ufw_state="unknown"
    [ -z "$default_in" ] && default_in="unknown"
else
    ufw_state="requires_root"
    default_in="requires_root"
fi
record "MD-CIS-012" "UFW status" "active" "$ufw_state" "$([ "$ufw_state" = "active" ] && echo 1 || echo 0)"
record "MD-CIS-012" "Default incoming" "deny" "$default_in" "$([ "$default_in" = "deny" ] && echo 1 || echo 0)"

# --- Write JSON + summary -----------------------------------------------------
RESULTS_JSON=$(jq -s '.' <<<"$RESULTS_JSONL")
jq -n --argjson results "$RESULTS_JSON" \
  --arg generated "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson pass "$PASS_COUNT" --argjson fail "$FAIL_COUNT" \
  --argjson is_root "$([ "$IS_ROOT" -eq 1 ] && echo true || echo false)" \
  '{
    generated: $generated,
    executed_as_root: $is_root,
    summary: { total: ($results | length), passed: $pass, failed: $fail },
    results: $results
  }' > "$OUT_JSON"

[ "$FAIL_COUNT" -eq 0 ]
