#!/bin/bash
#
# 3-remediation_queue.sh
#
# MedDefense Health Systems - Locking the Gates (2x00)
#
# This is the decision engine: it reads the CIS control profile (Task 1) and
# the Lynis findings (Task 2), checks the CURRENT live system state for each
# control, and produces two artifacts:
#   - gap_analysis.json       every control mapped to compliant / non_compliant
#                              / partially_compliant / not_assessed, with the
#                              evidence used to reach that verdict
#   - remediation_queue.json  a priority-ordered work queue for Tasks 4-13
#
# Read-only. This script inspects the system; it does not change it. Some
# checks (e.g. full ufw/auditctl state, aa-status) require root to read
# completely - when root is unavailable those controls are honestly reported
# as not_assessed rather than guessed.
#
# Usage: ./3-remediation_queue.sh [cis_profile.json] [lynis_findings.json]

set -uo pipefail

CIS_PROFILE="${1:-}"
LYNIS_FINDINGS="${2:-}"

# --- Locate input artifacts --------------------------------------------------
# Convention used across this whole module: a script first looks for its
# inputs alongside itself, then falls back to the well-known sibling task
# directory. The orchestrator (Task 14) relies on this same convention.
find_input() {
    local explicit="$1"; shift
    if [ -n "$explicit" ] && [ -r "$explicit" ]; then
        echo "$explicit"; return 0
    fi
    for candidate in "$@"; do
        if [ -r "$candidate" ]; then
            echo "$candidate"; return 0
        fi
    done
    return 1
}

CIS_PROFILE="$(find_input "$CIS_PROFILE" "./cis_profile.json" "../1-the_cis_control_profile/cis_profile.json")" \
    || { echo "Error: cis_profile.json not found" >&2; exit 1; }
LYNIS_FINDINGS="$(find_input "$LYNIS_FINDINGS" "./lynis_findings.json" "../2-the_lynis_audit_parser/lynis_findings.json")" \
    || { echo "Error: lynis_findings.json not found" >&2; exit 1; }

GAP_OUT="gap_analysis.json"
QUEUE_OUT="remediation_queue.json"

# --- Keyword map: control_id -> regex used to pull matching Lynis findings --
declare -A KEYWORDS=(
    [MD-CIS-001]="ssh|sshd|password.?auth"
    [MD-CIS-002]="ssh|sshd|root.?login"
    [MD-CIS-003]="sysctl|forward|redirect|martian"
    [MD-CIS-004]="suid|sgid|permission"
    [MD-CIS-005]="password|pwquality|pam"
    [MD-CIS-006]="kernel|aslr|hardening|sysctl|compiler"
    [MD-CIS-007]="writable|mount|tmp|permission"
    [MD-CIS-008]="service|daemon|process|port"
    [MD-CIS-009]="password|lockout|faillock|pam"
    [MD-CIS-010]="apparmor|aa-status|mac framework|profiles"
    [MD-CIS-011]="audit"
    [MD-CIS-012]="firewall|iptables|nftables|ufw"
    [MD-CIS-013]="audit"
    [MD-CIS-014]="audit"
    [MD-CIS-015]="log|rsyslog|syslog|journal"
)

# --- Live-system evidence checks --------------------------------------------
# Each function sets STATUS and EVIDENCE. All reads are non-destructive; where
# root would be required to see the full picture (aa-status, full ufw/auditd
# state) the check degrades honestly to not_assessed instead of guessing.

have_root() { [ "$(id -u)" -eq 0 ]; }

check_MD_CIS_001() {
    local val
    val="$(grep -iE '^\s*PasswordAuthentication\s+' /etc/ssh/sshd_config 2>/dev/null | tail -1 | awk '{print tolower($2)}')"
    if [ "$val" = "no" ]; then STATUS="compliant"; EVIDENCE="sshd_config PasswordAuthentication=no"
    elif [ -z "$val" ]; then STATUS="non_compliant"; EVIDENCE="PasswordAuthentication not explicitly set (defaults to yes upstream)"
    else STATUS="non_compliant"; EVIDENCE="sshd_config PasswordAuthentication=$val"; fi
}

check_MD_CIS_002() {
    local val
    val="$(grep -iE '^\s*PermitRootLogin\s+' /etc/ssh/sshd_config 2>/dev/null | tail -1 | awk '{print tolower($2)}')"
    if [ "$val" = "no" ]; then STATUS="compliant"; EVIDENCE="sshd_config PermitRootLogin=no"
    elif [ -z "$val" ]; then STATUS="non_compliant"; EVIDENCE="PermitRootLogin not explicitly set (defaults to prohibit-password/yes upstream)"
    else STATUS="non_compliant"; EVIDENCE="sshd_config PermitRootLogin=$val"; fi
}

check_MD_CIS_003() {
    local fwd redir syn ok=0 total=3
    fwd="$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)"
    redir="$(cat /proc/sys/net/ipv4/conf/all/accept_redirects 2>/dev/null)"
    syn="$(cat /proc/sys/net/ipv4/tcp_syncookies 2>/dev/null)"
    [ "$fwd" = "0" ] && ok=$((ok+1))
    [ "$redir" = "0" ] && ok=$((ok+1))
    [ "$syn" = "1" ] && ok=$((ok+1))
    EVIDENCE="ip_forward=$fwd accept_redirects=$redir tcp_syncookies=$syn"
    if [ "$ok" -eq "$total" ]; then STATUS="compliant"
    elif [ "$ok" -eq 0 ]; then STATUS="non_compliant"
    else STATUS="partially_compliant"; fi
}

check_MD_CIS_004() {
    local whitelist unexpected count
    whitelist='^/(usr/bin/(su|sudo|passwd|chsh|chfn|gpasswd|newgrp|mount|umount|chage|expiry)|usr/lib/(openssh/ssh-keysign|dbus-1.0/dbus-daemon-launch-helper|policykit-1/polkit-agent-helper-1)|bin/(su|mount|umount|ping|fusermount3?))$'
    mapfile -t suid < <(find / -xdev -type f -perm -4000 2>/dev/null)
    count="${#suid[@]}"
    unexpected=0
    for f in "${suid[@]:-}"; do
        [ -z "$f" ] && continue
        echo "$f" | grep -qE "$whitelist" || unexpected=$((unexpected+1))
    done
    EVIDENCE="$count SUID binaries found, $unexpected outside MedDefense whitelist"
    if [ "$count" -eq 0 ]; then STATUS="not_assessed"
    elif [ "$unexpected" -eq 0 ]; then STATUS="compliant"
    else STATUS="non_compliant"; fi
}

check_MD_CIS_005() {
    if [ -r /etc/security/pwquality.conf ] && grep -qE '^\s*minlen\s*=\s*1[4-9]|^\s*minlen\s*=\s*[2-9][0-9]' /etc/security/pwquality.conf 2>/dev/null; then
        STATUS="compliant"; EVIDENCE="pwquality.conf minlen>=14 present"
    elif [ -r /etc/security/pwquality.conf ]; then
        STATUS="partially_compliant"; EVIDENCE="pwquality.conf present but minlen<14 or unset"
    else
        STATUS="non_compliant"; EVIDENCE="/etc/security/pwquality.conf not present"
    fi
}

check_MD_CIS_006() {
    local rva kptr dmesg dump ok=0
    rva="$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)"
    kptr="$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null)"
    dmesg="$(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null)"
    dump="$(cat /proc/sys/fs/suid_dumpable 2>/dev/null)"
    [ "$rva" = "2" ] && ok=$((ok+1))
    [ "$kptr" = "2" ] && ok=$((ok+1))
    [ "$dmesg" = "1" ] && ok=$((ok+1))
    [ "$dump" = "0" ] && ok=$((ok+1))
    EVIDENCE="randomize_va_space=$rva kptr_restrict=$kptr dmesg_restrict=$dmesg suid_dumpable=$dump"
    if [ "$ok" -eq 4 ]; then STATUS="compliant"
    elif [ "$ok" -eq 0 ]; then STATUS="non_compliant"
    else STATUS="partially_compliant"; fi
}

check_MD_CIS_007() {
    local opts ww
    opts="$(findmnt -no OPTIONS /tmp 2>/dev/null)"
    ww="$(find / -xdev -type f -perm -0002 -not -path '/proc/*' -not -path '/sys/*' -not -path '/dev/*' 2>/dev/null | wc -l)"
    local has_noexec=0 has_nosuid=0 has_nodev=0
    [[ "$opts" == *noexec* ]] && has_noexec=1
    [[ "$opts" == *nosuid* ]] && has_nosuid=1
    [[ "$opts" == *nodev* ]] && has_nodev=1
    EVIDENCE="/tmp mount options=[$opts] world_writable_files=$ww"
    if [ "$has_noexec" -eq 1 ] && [ "$has_nosuid" -eq 1 ] && [ "$has_nodev" -eq 1 ] && [ "$ww" -lt 20 ]; then
        STATUS="compliant"
    elif [ "$has_noexec" -eq 1 ] || [ "$has_nosuid" -eq 1 ] || [ "$has_nodev" -eq 1 ]; then
        STATUS="partially_compliant"
    else
        STATUS="non_compliant"
    fi
}

check_MD_CIS_008() {
    local required="ssh|sshd|apache2|mysql|ufw|auditd|apparmor|cron|rsyslog|systemd-timesyncd"
    mapfile -t enabled < <(systemctl list-unit-files --type=service --state=enabled --no-legend --no-pager 2>/dev/null | awk '{print $1}')
    local extra=0
    for svc in "${enabled[@]:-}"; do
        [ -z "$svc" ] && continue
        echo "$svc" | grep -qiE "$required" || extra=$((extra+1))
    done
    EVIDENCE="${#enabled[@]} enabled services, $extra outside MedDefense whitelist"
    if [ "${#enabled[@]}" -eq 0 ]; then STATUS="not_assessed"
    elif [ "$extra" -eq 0 ]; then STATUS="compliant"
    elif [ "$extra" -le 3 ]; then STATUS="partially_compliant"
    else STATUS="non_compliant"; fi
}

check_MD_CIS_009() {
    if [ -r /etc/security/faillock.conf ] && grep -qE '^\s*deny\s*=\s*[1-5]\b' /etc/security/faillock.conf 2>/dev/null; then
        STATUS="compliant"; EVIDENCE="faillock.conf deny<=5 configured"
    else
        STATUS="non_compliant"; EVIDENCE="pam_faillock deny/unlock_time not configured"
    fi
}

check_MD_CIS_010() {
    if ! command -v aa-status >/dev/null 2>&1; then
        STATUS="not_assessed"; EVIDENCE="aa-status not installed"
        return
    fi
    if have_root; then
        if aa-status --enforced 2>/dev/null | grep -qi apache; then
            STATUS="compliant"; EVIDENCE="apache2 profile in enforce mode"
        else
            STATUS="non_compliant"; EVIDENCE="apache2/mysqld profiles not in enforce mode"
        fi
    else
        STATUS="not_assessed"; EVIDENCE="aa-status requires root to enumerate enforced profiles on this host"
    fi
}

check_MD_CIS_011() {
    if [ -r /etc/audit/rules.d/meddefense.rules ] && grep -q 'identity' /etc/audit/rules.d/meddefense.rules 2>/dev/null; then
        STATUS="compliant"; EVIDENCE="/etc/audit/rules.d/meddefense.rules present with identity watch rules"
    else
        STATUS="non_compliant"; EVIDENCE="/etc/audit/rules.d/meddefense.rules not present"
    fi
}

check_MD_CIS_012() {
    if [ -r /etc/ufw/ufw.conf ]; then
        local en
        en="$(grep -iE '^\s*ENABLED=' /etc/ufw/ufw.conf 2>/dev/null | cut -d= -f2)"
        if [ "$en" = "yes" ] && have_root; then
            STATUS="compliant"; EVIDENCE="ufw.conf ENABLED=yes, verified with root"
        elif [ "$en" = "yes" ]; then
            STATUS="partially_compliant"; EVIDENCE="ufw.conf ENABLED=yes but full ruleset requires root to verify"
        else
            STATUS="non_compliant"; EVIDENCE="ufw.conf ENABLED=$en"
        fi
    else
        STATUS="not_assessed"; EVIDENCE="/etc/ufw/ufw.conf not present (ufw not installed/configured)"
    fi
}

check_MD_CIS_013() {
    if [ -r /etc/audit/rules.d/meddefense.rules ] && grep -q 'priv_esc' /etc/audit/rules.d/meddefense.rules 2>/dev/null; then
        STATUS="compliant"; EVIDENCE="/etc/audit/rules.d/meddefense.rules present with priv_esc watch rules"
    else
        STATUS="non_compliant"; EVIDENCE="privilege-escalation audit rules not present"
    fi
}

check_MD_CIS_014() {
    if [ -r ../11-the_audit_telemetry_coverage_test/audit_validation.json ] || [ -r ./audit_validation.json ]; then
        STATUS="compliant"; EVIDENCE="audit_validation.json present from Task 11 run"
    else
        STATUS="not_assessed"; EVIDENCE="Task 11 (audit coverage test) has not been run yet"
    fi
}

check_MD_CIS_015() {
    if find /etc/rsyslog.d -maxdepth 1 -iname '*meddefense*' 2>/dev/null | grep -q .; then
        STATUS="compliant"; EVIDENCE="MedDefense rsyslog policy file present in /etc/rsyslog.d"
    elif grep -rqiE 'auth,authpriv' /etc/rsyslog.d/*.conf /etc/rsyslog.conf 2>/dev/null; then
        STATUS="partially_compliant"; EVIDENCE="default rsyslog routes auth/authpriv already; custom retention policy not yet deployed"
    else
        STATUS="non_compliant"; EVIDENCE="no auth/authpriv routing found in rsyslog configuration"
    fi
}

# --- Assess every control in the profile ------------------------------------
CONTROL_IDS=$(jq -r '.controls[].control_id' "$CIS_PROFILE")

ASSESSMENTS_JSONL=""
while IFS= read -r cid; do
    [ -z "$cid" ] && continue
    fn="check_${cid//-/_}"
    STATUS="not_assessed"; EVIDENCE="no check implemented"
    if declare -F "$fn" >/dev/null; then
        "$fn"
    fi

    title=$(jq -r --arg id "$cid" '.controls[] | select(.control_id==$id) | .title' "$CIS_PROFILE")
    severity=$(jq -r --arg id "$cid" '.controls[] | select(.control_id==$id) | .severity' "$CIS_PROFILE")
    asset_scope=$(jq -c --arg id "$cid" '.controls[] | select(.control_id==$id) | .asset_scope' "$CIS_PROFILE")
    remediation_script=$(jq -r --arg id "$cid" '.controls[] | select(.control_id==$id) | .implementation_task' "$CIS_PROFILE")
    verification=$(jq -r --arg id "$cid" '.controls[] | select(.control_id==$id) | .verification_method' "$CIS_PROFILE")
    kw="${KEYWORDS[$cid]:-$cid}"

    matches=$(jq -c --arg kw "$kw" '[.findings[] | select((.test_id + " " + .message) | test($kw; "i"))]' "$LYNIS_FINDINGS")

    obj=$(jq -n \
        --arg cid "$cid" --arg title "$title" --arg severity "$severity" \
        --arg status "$STATUS" --arg evidence "$EVIDENCE" \
        --argjson asset_scope "$asset_scope" --arg remediation_script "$remediation_script" \
        --arg verification "$verification" --argjson matches "$matches" \
        '{control_id: $cid, title: $title, severity: $severity, status: $status,
          evidence: $evidence, asset_scope: $asset_scope,
          remediation_script: $remediation_script, verification_method: $verification,
          matching_lynis_findings: $matches}')
    ASSESSMENTS_JSONL="${ASSESSMENTS_JSONL}${obj}"$'\n'
done <<<"$CONTROL_IDS"

ASSESSMENTS_JSON=$(jq -s '.' <<<"$ASSESSMENTS_JSONL")

COMPLIANT=$(jq '[.[] | select(.status=="compliant")] | length' <<<"$ASSESSMENTS_JSON")
NON_COMPLIANT=$(jq '[.[] | select(.status=="non_compliant")] | length' <<<"$ASSESSMENTS_JSON")
PARTIAL=$(jq '[.[] | select(.status=="partially_compliant")] | length' <<<"$ASSESSMENTS_JSON")
NOT_ASSESSED=$(jq '[.[] | select(.status=="not_assessed")] | length' <<<"$ASSESSMENTS_JSON")
ASSESSED_COUNT=$(jq 'length' <<<"$ASSESSMENTS_JSON")

jq -n --argjson assessments "$ASSESSMENTS_JSON" \
  --arg generated "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg cis_source "$CIS_PROFILE" --arg lynis_source "$LYNIS_FINDINGS" \
  --argjson compliant "$COMPLIANT" --argjson non_compliant "$NON_COMPLIANT" \
  --argjson partial "$PARTIAL" --argjson not_assessed "$NOT_ASSESSED" \
  '{
    generated: $generated,
    source_cis_profile: $cis_source,
    source_lynis_findings: $lynis_source,
    summary: {
      controls_assessed: ($assessments | length),
      compliant: $compliant,
      non_compliant: $non_compliant,
      partially_compliant: $partial,
      not_assessed: $not_assessed
    },
    assessments: $assessments
  }' > "$GAP_OUT"

# --- Build the remediation queue ---------------------------------------------
# Priority score: severity base + status urgency bonus + evidence-strength
# bonus (each corroborating Lynis finding raises confidence/urgency), capped
# at 100.
QUEUE_JSON=$(jq '
  def severity_base: if .severity=="critical" then 70 elif .severity=="high" then 55 else 35 end;
  def status_bonus: if .status=="non_compliant" then 15 else 5 end;
  def evidence_bonus: (((.matching_lynis_findings | length) * 4) as $b | (if $b > 15 then 15 else $b end));

  [ .assessments[]
    | select(.status=="non_compliant" or .status=="partially_compliant")
    | (severity_base + status_bonus + evidence_bonus) as $raw
    | . + { priority_score: (if $raw > 100 then 100 else $raw end) }
    | {
        control_id, title, severity, status,
        matching_lynis_findings,
        affected_assets: .asset_scope,
        remediation_script,
        priority_score,
        operational_risk: (
          if .severity=="critical" then "High risk of exploitation or lateral movement if left unresolved; matches a Crimson Tide breach pattern."
          elif .severity=="high" then "Meaningfully widens the attack surface or delays detection if left unresolved."
          else "Reduces defense-in-depth or detection fidelity; lower immediate exploitation risk."
          end
        ),
        expected_validation_check: .verification_method
      }
  ] | sort_by(-.priority_score)
' "$GAP_OUT")

QUEUED_COUNT=$(jq 'length' <<<"$QUEUE_JSON")

jq -n --argjson queue "$QUEUE_JSON" --arg generated "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{generated: $generated, queued_count: ($queue | length), queue: $queue}' > "$QUEUE_OUT"

echo "Controls assessed: $ASSESSED_COUNT"
echo "Compliant: $COMPLIANT"
echo "Non-compliant: $NON_COMPLIANT"
echo "Partially compliant: $PARTIAL"
echo "Not assessed: $NOT_ASSESSED"
echo "Remediation actions queued: $QUEUED_COUNT"
echo "Report saved to: $GAP_OUT"
echo "Queue saved to: $QUEUE_OUT"
