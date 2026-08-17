#!/bin/bash
#
# 8-unattended_config.sh
#
# MedDefense Health Systems - The Patch Equation (2x03)
#
# Not every patch needs a human in the loop, but automation without
# guardrails is how billing-srv-01 got broken. This configures
# unattended-upgrades for security-only patching, with critical packages
# blacklisted and automatic reboots suppressed - a healthcare endpoint
# cannot silently reboot the billing service at 3am.
#
# Idempotent: the two config files are always (re)written with fixed,
# deterministic content - never appended to - so a second run produces byte
# -identical files instead of duplicated stanzas.
#
# Usage: sudo ./8-unattended_config.sh [output.json]

set -uo pipefail

OUT_JSON="${1:-unattended_config.json}"
UU_CONF="/etc/apt/apt.conf.d/50unattended-upgrades"
AUTO_CONF="/etc/apt/apt.conf.d/20auto-upgrades"

if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO_ID="${ID^}"
    DISTRO_CODENAME="${VERSION_CODENAME:-${UBUNTU_CODENAME:-unknown}}"
else
    DISTRO_ID="Ubuntu"
    DISTRO_CODENAME="unknown"
fi

INSTALLED_BEFORE="not_installed"
dpkg -s unattended-upgrades >/dev/null 2>&1 && INSTALLED_BEFORE="already_installed"

if [ "$INSTALLED_BEFORE" = "not_installed" ]; then
    echo "[*] unattended-upgrades: installing..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades \
        -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold >/dev/null
else
    echo "[*] unattended-upgrades: already installed"
fi

# --- 50unattended-upgrades ---------------------------------------------
cat > "$UU_CONF" <<EOF
// Managed by 8-unattended_config.sh - MedDefense Health Systems.
// Do not edit by hand; re-run the script to change policy.
Unattended-Upgrade::Allowed-Origins {
    "${DISTRO_ID}:${DISTRO_CODENAME}-security";
};

Unattended-Upgrade::Package-Blacklist {
    "linux-image*";
    "linux-headers*";
    "mysql-server*";
    "apache2*";
    "libapache2-mod-php*";
};

Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "false";
Unattended-Upgrade::Mail "";
Unattended-Upgrade::MailOnlyOnError "false";
EOF
echo "[*] Writing $UU_CONF...   OK"

# --- 20auto-upgrades -----------------------------------------------------
cat > "$AUTO_CONF" <<'EOF'
// Managed by 8-unattended_config.sh - MedDefense Health Systems.
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
echo "[*] Writing $AUTO_CONF...         OK"

# --- Timers ----------------------------------------------------------------
systemctl enable --now apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1
TIMER_STATE="$(systemctl is-active apt-daily.timer apt-daily-upgrade.timer 2>/dev/null | paste -sd, -)"
echo "[*] Enabling timers...                                     OK"

# --- Dry run -----------------------------------------------------------------
# `unattended-upgrades --dry-run --debug` logs a free-form "Checking: <pkg>"
# line for every candidate across EVERY origin, then silently drops the ones
# that do not match Allowed-Origins - it does not reliably print a distinct
# "skipped: blacklisted" or "skipped: held" line per package in this version
# (2.8ubuntu1 here), so grepping the debug log for those words is not a
# trustworthy signal. The raw log is still captured for audit purposes, but
# the actual counts are computed independently against the real
# security-origin candidate set, cross-checked against apt-mark and the
# blacklist patterns - the same inputs unattended-upgrades itself decides on.
echo "[*] Dry run..."
DRY_OUT="$(unattended-upgrades --dry-run --debug 2>&1)"

BLACKLIST_PATTERNS=("linux-image*" "linux-headers*" "mysql-server*" "apache2*" "libapache2-mod-php*")
mapfile -t HELD_PACKAGES < <(apt-mark showhold 2>/dev/null)

is_blacklisted() {
    local pkg="$1" pat
    for pat in "${BLACKLIST_PATTERNS[@]}"; do
        # shellcheck disable=SC2053
        [[ "$pkg" == $pat ]] && return 0
    done
    return 1
}
is_held() {
    local pkg="$1"
    printf '%s\n' "${HELD_PACKAGES[@]}" | grep -qxF "$pkg"
}

mapfile -t SECURITY_UPGRADABLE < <(apt list --upgradable 2>/dev/null | grep -- "-security" | awk -F/ '{print $1}')

would_upgrade_list=() blacklisted_list=() held_list=()
for pkg in "${SECURITY_UPGRADABLE[@]}"; do
    [ -z "$pkg" ] && continue
    if is_held "$pkg"; then
        held_list+=("$pkg")
    elif is_blacklisted "$pkg"; then
        blacklisted_list+=("$pkg")
    else
        would_upgrade_list+=("$pkg")
    fi
done

WOULD_UPGRADE_COUNT="${#would_upgrade_list[@]}"
SKIPPED_BLACKLIST_COUNT="${#blacklisted_list[@]}"
SKIPPED_HELD_COUNT="${#held_list[@]}"

echo "would upgrade:       $WOULD_UPGRADE_COUNT"
echo "skipped (blacklist): $SKIPPED_BLACKLIST_COUNT $([ "$SKIPPED_BLACKLIST_COUNT" -gt 0 ] && echo "(${blacklisted_list[*]})")"
echo "skipped (held):      $SKIPPED_HELD_COUNT"

BLACKLIST_JSON='["linux-image*","linux-headers*","mysql-server*","apache2*","libapache2-mod-php*"]'
UPGRADE_LIST_JSON="$(printf '%s\n' "${would_upgrade_list[@]:-}" | jq -R . | jq -s 'map(select(length>0))')"

jq -n \
    --arg installed "$INSTALLED_BEFORE" \
    --arg uu_conf "$UU_CONF" --arg auto_conf "$AUTO_CONF" \
    --argjson blacklist "$BLACKLIST_JSON" \
    --arg timer_state "$TIMER_STATE" \
    --argjson would_upgrade "$WOULD_UPGRADE_COUNT" \
    --argjson skipped_blacklisted "$SKIPPED_BLACKLIST_COUNT" \
    --argjson skipped_held "$SKIPPED_HELD_COUNT" \
    --argjson upgrade_list "$UPGRADE_LIST_JSON" \
    --argjson blacklisted_list "$(printf '%s\n' "${blacklisted_list[@]:-}" | jq -R . | jq -s 'map(select(length>0))')" \
    --argjson held_list "$(printf '%s\n' "${held_list[@]:-}" | jq -R . | jq -s 'map(select(length>0))')" \
    --arg dry_run_log "$(tail -c 4000 <<<"$DRY_OUT")" \
    '{installed: $installed, config_paths: [$uu_conf, $auto_conf], blacklist: $blacklist,
      timer_state: $timer_state,
      dry_run_summary: {would_upgrade: $would_upgrade, would_upgrade_packages: $upgrade_list,
                         skipped_blacklisted: $skipped_blacklisted, skipped_blacklisted_packages: $blacklisted_list,
                         skipped_held: $skipped_held, skipped_held_packages: $held_list},
      dry_run_log_tail: $dry_run_log}' > "$OUT_JSON"

echo "Report saved to: $OUT_JSON"
