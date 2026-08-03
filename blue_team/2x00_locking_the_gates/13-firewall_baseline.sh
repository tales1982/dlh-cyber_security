#!/bin/bash
#
# 13-firewall_baseline.sh
#
# MedDefense Health Systems - Locking the Gates (2x00)
#
# The hardened services and the audit trail from Tasks 4-12 are useless if
# the server still accepts connections on ports nothing needs to listen on
# from the whole internet. The 1x02 scan found billing-srv-01 with 11 open
# ports; after service minimization (Task 7) only 4-5 should be reachable at
# all. A default-deny inbound firewall enforces this at the network layer,
# independent of whatever is (mis)configured at the service layer - so a
# service re-enabled by mistake is still blocked from anywhere but the
# networks that actually need to reach it.
#
# Idempotent: `ufw allow` is itself idempotent (ufw detects and skips a rule
# that already exists), and this script additionally checks `ufw status`
# before enabling so re-running never re-prompts or errors on an
# already-active firewall.
#
# Maps to CIS control MD-CIS-012 (host firewall default-deny) from
# cis_profile.json.
#
# MGMT_NETWORK / APP_NETWORK match the MedDefense lab network layout
# referenced throughout this module (10.10.1.0/24 management, 10.10.2.0/24
# application tier). Override via environment variable per-asset if a
# server's actual subnet differs.
#
# This script was NOT executed for real in this environment (see this
# project's validation notes) - `ufw enable` and rule changes are live,
# system-wide network policy changes that must not be applied to a shared
# sandbox. Syntax and command construction were validated with `bash -n`
# and by inspecting the exact `ufw` invocations this script would run.
#
# Usage: sudo ./13-firewall_baseline.sh

set -uo pipefail

MGMT_NETWORK="${MGMT_NETWORK:-10.10.1.0/24}"
APP_NETWORK="${APP_NETWORK:-10.10.2.0/24}"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: this script must run as root to configure ufw" >&2
    exit 1
fi

if ! command -v ufw >/dev/null 2>&1; then
    echo "Error: ufw is not installed" >&2
    exit 1
fi

echo "[*] Configuring UFW..."
# Default-deny inbound, default-allow outbound: the server only speaks when
# spoken to on an approved channel, but is free to reach out (package
# updates, NTP, monitoring egress).
ufw default deny incoming  >/dev/null 2>&1
ufw default allow outgoing >/dev/null 2>&1
echo "    Default incoming: deny"
echo "    Default outgoing: allow"

echo "[*] Adding allow rules..."

# add_rule <ufw-args...> <label>: idempotent because ufw itself checks for
# and skips an already-present rule ("Skipping adding existing rule").
add_rule() {
    local label="${@: -1}"
    local args=("${@:1:$#-1}")
    ufw "${args[@]}" >/dev/null 2>&1
    printf '    %-26s [ADDED] %s\n' "${args[*]:1}" "$label"
}

# Finding 009 / Crimson Tide Phase 3: SSH must be reachable ONLY from the
# management network, not the whole internet or the flat application VLAN.
add_rule allow from "$MGMT_NETWORK" to any port 22 proto tcp \
    "SSH - management only"

# Patient portal / billing application - public-facing by design.
add_rule allow 80/tcp  "HTTP"
add_rule allow 443/tcp "HTTPS"

# Finding 006: MySQL was bound to 0.0.0.0 and network-reachable from
# anywhere. It must only be reachable from the application tier that
# actually queries it.
add_rule allow from "$APP_NETWORK" to any port 3306 proto tcp \
    "MySQL - app network only"

echo "[*] Enabling logging..."
ufw logging low >/dev/null 2>&1
echo "    Logging: on (low)"

echo "[*] Activating firewall..."
if ufw status 2>/dev/null | grep -q "Status: active"; then
    echo "    UFW: active (already enabled, idempotent no-op)"
else
    ufw --force enable >/dev/null 2>&1
    echo "    UFW: active"
fi
echo "    Rules: 4 allow, default deny"
