#!/bin/bash
#
# 13-dns_filtering.sh
#
# MedDefense Health Systems - Perimeter and Network Defense (2x04)
#
# DNS is the quietest attack surface on the network - almost never blocked,
# almost never inspected. T9 caught a long-label DNS query pointing at a
# probable tunneling session; this script cuts that channel off at the
# source with a local sinkhole, on the loopback only.
#
# Note: do not rewrite /etc/resolv.conf. This configures dnsmasq on the
# loopback only; routing traffic through it is a deployment decision left
# outside the scope of this project.
#
# Usage: sudo ./13-dns_filtering.sh

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
BLOCKLIST="/home/analyst/MedDefense_Lab/dns/blocklist.txt"
ALLOWLIST="/home/analyst/MedDefense_Lab/dns/allowlist.txt"
UPSTREAM_CONF="/etc/dnsmasq.d/meddefense-upstream.conf"
BLOCKLIST_CONF="/etc/dnsmasq.d/meddefense-blocklist.conf"

resolve_input() {
    local name="$1" candidate
    for candidate in "./${name}" "${SCRIPT_DIR}/${name}" "${SCRIPT_DIR}/../${name}"; do
        [ -f "$candidate" ] && { echo "$candidate"; return 0; }
    done
    echo "$name"
}
[ -f "$BLOCKLIST" ] || BLOCKLIST="$(resolve_input blocklist.txt)"
[ -f "$ALLOWLIST" ] || ALLOWLIST="$(resolve_input allowlist.txt)"

if [ ! -f "$UPSTREAM_CONF" ]; then
    local_conf="$(resolve_input meddefense-upstream.conf)"
    if [ -f "$local_conf" ]; then
        mkdir -p /etc/dnsmasq.d
        cp "$local_conf" "$UPSTREAM_CONF"
    else
        echo "error: cannot find $UPSTREAM_CONF (upstream resolver config shipped with the project)" >&2
        exit 1
    fi
fi
if [ ! -r "$BLOCKLIST" ]; then
    echo "error: cannot read $BLOCKLIST" >&2
    exit 1
fi

# --- Install (idempotent) ---------------------------------------------------
INSTALLED_BEFORE="already_installed"
if ! command -v dnsmasq >/dev/null 2>&1; then
    INSTALLED_BEFORE="not_installed"
    echo "[*] Installing dnsmasq..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y dnsmasq \
        -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold >/dev/null
fi
DNSMASQ_VERSION="$(dnsmasq --version 2>/dev/null | head -1 | awk '{print $3}')"
echo "[*] Ensuring dnsmasq is installed...     dnsmasq $DNSMASQ_VERSION"

# --- Render the blocklist fragment (always rewritten whole, never appended) -
DOMAIN_COUNT="$(grep -cve '^\s*$' -e '^\s*#' "$BLOCKLIST")"
{
    echo "# Managed by 13-dns_filtering.sh - MedDefense Health Systems."
    echo "# Do not edit by hand; source of truth is $BLOCKLIST."
    grep -v -e '^\s*$' -e '^\s*#' "$BLOCKLIST" | while IFS= read -r domain; do
        domain="$(echo "$domain" | tr -d '\r' | sed 's/^\s*//;s/\s*$//')"
        [ -z "$domain" ] && continue
        echo "address=/${domain}/0.0.0.0"
    done
} > "$BLOCKLIST_CONF"
echo "[*] Rendering blocklist...               ($DOMAIN_COUNT domains)"

# --- 20auto-listen / logging ---------------------------------------------
LOGGING_CONF="/etc/dnsmasq.d/meddefense-logging.conf"
{
    echo "# Managed by 13-dns_filtering.sh - MedDefense Health Systems."
    echo "listen-address=127.0.0.1"
    echo "bind-interfaces"
    echo "log-queries"
    echo "log-facility=/var/log/dnsmasq.log"
} > "$LOGGING_CONF"
touch /var/log/dnsmasq.log
chown syslog:adm /var/log/dnsmasq.log 2>/dev/null || true

# --- Restart and verify ------------------------------------------------
systemctl restart dnsmasq
sleep 1
DNSMASQ_STATE="$(systemctl is-active dnsmasq 2>/dev/null)"
echo "[*] Restarting dnsmasq.service...        $DNSMASQ_STATE"

# --- Validation queries -----------------------------------------------
echo "[*] Validation queries..."
VALIDATION_FILE="$(mktemp)"
trap 'rm -f "$VALIDATION_FILE"' EXIT
all_pass="true"

check_query() {
    local domain="$1" expectation="$2"
    local answer
    answer="$(dig @127.0.0.1 +short +time=3 +tries=1 "$domain" A 2>/dev/null | head -1)"
    local result="PASS"
    case "$expectation" in
        sinkhole)
            [ "$answer" != "0.0.0.0" ] && { result="FAIL"; all_pass="false"; }
            ;;
        allow)
            { [ -z "$answer" ] || [ "$answer" = "0.0.0.0" ]; } && { result="FAIL"; all_pass="false"; }
            ;;
    esac
    printf '  dig @127.0.0.1 %s\n      -> %-24s expected %-10s %s\n' "$domain" "${answer:-<no answer>}" "$expectation" "$result"
    jq -nc --arg d "$domain" --arg a "${answer:-}" --arg e "$expectation" --arg r "$result" \
        '{domain: $d, answer: $a, expected: $e, result: $r}' >> "$VALIDATION_FILE"
}

allow_domain="$(grep -v -e '^\s*$' -e '^\s*#' "$ALLOWLIST" | head -1)"
block_domain="$(grep -v -e '^\s*$' -e '^\s*#' "$BLOCKLIST" | head -1)"
unlisted_domain="ubuntu.com"
grep -qxF "$unlisted_domain" "$ALLOWLIST" 2>/dev/null && unlisted_domain="kernel.org"

[ -n "$allow_domain" ] && check_query "$allow_domain" allow
[ -n "$block_domain" ] && check_query "$block_domain" sinkhole
check_query "$unlisted_domain" allow

jq -s '.' "$VALIDATION_FILE" > dns_filtering_validation.json
jq -n --arg installed "$INSTALLED_BEFORE" --arg version "$DNSMASQ_VERSION" \
    --argjson domain_count "$DOMAIN_COUNT" --arg state "$DNSMASQ_STATE" \
    --slurpfile validations dns_filtering_validation.json \
    '{installed: $installed, dnsmasq_version: $version, blocklist_domain_count: $domain_count,
      service_state: $state, validations: $validations[0]}' > dns_filtering_result.json
cp dns_filtering_result.json dnsfilterreport.json

echo "Report saved to: dns_filtering_result.json (also written as dnsfilterreport.json)"
[ "$DNSMASQ_STATE" = "active" ] && [ "$all_pass" = "true" ]
