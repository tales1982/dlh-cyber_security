#!/bin/bash
#
# 1-attack_surface.sh
#
# MedDefense Health Systems - Perimeter and Network Defense (2x04)
#
# The baseline (T0) says which ports are open. It does not say which ones
# should be. This script tags every listener with what it actually is
# (function, criticality) and flags the ones that never belong on an
# open interface - a database or RPC service on 0.0.0.0, or any protocol
# that ships credentials or data in cleartext.
#
# Read-only. This script makes no configuration changes to the system.
#
# Usage: sudo ./1-attack_surface.sh [network_baseline.json] [output.json]

set -uo pipefail

BASELINE_JSON="${1:-network_baseline.json}"
OUT_JSON="${2:-attack_surface.json}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

resolve_input() {
    local name="$1" candidate
    for candidate in "./${name}" "${SCRIPT_DIR}/${name}" "${SCRIPT_DIR}/../${name}"; do
        [ -f "$candidate" ] && { echo "$candidate"; return 0; }
    done
    echo "$name"
}
[ -f "$BASELINE_JSON" ] || BASELINE_JSON="$(resolve_input network_baseline.json)"
CATALOG_JSON="$(resolve_input service_catalog.json)"
CRITICALITY_JSON="$(resolve_input service_criticality.json)"

if [ ! -r "$BASELINE_JSON" ]; then
    echo "error: cannot read $BASELINE_JSON (run 0-network_baseline.sh first)" >&2
    exit 1
fi

HOSTNAME_VAL="$(hostname)"
GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
INSECURE_FUNCTIONS=(telnet ftp snmpv1 snmpv2c rlogin nfsv2 nfsv3)

is_insecure_function() {
    local fn="$1" f
    for f in "${INSECURE_FUNCTIONS[@]}"; do
        [ "$fn" = "$f" ] && return 0
    done
    return 1
}

owning_package() {
    local exec_path="$1" line pkg
    [ -z "$exec_path" ] && { echo "unknown"; return; }
    line="$(dpkg -S "$exec_path" 2>/dev/null | grep -v '^diversion by ' | head -1)"
    pkg="${line%%: *}"; pkg="${pkg%%,*}"; pkg="${pkg%%:*}"
    echo "${pkg:-unknown}"
}

unit_for_pid() {
    local pid="$1"
    [ -z "$pid" ] || [ "$pid" = "null" ] || [ ! -r "/proc/$pid/cgroup" ] && { echo "null"; return; }
    grep -oE '[a-zA-Z0-9@._-]+\.service' "/proc/$pid/cgroup" 2>/dev/null | head -1
}

function_for() {
    local proc="$1"
    jq -r --arg p "$proc" '.[$p] // "unknown"' "$CATALOG_JSON" 2>/dev/null
}
criticality_for() {
    local proc="$1"
    jq -r --arg p "$proc" '.[$p] // "low"' "$CRITICALITY_JSON" 2>/dev/null
}

RESULTS_FILE="$(mktemp)"
trap 'rm -f "$RESULTS_FILE"' EXIT

flagged_critical=0; flagged_high=0; flagged_medium=0; unknown_count=0

while IFS= read -r sock; do
    proto="$(jq -r '.proto' <<<"$sock")"
    bind_addr="$(jq -r '.bind_addr' <<<"$sock")"
    port="$(jq -r '.port' <<<"$sock")"
    proc="$(jq -r '.process' <<<"$sock")"
    pid="$(jq -r '.pid' <<<"$sock")"

    exec_path=""
    [ "$pid" != "null" ] && [ -n "$pid" ] && exec_path="$(readlink -f "/proc/$pid/exe" 2>/dev/null)"
    package="$(owning_package "$exec_path")"

    unit="null"
    [ -n "$exec_path" ] && unit="$(unit_for_pid "$pid")"
    [ -z "$unit" ] && unit="null"

    fn="$(function_for "$proc")"
    [ "$fn" = "unknown" ] && unknown_count=$((unknown_count + 1))
    criticality="$(criticality_for "$proc")"

    # The rule is a compound OR, not "flag every 0.0.0.0 bind": sshd and
    # apache2 on 0.0.0.0 are normal and must NOT be flagged just for that -
    # only database/rpc bound wide-open, or an inherently insecure protocol
    # regardless of bind address, count as exposure here.
    flags=()
    is_bound_any="false"
    case "$bind_addr" in
        0.0.0.0|\*|\[::\]|::) is_bound_any="true" ;;
    esac
    if [ "$is_bound_any" = "true" ] && [ "$fn" = "database" ]; then
        flags+=("bound_0.0.0.0" "database_exposed")
    fi
    if [ "$is_bound_any" = "true" ] && [ "$fn" = "rpc" ]; then
        flags+=("bound_0.0.0.0" "rpc_exposed")
    fi
    if is_insecure_function "$fn"; then
        flags+=("insecure_protocol_${fn}")
    fi

    flags_json="$(printf '%s\n' "${flags[@]:-}" | jq -R . | jq -s 'map(select(length>0))')"

    case "$criticality" in
        critical) [ "$(jq 'length' <<<"$flags_json")" -gt 0 ] && flagged_critical=$((flagged_critical + 1)) ;;
        high) [ "$(jq 'length' <<<"$flags_json")" -gt 0 ] && flagged_high=$((flagged_high + 1)) ;;
        medium) [ "$(jq 'length' <<<"$flags_json")" -gt 0 ] && flagged_medium=$((flagged_medium + 1)) ;;
    esac

    unit_json="null"
    [ "$unit" != "null" ] && unit_json="\"$unit\""

    jq -nc \
        --arg proto "$proto" --argjson port "$([ "$port" != "null" ] && [[ "$port" =~ ^[0-9]+$ ]] && echo "$port" || echo "null")" \
        --arg port_raw "$port" --arg bind_addr "$bind_addr" --arg process "$proc" \
        --arg package "$package" --argjson unit "$unit_json" --arg function "$fn" \
        --arg criticality "$criticality" --argjson exposure_flags "$flags_json" \
        '{proto: $proto, port: ($port // $port_raw), bind_addr: $bind_addr, process: $process,
          package: $package, systemd_unit: $unit, function: $function, criticality: $criticality,
          exposure_flags: $exposure_flags}' >> "$RESULTS_FILE"
done < <(jq -c '.listening_sockets[]' "$BASELINE_JSON")

TOTAL="$(wc -l < "$RESULTS_FILE" | tr -d ' ')"
FLAGGED_TOTAL="$(jq -s '[.[] | select((.exposure_flags | length) > 0)] | length' "$RESULTS_FILE")"

jq -s \
    --arg generated_at "$GENERATED_AT" --arg hostname "$HOSTNAME_VAL" \
    --argjson total "$TOTAL" --argjson flagged "$FLAGGED_TOTAL" \
    --argjson fc "$flagged_critical" --argjson fh "$flagged_high" --argjson fm "$flagged_medium" \
    --argjson unknown "$unknown_count" \
    '{generated_at: $generated_at, hostname: $hostname, sockets: .,
      summary: {total_sockets: $total, flagged: $flagged,
                flagged_by_criticality: {critical: $fc, high: $fh, medium: $fm},
                unknown_function: $unknown}}' "$RESULTS_FILE" > "$OUT_JSON"

echo "Sockets classified: $TOTAL"
echo "Flagged: $FLAGGED_TOTAL (critical: $flagged_critical, high: $flagged_high, medium: $flagged_medium)"
echo "Unknown function: $unknown_count"
echo "Report saved to: $OUT_JSON"
