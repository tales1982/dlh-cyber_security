#!/bin/bash
#
# 7-apt_recovery.sh
#
# MedDefense Health Systems - The Patch Equation (2x03)
#
# billing-srv-01's leftover damage from Mike Torres's aborted `apt upgrade
# -y`: dpkg locked, apache2 half-configured. Recovery is a specific
# sequence - never the same command twice, never out of order. This script
# diagnoses first, refuses to touch anything if apt/dpkg is genuinely still
# running, then repairs in the one order that is actually safe.
#
# Usage: sudo ./7-apt_recovery.sh [output.json]

set -uo pipefail

OUT_JSON="${1:-apt_recovery.json}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
DEPMAP_JSON="$(
    for c in "./service_dependency_map.json" "${SCRIPT_DIR}/service_dependency_map.json" "${SCRIPT_DIR}/../service_dependency_map.json"; do
        [ -f "$c" ] && { echo "$c"; break; }
    done
)"

START_TS=$(date +%s)
LOCK_FILES=(/var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock)

# --- Diagnose -----------------------------------------------------------
echo "[*] Diagnosing..."

mapfile -t LIVE_PROCS < <(pgrep -fa '(^|/)(dpkg|apt-get|apt)( |$)' 2>/dev/null | grep -v "$$" | grep -vi "$0")
live_count="${#LIVE_PROCS[@]}"
echo "    live dpkg/apt processes: $([ "$live_count" -eq 0 ] && echo none || echo "$live_count")"

# The three lock files exist as empty placeholder files on every healthy
# Debian/Ubuntu system at all times - dpkg/apt flock() them, they are never
# deleted after use. Presence alone means nothing; what matters is whether a
# process currently HOLDS the lock. A lock file held by nobody (fuser finds
# no PID) while we already confirmed no live dpkg/apt process exists is what
# "stale" actually means here.
STALE_LOCKS=()
for lf in "${LOCK_FILES[@]}"; do
    [ -e "$lf" ] || continue
    holder="$(fuser "$lf" 2>/dev/null)"
    [ -z "$holder" ] && [ "$live_count" -eq 0 ] && STALE_LOCKS+=("$lf")
done
echo "    stale (unheld) lock files: ${STALE_LOCKS[*]:-none}"

AUDIT_OUT="$(dpkg --audit 2>&1)"
mapfile -t AUDIT_PKGS < <(dpkg --audit 2>/dev/null | grep -oE '^\s+[a-zA-Z0-9+.-]+' | awk '{print $1}')
echo "    dpkg --audit: ${AUDIT_PKGS[*]:-clean}"

# Any dpkg status flag other than ii (installed)/rc (removed, config kept)/
# un (unknown) is a broken package: half-configured, half-installed,
# unpacked or triggers-pending all show up here.
mapfile -t BROKEN_PKGS < <(dpkg -l 2>/dev/null | awk '$1 !~ /^(ii|rc|un)$/ && NR>5 {print $2}')
echo "    broken packages: ${#BROKEN_PKGS[@]}"

root_avail_kb="$(df -k / | awk 'NR==2{print $4}')"
var_avail_kb="$(df -k /var | awk 'NR==2{print $4}')"
echo "    free space: / = $((root_avail_kb / 1024))MB  /var = $((var_avail_kb / 1024))MB"

BROKEN_PKGS_JSON="$(printf '%s\n' "${BROKEN_PKGS[@]:-}" | jq -R . | jq -s 'map(select(length>0))')"
INITIAL_DIAGNOSIS="$(jq -n \
    --argjson live "$live_count" \
    --argjson locks "$(printf '%s\n' "${STALE_LOCKS[@]:-}" | jq -R . | jq -s 'map(select(length>0))')" \
    --arg audit "$AUDIT_OUT" \
    --argjson broken "$BROKEN_PKGS_JSON" \
    --argjson root_kb "$root_avail_kb" --argjson var_kb "$var_avail_kb" \
    '{live_processes: $live, lock_files_present: $locks, dpkg_audit_output: $audit,
      broken_packages: $broken, free_space_kb: {root: $root_kb, var: $var_kb}}')"

if [ "$live_count" -gt 0 ]; then
    echo "[!] Live dpkg/apt process detected - refusing to proceed"
    jq -n --argjson diag "$INITIAL_DIAGNOSIS" --arg reason "live process holds the lock" \
        '{initial_diagnosis: $diag, actions_taken: [], final_state: $diag,
          recovered: false, refused_reason: $reason, duration_seconds: 0}' > "$OUT_JSON"
    exit 2
fi

if [ "${#BROKEN_PKGS[@]}" -eq 0 ]; then
    echo "[*] Nothing to repair - system already clean."
    jq -n --argjson diag "$INITIAL_DIAGNOSIS" \
        '{initial_diagnosis: $diag, actions_taken: [], final_state: $diag, recovered: true, duration_seconds: 0}' > "$OUT_JSON"
    exit 0
fi

# --- Repair, in a strict, non-negotiable order -------------------------
echo "[*] Repairing..."
ACTIONS_FILE="$(mktemp)"
trap 'rm -f "$ACTIONS_FILE"' EXIT

log_action() {
    jq -nc --arg step "$1" --arg status "$2" --arg detail "${3:-}" \
        '{step: $step, status: $status, detail: $detail}' >> "$ACTIONS_FILE"
    printf '    %-38s %s\n' "$1" "$2"
}

# Locks are only removed here because the diagnosis above already proved no
# live process holds them - a lock file with a live owner is never stale.
for lf in "${STALE_LOCKS[@]:-}"; do
    [ -z "$lf" ] && continue
    if rm -f "$lf" 2>/dev/null; then
        log_action "remove stale lock $lf" "OK"
    else
        log_action "remove stale lock $lf" "FAILED"
    fi
done

if dpkg --configure -a >/tmp/dpkg_configure.$$ 2>&1; then
    log_action "dpkg --configure -a" "OK"
else
    log_action "dpkg --configure -a" "FAILED" "$(tail -c 500 /tmp/dpkg_configure.$$)"
fi
rm -f /tmp/dpkg_configure.$$

if DEBIAN_FRONTEND=noninteractive apt-get --fix-broken install -y \
    -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
    >/tmp/apt_fix.$$ 2>&1; then
    log_action "apt-get --fix-broken install" "OK"
else
    log_action "apt-get --fix-broken install" "FAILED" "$(tail -c 500 /tmp/apt_fix.$$)"
fi
rm -f /tmp/apt_fix.$$

FINAL_AUDIT="$(dpkg --audit 2>&1)"
if [ -z "$FINAL_AUDIT" ]; then
    log_action "dpkg --audit (re-run)" "clean"
    recovered="true"
else
    log_action "dpkg --audit (re-run)" "still broken"
    recovered="false"
fi

# --- Restart services owned by packages that were broken ---------------------
RESTARTED_JSON="[]"
if [ "$recovered" = "true" ] && [ -n "$DEPMAP_JSON" ] && [ -f "$DEPMAP_JSON" ] && [ "${#BROKEN_PKGS[@]}" -gt 0 ]; then
    echo "[*] Restarting affected services..."
    while IFS= read -r svc; do
        [ -z "$svc" ] && continue
        if systemctl try-restart "$svc" >/dev/null 2>&1; then
            state="$(systemctl show "$svc" -p ActiveState --value 2>/dev/null)"
        else
            state="failed"
        fi
        printf '    %-38s %s\n' "$svc" "$state"
        RESTARTED_JSON="$(jq -c --argjson r "$RESTARTED_JSON" --arg s "$svc" --arg st "$state" '$r + [{service: $s, state: $st}]' <<<'{}')"
    done < <(jq -r --argjson broken "$BROKEN_PKGS_JSON" \
        '[.[] | select(.owning_package as $o | $broken | index($o)) | .service] | unique[]' "$DEPMAP_JSON")
fi

FINAL_BROKEN_JSON="$(dpkg -l 2>/dev/null | awk '$1 !~ /^(ii|rc|un)$/ && NR>5 {print $2}' | jq -R . | jq -s 'map(select(length>0))')"
FINAL_STATE="$(jq -n --arg audit "$FINAL_AUDIT" --argjson broken "$FINAL_BROKEN_JSON" --argjson restarted "$RESTARTED_JSON" \
    '{dpkg_audit_output: $audit, broken_packages: $broken, services_restarted: $restarted}')"

END_TS=$(date +%s)
DURATION=$((END_TS - START_TS))

jq -n --argjson diag "$INITIAL_DIAGNOSIS" --slurpfile actions <(jq -s '.' "$ACTIONS_FILE") \
    --argjson final "$FINAL_STATE" --argjson recovered "$recovered" --argjson duration "$DURATION" \
    '{initial_diagnosis: $diag, actions_taken: $actions[0], final_state: $final,
      recovered: $recovered, duration_seconds: $duration}' > "$OUT_JSON"

echo "RECOVERED: $([ "$recovered" = "true" ] && echo yes || echo no)"
echo "Duration: ${DURATION}s"
echo "Report saved to: $OUT_JSON"

# Exit 0 on success, exit 1 on residual broken state.
if [ "$recovered" = "true" ]; then
    exit 0
else
    exit 1
fi
