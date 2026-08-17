#!/bin/bash
#
# 5-post_patch_validate.sh
#
# MedDefense Health Systems - The Patch Equation (2x03)
#
# An apt command that exits 0 proves nothing on its own. This script closes
# the loop: compare the live system against the pre-patch snapshot (T2) and
# run liveness probes on every critical service, so "the patch ran" and
# "the patch is safe" stop being the same claim.
#
# Read-only. This script makes no configuration changes to the system.
#
# Usage: sudo ./5-post_patch_validate.sh [pre_patch_state.json] [output.json]

set -uo pipefail

PRE_JSON="${1:-pre_patch_state.json}"
OUT_JSON="${2:-post_patch_validation.json}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

resolve_input() {
    local name="$1" candidate
    for candidate in "./${name}" "${SCRIPT_DIR}/${name}" "${SCRIPT_DIR}/../${name}"; do
        [ -f "$candidate" ] && { echo "$candidate"; return 0; }
    done
    echo "$name"
}
[ -f "$PRE_JSON" ] || PRE_JSON="$(resolve_input pre_patch_state.json)"
DEPMAP_JSON="$(resolve_input service_dependency_map.json)"
PROBES_JSON="$(resolve_input service_probes.json)"

if [ ! -r "$PRE_JSON" ]; then
    echo "error: cannot read $PRE_JSON (run 2-pre_patch_snapshot.sh first)" >&2
    exit 1
fi

DETAILS_FILE="$(mktemp)"
trap 'rm -f "$DETAILS_FILE"' EXIT

add_detail() {
    jq -nc --arg t "$1" --arg target "$2" --arg status "$3" --arg note "${4:-}" \
        '{check_type: $t, target: $target, status: $status, note: $note}' >> "$DETAILS_FILE"
}

# --- 1. Service state checks -------------------------------------------------
svc_pass=0; svc_total=0
while IFS=$'\t' read -r svc pre_state; do
    [ -z "$svc" ] && continue
    svc_total=$((svc_total + 1))
    cur_state="$(systemctl show "$svc" -p ActiveState --value 2>/dev/null || echo "unknown")"
    if [ "$cur_state" = "active" ] || { [ "$pre_state" != "active" ] && [ "$cur_state" = "$pre_state" ]; }; then
        add_detail "service_state" "$svc" "pass" "was=$pre_state now=$cur_state"
        svc_pass=$((svc_pass + 1))
    else
        add_detail "service_state" "$svc" "regression" "was=$pre_state now=$cur_state"
    fi
done < <(jq -r '.services // {} | to_entries[] | "\(.key)\t\(.value.active_state)"' "$PRE_JSON")

# --- 2. Listening socket checks ----------------------------------------------
mapfile -t CURRENT_LISTENING < <(ss -tulnH 2>/dev/null | awk '{print $1, $5}' | sort -u)
sock_pass=0; sock_total=0
while IFS=$'\t' read -r proto addr; do
    [ -z "$proto" ] && continue
    sock_total=$((sock_total + 1))
    target="$proto $addr"
    if printf '%s\n' "${CURRENT_LISTENING[@]}" | grep -qxF "$target"; then
        add_detail "listening_socket" "$target" "pass"
        sock_pass=$((sock_pass + 1))
    else
        add_detail "listening_socket" "$target" "regression" "no longer listening"
    fi
done < <(jq -r '.listening // [] | .[] | "\(.proto)\t\(.local_address)"' "$PRE_JSON")

# --- 3. Critical-service liveness probes -------------------------------------
run_probe() {
    local type="$1" target="$2"
    case "$type" in
        http) curl -fsS --max-time 5 -o /dev/null "$target" ;;
        tcp)
            local host="${target%:*}" port="${target##*:}"
            timeout 5 bash -c "exec 3<>/dev/tcp/${host}/${port}" 2>/dev/null ;;
        command) timeout 10 bash -c "$target" >/dev/null 2>&1 ;;
        *) return 3 ;;
    esac
}

probe_pass=0; probe_total=0
if [ -f "$DEPMAP_JSON" ] && [ -f "$PROBES_JSON" ]; then
    while IFS= read -r svc; do
        [ -z "$svc" ] && continue
        probe_total=$((probe_total + 1))
        type="$(jq -r --arg s "$svc" '.[$s].type // empty' "$PROBES_JSON")"
        target="$(jq -r --arg s "$svc" '.[$s].target // empty' "$PROBES_JSON")"
        if [ -z "$type" ]; then
            add_detail "liveness_probe" "$svc" "probe_failed" "no probe defined in service_probes.json"
            continue
        fi
        if run_probe "$type" "$target"; then
            add_detail "liveness_probe" "$svc ($type: $target)" "pass"
            probe_pass=$((probe_pass + 1))
        else
            add_detail "liveness_probe" "$svc ($type: $target)" "probe_failed"
        fi
    done < <(jq -r '.[] | select(.criticality=="critical") | .service' "$DEPMAP_JSON")
fi

# --- Assemble -----------------------------------------------------------
jq -s \
    --argjson svc_total "$svc_total" --argjson svc_pass "$svc_pass" \
    --argjson sock_total "$sock_total" --argjson sock_pass "$sock_pass" \
    --argjson probe_total "$probe_total" --argjson probe_pass "$probe_pass" \
    '{
      total_checks: ($svc_total + $sock_total + $probe_total),
      passed: ($svc_pass + $sock_pass + $probe_pass),
      failed: (($svc_total + $sock_total + $probe_total) - ($svc_pass + $sock_pass + $probe_pass)),
      service_state_checks: {total: $svc_total, passed: $svc_pass},
      listening_socket_checks: {total: $sock_total, passed: $sock_pass},
      liveness_probe_checks: {total: $probe_total, passed: $probe_pass},
      details: .
    }' "$DETAILS_FILE" > "$OUT_JSON"

# --- Human-readable summary --------------------------------------------------
total="$(jq '.total_checks' "$OUT_JSON")"
passed="$(jq '.passed' "$OUT_JSON")"
echo "Service state checks:     ${svc_pass}/${svc_total}   $([ "$svc_pass" -eq "$svc_total" ] && echo PASS || echo FAIL)"
echo "Listening socket checks:  ${sock_pass}/${sock_total}   $([ "$sock_pass" -eq "$sock_total" ] && echo PASS || echo FAIL)"
echo "Critical liveness probes: ${probe_pass}/${probe_total}   $([ "$probe_pass" -eq "$probe_total" ] && echo PASS || echo FAIL)"
if [ "$passed" -eq "$total" ]; then
    echo "VERDICT: PASS ($passed/$total)"
else
    echo "VERDICT: FAIL ($passed/$total)"
fi
echo "Report saved to: $OUT_JSON"

[ "$passed" -eq "$total" ]
