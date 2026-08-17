#!/bin/bash
#
# 9-rollback.sh
#
# MedDefense Health Systems - The Patch Equation (2x03)
#
# Every patch this pipeline applies must be reversible - not as a runbook
# entry someone reads at 03:00, but as a script that takes a package name
# and returns it to the exact version recorded before the patch ran.
#
# Usage: sudo ./9-rollback.sh <package> [pre_patch_state.json]

set -uo pipefail

PKG="${1:-}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

resolve_input() {
    local name="$1" candidate
    for candidate in "./${name}" "${SCRIPT_DIR}/${name}" "${SCRIPT_DIR}/../${name}"; do
        [ -f "$candidate" ] && { echo "$candidate"; return 0; }
    done
    echo "$name"
}

if [ -z "$PKG" ]; then
    echo "usage: $0 <package> [pre_patch_state.json]" >&2
    exit 1
fi

PRE_JSON="${2:-$(resolve_input pre_patch_state.json)}"
DEPMAP_JSON="$(resolve_input service_dependency_map.json)"
PROBES_JSON="$(resolve_input service_probes.json)"

if [ ! -r "$PRE_JSON" ]; then
    echo "error: cannot read $PRE_JSON (run 2-pre_patch_snapshot.sh first)" >&2
    exit 1
fi

TARGET_VERSION="$(jq -r --arg p "$PKG" '.packages[$p] // empty' "$PRE_JSON")"
if [ -z "$TARGET_VERSION" ]; then
    echo "error: '$PKG' not found in $PRE_JSON - no pre-patch version on record, cannot roll back" >&2
    exit 1
fi
echo "[*] Target version from $PRE_JSON: $TARGET_VERSION"

CURRENT_VERSION="$(dpkg-query -W -f='${Version}' "$PKG" 2>/dev/null || echo "not_installed")"

# --- Confirm the target version is actually obtainable ----------------------
AVAILABLE="false"
if apt-cache madison "$PKG" 2>/dev/null | awk '{print $3}' | grep -qxF "$TARGET_VERSION"; then
    AVAILABLE="true"
fi
echo "[*] Version available in cache or repository: $([ "$AVAILABLE" = "true" ] && echo yes || echo no)"

if [ "$AVAILABLE" != "true" ]; then
    echo "ROLLBACK: failed (target version not obtainable)"
    exit 1
fi

# --- Downgrade ----------------------------------------------------------
echo "[*] Downgrading $PKG..."
DOWNGRADE_OK="false"
if DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades \
    -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
    "${PKG}=${TARGET_VERSION}" >/tmp/rollback_apt.$$ 2>&1; then
    DOWNGRADE_OK="true"
    echo "                                                             OK"
else
    echo "                                                             FAILED"
    tail -20 /tmp/rollback_apt.$$ >&2
fi
rm -f /tmp/rollback_apt.$$

if [ "$DOWNGRADE_OK" != "true" ]; then
    echo "ROLLBACK: failed"
    exit 1
fi

# --- Hold, so unattended-upgrades does not immediately undo this -----------
HOLD_OK="false"
if apt-mark hold "$PKG" >/dev/null 2>&1; then
    HOLD_OK="true"
    echo "[*] apt-mark hold $PKG                                       OK"
else
    echo "[*] apt-mark hold $PKG                                       FAILED"
fi

# --- Re-probe every service linked to this package --------------------------
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

echo "[*] Re-running probes for affected services..."
PROBE_RESULTS="[]"
ALL_PROBES_OK="true"
if [ -f "$DEPMAP_JSON" ] && [ -f "$PROBES_JSON" ]; then
    while IFS= read -r svc; do
        [ -z "$svc" ] && continue
        type="$(jq -r --arg s "$svc" '.[$s].type // empty' "$PROBES_JSON")"
        target="$(jq -r --arg s "$svc" '.[$s].target // empty' "$PROBES_JSON")"
        [ -z "$type" ] && continue
        if run_probe "$type" "$target"; then
            result="pass"
        else
            result="fail"
            ALL_PROBES_OK="false"
        fi
        printf '    %-38s %s\n' "$svc probe" "$([ "$result" = "pass" ] && echo PASS || echo FAIL)"
        PROBE_RESULTS="$(jq -c --argjson r "$PROBE_RESULTS" --arg s "$svc" --arg res "$result" '$r + [{service: $s, result: $res}]' <<<'{}')"
    done < <(jq -r --arg pkg "$PKG" \
        '[.[] | select(.linked_packages // [] | index($pkg) != null) | .service] | unique[]' "$DEPMAP_JSON")
fi

SUCCESS="false"
[ "$DOWNGRADE_OK" = "true" ] && [ "$HOLD_OK" = "true" ] && [ "$ALL_PROBES_OK" = "true" ] && SUCCESS="true"

jq -n \
    --arg package "$PKG" --arg current_before "$CURRENT_VERSION" --arg target "$TARGET_VERSION" \
    --argjson available "$AVAILABLE" --argjson downgrade_ok "$DOWNGRADE_OK" --argjson hold_ok "$HOLD_OK" \
    --argjson probes "$PROBE_RESULTS" --argjson success "$SUCCESS" \
    '{package: $package, version_before: $current_before, version_target: $target,
      version_confirmed_available: $available, downgrade_succeeded: $downgrade_ok,
      hold_applied: $hold_ok, affected_service_probes: $probes, success: $success}' > rollback_result.json

echo "ROLLBACK: $([ "$SUCCESS" = "true" ] && echo success || echo failed)"
echo "from $CURRENT_VERSION to $TARGET_VERSION"

# Exit 0 only if downgrade, hold, and all affected service probes succeeded; exit 1 otherwise.
if [ "$SUCCESS" = "true" ]; then
    exit 0
else
    exit 1
fi
