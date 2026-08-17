#!/bin/bash
#
# 10-version_hold.sh
#
# MedDefense Health Systems - The Patch Equation (2x03)
#
# A held package without a recorded reason becomes permanent by accident.
# This script is the ONLY thing allowed to change apt-mark holds and
# /etc/apt/preferences.d/meddefense-pins - every hold that exists on the
# system either has an entry in hold_registry.json with an owner and a
# review date, or it gets released. Convergence, not accumulation.
#
# Usage: sudo ./10-version_hold.sh [hold_registry.json] [output.json]

set -uo pipefail

REGISTRY_JSON="${1:-hold_registry.json}"
OUT_JSON="${2:-hold_management.json}"
PIN_FILE="/etc/apt/preferences.d/meddefense-pins"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

resolve_input() {
    local name="$1" candidate
    for candidate in "./${name}" "${SCRIPT_DIR}/${name}" "${SCRIPT_DIR}/../${name}"; do
        [ -f "$candidate" ] && { echo "$candidate"; return 0; }
    done
    echo "$name"
}
[ -f "$REGISTRY_JSON" ] || REGISTRY_JSON="$(resolve_input hold_registry.json)"

if [ ! -r "$REGISTRY_JSON" ]; then
    echo "error: cannot read $REGISTRY_JSON" >&2
    exit 1
fi
if ! jq empty "$REGISTRY_JSON" 2>/dev/null; then
    echo "error: invalid JSON in $REGISTRY_JSON" >&2
    exit 1
fi

mapfile -t REGISTRY_PKGS < <(jq -r '.holds[].package' "$REGISTRY_JSON")
mapfile -t CURRENT_HOLDS < <(apt-mark showhold 2>/dev/null)
echo "[*] Reading $REGISTRY_JSON...           (${#REGISTRY_PKGS[@]} entries)"
echo "[*] Reading current apt-mark showhold...    (${#CURRENT_HOLDS[@]} entries)"

APPLIED_FILE="$(mktemp)"
RELEASED_FILE="$(mktemp)"
OVERDUE_FILE="$(mktemp)"
PIN_BODY_FILE="$(mktemp)"
trap 'rm -f "$APPLIED_FILE" "$RELEASED_FILE" "$OVERDUE_FILE" "$PIN_BODY_FILE"' EXIT

TODAY_EPOCH="$(date -u -d "$(date -u +%F)" +%s)"

echo "Applying holds:"
while IFS=$'\t' read -r pkg reason owner review_date pin_version; do
    [ -z "$pkg" ] && continue

    hold_ok="false"
    apt-mark hold "$pkg" >/dev/null 2>&1 && hold_ok="true"

    {
        echo "Package: $pkg"
        echo "Pin: version $pin_version"
        echo "Pin-Priority: 1001"
        echo ""
    } >> "$PIN_BODY_FILE"

    review_epoch="$(date -u -d "$review_date" +%s 2>/dev/null || echo "$TODAY_EPOCH")"
    days_to_review=$(( (review_epoch - TODAY_EPOCH) / 86400 ))

    printf '  %-24s hold + pin %-30s %s\n' "$pkg" "$pin_version" "$([ "$hold_ok" = "true" ] && echo OK || echo FAILED)"

    jq -nc --arg pkg "$pkg" --arg reason "$reason" --arg owner "$owner" \
        --arg review_date "$review_date" --arg pin_version "$pin_version" \
        --argjson days "$days_to_review" --argjson ok "$hold_ok" \
        '{package: $pkg, reason: $reason, owner: $owner, review_date: $review_date,
          pin_version: $pin_version, days_to_review: $days, hold_applied: $ok}' >> "$APPLIED_FILE"

    if [ "$days_to_review" -lt 0 ]; then
        jq -nc --arg pkg "$pkg" --arg owner "$owner" --arg review_date "$review_date" --argjson days "$days_to_review" \
            '{package: $pkg, owner: $owner, review_date: $review_date, days_overdue: (-$days)}' >> "$OVERDUE_FILE"
    fi
done < <(jq -r '.holds[] | [.package, .reason, .owner, .review_date, .pin_version] | @tsv' "$REGISTRY_JSON")

# --- Write the pin fragment as one deterministic file, not an append -------
{
    echo "# Managed by 10-version_hold.sh - MedDefense Health Systems."
    echo "# Do not edit by hand; the only writer is hold_registry.json + this script."
    echo ""
    cat "$PIN_BODY_FILE"
} > "$PIN_FILE"

# --- Convergence: release any hold not in the registry -----------------------
echo "Releasing holds no longer in registry:"
released_any="false"
for held in "${CURRENT_HOLDS[@]:-}"; do
    [ -z "$held" ] && continue
    if ! printf '%s\n' "${REGISTRY_PKGS[@]}" | grep -qxF "$held"; then
        released_any="true"
        release_ok="false"
        apt-mark unhold "$held" >/dev/null 2>&1 && release_ok="true"
        printf '  %-24s %s\n' "$held" "$([ "$release_ok" = "true" ] && echo released || echo FAILED)"
        jq -nc --arg pkg "$held" --argjson ok "$release_ok" '{package: $pkg, released: $ok}' >> "$RELEASED_FILE"
    fi
done
[ "$released_any" = "false" ] && echo "  (none)"

overdue_count="$(wc -l < "$OVERDUE_FILE" | tr -d ' ')"
total_held="$(apt-mark showhold 2>/dev/null | wc -l | tr -d ' ')"

jq -n \
    --slurpfile applied <(jq -s '.' "$APPLIED_FILE") \
    --slurpfile released <(jq -s '.' "$RELEASED_FILE") \
    --slurpfile overdue <(jq -s '.' "$OVERDUE_FILE") \
    --argjson total_held "$total_held" \
    '{applied: $applied[0], released: $released[0], overdue_reviews: $overdue[0], total_held: $total_held}' > "$OUT_JSON"

echo "Overdue reviews: $overdue_count"
echo "Report saved to: $OUT_JSON"
