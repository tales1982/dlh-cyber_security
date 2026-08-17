#!/bin/bash
#
# 6-config_drift.sh
#
# MedDefense Health Systems - The Patch Equation (2x03)
#
# Patches ship new config defaults. Most of the time apt keeps the admin's
# version, but sometimes an auxiliary /etc file changes anyway - silently
# reintroducing a setting that was hardened in project 2x00. This script
# finds every file that moved and separates "the package I just patched did
# this on purpose" from "something else touched this file".
#
# Design note: T2 (pre_patch_snapshot) only records a SHA-256 per conffile,
# not its content - there is nothing to diff against on the very first drift
# a file ever shows. This script keeps its own content cache
# (./conffile_baseline/) of every file last seen matching its T2 hash, and
# only produces a real unified diff once a second "known good" copy exists
# to compare against. Until then it says so explicitly instead of pretending.
#
# Read-only against the system; only writes into its own baseline cache dir.
#
# Usage: sudo ./6-config_drift.sh [pre_patch_state.json] [patch_execution_log.json] [output.json]

set -uo pipefail

PRE_JSON="${1:-pre_patch_state.json}"
EXEC_LOG_JSON="${2:-patch_execution_log.json}"
OUT_JSON="${3:-config_drift.json}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
CACHE_DIR="${CACHE_DIR:-${SCRIPT_DIR}/conffile_baseline}"

resolve_input() {
    local name="$1" candidate
    for candidate in "./${name}" "${SCRIPT_DIR}/${name}" "${SCRIPT_DIR}/../${name}"; do
        [ -f "$candidate" ] && { echo "$candidate"; return 0; }
    done
    echo "$name"
}
[ -f "$PRE_JSON" ] || PRE_JSON="$(resolve_input pre_patch_state.json)"
[ -f "$EXEC_LOG_JSON" ] || EXEC_LOG_JSON="$(resolve_input patch_execution_log.json)"

if [ ! -r "$PRE_JSON" ]; then
    echo "error: cannot read $PRE_JSON (run 2-pre_patch_snapshot.sh first)" >&2
    exit 1
fi
mkdir -p "$CACHE_DIR"

# Packages this run actually touched successfully - used to label drift
# "expected" vs "unexpected".
PATCHED_PACKAGES_JSON="[]"
if [ -r "$EXEC_LOG_JSON" ]; then
    PATCHED_PACKAGES_JSON="$(jq -c '[.entries[]? | select(.status=="ok") | .package]' "$EXEC_LOG_JSON")"
fi

owning_package() {
    local line pkg
    line="$(dpkg -S "$1" 2>/dev/null | grep -v '^diversion by ' | head -1)"
    pkg="${line%%: *}"
    pkg="${pkg%%,*}"
    pkg="${pkg%%:*}"
    echo "$pkg"
}

DETAILS_FILE="$(mktemp)"
trap 'rm -f "$DETAILS_FILE"' EXIT

mapfile -t CURRENT_CONFFILES < <(cat /var/lib/dpkg/info/*.conffiles 2>/dev/null | grep '^/etc/' | sort -u)
mapfile -t PRE_PATHS < <(jq -r '.conffile_hashes // {} | keys[]' "$PRE_JSON")

declare -A IS_PRE
for f in "${PRE_PATHS[@]}"; do IS_PRE["$f"]=1; done

unchanged=0; modified=0; missing=0; new=0
UNEXPECTED_COUNT=0

# --- New conffiles: tracked now, not seen at pre-patch time ------------------
for f in "${CURRENT_CONFFILES[@]}"; do
    [ -n "${IS_PRE[$f]:-}" ] && continue
    new=$((new + 1))
    pkg="$(owning_package "$f")"
    expected="$(jq --arg p "${pkg:-}" '$p as $pkg | any(.[]; . == $pkg)' <<<"$PATCHED_PACKAGES_JSON")"
    jq -nc --arg path "$f" --arg pkg "${pkg:-unknown}" --arg cls "new" --argjson expected "$expected" \
        '{path: $path, owning_package: $pkg, classification: $cls, expected: $expected}' >> "$DETAILS_FILE"
done

# --- Existing conffiles: unchanged / modified / missing ----------------------
while IFS=$'\t' read -r path pre_hash; do
    [ -z "$path" ] && continue

    if [ ! -r "$path" ]; then
        missing=$((missing + 1))
        pkg="$(owning_package "$path")"
        jq -nc --arg path "$path" --arg pkg "${pkg:-unknown}" --arg cls "missing" \
            '{path: $path, owning_package: $pkg, classification: $cls, expected: null}' >> "$DETAILS_FILE"
        continue
    fi

    cur_hash="$(sha256sum -- "$path" 2>/dev/null | awk '{print $1}')"
    cache_file="${CACHE_DIR}${path}"

    if [ "$cur_hash" = "$pre_hash" ]; then
        unchanged=$((unchanged + 1))
        mkdir -p "$(dirname "$cache_file")"
        cp -p -- "$path" "$cache_file" 2>/dev/null
        continue
    fi

    modified=$((modified + 1))
    pkg="$(owning_package "$path")"
    expected="$(jq --arg p "${pkg:-}" '$p as $pkg | any(.[]; . == $pkg)' <<<"$PATCHED_PACKAGES_JSON")"
    [ "$expected" != "true" ] && UNEXPECTED_COUNT=$((UNEXPECTED_COUNT + 1))

    diff_text=""
    if [ -r "$cache_file" ]; then
        diff_text="$(diff -u "$cache_file" "$path" 2>/dev/null | head -40)"
    else
        diff_text="(no prior content cached for this file - only its hash was recorded in T2; nothing to diff against yet. A baseline copy is not created for a file that is already showing drift.)"
    fi

    jq -nc --arg path "$path" --arg pkg "${pkg:-unknown}" --arg cls "modified" \
        --argjson expected "$expected" --arg diff "$diff_text" \
        '{path: $path, owning_package: $pkg, classification: $cls, expected: $expected, diff: $diff}' >> "$DETAILS_FILE"
done < <(jq -r '.conffile_hashes // {} | to_entries[] | select(.value != "missing") | "\(.key)\t\(.value)"' "$PRE_JSON")

jq -s \
    --argjson unchanged "$unchanged" --argjson modified "$modified" \
    --argjson missing "$missing" --argjson new "$new" \
    '{summary: {unchanged: $unchanged, modified: $modified, missing: $missing, new: $new},
      files: .}' "$DETAILS_FILE" > "$OUT_JSON"

echo "Unchanged: $unchanged   Modified: $modified   Missing: $missing   New: $new"
echo "Unexpected drift: $UNEXPECTED_COUNT"
echo "Report saved to: $OUT_JSON"

[ "$UNEXPECTED_COUNT" -eq 0 ]
