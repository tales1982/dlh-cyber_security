#!/bin/bash
#
# 2-pre_patch_snapshot.sh
#
# MedDefense Health Systems - The Patch Equation (2x03)
#
# The exact "before" state every later task measures against: Task 5 proves
# no service regressed, Task 6 proves no config drifted, Task 9 rolls back
# to the versions recorded here. If this snapshot is wrong or incomplete,
# every downstream comparison is wrong too.
#
# Read-only. This script makes no configuration changes to the system.
#
# Usage: sudo ./2-pre_patch_snapshot.sh [output.json]

set -uo pipefail

OUT_JSON="${1:-pre_patch_state.json}"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
HOSTNAME_VAL="$(hostname)"
KERNEL_VAL="$(uname -r)"
REBOOT_REQUIRED="false"
[ -f /var/run/reboot-required ] && REBOOT_REQUIRED="true"

# --- Package versions ---------------------------------------------------
# One jq call turns "pkg version" lines into an object, instead of one
# jq -n call per package (2000+ installed packages would make that the
# slowest part of the script for no reason).
PACKAGES_JSON="$(dpkg-query -W -f='${binary:Package} ${Version} ${Status}\n' 2>/dev/null \
    | grep 'install ok installed$' \
    | awk '{print $1, $2}' \
    | jq -R -s '
        split("\n") | map(select(length > 0) | split(" "))
        | map({key: .[0], value: .[1]}) | from_entries')"

# --- Service state (ActiveState, SubState, MainPID) ----------------------
# ActiveState/SubState come straight out of `list-units` columns 3 and 4.
# MainPID needs a second call, but ONE batched call for every unit at once -
# not one call per service.
# list-units and MainPID come from two calls, but each ONE call for every
# unit at once (not one call per service). Both list-units invocations return
# rows in the same, stable order, so the arrays can be zipped by index below.
mapfile -t ACTIVE_UNITS < <(systemctl list-units --type=service --state=active --no-legend --no-pager 2>/dev/null | awk '{print $1}')
mapfile -t UNIT_STATES < <(systemctl list-units --type=service --state=active --no-legend --no-pager 2>/dev/null | awk '{print $3, $4}')

SERVICES_JSON="{}"
if [ "${#ACTIVE_UNITS[@]}" -gt 0 ]; then
    mapfile -t MAIN_PIDS < <(systemctl show "${ACTIVE_UNITS[@]}" -p MainPID --value 2>/dev/null | grep -v '^$')
    ROWS_FILE="$(mktemp)"
    for i in "${!ACTIVE_UNITS[@]}"; do
        printf '%s\t%s\t%s\n' "${ACTIVE_UNITS[$i]}" "${UNIT_STATES[$i]}" "${MAIN_PIDS[$i]:-0}" >> "$ROWS_FILE"
    done
    SERVICES_JSON="$(jq -R -s '
        split("\n") | map(select(length > 0) | split("\t"))
        | map(. as $row | ($row[1] | split(" ")) as $s |
               {key: $row[0], value: {active_state: $s[0], sub_state: $s[1], main_pid: ($row[2] | tonumber)}})
        | from_entries' "$ROWS_FILE")"
    rm -f "$ROWS_FILE"
fi

# --- Listening sockets -----------------------------------------------------
LISTENING_JSON="$(ss -tulnH 2>/dev/null | awk '{print $1, $5}' | sort -u | jq -R -s '
    split("\n") | map(select(length > 0) | split(" "))
    | map({proto: .[0], local_address: .[1]})')"

# --- SHA-256 hashes of every conffile tracked by a package ------------------
# dpkg records the conffile list per package in /var/lib/dpkg/info/*.conffiles
# - reading those is orders of magnitude faster than iterating every package
# with `dpkg -L` just to filter for /etc.
mapfile -t CONFFILES < <(cat /var/lib/dpkg/info/*.conffiles 2>/dev/null | grep '^/etc/' | sort -u)

CONFFILE_HASHES_JSON="{}"
if [ "${#CONFFILES[@]}" -gt 0 ]; then
    EXISTING=()
    MISSING=()
    for f in "${CONFFILES[@]}"; do
        if [ -r "$f" ]; then
            EXISTING+=("$f")
        else
            MISSING+=("$f")
        fi
    done

    HASH_ROWS="$(mktemp)"
    if [ "${#EXISTING[@]}" -gt 0 ]; then
        sha256sum -- "${EXISTING[@]}" 2>/dev/null \
            | awk '{h=$1; $1=""; sub(/^ /,""); print $0"\t"h}' > "$HASH_ROWS"
    fi
    for f in "${MISSING[@]:-}"; do
        [ -n "$f" ] && printf '%s\tmissing\n' "$f" >> "$HASH_ROWS"
    done

    CONFFILE_HASHES_JSON="$(jq -R -s '
        split("\n") | map(select(length > 0) | split("\t"))
        | map({key: .[0], value: .[1]}) | from_entries' "$HASH_ROWS")"
    rm -f "$HASH_ROWS"
fi

# --- Assemble -----------------------------------------------------------
jq -n \
    --arg ts "$TS" \
    --arg hostname "$HOSTNAME_VAL" \
    --arg kernel "$KERNEL_VAL" \
    --argjson reboot_required "$REBOOT_REQUIRED" \
    --argjson packages "$PACKAGES_JSON" \
    --argjson services "$SERVICES_JSON" \
    --argjson listening "$LISTENING_JSON" \
    --argjson conffile_hashes "$CONFFILE_HASHES_JSON" \
    '{timestamp: $ts, hostname: $hostname, kernel: $kernel, reboot_required: $reboot_required,
      packages: $packages, services: $services, listening: $listening,
      conffile_hashes: $conffile_hashes}' > "$OUT_JSON"

# --- Human-readable summary --------------------------------------------------
SIZE="$(du -h "$OUT_JSON" | cut -f1)"
echo "Snapshot: $OUT_JSON"
echo "Size: $SIZE"
echo "Kernel: $KERNEL_VAL"
echo "Reboot required: $REBOOT_REQUIRED"
echo "Packages: $(jq '.packages | length' "$OUT_JSON")  Services: $(jq '.services | length' "$OUT_JSON")  Conffiles: $(jq '.conffile_hashes | length' "$OUT_JSON")"
