#!/bin/bash
#
# 12-change_log.sh
#
# MedDefense Health Systems - The Patch Equation (2x03)
#
# Auditors ask one question: "show me every change to this system in the
# last 30 days and prove it was authorized". This script builds that answer
# from /var/log/apt/history.log* - the same source of truth apt itself
# uses - instead of trusting a human-maintained change record.
#
# Idempotent by construction: every fact used (log timestamps, AS_OF window
# lookups, package lists) is derived from the static log files, never from
# the live clock - running this twice on the same logs must produce
# byte-identical JSON (modulo key ordering), which is why 11-maintenance_
# window.sh is always called with AS_OF pinned to the event's own timestamp.
#
# Usage: sudo ./12-change_log.sh [output.json]

set -uo pipefail

OUT_JSON="${1:-patch_change_log.json}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
EVENT_GAP_SECONDS=900   # 15 minutes
FS_SEP=$'\x1f'   # Unit Separator - unlike a tab, `read`/`split` never treat
                 # this as IFS "whitespace", so empty fields (e.g. a
                 # transaction with no Requested-By) are never silently
                 # collapsed into the next column.

resolve_input() {
    local name="$1" candidate
    for candidate in "./${name}" "${SCRIPT_DIR}/${name}" "${SCRIPT_DIR}/../${name}"; do
        [ -f "$candidate" ] && { echo "$candidate"; return 0; }
    done
    echo "$name"
}
MW_SCRIPT="$(resolve_input 11-maintenance_window.sh)"
EXEC_LOG_JSON="$(resolve_input patch_execution_log.json)"
VULN_JSON="$(resolve_input vulnerability_inventory.json)"

# --- Read every history log, oldest rotation first, plain text -------------
RAW_FILE="$(mktemp)"
trap 'rm -f "$RAW_FILE" "$TXN_FILE" "$EVENTS_FILE"' EXIT
mapfile -t ROTATED_LOGS < <(find /var/log/apt -maxdepth 1 -name 'history.log.*.gz' 2>/dev/null | sort -t. -k3 -rn)
for f in "${ROTATED_LOGS[@]:-}"; do
    [ -z "$f" ] && continue
    zcat "$f" 2>/dev/null >> "$RAW_FILE"
    echo "" >> "$RAW_FILE"
done
[ -f /var/log/apt/history.log ] && cat /var/log/apt/history.log >> "$RAW_FILE"

# --- Split into transactions, one JSON line per Start-Date block -----------
# /var/log/apt/history.log fields parsed below: Start-Date:, End-Date:,
# Commandline:, Requested-By:, Install:, Upgrade:, Remove:, Purge:.
TXN_FILE="$(mktemp)"
awk -v RS="" -v FS_SEP="$FS_SEP" '
{
    start=""; end=""; cmdline=""; reqby=""; pkgs="";
    n = split($0, lines, "\n");
    for (i=1; i<=n; i++) {
        line = lines[i];
        if (line ~ /^Start-Date: /)   { start = substr(line, 13); }
        else if (line ~ /^End-Date: /)     { end = substr(line, 11); }
        else if (line ~ /^Commandline: /)  { cmdline = substr(line, 14); }
        else if (line ~ /^Requested-By: /) { reqby = substr(line, 15); }
        else if (line ~ /^(Install|Upgrade|Remove|Purge): /) {
            colon = index(line, ": ");
            body = substr(line, colon + 2);
            pkgs = (pkgs == "" ? body : pkgs "," body);
        }
    }
    if (start != "") {
        gsub(/\t/, " ", cmdline);
        print start FS_SEP end FS_SEP reqby FS_SEP cmdline FS_SEP pkgs;
    }
}' "$RAW_FILE" | sort -t"$FS_SEP" -k1,1 > "$TXN_FILE"

# --- Extract package names from the Install/Upgrade/Remove/Purge blob ------
extract_pkg_names() {
    # "pkg1:amd64 (1.0, 1.1), pkg2:amd64 (2.0, automatic)" -> "pkg1\npkg2"
    # Splitting on every comma would also split the (old, new) version pair
    # and the "automatic" marker inside each package's own parentheses,
    # producing fake "package names" like "1.1)" or "automatic)". Instead,
    # scan directly for a name(:arch)? token immediately followed by " (" -
    # that shape only occurs once per real package entry.
    grep -oE '[a-zA-Z0-9][a-zA-Z0-9+.:-]* \(' | sed -E 's/(:[a-zA-Z0-9_-]+)? \($//'
}

# --- Group transactions into change events (gap <= 15 min = same change event) ---
EVENTS_FILE="$(mktemp)"
prev_epoch=""
event_start=""; event_end=""; event_user=""; event_pkgs_file=""
flush_event() {
    [ -z "$event_start" ] && return
    local pkg_count
    pkg_count="$(sort -u "$event_pkgs_file" | grep -c . || true)"
    printf '%s\n' "${event_start}${FS_SEP}${event_end}${FS_SEP}${event_user}${FS_SEP}${pkg_count}${FS_SEP}${event_pkgs_file}" >> "$EVENTS_FILE"
}

while IFS="$FS_SEP" read -r start end reqby _cmdline pkgs; do
    [ -z "$start" ] && continue
    epoch="$(date -d "$start" +%s 2>/dev/null)"
    [ -z "$epoch" ] && continue
    user="$(echo "$reqby" | sed -E 's/ \(.*//')"

    if [ -z "$prev_epoch" ] || [ $((epoch - prev_epoch)) -gt "$EVENT_GAP_SECONDS" ]; then
        flush_event
        event_start="$start"
        event_pkgs_file="$(mktemp)"
        event_user="$user"
    fi
    event_end="${end:-$start}"
    echo "$pkgs" | extract_pkg_names >> "$event_pkgs_file"
    prev_epoch="$epoch"
done < "$TXN_FILE"
flush_event

# --- Enrich each event and emit -----------------------------------------
RESULTS_FILE="$(mktemp)"
inside=0; outside=0; total_cves_resolved=0

while IFS="$FS_SEP" read -r started ended user pkg_count pkgs_file; do
    [ -z "$started" ] && continue
    started_iso="$(date -u -d "$started" +%Y-%m-%dT%H:%M:%S%:z 2>/dev/null || echo "$started")"
    ended_iso="$(date -u -d "${ended:-$started}" +%Y-%m-%dT%H:%M:%S%:z 2>/dev/null || echo "$started_iso")"

    within="outside"
    if [ -x "$MW_SCRIPT" ] || [ -f "$MW_SCRIPT" ]; then
        decision="$(AS_OF="$started" bash "$MW_SCRIPT" --report >/dev/null 2>&1; jq -r '.decision // "unknown"' maintenance_window.json 2>/dev/null)"
        [[ "$decision" == proceed* ]] && within="inside"
    fi
    [ "$within" = "inside" ] && inside=$((inside + 1)) || outside=$((outside + 1))

    linked_log="null"
    if [ -f "$EXEC_LOG_JSON" ]; then
        overlaps="$(jq -r --arg s "$started_iso" --arg e "$ended_iso" \
            'if (.started_at <= $e and .finished_at >= $s) then "yes" else "no" end' "$EXEC_LOG_JSON" 2>/dev/null)"
        [ "$overlaps" = "yes" ] && linked_log="\"$EXEC_LOG_JSON\""
    fi

    cves_json="[]"
    if [ -f "$VULN_JSON" ] && [ -s "$pkgs_file" ]; then
        cves_json="$(jq -c --slurpfile pkgs <(sort -u "$pkgs_file" | jq -R . | jq -s .) \
            '[.packages[] | select(.package as $p | $pkgs[0] | index($p) != null) | .cves[]?] | unique' "$VULN_JSON" 2>/dev/null)"
        [ -z "$cves_json" ] && cves_json="[]"
    fi
    cve_count="$(jq 'length' <<<"$cves_json" 2>/dev/null || echo 0)"
    total_cves_resolved=$((total_cves_resolved + cve_count))

    packages_json="[]"
    [ -s "$pkgs_file" ] && packages_json="$(sort -u "$pkgs_file" | jq -R . | jq -s .)"

    jq -nc \
        --arg started "$started_iso" --arg ended "$ended_iso" --arg user "${user:-unknown}" \
        --argjson pkg_count "$pkg_count" --argjson packages "$packages_json" \
        --arg within "$within" --argjson linked_log "$linked_log" --argjson cves "$cves_json" \
        '{started: $started, ended: $ended, user: $user, packages: $pkg_count,
          package_names: $packages, within_window: $within,
          linked_execution_log: $linked_log, cves_resolved: $cves}' >> "$RESULTS_FILE"

    rm -f "$pkgs_file"
done < "$EVENTS_FILE"

TOTAL_EVENTS="$(wc -l < "$RESULTS_FILE" | tr -d ' ')"
PERIOD_START="$(jq -rs 'map(.started) | min // ""' "$RESULTS_FILE")"
PERIOD_END="$(jq -rs 'map(.ended) | max // ""' "$RESULTS_FILE")"

jq -n \
    --arg start "$PERIOD_START" --arg finish "$PERIOD_END" \
    --slurpfile events <(jq -s '.' "$RESULTS_FILE") \
    --argjson total "$TOTAL_EVENTS" --argjson inside "$inside" --argjson outside "$outside" \
    --argjson cves "$total_cves_resolved" \
    '{period_start: $start, period_end: $finish, events: $events[0],
      summary: {total_events: $total, inside_window: $inside, outside_window: $outside, cves_resolved: $cves}}' > "$OUT_JSON"

echo "Events found: $TOTAL_EVENTS (inside window: $inside, outside: $outside)"
echo "Report saved to: $OUT_JSON"
