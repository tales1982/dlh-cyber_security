#!/bin/bash
#
# 6-log_source_map.sh
#
# MedDefense Health Systems - Eyes on the Endpoint (2x02), Task 6.
#
# Linux telemetry comes from multiple sources with different formats:
# auditd produces structured records, auth.log uses syslog format,
# application logs vary by service. Before 7-linux_export.sh can export
# this data in a consistent format, this script inventories exactly what
# sources exist - path, format, rotation policy (read from the real
# logrotate configuration, not assumed), current size, an estimated
# event rate, and a security relevance rating - and flags any expected
# source that is missing or silent.
#
# Read-only. Makes no configuration changes.
#
# Usage: ./6-log_source_map.sh

set -euo pipefail

# --- Source Inventory: name|path|format|relevance -----------------------------------------------
# The fixed set of sources this task requires (auth.log, syslog, audit.log,
# kern.log, apache2 access/error, dpkg.log), plus any other
# security-relevant source discovered on this specific host (ufw, fail2ban).
SOURCES="
auth.log|/var/log/auth.log|syslog|critical
audit.log|/var/log/audit/audit.log|audit|critical
syslog|/var/log/syslog|syslog|high
kern.log|/var/log/kern.log|syslog|medium
apache2 access|/var/log/apache2/access.log|combined|high
apache2 error|/var/log/apache2/error.log|custom|high
dpkg.log|/var/log/dpkg.log|custom|medium
"
EXTRA_SOURCES="
ufw.log|/var/log/ufw.log|syslog|high
fail2ban.log|/var/log/fail2ban.log|custom|high
"

# get_rotation_days <path>: finds the logrotate.d stanza covering this path
# and converts its interval (daily/weekly/monthly/yearly) x rotate count
# into an approximate total retention in days. Falls back to "unmanaged"
# when no logrotate config references the path (e.g. audit.log, which
# auditd usually rotates itself via /etc/audit/auditd.conf, not logrotate).
get_rotation_days() {
    local target="$1" cfg interval_days count
    cfg=$(grep -rl -F -- "$target" /etc/logrotate.d/ /etc/logrotate.conf 2>/dev/null | head -1) || true
    if [ -z "${cfg:-}" ]; then
        echo "unmanaged"
        return
    fi
    interval_days=1
    if grep -qE '^\s*daily\b' "$cfg" 2>/dev/null; then interval_days=1
    elif grep -qE '^\s*weekly\b' "$cfg" 2>/dev/null; then interval_days=7
    elif grep -qE '^\s*monthly\b' "$cfg" 2>/dev/null; then interval_days=30
    elif grep -qE '^\s*yearly\b' "$cfg" 2>/dev/null; then interval_days=365
    fi
    count=$(grep -oE 'rotate[[:space:]]+[0-9]+' "$cfg" 2>/dev/null | head -1 | awk '{print $2}') || true
    if [ -z "${count:-}" ]; then
        echo "unmanaged"
        return
    fi
    echo "$((interval_days * count)) days"
}

# estimate_events_per_hour <path>: estimates events/hr using the file's
# own first/last timestamps when they parse as a recognizable date
# (syslog "Mon DD HH:MM:SS" style, ISO 8601, or audit's embedded epoch),
# dividing total line count by elapsed hours. Falls back to
# total_lines/24 (one day's assumed span) when timestamps cannot be
# parsed - still a genuine estimate, just a coarser one.
estimate_events_per_hour() {
    local path="$1" total first_epoch last_epoch elapsed_hours
    total=$(wc -l < "$path" 2>/dev/null) || true
    total="${total:-0}"
    if [ "$total" -eq 0 ]; then
        echo "0"
        return
    fi

    if [[ "$path" == *audit.log ]]; then
        first_epoch=$(grep -oE 'audit\([0-9]+\.' "$path" 2>/dev/null | head -1 | grep -oE '[0-9]+') || true
        last_epoch=$(grep -oE 'audit\([0-9]+\.' "$path" 2>/dev/null | tail -1 | grep -oE '[0-9]+') || true
    else
        first_epoch=$(date -d "$(head -1 "$path" 2>/dev/null | cut -c1-15)" +%s 2>/dev/null) || true
        last_epoch=$(date -d "$(tail -1 "$path" 2>/dev/null | cut -c1-15)" +%s 2>/dev/null) || true
    fi

    if [ -n "${first_epoch:-}" ] && [ -n "${last_epoch:-}" ] && [ "$last_epoch" -gt "$first_epoch" ] 2>/dev/null; then
        elapsed_hours=$(( (last_epoch - first_epoch) / 3600 ))
        [ "$elapsed_hours" -lt 1 ] && elapsed_hours=1
        echo "$((total / elapsed_hours))"
    else
        local rate=$((total / 24))
        if [ "$rate" -lt 1 ]; then echo "<1"; else echo "$rate"; fi
    fi
}

echo "[*] Discovering log sources..."
printf '%-18s %-28s %-9s %-10s %-10s %s\n' "Source" "Path" "Format" "Rotation" "Events/hr" "Relevance"
printf '%-18s %-28s %-9s %-10s %-10s %s\n' "------" "----" "------" "--------" "---------" "---------"

FOUND=0
MISSING=0
INACTIVE=0
RESULTS_JSONL=""

inventory_source() {
    local name="$1" path="$2" format="$3" relevance="$4"
    if [ ! -f "$path" ]; then
        MISSING=$((MISSING + 1))
        printf '%-18s %-28s %-9s %-10s %-10s %s\n' "$name" "$path" "$format" "n/a" "0" "MISSING"
        RESULTS_JSONL="${RESULTS_JSONL}$(jq -n --arg name "$name" --arg path "$path" --arg format "$format" \
            --arg relevance "$relevance" '{source: $name, path: $path, format: $format, present: false, relevance: $relevance}')"$'\n'
        return
    fi
    FOUND=$((FOUND + 1))
    local rotation size events_per_hour size_human status_note=""
    rotation=$(get_rotation_days "$path")
    events_per_hour=$(estimate_events_per_hour "$path")
    size=$(stat -c%s "$path" 2>/dev/null) || true
    size="${size:-0}"
    size_human=$(numfmt --to=iec --suffix=B "$size" 2>/dev/null) || size_human="${size}B"
    # A source that exists but has produced zero lines is present in name
    # only - flagged distinctly from a genuinely missing file, since the
    # remediation is different (check why the daemon/service feeding it
    # is silent, not why the file itself is absent).
    if [ "$events_per_hour" = "0" ]; then
        INACTIVE=$((INACTIVE + 1))
        status_note=" [INACTIVE - not generating events]"
    fi
    printf '%-18s %-28s %-9s %-10s %-10s %s%s\n' "$name" "$path" "$format" "$rotation" "$events_per_hour" "$relevance" "$status_note"
    RESULTS_JSONL="${RESULTS_JSONL}$(jq -n --arg name "$name" --arg path "$path" --arg format "$format" \
        --arg rotation "$rotation" --arg size_bytes "$size" --arg size_human "$size_human" \
        --arg events_per_hour "$events_per_hour" --arg relevance "$relevance" \
        --argjson active "$([ "$events_per_hour" != "0" ] && echo true || echo false)" \
        '{source: $name, path: $path, format: $format, present: true, rotation_policy: $rotation,
          size_bytes: ($size_bytes | tonumber), size_human: $size_human,
          estimated_events_per_hour: $events_per_hour, relevance: $relevance, active: $active}')"$'\n'
}

while IFS='|' read -r name path format relevance; do
    [ -z "$name" ] && continue
    inventory_source "$name" "$path" "$format" "$relevance"
done <<<"$SOURCES"

EXTRA_JSONL=""
while IFS='|' read -r name path format relevance; do
    [ -z "$name" ] && continue
    [ -f "$path" ] || continue
    rotation=$(get_rotation_days "$path")
    events_per_hour=$(estimate_events_per_hour "$path")
    size=$(stat -c%s "$path" 2>/dev/null) || true
    size="${size:-0}"
    status_note=""
    if [ "$events_per_hour" = "0" ]; then
        INACTIVE=$((INACTIVE + 1))
        status_note=" [INACTIVE - not generating events]"
    fi
    printf '%-18s %-28s %-9s %-10s %-10s %s%s\n' "$name" "$path" "$format" "$rotation" "$events_per_hour" "$relevance" "$status_note"
    EXTRA_JSONL="${EXTRA_JSONL}$(jq -n --arg name "$name" --arg path "$path" --arg format "$format" \
        --arg rotation "$rotation" --arg events_per_hour "$events_per_hour" --arg relevance "$relevance" \
        --argjson active "$([ "$events_per_hour" != "0" ] && echo true || echo false)" \
        '{source: $name, path: $path, format: $format, rotation_policy: $rotation,
          estimated_events_per_hour: $events_per_hour, relevance: $relevance, active: $active}')"$'\n'
    FOUND=$((FOUND + 1))
done <<<"$EXTRA_SOURCES"

echo "Sources found: $FOUND | Missing: $MISSING | Inactive (not generating events): $INACTIVE"

SOURCES_JSON=$(jq -s '.' <<<"$RESULTS_JSONL")
EXTRA_SOURCES_JSON=$(jq -s '.' <<<"${EXTRA_JSONL:-}")
jq -n --argjson sources "$SOURCES_JSON" --argjson extra_sources "$EXTRA_SOURCES_JSON" \
  --arg generated "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson found "$FOUND" --argjson missing "$MISSING" --argjson inactive "$INACTIVE" \
  '{
    generated: $generated,
    sources_found: $found,
    sources_missing: $missing,
    sources_inactive: $inactive,
    required_sources: $sources,
    additional_sources_discovered: $extra_sources
  }' > log_source_map.json

echo "Report saved to: log_source_map.json"
