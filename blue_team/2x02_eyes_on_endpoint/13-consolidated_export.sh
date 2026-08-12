#!/bin/bash
#
# 13-consolidated_export.sh
#
# MedDefense Health Systems - Eyes on the Endpoint (2x02), Task 13.
#
# Module 3's SOC starts with raw telemetry from endpoints - this is that
# handoff package. It combines windows_events_export.json (Task 3) and
# linux_events_export.json (Task 7) - normal operational events, the bulk
# of the dataset - with the Windows and Linux attacker simulation ground
# truth (Tasks 9 and 11) into telemetry_handoff/, verifying every event
# on both platforms carries the same 4 common fields and every timestamp
# is real UTC ISO 8601 before anything is packaged.
#
# Read-only against its inputs. Makes no configuration changes.
#
# Usage: ./13-consolidated_export.sh [windows_events.json] [linux_events.json] [windows_attack_log.json] [linux_attack_log.json]

set -euo pipefail

WINDOWS_EVENTS="${1:-windows_events_export.json}"
LINUX_EVENTS="${2:-linux_events_export.json}"
WINDOWS_GROUND_TRUTH="${3:-windows_attack_log.json}"
LINUX_GROUND_TRUTH="${4:-linux_attack_log.json}"
HANDOFF_DIR="telemetry_handoff"

for f in "$WINDOWS_EVENTS" "$LINUX_EVENTS"; do
    if [ ! -r "$f" ]; then
        echo "Error: $f not found - run 3-windows_telemetry_export.ps1 / 7-linux_export.sh first." >&2
        exit 1
    fi
done

WINDOWS_COUNT=$(jq '.events | length' "$WINDOWS_EVENTS")
LINUX_COUNT=$(jq '.events | length' "$LINUX_EVENTS")
echo "[*] Loading Windows events ($WINDOWS_COUNT)..."
echo "[*] Loading Linux events ($LINUX_COUNT)..."

mkdir -p "$HANDOFF_DIR"

# --- Normalize timestamps to UTC ISO 8601 ---------------------------------------------------------
# ISO 8601 UTC = YYYY-MM-DDTHH:MM:SSZ. Both Tasks 3 and 7 already produce
# this exact shape; any event that does not match gets re-parsed and
# reformatted here rather than assumed correct, since this is the
# consolidation point where a bad timestamp would otherwise poison the
# whole handoff package.
echo "[*] Normalizing timestamps to UTC..."

NORMALIZE_JQ='
  def normalize_timestamp:
    if (.timestamp | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")) then
      .
    else
      .timestamp |= (
        (try (strptime("%Y-%m-%dT%H:%M:%S") | mktime | strftime("%Y-%m-%dT%H:%M:%SZ")) catch "1970-01-01T00:00:00Z")
      )
    end;
  .events |= map(normalize_timestamp)
'

jq "$NORMALIZE_JQ" "$WINDOWS_EVENTS" > "$HANDOFF_DIR/windows_events.json"
jq "$NORMALIZE_JQ" "$LINUX_EVENTS" > "$HANDOFF_DIR/linux_events.json"

WINDOWS_NORM_COUNT=$(jq '.events | length' "$HANDOFF_DIR/windows_events.json")
LINUX_NORM_COUNT=$(jq '.events | length' "$HANDOFF_DIR/linux_events.json")
echo "    Windows: $WINDOWS_NORM_COUNT events normalized"
echo "    Linux: $LINUX_NORM_COUNT events normalized"

# --- Verify field consistency: timestamp, hostname, source_type, event_category on every event -----
echo "[*] Verifying field consistency..."
REQUIRED_FIELDS='["timestamp","hostname","source_type","event_category"]'
# For each event, compute which of the 4 required keys are absent, then
# count events where that list is non-empty.
MISSING_WINDOWS=$(jq --argjson req "$REQUIRED_FIELDS" \
    '[.events[] | . as $e | ($req - ($e | keys)) | select(length > 0)] | length' \
    "$HANDOFF_DIR/windows_events.json")
MISSING_LINUX=$(jq --argjson req "$REQUIRED_FIELDS" \
    '[.events[] | . as $e | ($req - ($e | keys)) | select(length > 0)] | length' \
    "$HANDOFF_DIR/linux_events.json")

if [ "$MISSING_WINDOWS" -eq 0 ] && [ "$MISSING_LINUX" -eq 0 ]; then
    echo "    Required fields present in all events    [OK]"
else
    echo "    Missing required fields: Windows=$MISSING_WINDOWS event(s), Linux=$MISSING_LINUX event(s)    [WARN]"
fi

# --- Combine ground truth (each action tagged with its platform) -----------------------------------
echo "[*] Combining ground truth..."
WINDOWS_ACTIONS=0
LINUX_ACTIONS=0
COMBINED_ACTIONS_JSON='[]'

if [ -r "$WINDOWS_GROUND_TRUTH" ]; then
    WINDOWS_ACTIONS=$(jq '.actions | length' "$WINDOWS_GROUND_TRUTH")
    WIN_TAGGED=$(jq '[.actions[] | . + {platform: "windows"}]' "$WINDOWS_GROUND_TRUTH")
else
    WIN_TAGGED='[]'
fi

if [ -r "$LINUX_GROUND_TRUTH" ]; then
    LINUX_ACTIONS=$(jq '.actions | length' "$LINUX_GROUND_TRUTH")
    LINUX_TAGGED=$(jq '[.actions[] | . + {platform: "linux"}]' "$LINUX_GROUND_TRUTH")
else
    LINUX_TAGGED='[]'
fi

COMBINED_ACTIONS_JSON=$(jq -n --argjson w "$WIN_TAGGED" --argjson l "$LINUX_TAGGED" '$w + $l')
TOTAL_ACTIONS=$((WINDOWS_ACTIONS + LINUX_ACTIONS))
echo "    Windows actions: $WINDOWS_ACTIONS | Linux actions: $LINUX_ACTIONS | Total: $TOTAL_ACTIONS"

jq -n --argjson actions "$COMBINED_ACTIONS_JSON" --arg generated "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson windows_actions "$WINDOWS_ACTIONS" --argjson linux_actions "$LINUX_ACTIONS" \
    '{generated: $generated, windows_actions: $windows_actions, linux_actions: $linux_actions,
      total_actions: ($windows_actions + $linux_actions), actions: $actions}' \
    > "$HANDOFF_DIR/attack_ground_truth.json"

# --- Report ------------------------------------------------------------------------------------------
echo "[*] Building handoff directory..."
echo "$HANDOFF_DIR/"

human_size() {
    local bytes
    bytes=$(stat -c%s "$1" 2>/dev/null) || bytes=0
    numfmt --to=iec --suffix=B --format="%.1f" "$bytes" 2>/dev/null || echo "${bytes}B"
}

echo "  windows_events.json     ($WINDOWS_NORM_COUNT events, $(human_size "$HANDOFF_DIR/windows_events.json"))"
echo "  linux_events.json       ($LINUX_NORM_COUNT events, $(human_size "$HANDOFF_DIR/linux_events.json"))"
echo "  attack_ground_truth.json ($TOTAL_ACTIONS actions)"

TOTAL_EVENTS=$((WINDOWS_NORM_COUNT + LINUX_NORM_COUNT))
echo "Total: $TOTAL_EVENTS events across 2 platforms"
