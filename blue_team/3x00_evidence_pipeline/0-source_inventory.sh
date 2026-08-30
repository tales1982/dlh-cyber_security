#!/bin/bash
#
# 0-source_inventory.sh - walks the evidence pack's windows/, linux/ and
# network/ directories and produces a structured manifest (source_inventory.json)
# recording, per file: path, source_type, size_bytes, sha256, record_count,
# and a best-effort first_event_time/last_event_time.
#
# Usage: ./0-source_inventory.sh [pack_root]
#   pack_root defaults to $HOME/evidence_pack_primary

set -uo pipefail

PACK_ROOT="${1:-$HOME/evidence_pack_primary}"
OUTPUT_JSON="source_inventory.json"
TMP_RECORDS=$(mktemp)
trap 'rm -f "$TMP_RECORDS"' EXIT

if ! command -v jq >/dev/null 2>&1; then
    echo "Error: required command 'jq' not found." >&2
    exit 2
fi

if [ ! -d "$PACK_ROOT" ]; then
    echo "Error: evidence pack root '$PACK_ROOT' not found." >&2
    exit 2
fi

# --- Timestamp extraction helpers ------------------------------------------
# Each one prints exactly two lines on success: earliest ISO-8601 UTC value,
# then latest. Nothing is assumed about file ordering - every record is
# actually inspected before deciding first/last.

range_from_json_field() {
    local file="$1" field="$2"
    jq -r ".${field}" "$file" 2>/dev/null | sort | sed -n '1p;$p'
}

range_from_syslog() {
    local file="$1"
    # Classic syslog prefix "Mon DD HH:MM:SS" is a fixed 15 characters.
    # No year in the source - assumes the current year, and treats the
    # value as UTC per the evidence pack's own documented convention.
    cut -c1-15 "$file" | TZ=UTC date -f - -u +'%Y-%m-%dT%H:%M:%SZ' 2>/dev/null | sort | sed -n '1p;$p'
}

range_from_audit() {
    local file="$1" epoch
    grep -oP 'audit\(\K[0-9]+' "$file" | sort -n | sed -n '1p;$p' | while read -r epoch; do
        TZ=UTC date -u -d "@$epoch" +'%Y-%m-%dT%H:%M:%SZ'
    done
}

range_from_csv_epoch() {
    local file="$1" epoch
    awk -F, 'NR>1{print $1}' "$file" | sort -n | sed -n '1p;$p' | while read -r epoch; do
        TZ=UTC date -u -d "@$epoch" +'%Y-%m-%dT%H:%M:%SZ'
    done
}

range_from_pcap() {
    local file="$1"
    # start_time is US-format 12h, documented as CST (UTC-6). Appending the
    # zone name lets `date` do the UTC conversion directly.
    jq -r '.start_time' "$file" 2>/dev/null | sed 's/$/ CST/' | TZ=UTC date -f - -u +'%Y-%m-%dT%H:%M:%SZ' 2>/dev/null | sort | sed -n '1p;$p'
}

# --- Category totals ---------------------------------------------------
WINDOWS_COUNT=0; WINDOWS_BYTES=0
LINUX_COUNT=0;   LINUX_BYTES=0
NETWORK_COUNT=0; NETWORK_BYTES=0

for PASTA in windows linux network; do

    if [ ! -d "$PACK_ROOT/$PASTA" ]; then
        echo "Pasta $PASTA não existe" >&2
        continue
    fi

    for ARQUIVO in "$PACK_ROOT/$PASTA"/*; do
        [ -f "$ARQUIVO" ] || continue

        if [ "$PASTA" = "windows" ]; then
            TIPO="windows_json"
        elif [ "$PASTA" = "linux" ]; then
            TIPO="linux_text"
        elif [ "$PASTA" = "network" ]; then
            case "$ARQUIVO" in
                *.csv)
                    TIPO="network_csv"
                    ;;
                *.json)
                    TIPO="network_json"
                    ;;
                *)
                    TIPO="unknown"
                    ;;
            esac
        fi

        BYTE_SIZE=$(stat -c %s "$ARQUIVO")
        HASH=$(sha256sum "$ARQUIVO" | awk '{print $1}')

        RECORD_COUNT=$(wc -l < "$ARQUIVO")
        if [ "$TIPO" = "network_csv" ]; then
            RECORD_COUNT=$((RECORD_COUNT - 1))
        fi

        RANGE=""
        case "$ARQUIVO" in
            */security.json|*/sysmon.json|*/powershell.json)
                RANGE=$(range_from_json_field "$ARQUIVO" "timestamp_raw")
                ;;
            */suricata_eve.json)
                RANGE=$(range_from_json_field "$ARQUIVO" "timestamp")
                ;;
            */pcap_summary.json)
                RANGE=$(range_from_pcap "$ARQUIVO")
                ;;
            */auth.log|*/syslog)
                RANGE=$(range_from_syslog "$ARQUIVO")
                ;;
            */audit.log)
                RANGE=$(range_from_audit "$ARQUIVO")
                ;;
            */firewall.csv)
                RANGE=$(range_from_csv_epoch "$ARQUIVO")
                ;;
        esac

        FIRST_TIME=$(echo "$RANGE" | sed -n '1p')
        LAST_TIME=$(echo "$RANGE" | sed -n '2p')

        REL_PATH="${ARQUIVO#"$PACK_ROOT"/}"

        jq -n \
            --arg path "$REL_PATH" \
            --arg source_type "$TIPO" \
            --argjson size_bytes "$BYTE_SIZE" \
            --arg sha256 "$HASH" \
            --argjson record_count "$RECORD_COUNT" \
            --arg first_event_time "$FIRST_TIME" \
            --arg last_event_time "$LAST_TIME" \
            '{
                path: $path,
                source_type: $source_type,
                size_bytes: $size_bytes,
                sha256: $sha256,
                record_count: $record_count,
                first_event_time: $first_event_time,
                last_event_time: $last_event_time
            }' >> "$TMP_RECORDS"

        case "$PASTA" in
            windows) WINDOWS_COUNT=$((WINDOWS_COUNT + 1)); WINDOWS_BYTES=$((WINDOWS_BYTES + BYTE_SIZE)) ;;
            linux)   LINUX_COUNT=$((LINUX_COUNT + 1));     LINUX_BYTES=$((LINUX_BYTES + BYTE_SIZE)) ;;
            network) NETWORK_COUNT=$((NETWORK_COUNT + 1)); NETWORK_BYTES=$((NETWORK_BYTES + BYTE_SIZE)) ;;
        esac
    done
done

TOTAL_COUNT=$((WINDOWS_COUNT + LINUX_COUNT + NETWORK_COUNT))
TOTAL_BYTES=$((WINDOWS_BYTES + LINUX_BYTES + NETWORK_BYTES))

# --- Human-readable summary ------------------------------------------------
printf "%-7s : %d files  |  %5.1f MB\n" "windows" "$WINDOWS_COUNT" "$(awk -v b="$WINDOWS_BYTES" 'BEGIN{printf "%.1f", b/1000000}')"
printf "%-7s : %d files  |  %5.1f MB\n" "linux"   "$LINUX_COUNT"   "$(awk -v b="$LINUX_BYTES" 'BEGIN{printf "%.1f", b/1000000}')"
printf "%-7s : %d files  |  %5.1f MB\n" "network" "$NETWORK_COUNT" "$(awk -v b="$NETWORK_BYTES" 'BEGIN{printf "%.1f", b/1000000}')"
printf "%-7s : %d files  |  %5.1f MB\n" "total"   "$TOTAL_COUNT"   "$(awk -v b="$TOTAL_BYTES" 'BEGIN{printf "%.1f", b/1000000}')"

# --- Assemble final manifest ------------------------------------------------
jq -s \
    --arg generated_at "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
    --arg pack_root "$PACK_ROOT" \
    --argjson windows_count "$WINDOWS_COUNT" --argjson windows_bytes "$WINDOWS_BYTES" \
    --argjson linux_count "$LINUX_COUNT" --argjson linux_bytes "$LINUX_BYTES" \
    --argjson network_count "$NETWORK_COUNT" --argjson network_bytes "$NETWORK_BYTES" \
    --argjson total_count "$TOTAL_COUNT" --argjson total_bytes "$TOTAL_BYTES" \
    '{
        generated_at: $generated_at,
        pack_root: $pack_root,
        summary: {
            windows: {file_count: $windows_count, total_bytes: $windows_bytes},
            linux:   {file_count: $linux_count,   total_bytes: $linux_bytes},
            network: {file_count: $network_count, total_bytes: $network_bytes},
            total:   {file_count: $total_count,   total_bytes: $total_bytes}
        },
        files: .
    }' "$TMP_RECORDS" > "$OUTPUT_JSON"

echo "manifest written to $OUTPUT_JSON"
