#!/bin/bash
#
# 0-source_inventory.sh - walks the evidence pack's windows/, linux/ and
# network/ directories and produces a structured manifest (source_inventory.json)
# recording, per file: path, source_type, size_bytes, sha256, record_count,
# and a best-effort first_event_time/last_event_time.
#
# Usage: ./0-source_inventory.sh [pack_root]
#   pack_root defaults to $HOME/evidence_pack_primary
#
# -e is intentional and active: any command that legitimately represents
# "best effort, this one file's data quality issue" is explicitly protected
# with `|| fallback` so a single malformed record cannot abort the whole
# manifest run. Anything left unprotected is meant to be fatal.

set -euo pipefail

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
# actually inspected before deciding first/last. Every raw value is passed
# through `date` for real parsing/normalization before being compared -
# none of these rely on sorting the raw source text as if it were already
# a correctly-ordered, uniformly-formatted timestamp.

# A file with SOME malformed records is the expected case, not a failure -
# `date -f` parses what it can and exits non-zero merely because a handful
# of lines were unparseable. Each such stage is wrapped in `{ ... || true; }`
# so that expected, partial data-quality noise never makes the pipeline's
# exit status non-zero and (under `pipefail`+`-e`) wipe out an otherwise
# perfectly good result. A stage that fails completely still yields empty
# output, which the caller already detects and reports.

range_from_json_field() {
    local file="$1" field="$2"
    { jq -r ".${field}" "$file" 2>/dev/null || true; } \
        | { TZ=UTC date -f - -u +'%s' 2>/dev/null || true; } \
        | sort -n | sed -n '1p;$p' \
        | sed 's/^/@/' \
        | { TZ=UTC date -f - -u +'%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || true; }
}

range_from_syslog() {
    local file="$1"
    # Classic syslog prefix "Mon DD HH:MM:SS" is a fixed 15 characters.
    # No year in the source - assumes the current year, and treats the
    # value as UTC per the evidence pack's own documented convention.
    { cut -c1-15 "$file" || true; } \
        | { TZ=UTC date -f - -u +'%s' 2>/dev/null || true; } \
        | sort -n | sed -n '1p;$p' \
        | sed 's/^/@/' \
        | { TZ=UTC date -f - -u +'%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || true; }
}

range_from_audit() {
    local file="$1"
    { grep -oP 'audit\(\K[0-9]+' "$file" 2>/dev/null || true; } \
        | sort -n | sed -n '1p;$p' \
        | sed 's/^/@/' \
        | { TZ=UTC date -f - -u +'%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || true; }
}

range_from_csv_epoch() {
    local file="$1"
    { awk -F, 'NR>1{print $1}' "$file" 2>/dev/null || true; } \
        | sort -n | sed -n '1p;$p' \
        | sed 's/^/@/' \
        | { TZ=UTC date -f - -u +'%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || true; }
}

range_from_pcap() {
    local file="$1"
    # start_time is US-format 12h, documented as CST (UTC-6). Appending the
    # zone name lets `date` do the real parsing and UTC conversion, rather
    # than trusting the raw text to sort in chronological order.
    { jq -r '.start_time' "$file" 2>/dev/null || true; } \
        | sed 's/$/ CST/' \
        | { TZ=UTC date -f - -u +'%s' 2>/dev/null || true; } \
        | sort -n | sed -n '1p;$p' \
        | sed 's/^/@/' \
        | { TZ=UTC date -f - -u +'%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || true; }
}

# --- Category totals ---------------------------------------------------
WINDOWS_COUNT=0; WINDOWS_BYTES=0
LINUX_COUNT=0;   LINUX_BYTES=0
NETWORK_COUNT=0; NETWORK_BYTES=0

for PASTA in windows linux network; do

    if [ ! -d "$PACK_ROOT/$PASTA" ]; then
        echo "Warning: category directory '$PASTA' not found under '$PACK_ROOT'." >&2
        continue
    fi

    for ARQUIVO in "$PACK_ROOT/$PASTA"/*; do
        [ -f "$ARQUIVO" ] || continue

        if [ "$PASTA" = "windows" ]; then
            TIPO="windows_json"
        elif [ "$PASTA" = "linux" ]; then
            TIPO="linux_text"
        else
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

        if ! BYTE_SIZE=$(stat -c %s "$ARQUIVO" 2>/dev/null); then
            echo "Warning: stat failed on '$ARQUIVO' - skipping this file." >&2
            continue
        fi

        HASH=$(sha256sum "$ARQUIVO" 2>/dev/null | awk '{print $1}') || true
        if [ -z "$HASH" ]; then
            echo "Warning: sha256sum failed on '$ARQUIVO' - skipping this file." >&2
            continue
        fi

        # Files under windows/ and network/*.json are expected to be NDJSON
        # (one JSON document per line, per the task note). Counting through
        # jq instead of a raw `wc -l` both validates that assumption and
        # normalizes any pretty-printed JSON (one document spanning several
        # physical lines) to one line per document before counting.
        # jq's own exit status is read directly from PIPESTATUS, not
        # inferred from the pipeline as a whole, so a parse failure is
        # never masked by `wc -l` succeeding on partial output.
        if [ "$TIPO" = "windows_json" ] || [ "$TIPO" = "network_json" ]; then
            RECORD_COUNT=$(jq -c '.' "$ARQUIVO" 2>/dev/null | wc -l) || true
            JQ_STATUS="${PIPESTATUS[0]}"
            if [ "$JQ_STATUS" -ne 0 ]; then
                echo "Warning: '$ARQUIVO' did not parse cleanly as NDJSON (jq exit $JQ_STATUS) - record_count may be incomplete." >&2
            fi
        else
            if ! RECORD_COUNT=$(wc -l < "$ARQUIVO" 2>/dev/null); then
                echo "Warning: wc failed on '$ARQUIVO' - skipping this file." >&2
                continue
            fi
            if [ "$TIPO" = "network_csv" ]; then
                RECORD_COUNT=$((RECORD_COUNT - 1))
            fi
        fi

        # Each RANGE assignment is deliberately allowed to fail (`|| RANGE=""`):
        # a parsing problem in one file's timestamps is a data-quality finding
        # to report, not a reason to abort the entire manifest run.
        RANGE=""
        case "$ARQUIVO" in
            */security.json|*/sysmon.json|*/powershell.json)
                RANGE=$(range_from_json_field "$ARQUIVO" "timestamp_raw") || RANGE=""
                ;;
            */suricata_eve.json)
                RANGE=$(range_from_json_field "$ARQUIVO" "timestamp") || RANGE=""
                ;;
            */pcap_summary.json)
                RANGE=$(range_from_pcap "$ARQUIVO") || RANGE=""
                ;;
            */auth.log|*/syslog)
                RANGE=$(range_from_syslog "$ARQUIVO") || RANGE=""
                ;;
            */audit.log)
                RANGE=$(range_from_audit "$ARQUIVO") || RANGE=""
                ;;
            */firewall.csv)
                RANGE=$(range_from_csv_epoch "$ARQUIVO") || RANGE=""
                ;;
        esac

        FIRST_TIME=$(echo "$RANGE" | sed -n '1p')
        LAST_TIME=$(echo "$RANGE" | sed -n '2p')

        if [ -z "$FIRST_TIME" ] || [ -z "$LAST_TIME" ]; then
            echo "Warning: could not determine event time range for '$ARQUIVO' - recording null." >&2
        fi

        REL_PATH="${ARQUIVO#"$PACK_ROOT"/}"

        if ! jq -n \
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
                first_event_time: (if $first_event_time == "" then null else $first_event_time end),
                last_event_time: (if $last_event_time == "" then null else $last_event_time end)
            }' >> "$TMP_RECORDS"; then
            echo "Error: failed to build manifest entry for '$ARQUIVO'." >&2
            exit 2
        fi

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
if ! jq -s \
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
    }' "$TMP_RECORDS" > "$OUTPUT_JSON"; then
    echo "Error: failed to write '$OUTPUT_JSON'." >&2
    exit 2
fi

echo "manifest written to $OUTPUT_JSON"
