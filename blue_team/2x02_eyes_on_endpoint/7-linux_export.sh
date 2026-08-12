#!/bin/bash
#
# 7-linux_export.sh
#
# MedDefense Health Systems - Eyes on the Endpoint (2x02), Task 7.
#
# The Linux counterpart to 3-windows_telemetry_export.ps1: the analyst
# needs Linux telemetry in the same structured JSON shape as the Windows
# export, queryable with jq alongside it. auth.log records SSH logins and
# sudo/su usage; auditd records syscall-level execve/file-access/network
# events; syslog captures service lifecycle and error conditions. Each
# parsed event is normalized to a common timestamp/hostname/source_type/
# event_category shape, with format-specific key fields layered on top.
#
# Performance note: parsing is done with one awk pass per log file (not a
# bash loop with a grep/date subprocess per line) - audit.log alone can
# run to tens of thousands of lines, and a per-line subprocess design
# measured minutes to run against a real file. Timestamp normalization to
# ISO 8601 UTC is likewise done in a single jq pass at the end, using the
# host's current UTC offset (captured once) to convert the classic
# syslog timestamp style, which carries no timezone of its own.
#
# Read-only. Makes no configuration changes.
#
# Usage: ./7-linux_export.sh [output.json]

set -euo pipefail

AUTH_LOG="${AUTH_LOG:-/var/log/auth.log}"
AUDIT_LOG="${AUDIT_LOG:-/var/log/audit/audit.log}"
SYSLOG="${SYSLOG:-/var/log/syslog}"
OUT_JSON="${1:-linux_events_export.json}"
HOSTNAME_VAL="$(hostname)"
CURRENT_YEAR="$(date +%Y)"
LOCAL_UTC_OFFSET="$(date +%z)"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

AUTH_TSV="$WORKDIR/auth.tsv"
AUDIT_TSV="$WORKDIR/audit.tsv"
SYSLOG_TSV="$WORKDIR/syslog.tsv"

# --- auth.log: SSH login success/failure, sudo, su, other PAM events -----------------------------
echo "[*] Parsing auth.log..."

if [ -r "$AUTH_LOG" ]; then
    awk '
    {
        line = $0
        ts = substr(line, 1, 15)
        if (line ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}T/) { split(line, p, " "); ts = p[1] }

        category = ""; user = ""; source_ip = ""; extra = ""

        if (index(line, "Accepted") > 0 && line ~ /sshd\[[0-9]+\]:/) {
            category = "ssh_login_success"
            n = split(line, a, " for "); rest = a[n]
            split(rest, b, " from "); user = b[1]
            split(b[2], c, " "); source_ip = c[1]
        } else if (index(line, "Failed password") > 0 && line ~ /sshd\[[0-9]+\]:/) {
            category = "ssh_login_failure"
            n = split(line, a, "Failed password for "); rest = a[n]
            gsub(/^invalid user /, "", rest)
            split(rest, b, " from "); user = b[1]
            split(b[2], c, " "); source_ip = c[1]
        } else if (line ~ /sudo:[ \t]/ && index(line, "COMMAND=") > 0) {
            category = "sudo"
            n = split(line, a, "sudo:"); rest = a[n]
            split(rest, b, " "); user = b[1]
            idx = index(line, "COMMAND="); extra = substr(line, idx + 8)
        } else if (line ~ /su(\[[0-9]+\])?:/ && line ~ /session (opened|closed) for user/) {
            category = "su"
            idx = index(line, "for user "); rest = substr(line, idx + 9)
            split(rest, b, "("); split(b[1], c, " "); user = c[1]
        } else if (index(line, "pam_unix") > 0) {
            category = "pam"
        } else {
            next
        }

        gsub(/\t/, " ", line)
        print ts "\t" category "\t" user "\t" source_ip "\t" extra "\t" line
    }' "$AUTH_LOG" > "$AUTH_TSV"
else
    : > "$AUTH_TSV"
fi

SSH_COUNT=$(awk -F'\t' '$2 ~ /^ssh_login/' "$AUTH_TSV" | wc -l)
SUDO_COUNT=$(awk -F'\t' '$2 == "sudo"' "$AUTH_TSV" | wc -l)
SU_COUNT=$(awk -F'\t' '$2 == "su"' "$AUTH_TSV" | wc -l)
PAM_COUNT=$(awk -F'\t' '$2 == "pam"' "$AUTH_TSV" | wc -l)
AUTH_TOTAL=$((SSH_COUNT + SUDO_COUNT + SU_COUNT + PAM_COUNT))
echo "    $AUTH_TOTAL events"
echo "    SSH logins: $SSH_COUNT | sudo: $SUDO_COUNT | su: $SU_COUNT | PAM: $PAM_COUNT"

# --- audit.log: execve (process execution), file access (PATH records), network (SOCKADDR) -------
# Parsed directly from the raw file rather than via ausearch: ausearch is
# a per-query subprocess, and this file alone can run to tens of
# thousands of lines - the same per-line-subprocess cost this script's
# own header comment measured in minutes is exactly what shelling out to
# ausearch per record (or even once per event type) would reintroduce.
echo "[*] Parsing audit.log..."

if [ -r "$AUDIT_LOG" ]; then
    awk '
    {
        line = $0
        epoch = ""
        if (match(line, /audit\([0-9]+\./)) { epoch = substr(line, RSTART + 6, RLENGTH - 7) }

        category = "other"; field1 = ""; field2 = ""
        # x86_64 syscall table: execve=59, execveat=322 (also matched by name
        # in case the tool that wrote the log resolved it via ausyscall).
        if (index(line, "type=SYSCALL") > 0 && line ~ /syscall=(59|322|execve|execveat)([^0-9]|$)/) {
            category = "execve"
            if (match(line, /comm="[^"]*"/)) field1 = substr(line, RSTART, RLENGTH)
            if (match(line, /exe="[^"]*"/))  field2 = substr(line, RSTART, RLENGTH)
        } else if (index(line, "type=PATH") > 0) {
            category = "file_access"
            if (match(line, /name="[^"]*"/)) field1 = substr(line, RSTART, RLENGTH)
            # nametype is the operation performed on the path this record
            # names - CREATE/DELETE/NORMAL/PARENT/UNKNOWN - unquoted in the
            # raw record, unlike name=.
            if (match(line, /nametype=[A-Z]+/)) field2 = substr(line, RSTART, RLENGTH)
        } else if (index(line, "type=SOCKADDR") > 0) {
            category = "network"
            if (match(line, /saddr=[0-9A-Fa-f]+/)) field1 = substr(line, RSTART, RLENGTH)
        }

        gsub(/\t/, " ", line)
        print epoch "\t" category "\t" field1 "\t" field2 "\t" line
    }' "$AUDIT_LOG" > "$AUDIT_TSV"
else
    : > "$AUDIT_TSV"
fi

EXECVE_COUNT=$(awk -F'\t' '$2 == "execve"' "$AUDIT_TSV" | wc -l)
FILE_ACCESS_COUNT=$(awk -F'\t' '$2 == "file_access"' "$AUDIT_TSV" | wc -l)
NETWORK_COUNT=$(awk -F'\t' '$2 == "network"' "$AUDIT_TSV" | wc -l)
AUDIT_OTHER_COUNT=$(awk -F'\t' '$2 == "other"' "$AUDIT_TSV" | wc -l)
AUDIT_TOTAL=$((EXECVE_COUNT + FILE_ACCESS_COUNT + NETWORK_COUNT + AUDIT_OTHER_COUNT))
echo "    $AUDIT_TOTAL events"
echo "    execve: $EXECVE_COUNT | file_access: $FILE_ACCESS_COUNT | network: $NETWORK_COUNT | other: $AUDIT_OTHER_COUNT"

# --- syslog: service start/stop and error conditions ---------------------------------------------
echo "[*] Parsing syslog..."

if [ -r "$SYSLOG" ]; then
    awk '
    {
        line = $0
        ts = substr(line, 1, 15)
        if (line ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}T/) { split(line, p, " "); ts = p[1] }

        category = "other"
        if (line ~ /systemd\[1\]: (Started|Stopping|Stopped|Starting)/) {
            category = "service"
        } else if (line ~ /[Ee]rror|[Ff]ail(ed|ure)?|[Cc]ritical/) {
            category = "error"
        }

        gsub(/\t/, " ", line)
        print ts "\t" category "\t" line
    }' "$SYSLOG" > "$SYSLOG_TSV"
else
    : > "$SYSLOG_TSV"
fi

SERVICE_COUNT=$(awk -F'\t' '$2 == "service"' "$SYSLOG_TSV" | wc -l)
ERROR_COUNT=$(awk -F'\t' '$2 == "error"' "$SYSLOG_TSV" | wc -l)
SYSLOG_OTHER_COUNT=$(awk -F'\t' '$2 == "other"' "$SYSLOG_TSV" | wc -l)
SYSLOG_TOTAL=$((SERVICE_COUNT + ERROR_COUNT + SYSLOG_OTHER_COUNT))
echo "    $SYSLOG_TOTAL events"
echo "    service: $SERVICE_COUNT | error: $ERROR_COUNT | other: $SYSLOG_OTHER_COUNT"

# --- Build normalized JSON ------------------------------------------------------------------------
# jq date helpers, shared by the auth.log/syslog pass (syslog-style leading
# timestamp, either ISO-8601-with-offset or classic "Mon DD HH:MM:SS" with
# no timezone of its own) and the audit.log pass (raw epoch seconds).
JQ_DATE_LIB='
  def offset_seconds($off):
    ($off[0:1]) as $sign
    | (($off[1:3] | tonumber) * 3600 + ($off[3:5] | tonumber) * 60) as $mag
    | if $sign == "-" then -$mag else $mag end;

  def normalize_syslog_ts($year; $local_offset):
    if test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}") then
      (.[0:19] | strptime("%Y-%m-%dT%H:%M:%S") | mktime) as $naive
      | (if test("[+-][0-9]{2}:?[0-9]{2}$")
         then (.[-6:] | gsub(":";""))
         else "+0000" end) as $off
      | ($naive - offset_seconds($off)) | strftime("%Y-%m-%dT%H:%M:%SZ")
    elif test("^[A-Za-z]{3} +[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2}") then
      (($year + " " + .) | strptime("%Y %b %d %H:%M:%S") | mktime) as $naive
      | ($naive - offset_seconds($local_offset)) | strftime("%Y-%m-%dT%H:%M:%SZ")
    else
      "1970-01-01T00:00:00Z"
    end;
'

AUTH_JSON_FILE="$WORKDIR/auth.json"
AUDIT_JSON_FILE="$WORKDIR/audit.json"
SYSLOG_JSON_FILE="$WORKDIR/syslog.json"

jq -R -s "$JQ_DATE_LIB"'
  split("\n") | map(select(length > 0)) | map(split("\t")) |
  map({
    timestamp: (.[0] | normalize_syslog_ts($year; $local_offset)),
    hostname: $host, source_type: "auth.log", event_category: .[1],
    user: (.[2] // ""), source_ip: (.[3] // ""), command: (.[4] // ""), raw_message: .[5]
  })' --arg host "$HOSTNAME_VAL" --arg year "$CURRENT_YEAR" --arg local_offset "$LOCAL_UTC_OFFSET" \
  < "$AUTH_TSV" > "$AUTH_JSON_FILE"

jq -R -s '
  split("\n") | map(select(length > 0)) | map(split("\t")) |
  map({
    timestamp: (if .[0] != "" then (.[0] | tonumber | strftime("%Y-%m-%dT%H:%M:%SZ")) else "1970-01-01T00:00:00Z" end),
    hostname: $host, source_type: "audit.log", event_category: .[1],
    field1: (.[2] // ""), field2: (.[3] // ""), raw_message: .[4]
  })' --arg host "$HOSTNAME_VAL" < "$AUDIT_TSV" > "$AUDIT_JSON_FILE"

jq -R -s "$JQ_DATE_LIB"'
  split("\n") | map(select(length > 0)) | map(split("\t")) |
  map({
    timestamp: (.[0] | normalize_syslog_ts($year; $local_offset)),
    hostname: $host, source_type: "syslog", event_category: .[1],
    raw_message: .[2]
  })' --arg host "$HOSTNAME_VAL" --arg year "$CURRENT_YEAR" --arg local_offset "$LOCAL_UTC_OFFSET" \
  < "$SYSLOG_TSV" > "$SYSLOG_JSON_FILE"

ALL_TIMESTAMPS=$(jq -s -r '[.[][] | .timestamp] | sort | .[0], .[-1]' \
    "$AUTH_JSON_FILE" "$AUDIT_JSON_FILE" "$SYSLOG_JSON_FILE" 2>/dev/null) || true
RANGE_START=$(echo "$ALL_TIMESTAMPS" | sed -n 1p)
RANGE_END=$(echo "$ALL_TIMESTAMPS" | sed -n 2p)
RANGE_START="${RANGE_START:-1970-01-01T00:00:00Z}"
RANGE_END="${RANGE_END:-1970-01-01T00:00:00Z}"

TOTAL_EVENTS=$((AUTH_TOTAL + AUDIT_TOTAL + SYSLOG_TOTAL))

jq -n --slurpfile auth "$AUTH_JSON_FILE" --slurpfile audit "$AUDIT_JSON_FILE" --slurpfile syslog "$SYSLOG_JSON_FILE" \
  --arg generated "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg range_start "$RANGE_START" --arg range_end "$RANGE_END" \
  --argjson total "$TOTAL_EVENTS" \
  '{
    generated: $generated,
    time_range: { start: $range_start, end: $range_end },
    total_events: $total,
    events: ($auth[0] + $audit[0] + $syslog[0])
  }' > "$OUT_JSON"

echo "Total events: $TOTAL_EVENTS"
echo "Time range: $RANGE_START to $RANGE_END"
echo "Output: $OUT_JSON"
