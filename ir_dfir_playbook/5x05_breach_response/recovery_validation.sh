#!/bin/bash
# recovery_validation.sh - recovery gate for IR-2026-0420-01
#
# Proves the environment is clean before the six affected hosts leave EDR containment.
# Exits 0 only if every check passes. Any FAIL (or missing input) exits 1.
#
# Checks
#   1. beacon      no svchost32.exe (or child of it, or WinHealthSvc install) in the last 24 h on any affected host
#   2. c2          no allowed outbound connection to staging.office365-cdn[.]net / 45.152.66.114
#   3. staging     no .bat/.ps1 in Windows\System32 or ProgramData outside the gold-image allowlist,
#                  no encryption_staging.ps1, and every affected host was scanned
#   4. services    epic-api, lis-api, scheduling-api answer HTTP 200
#   5. edr         every affected host's EDR agent reported in the last 5 minutes
#   6. detection   sigma_cobalt_strike_beacon.yml active in the SIEM and a synthetic beacon event matches it
#   7. evidence    11/11 evidence artifacts match their SHA-256 baseline (hashes.txt)
#
# Inputs (SIEM / EDR exports written by the scheduled export jobs; defaults in brackets)
#   RV_DATA_DIR     directory with the exports                       [<script dir>/recovery_data]
#     export_meta.txt              exported_at=<UTC ISO>, window_hours=<n>
#     process_events_24h.jsonl     Sysmon EID 1 + 13, last 24 h, affected hosts
#     network_events_24h.jsonl     Sysmon EID 3 + proxy + firewall, last 24 h, all hosts
#     staging_scan.tsv             host<TAB>path<TAB>sha256 of every .bat/.ps1 in System32 + ProgramData
#     staging_allowlist.txt        sha256 of gold-image scripts allowed in those folders
#     edr_agents.csv               host,status,last_seen_utc
#     service_status.txt           name<TAB>url<TAB>http_code  (export mode only)
#     siem_rules_active.txt        one active rule id or file name per line
#     synthetic_beacon_event.json  test event the new rule must match
#   RV_MODE         export | live. live = curl the service URLs now and use "now" as reference time [export]
#   SERVICE_URLS    live mode: "name=url ..."                       [epic/lis/scheduling health URLs below]
#   SIGMA_RULE      rule file                                       [<script dir>/sigma_cobalt_strike_beacon.yml]
#   EVIDENCE_DIR    evidence store with hashes.txt                  [/evidence/IR-2026-0420-01]
#   EXPECTED_ARTIFACTS  number of baseline artifacts                [11]
#
# Dependencies: bash, grep, awk, sed, date, sha256sum (curl only in live mode). No jq needed.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RV_DATA_DIR="${RV_DATA_DIR:-$SCRIPT_DIR/recovery_data}"
RV_MODE="${RV_MODE:-export}"
SIGMA_RULE="${SIGMA_RULE:-$SCRIPT_DIR/sigma_cobalt_strike_beacon.yml}"
EVIDENCE_DIR="${EVIDENCE_DIR:-/evidence/IR-2026-0420-01}"
EXPECTED_ARTIFACTS="${EXPECTED_ARTIFACTS:-11}"
SERVICE_URLS="${SERVICE_URLS:-epic-api=https://epic-api.meddefense.org/health lis-api=https://lis-api.meddefense.org/health scheduling-api=https://scheduling-api.meddefense.org/health}"

AFFECTED_HOSTS=(CS-WS-101 CS-WS-104 CS-WS-107 CS-WS-112 FILE-SVR-01 SCHED-SVR-01)
EXPECTED_SERVICES=(epic-api lis-api scheduling-api)
C2_DOMAIN="staging.office365-cdn.net"
C2_DOMAIN_RE='office365-cdn\.net'
C2_IP="45.152.66.114"
C2_IP_RE='45\.152\.66\.114'
EDR_MAX_AGE_S=300

FAILS=0
pass() { printf '[PASS] %s\n' "$1"; }
fail() { printf '[FAIL] %s\n' "$1"; FAILS=$((FAILS + 1)); }

need_file() {
    # need_file <check name> <path>; prints FAIL and returns 1 if missing
    if [[ ! -r "$2" ]]; then
        fail "$1: input missing or unreadable: $2"
        return 1
    fi
}

to_epoch() { date -u -d "$1" +%s 2>/dev/null; }

# Reference time: the export timestamp in export mode, the current time in live mode
ref_time() {
    local t=""
    if [[ "$RV_MODE" != "live" && -r "$RV_DATA_DIR/export_meta.txt" ]]; then
        t="$(sed -n 's/^exported_at=//p' "$RV_DATA_DIR/export_meta.txt" | head -n1)"
    fi
    if [[ -n "$t" ]]; then to_epoch "$t"; else date -u +%s; fi
}

hosts_label() { local IFS=,; echo "${AFFECTED_HOSTS[*]}"; }

# ---------------------------------------------------------------------------
# 1. Beacon process tree
# ---------------------------------------------------------------------------
check_beacon() {
    local f="$RV_DATA_DIR/process_events_24h.jsonl" hits
    need_file "beacon" "$f" || return
    if [[ ! -s "$f" ]]; then
        fail "beacon: process export is empty (no telemetry is not proof of absence)"
        return
    fi
    # stager by name, anything parented by it, the persistence service, svchost.exe outside System32
    hits="$(grep -iE 'svchost32\.exe|WinHealthSvc|encryption_staging' "$f";
            grep -iE '"image":"[^"]*\\\\svchost\.exe"' "$f" | grep -viE '"image":"C:\\\\Windows\\\\(System32|SysWOW64)\\\\svchost\.exe"')"
    if [[ -n "$hits" ]]; then
        fail "beacon: $(printf '%s\n' "$hits" | grep -c .) matching event(s) in last 24h, first: $(printf '%s\n' "$hits" | head -n1 | cut -c1-160)"
        return
    fi
    local h missing=()
    for h in "${AFFECTED_HOSTS[@]}"; do
        grep -q "\"host\":\"$h\"" "$f" || missing+=("$h")
    done
    if (( ${#missing[@]} )); then
        fail "beacon: no process telemetry from ${missing[*]} in last 24h (cannot prove absence)"
        return
    fi
    pass "beacon: no svchost32.exe or related process tree in last 24h across all affected hosts"
}

# ---------------------------------------------------------------------------
# 2. C2 connections
# ---------------------------------------------------------------------------
check_c2() {
    local f="$RV_DATA_DIR/network_events_24h.jsonl" hits
    need_file "c2" "$f" || return
    # a blocked/denied/sinkholed attempt is not a connection; anything else is
    hits="$(grep -iE "$C2_DOMAIN_RE|$C2_IP_RE" "$f" | grep -viE '"action":"(blocked|denied|deny|sinkholed)"')"
    if [[ -n "$hits" ]]; then
        fail "c2: $(printf '%s\n' "$hits" | grep -c .) outbound connection(s) to ${C2_DOMAIN/./[.]} or $C2_IP, first: $(printf '%s\n' "$hits" | head -n1 | cut -c1-160)"
        return
    fi
    pass "c2: no outbound connections to staging.office365-cdn[.]net or $C2_IP"
}

# ---------------------------------------------------------------------------
# 3. Ransomware staging scripts
# ---------------------------------------------------------------------------
check_staging() {
    local scan="$RV_DATA_DIR/staging_scan.tsv" allow="$RV_DATA_DIR/staging_allowlist.txt"
    need_file "ransomware staging" "$scan" || return
    need_file "ransomware staging" "$allow" || return

    local h missing=()
    for h in "${AFFECTED_HOSTS[@]}"; do
        grep -q "^$h	" "$scan" || missing+=("$h")
    done
    if (( ${#missing[@]} )); then
        fail "ransomware staging: no scan result from ${missing[*]}"
        return
    fi

    local bad
    bad="$(awk -F'\t' -v allowfile="$allow" '
        BEGIN { while ((getline l < allowfile) > 0) { sub(/[ \t].*/, "", l); if (l != "") ok[tolower(l)] = 1 } }
        /^#/ || NF < 3 { next }
        $3 == "NONE" { next }                                   # host scanned, nothing found
        {
            p = tolower($2)
            if (p !~ /\.(bat|ps1)$/) next
            if (p !~ /^c:\\windows\\system32\\|^c:\\programdata\\/) next
            if (p ~ /encryption_staging/ || !(tolower($3) in ok)) print $1 " " $2
        }' "$scan")"
    if [[ -n "$bad" ]]; then
        fail "ransomware staging: $(printf '%s\n' "$bad" | grep -c .) unapproved script(s): $(printf '%s\n' "$bad" | head -n3 | tr '\n' ';')"
        return
    fi
    pass "ransomware staging: no .bat or .ps1 staging scripts found in Windows\\System32 or ProgramData"
}

# ---------------------------------------------------------------------------
# 4. Clinical service endpoints
# ---------------------------------------------------------------------------
check_services() {
    local name code summary="" bad=0 pair url
    if [[ "$RV_MODE" == "live" ]]; then
        if ! command -v curl >/dev/null 2>&1; then
            fail "services: curl not found (live mode)"
            return
        fi
        for pair in $SERVICE_URLS; do
            name="${pair%%=*}"; url="${pair#*=}"
            code="$(curl -s -o /dev/null -m 10 -w '%{http_code}' "$url" 2>/dev/null)"
            [[ "$code" == "200" ]] || bad=1
            summary+="$name ${code:-000}, "
        done
    else
        local f="$RV_DATA_DIR/service_status.txt"
        need_file "services" "$f" || return
        for name in "${EXPECTED_SERVICES[@]}"; do
            code="$(awk -F'\t' -v n="$name" '$1 == n { print $3; exit }' "$f")"
            [[ "$code" == "200" ]] || bad=1
            summary+="$name ${code:-missing}, "
        done
    fi
    summary="${summary%, }"
    if (( bad )); then fail "services: $summary"; else pass "services: $summary"; fi
}

# ---------------------------------------------------------------------------
# 5. EDR agents reporting
# ---------------------------------------------------------------------------
check_edr() {
    local f="$RV_DATA_DIR/edr_agents.csv" now h line status seen seen_e age stale=()
    need_file "edr" "$f" || return
    now="$(ref_time)"
    for h in "${AFFECTED_HOSTS[@]}"; do
        line="$(grep -i "^$h," "$f" | head -n1)"
        if [[ -z "$line" ]]; then stale+=("$h(absent)"); continue; fi
        status="$(cut -d, -f2 <<<"$line")"
        seen="$(cut -d, -f3 <<<"$line")"
        seen_e="$(to_epoch "$seen")"
        if [[ -z "$seen_e" ]]; then stale+=("$h(bad time)"); continue; fi
        age=$(( now - seen_e ))
        if [[ "${status,,}" != "online" ]] || (( age > EDR_MAX_AGE_S || age < -60 )); then
            stale+=("$h(${status},${age}s)")
        fi
    done
    if (( ${#stale[@]} )); then
        fail "edr: not reporting in last 5 minutes: ${stale[*]}"
        return
    fi
    pass "edr: all ${#AFFECTED_HOSTS[@]} hosts reporting to EDR console in last 5 minutes ($(hosts_label))"
}

# ---------------------------------------------------------------------------
# 6. Detection rule active + synthetic test
# ---------------------------------------------------------------------------
rule_endswith_values() {
    # prints the values of the first "Image|endswith:" list in the rule
    awk '
        /Image\|endswith:/ { inlist = 1; next }
        inlist && /^[[:space:]]*-[[:space:]]/ { v = $0; sub(/^[[:space:]]*-[[:space:]]*/, "", v); gsub(/'\''/, "", v); print v; next }
        inlist { exit }' "$1"
}

rule_startswith_values() {
    awk '
        /Image\|startswith:/ { inlist = 1; next }
        inlist && /^[[:space:]]*-[[:space:]]/ { v = $0; sub(/^[[:space:]]*-[[:space:]]*/, "", v); gsub(/'\''/, "", v); print v; next }
        inlist { exit }' "$1"
}

check_detection() {
    local active="$RV_DATA_DIR/siem_rules_active.txt" event="$RV_DATA_DIR/synthetic_beacon_event.json"
    local rule_name rule_id
    need_file "detection" "$SIGMA_RULE" || return
    need_file "detection" "$active" || return
    need_file "detection" "$event" || return
    rule_name="$(basename "$SIGMA_RULE")"
    rule_id="$(sed -n 's/^id:[[:space:]]*//p' "$SIGMA_RULE" | head -n1)"

    if grep -qiE '^status:[[:space:]]*(deprecated|unsupported)' "$SIGMA_RULE"; then
        fail "detection: $rule_name status is deprecated/unsupported"
        return
    fi
    if ! grep -qxF "$rule_name" "$active" && ! grep -qxF "$rule_id" "$active"; then
        fail "detection: $rule_name ($rule_id) not in the SIEM active rule list"
        return
    fi

    # Synthetic event: extract Image (JSON-escaped backslashes -> single) and match it like the rule does
    local image lc_image v hit=0
    image="$(sed -n 's/.*"Image"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$event" | head -n1 | sed 's/\\\\/\\/g')"
    if [[ -z "$image" ]]; then
        fail "detection: synthetic event has no Image field"
        return
    fi
    lc_image="${image,,}"
    while IFS= read -r v; do
        [[ -n "$v" && "$lc_image" == *"${v,,}" ]] && hit=1
    done < <(rule_endswith_values "$SIGMA_RULE")
    while IFS= read -r v; do
        [[ -n "$v" && "$lc_image" == "${v,,}"* ]] && hit=0
    done < <(rule_startswith_values "$SIGMA_RULE")
    grep -qE '"Initiated"[[:space:]]*:[[:space:]]*"?true' "$event" || hit=0
    grep -qE '"DestinationPort"[[:space:]]*:[[:space:]]*"?443' "$event" || hit=0

    if (( hit )); then
        pass "detection: $rule_name active; synthetic test event returned expected hit"
    else
        fail "detection: $rule_name active but synthetic event ($image) did not match"
    fi
}

# ---------------------------------------------------------------------------
# 7. Evidence integrity
# ---------------------------------------------------------------------------
check_evidence() {
    local manifest="$EVIDENCE_DIR/hashes.txt" total ok
    if ! command -v sha256sum >/dev/null 2>&1; then
        fail "evidence hashes: sha256sum not found"
        return
    fi
    need_file "evidence hashes" "$manifest" || return
    total="$(grep -cE '^[0-9a-fA-F]{64}[[:space:]]' "$manifest")"
    ok="$(cd "$EVIDENCE_DIR" && sha256sum -c hashes.txt 2>/dev/null | grep -c ': OK$')"
    if (( total == EXPECTED_ARTIFACTS && ok == total )); then
        pass "evidence hashes: $ok/$total artifacts match original SHA-256 baseline"
    else
        fail "evidence hashes: $ok/$EXPECTED_ARTIFACTS artifacts match baseline ($total listed in hashes.txt)"
    fi
}

# ---------------------------------------------------------------------------
check_beacon
check_c2
check_staging
check_services
check_edr
check_detection
check_evidence

if (( FAILS == 0 )); then
    echo "ALL CHECKS PASSED"
    exit 0
fi
echo "$FAILS CHECK(S) FAILED - hosts stay contained"
exit 1
