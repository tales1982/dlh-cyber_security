#!/bin/bash
#
# Artifact (relative to this script's directory):
#   capstone/telemetry/linux_events.json

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAPSTONE_DIR="${SCRIPT_DIR}/capstone"
TELEMETRY_DIR="${CAPSTONE_DIR}/telemetry"
OUTPUT_JSON_FILE="${TELEMETRY_DIR}/linux_events.json"
RULES_FILE="/etc/audit/rules.d/meddefense.rules"
REFINE_SCRIPT="${SCRIPT_DIR}/../2x02_eyes_on_endpoint/5-auditd_refine.sh"

for cmd in jq sudo auditctl ausearch; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Error: required command '$cmd' not found." >&2
        exit 2
    fi
done

if [[ "$(id -u)" -ne 0 ]] && ! sudo -n true 2>/dev/null; then
    echo "Error: this script requires root/sudo privileges." >&2
    exit 2
fi

mkdir -p "$TELEMETRY_DIR" || {
    echo "Error: unable to create '$TELEMETRY_DIR'." >&2
    exit 2
}

if ! sudo systemctl is-active --quiet auditd; then
    sudo systemctl start auditd 2>/dev/null || {
        echo "Error: auditd is not active and could not be started." >&2
        exit 2
    }
fi

if [[ ! -f "$RULES_FILE" ]]; then
    echo "Error: '$RULES_FILE' not found. Run Task 3 (3-linux_harden.sh) first." >&2
    exit 2
fi

if [[ -x "$REFINE_SCRIPT" ]]; then
    sudo "$REFINE_SCRIPT" > /dev/null 2>&1 || true
fi

sudo augenrules --load > /dev/null 2>&1 || true

check_key() {
    local key="$1"
    sudo ausearch -ts recent -k "$key" 2>/dev/null | grep -qc '^type=SYSCALL' && echo true || echo false
}

TEST_ID="meddefense_test_$$"
COVERAGE="[]"
ALL_FOUND=1

add_result() {
    local action="$1"
    local key="$2"
    local found="$3"
    if [[ "$found" != "true" ]]; then
        ALL_FOUND=0
    fi
    ENTRY=$(jq -n --arg action "$action" --arg key "$key" --argjson found "$found" \
        '{action: $action, key: $key, found: $found}')
    COVERAGE=$(jq --argjson e "$ENTRY" '. + [$e]' <<< "$COVERAGE")
}

# --- Test 1: create a user ---------------------------------------------------
sudo useradd -M -N -s /usr/sbin/nologin "$TEST_ID" > /dev/null 2>&1
sleep 1
add_result "create_user" "identity" "$(check_key identity)"

# --- Test 2: remove the user --------------------------------------------------
sudo userdel "$TEST_ID" > /dev/null 2>&1
sleep 1
add_result "remove_user" "identity" "$(check_key identity)"

# --- Test 3: service management action ---------------------------------------
sudo systemctl restart cron > /dev/null 2>&1 || sudo systemctl restart rsyslog > /dev/null 2>&1
sleep 1
add_result "service_management" "process_exec" "$(check_key process_exec)"

# --- Test 4: schedule a cron job, then remove it ------------------------------
EXISTING_CRONTAB=$(crontab -l 2>/dev/null || true)
{ echo "$EXISTING_CRONTAB"; echo "* * * * * /bin/true # ${TEST_ID}"; } | crontab -
sleep 1
add_result "schedule_cron_job" "cron_persist" "$(check_key cron_persist)"

if [[ -n "$EXISTING_CRONTAB" ]]; then
    echo "$EXISTING_CRONTAB" | crontab -
else
    crontab -r > /dev/null 2>&1 || true
fi
sleep 1
add_result "remove_cron_job" "cron_persist" "$(check_key cron_persist)"

# --- Test 5: short authorized find as root ------------------------------------
sudo find /tmp -maxdepth 1 -name "${TEST_ID}*" > /dev/null 2>&1
sleep 1
add_result "authorized_find" "process_exec" "$(check_key process_exec)"

# --- Export last 30 minutes of auditd + syslog records ------------------------
AUDIT_EVENTS_RAW=$(sudo ausearch -ts recent 2>/dev/null || true)
SYSLOG_EVENTS_RAW=$(sudo journalctl --since "30 minutes ago" --no-pager 2>/dev/null || sudo tail -n 500 /var/log/syslog 2>/dev/null || true)

HOSTNAME_VAL=$(hostname)
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

if ! jq -n \
    --arg timestamp "$TIMESTAMP" \
    --arg hostname "$HOSTNAME_VAL" \
    --argjson coverage "$COVERAGE" \
    --arg audit_events "$AUDIT_EVENTS_RAW" \
    --arg syslog_events "$SYSLOG_EVENTS_RAW" \
    '{
        timestamp: $timestamp,
        hostname: $hostname,
        coverage: $coverage,
        audit_events: ($audit_events | split("\n") | map(select(length > 0))),
        syslog_events: ($syslog_events | split("\n") | map(select(length > 0)))
    }' > "$OUTPUT_JSON_FILE"; then
    echo "Error: failed to write '$OUTPUT_JSON_FILE'." >&2
    exit 2
fi

echo "Telemetry coverage written to $OUTPUT_JSON_FILE"

if [[ "$ALL_FOUND" -eq 1 ]]; then
    exit 0
else
    exit 1
fi
