#!/bin/bash
#
# 4-patch_execute.sh
#
# MedDefense Health Systems - The Patch Equation (2x03)
#
# The plan (T3) is intent. This is the execution: apply each planned patch
# in order, record what happened before and after in enough detail that T5
# (validation) and T9 (rollback) never have to guess. This is also the
# script the incident with Mike Torres's aborted `apt upgrade -y` exists to
# prevent - every action here is logged, ordered and lock-protected.
#
# Usage: sudo ./4-patch_execute.sh [patch_plan.json] [output.json]
# Env:   PIPELINE_TEST=1   run `apt-get install --only-upgrade --dry-run` instead
#        LOCK_FILE         override the advisory lock path (default: /var/lock/meddefense-patch.lock)

set -uo pipefail

PLAN_JSON="${1:-patch_plan.json}"
OUT_JSON="${2:-patch_execution_log.json}"
LOCK_FILE="${LOCK_FILE:-/var/lock/meddefense-patch.lock}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
PIPELINE_TEST="${PIPELINE_TEST:-0}"

resolve_input() {
    local name="$1" candidate
    for candidate in "./${name}" "${SCRIPT_DIR}/${name}" "${SCRIPT_DIR}/../${name}"; do
        [ -f "$candidate" ] && { echo "$candidate"; return 0; }
    done
    echo "$name"
}
[ -f "$PLAN_JSON" ] || PLAN_JSON="$(resolve_input patch_plan.json)"
if [ ! -r "$PLAN_JSON" ]; then
    echo "error: cannot read $PLAN_JSON (run 3-patch_plan.sh first)" >&2
    exit 1
fi

# --- Advisory lock: two instances of this script must never race -----------
exec 200>"$LOCK_FILE" || { echo "error: cannot open lock file $LOCK_FILE" >&2; exit 2; }
if ! flock -n 200; then
    echo "error: another patch execution is already running (lock: $LOCK_FILE)" >&2
    exit 2
fi
echo "[*] Acquired lock $LOCK_FILE"
trap 'flock -u 200' EXIT

STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
HOSTNAME_VAL="$(hostname)"
PLAN_HASH="$(sha256sum "$PLAN_JSON" | awk '{print $1}')"

# --- Small helpers -----------------------------------------------------------
# Pre and post blocks both capture installed version and service states for
# every service linked to the package being patched.
installed_version_of() {
    dpkg-query -W -f='${Version}' "$1" 2>/dev/null || echo ""
}

service_state_of() {
    local svc="$1"
    [ "$svc" = "(kernel-wide)" ] && { echo '{"service":"(kernel-wide)","active_state":"n/a"}'; return; }
    local state
    state="$(systemctl show "$svc" -p ActiveState --value 2>/dev/null || echo "unknown")"
    jq -n --arg s "$svc" --arg st "$state" '{service: $s, active_state: $st}'
}

service_states_json() {
    local services_json="$1" rows="[]"
    local svc
    while IFS= read -r svc; do
        [ -z "$svc" ] && continue
        rows="$(jq -c --argjson r "$rows" --argjson item "$(service_state_of "$svc")" '$r + [$item]' <<<'{}')"
    done < <(jq -r '.[]?' <<<"$services_json")
    echo "$rows"
}

ENTRIES_FILE="$(mktemp)"
STAGE_STATUS="ok"

mapfile -t PLAN_LINES < <(jq -c '.plan[]' "$PLAN_JSON")
TOTAL="${#PLAN_LINES[@]}"
echo "[*] Loading plan: $PLAN_JSON ($TOTAL entries)"

for i in "${!PLAN_LINES[@]}"; do
    entry="${PLAN_LINES[$i]}"
    pkg="$(jq -r '.package' <<<"$entry")"
    bucket="$(jq -r '.bucket' <<<"$entry")"
    requires_restart="$(jq -r '.requires_restart' <<<"$entry")"
    requires_reboot="$(jq -r '.requires_reboot' <<<"$entry")"
    services_json="$(jq -c '.affected_services' <<<"$entry")"
    n=$((i + 1))

    pre_version="$(installed_version_of "$pkg")"
    pre_services="$(service_states_json "$services_json")"
    pre_json="$(jq -n --arg v "$pre_version" --argjson s "$pre_services" '{installed_version: $v, services: $s}')"

    printf '[%d/%d] %-20s %-11s apt-get ... ' "$n" "$TOTAL" "$pkg" "$bucket"

    start_ts=$(date +%s.%N)
    # DEBIAN_FRONTEND=noninteractive alone does NOT stop dpkg from prompting
    # on a modified conffile ("Modified since installation... keep/install?").
    # Without --force-confdef/--force-confold that prompt blocks on stdin
    # with no TTY attached and dpkg exits with "end of file on stdin at
    # conffile prompt" - a real failure mode hit while testing this script.
    # --force-confdef: auto-resolve when possible (keep if unchanged by the
    # admin). --force-confold when confdef can't decide: keep the currently
    # installed config rather than silently overwrite an admin's edits.
    apt_cmd=(apt-get install --only-upgrade -y
        -o Dpkg::Options::=--force-confdef
        -o Dpkg::Options::=--force-confold
        "$pkg")
    [ "$PIPELINE_TEST" = "1" ] && apt_cmd+=(--dry-run)

    # Capture stdout, stderr and exit status of every apt-get invocation.
    exit_code=0
    stdout_out="$(mktemp)"
    stderr_out="$(mktemp)"
    retry_delay=5
    elapsed_wait=0
    while :; do
        if DEBIAN_FRONTEND=noninteractive "${apt_cmd[@]}" >"$stdout_out" 2>"$stderr_out"; then
            exit_code=0
            break
        else
            exit_code=$?
            if grep -q "E: Could not get lock" "$stderr_out" && [ "$elapsed_wait" -lt 120 ]; then
                sleep "$retry_delay"
                elapsed_wait=$((elapsed_wait + retry_delay))
                retry_delay=$((retry_delay * 2))
                continue
            fi
            break
        fi
    done
    end_ts=$(date +%s.%N)
    duration="$(awk -v a="$start_ts" -v b="$end_ts" 'BEGIN{printf "%.1f", b-a}')"

    status="failed"
    restart_results="[]"
    if [ "$exit_code" -eq 0 ]; then
        status="ok"
        echo "OK (${duration}s)"
        post_version="$(installed_version_of "$pkg")"

        if [ "$requires_restart" = "true" ] && [ "$requires_reboot" != "true" ] && [ "$PIPELINE_TEST" != "1" ]; then
            while IFS= read -r svc; do
                [ -z "$svc" ] || [ "$svc" = "(kernel-wide)" ] && continue
                if systemctl try-restart "$svc" >/dev/null 2>&1; then
                    r="ok"
                else
                    r="failed"
                fi
                printf '      try-restart %-25s %s\n' "$svc" "$r"
                restart_results="$(jq -c --argjson r "$restart_results" --arg s "$svc" --arg res "$r" '$r + [{service: $s, result: $res}]' <<<'{}')"
            done < <(jq -r '.[]?' <<<"$services_json")
        fi
    else
        echo "FAILED (${duration}s)"
        post_version="$pre_version"
        STAGE_STATUS="failed"
    fi

    post_services="$(service_states_json "$services_json")"
    post_json="$(jq -n --arg v "$post_version" --argjson s "$post_services" '{installed_version: $v, services: $s}')"

    jq -n \
        --arg package "$pkg" --arg bucket "$bucket" --argjson pre "$pre_json" --argjson post "$post_json" \
        --arg status "$status" --argjson duration "$duration" --argjson exit_code "$exit_code" \
        --arg stdout_tail "$(tail -c 2000 "$stdout_out")" --arg stderr_tail "$(tail -c 2000 "$stderr_out")" \
        --argjson restarts "$restart_results" \
        '{package: $package, bucket: $bucket, pre: $pre, post: $post, status: $status,
          exit_code: $exit_code, duration_seconds: $duration, stdout_tail: $stdout_tail,
          stderr_tail: $stderr_tail, restarts: $restarts}' >> "$ENTRIES_FILE"

    rm -f "$stdout_out" "$stderr_out"

    if [ "$status" = "failed" ]; then
        echo "[!] $pkg failed - stopping execution loop, proceeding to finalization"
        break
    fi
done

FINISHED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

jq -n \
    --arg started_at "$STARTED_AT" --arg finished_at "$FINISHED_AT" --arg hostname "$HOSTNAME_VAL" \
    --arg plan_hash "$PLAN_HASH" --slurpfile entries <(jq -s '.' "$ENTRIES_FILE") \
    '{started_at: $started_at, finished_at: $finished_at, hostname: $hostname,
      plan_source_hash: $plan_hash, entries: $entries[0]}' > "$OUT_JSON"
rm -f "$ENTRIES_FILE"

succeeded="$(jq '[.entries[] | select(.status=="ok")] | length' "$OUT_JSON")"
failed="$(jq '[.entries[] | select(.status=="failed")] | length' "$OUT_JSON")"
echo "Succeeded: $succeeded  Failed: $failed"
echo "Log saved to: $OUT_JSON"

[ "$STAGE_STATUS" = "ok" ]
