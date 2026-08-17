#!/bin/bash
#
# 11-maintenance_window.sh
#
# MedDefense Health Systems - The Patch Equation (2x03)
#
# "Only patch inside the window" means nothing if enforcement is a human
# reading a clock. This turns the policy into a predicate every other patch
# script calls before touching anything. Pure decision logic - never
# changes package state, only reads maintenance_windows.json and the clock.
#
# Usage: ./11-maintenance_window.sh [--check|--report|--wait <seconds>] [maintenance_windows.json]
# Env:   MEDDEFENSE_EMERGENCY=1   accept the always-on emergency window as a green light

set -uo pipefail

MODE="--check"
WAIT_SECONDS=0
WINDOWS_JSON=""
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

while [ $# -gt 0 ]; do
    case "$1" in
        --check|--report) MODE="$1"; shift ;;
        --wait) MODE="--wait"; WAIT_SECONDS="${2:-0}"; shift 2 ;;
        *) WINDOWS_JSON="$1"; shift ;;
    esac
done

resolve_input() {
    local name="$1" candidate
    for candidate in "./${name}" "${SCRIPT_DIR}/${name}" "${SCRIPT_DIR}/../${name}"; do
        [ -f "$candidate" ] && { echo "$candidate"; return 0; }
    done
    echo "$name"
}
[ -n "$WINDOWS_JSON" ] || WINDOWS_JSON="$(resolve_input maintenance_windows.json)"

if [ ! -r "$WINDOWS_JSON" ]; then
    echo "error: cannot read $WINDOWS_JSON" >&2
    exit 1
fi

TZ_NAME="$(jq -r '.timezone // "UTC"' "$WINDOWS_JSON")"

# AS_OF lets a caller (like 12-change_log.sh) ask "was THIS past timestamp
# inside a window?" instead of always judging the live clock. Accepts
# anything `date -d` understands (e.g. "2026-03-21 23:01:05").
AS_OF="${AS_OF:-}"
date_at() {
    if [ -n "$AS_OF" ]; then
        TZ="$TZ_NAME" date -d "$AS_OF" "$@"
    else
        TZ="$TZ_NAME" date "$@"
    fi
}

# --- Evaluate the window set at a given moment, in the configured TZ -------
# Emits: decision, active_window, next_window, next_window_iso, seconds_until_next
evaluate() {
    local now_dow now_time now_dom now_iso week_of_month
    now_dow="$(LC_ALL=C date_at +%a)"
    now_time="$(date_at +%H:%M)"
    now_dom="$(date_at +%-d)"
    now_iso="$(date_at +%Y-%m-%dT%H:%M:%S%:z)"
    week_of_month=$(( (now_dom - 1) / 7 + 1 ))

    active=""
    emergency_present="false"

    mapfile -t WIN_ROWS < <(jq -c '.windows[]' "$WINDOWS_JSON")
    for row in "${WIN_ROWS[@]}"; do
        name="$(jq -r '.name' <<<"$row")"
        always="$(jq -r '.always // false' <<<"$row")"
        if [ "$always" = "true" ]; then
            emergency_present="true"
            continue
        fi

        matches_day="$(jq -r --arg d "$now_dow" '(.days // []) | index($d) != null' <<<"$row")"
        [ "$matches_day" != "true" ] && continue

        win_wom="$(jq -r '.week_of_month // empty' <<<"$row")"
        if [ -n "$win_wom" ] && [ "$win_wom" != "$week_of_month" ]; then
            continue
        fi

        start="$(jq -r '.start' <<<"$row")"
        end="$(jq -r '.end' <<<"$row")"
        in_range="false"
        if [[ "$start" < "$end" ]]; then
            [[ "$now_time" > "$start" || "$now_time" == "$start" ]] && [[ "$now_time" < "$end" ]] && in_range="true"
        else
            # window wraps past midnight (e.g. 22:00-02:00)
            { [[ "$now_time" > "$start" || "$now_time" == "$start" ]] || [[ "$now_time" < "$end" ]]; } && in_range="true"
        fi

        if [ "$in_range" = "true" ]; then
            active="$name"
            break
        fi
    done

    decision="defer"
    exit_code=20
    if [ -n "$active" ]; then
        decision="proceed"
        exit_code=0
    elif [ "$emergency_present" = "true" ]; then
        if [ "${MEDDEFENSE_EMERGENCY:-0}" = "1" ]; then
            decision="proceed (emergency override)"
            active="emergency"
            exit_code=0
        else
            decision="emergency_available_override_required"
            exit_code=10
        fi
    fi

    echo "$now_iso|$now_dow|$now_time|$active|$decision|$exit_code"
}

# --- Find when the next non-emergency window opens, scanning forward -------
# up to ~7 weeks so a "week_of_month"-restricted window (like "extended",
# only on the month's first Saturday) is guaranteed to be found even if this
# month's occurrence already passed.
next_window_info() {
    local now_epoch best_epoch="" best_name=""
    now_epoch="$(TZ="$TZ_NAME" date +%s)"

    for offset in $(seq 0 49); do
        candidate_date="$(TZ="$TZ_NAME" date -d "+${offset} days" +%Y-%m-%d)"
        candidate_dow="$(TZ="$TZ_NAME" LC_ALL=C date -d "$candidate_date" +%a)"
        candidate_dom="$(TZ="$TZ_NAME" date -d "$candidate_date" +%-d)"
        candidate_wom=$(( (candidate_dom - 1) / 7 + 1 ))

        while IFS= read -r row; do
            name="$(jq -r '.name' <<<"$row")"
            [ "$(jq -r '.always // false' <<<"$row")" = "true" ] && continue
            matches_day="$(jq -r --arg d "$candidate_dow" '(.days // []) | index($d) != null' <<<"$row")"
            [ "$matches_day" != "true" ] && continue
            win_wom="$(jq -r '.week_of_month // empty' <<<"$row")"
            [ -n "$win_wom" ] && [ "$win_wom" != "$candidate_wom" ] && continue

            start="$(jq -r '.start' <<<"$row")"
            cand_epoch="$(TZ="$TZ_NAME" date -d "$candidate_date $start" +%s 2>/dev/null)"
            [ -z "$cand_epoch" ] && continue
            [ "$cand_epoch" -le "$now_epoch" ] && continue

            if [ -z "$best_epoch" ] || [ "$cand_epoch" -lt "$best_epoch" ]; then
                best_epoch="$cand_epoch"
                best_name="$name"
            fi
        done < <(jq -c '.windows[]' "$WINDOWS_JSON")

        [ -n "$best_epoch" ] && break
    done

    if [ -n "$best_epoch" ]; then
        echo "${best_name}|$(TZ="$TZ_NAME" date -d "@${best_epoch}" +%Y-%m-%dT%H:%M:%S%:z)|$((best_epoch - now_epoch))"
    else
        echo "||"
    fi
}

RESULT="$(evaluate)"
IFS='|' read -r NOW_ISO NOW_DOW NOW_TIME ACTIVE DECISION EXIT_CODE <<<"$RESULT"

echo "now:            ${NOW_ISO%%T*} $NOW_TIME $TZ_NAME ($NOW_DOW)"
echo "active window:  ${ACTIVE:-(none)}"

NEXT_NAME=""; NEXT_ISO=""; SECONDS_UNTIL=""
if [ "$EXIT_CODE" -ne 0 ]; then
    NEXT_INFO="$(next_window_info)"
    IFS='|' read -r NEXT_NAME NEXT_ISO SECONDS_UNTIL <<<"$NEXT_INFO"
    [ -n "$NEXT_NAME" ] && echo "next window:    $NEXT_NAME  at $NEXT_ISO" && echo "seconds until:  $SECONDS_UNTIL"
fi
echo "decision:       $DECISION"

if [ "$MODE" = "--wait" ] && [ "$EXIT_CODE" -ne 0 ]; then
    waited=0
    poll_interval=5
    while [ "$waited" -lt "$WAIT_SECONDS" ]; do
        sleep "$poll_interval"
        waited=$((waited + poll_interval))
        RESULT="$(evaluate)"
        IFS='|' read -r NOW_ISO NOW_DOW NOW_TIME ACTIVE DECISION EXIT_CODE <<<"$RESULT"
        [ "$EXIT_CODE" -eq 0 ] && break
    done
    echo "waited:         ${waited}s"
fi

jq -n \
    --arg now "$NOW_ISO" --arg tz "$TZ_NAME" \
    --arg active "${ACTIVE:-}" --arg decision "$DECISION" \
    --arg next_name "${NEXT_NAME:-}" --arg next_iso "${NEXT_ISO:-}" \
    --arg seconds_until "${SECONDS_UNTIL:-}" \
    '{now: $now, timezone: $tz, active_window: (if $active == "" then null else $active end),
      next_window: (if $next_name == "" then null else {name: $next_name, at: $next_iso} end),
      seconds_until_next: (if $seconds_until == "" then null else ($seconds_until | tonumber) end),
      decision: $decision}' > maintenance_window.json

[ "$MODE" = "--report" ] && { cat maintenance_window.json; exit 0; }

echo "Report saved to: maintenance_window.json"
exit "$EXIT_CODE"
