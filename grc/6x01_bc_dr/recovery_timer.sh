#!/bin/bash
# recovery_timer.sh - wall-clock timer for the MedDefense LIS recovery test
#
# Usage:
#   ./recovery_timer.sh "<step name>" START    start timing a step (the first START also starts the test clock)
#   ./recovery_timer.sh "<step name>" PASS     close the step as PASS and append it to the log
#   ./recovery_timer.sh "<step name>" FAIL     close the step as FAIL and append it to the log
#   ./recovery_timer.sh SUMMARY                print the log, total elapsed time and the result against the RTO
#   ./recovery_timer.sh RESET                  archive the current log and state, then start a clean test
#
# Each completed step is written to the log the moment it ends, not at the end of the test.
# Log line format:
#   [STEP 01] <name> | Start: HH:MM:SS | End: HH:MM:SS | Duration: Xm Ys | PASS
#
# Environment (optional):
#   RTEST_STATE   state file                  (default /tmp/rtest_state)
#   RTEST_LOG     step log                    (default ./recovery_test_log.txt)
#   RTO_MINUTES   declared RTO in minutes     (default 30, LIS_RTO_MINUTES in app_config.env)

STATE_FILE="${RTEST_STATE:-/tmp/rtest_state}"
LOG_FILE="${RTEST_LOG:-./recovery_test_log.txt}"
RTO_MINUTES="${RTO_MINUTES:-30}"

usage() {
    echo "Usage: $0 \"<step name>\" START|PASS|FAIL" >&2
    echo "       $0 SUMMARY | RESET" >&2
    exit 2
}

fmt_duration() {
    local secs=$1
    printf '%dm %ds' $((secs / 60)) $((secs % 60))
}

# State file keys (one KEY=value per line):
#   TEST_START_EPOCH, TEST_START_HMS, STEP_COUNT, LAST_END_EPOCH,
#   CUR_NAME, CUR_START_EPOCH, CUR_START_HMS
load_state() {
    TEST_START_EPOCH=""; TEST_START_HMS=""; STEP_COUNT=0; LAST_END_EPOCH=""
    CUR_NAME=""; CUR_START_EPOCH=""; CUR_START_HMS=""
    if [[ -f "$STATE_FILE" ]]; then
        while IFS='=' read -r key value; do
            case "$key" in
                TEST_START_EPOCH) TEST_START_EPOCH="$value" ;;
                TEST_START_HMS) TEST_START_HMS="$value" ;;
                STEP_COUNT) STEP_COUNT="$value" ;;
                LAST_END_EPOCH) LAST_END_EPOCH="$value" ;;
                CUR_NAME) CUR_NAME="$value" ;;
                CUR_START_EPOCH) CUR_START_EPOCH="$value" ;;
                CUR_START_HMS) CUR_START_HMS="$value" ;;
            esac
        done < "$STATE_FILE"
    fi
}

save_state() {
    {
        echo "TEST_START_EPOCH=$TEST_START_EPOCH"
        echo "TEST_START_HMS=$TEST_START_HMS"
        echo "STEP_COUNT=$STEP_COUNT"
        echo "LAST_END_EPOCH=$LAST_END_EPOCH"
        echo "CUR_NAME=$CUR_NAME"
        echo "CUR_START_EPOCH=$CUR_START_EPOCH"
        echo "CUR_START_HMS=$CUR_START_HMS"
    } > "$STATE_FILE"
}

cmd_start() {
    local name="$1" now_epoch now_hms
    now_epoch=$(date +%s)
    now_hms=$(date '+%H:%M:%S')
    load_state
    if [[ -n "$CUR_NAME" ]]; then
        echo "ERROR: step \"$CUR_NAME\" is still open (started $CUR_START_HMS); close it with PASS or FAIL first" >&2
        exit 1
    fi
    if [[ -z "$TEST_START_EPOCH" ]]; then
        TEST_START_EPOCH="$now_epoch"
        TEST_START_HMS="$now_hms"
    fi
    CUR_NAME="$name"
    CUR_START_EPOCH="$now_epoch"
    CUR_START_HMS="$now_hms"
    save_state
    printf '[STEP %02d] %s | Start: %s\n' $((STEP_COUNT + 1)) "$name" "$now_hms"
}

cmd_end() {
    local name="$1" status="$2" now_epoch now_hms elapsed line
    now_epoch=$(date +%s)
    now_hms=$(date '+%H:%M:%S')
    load_state
    if [[ -z "$CUR_NAME" ]]; then
        echo "ERROR: no step is open; call \"$name\" START first" >&2
        exit 1
    fi
    if [[ "$CUR_NAME" != "$name" ]]; then
        echo "ERROR: open step is \"$CUR_NAME\", not \"$name\"" >&2
        exit 1
    fi
    elapsed=$((now_epoch - CUR_START_EPOCH))
    STEP_COUNT=$((STEP_COUNT + 1))
    line=$(printf '[STEP %02d] %s | Start: %s | End: %s | Duration: %s | %s' \
        "$STEP_COUNT" "$name" "$CUR_START_HMS" "$now_hms" "$(fmt_duration "$elapsed")" "$status")
    echo "$line" >> "$LOG_FILE"
    echo "$line"
    LAST_END_EPOCH="$now_epoch"
    CUR_NAME=""; CUR_START_EPOCH=""; CUR_START_HMS=""
    save_state
}

cmd_summary() {
    local end_epoch end_hms total rto_secs fails result
    load_state
    if [[ -z "$TEST_START_EPOCH" ]]; then
        echo "ERROR: no test has been started" >&2
        exit 1
    fi
    if [[ -n "$CUR_NAME" ]]; then
        echo "WARNING: step \"$CUR_NAME\" is still open; total uses the current time" >&2
        end_epoch=$(date +%s)
    else
        end_epoch="${LAST_END_EPOCH:-$(date +%s)}"
    fi
    end_hms=$(date -d "@$end_epoch" '+%H:%M:%S')
    total=$((end_epoch - TEST_START_EPOCH))
    rto_secs=$((RTO_MINUTES * 60))
    fails=0
    [[ -f "$LOG_FILE" ]] && fails=$(grep -c '| FAIL$' "$LOG_FILE")

    if [[ -f "$LOG_FILE" ]]; then
        cat "$LOG_FILE"
    fi
    echo "----------------------------------------------------------------"
    echo "Test start: $TEST_START_HMS | Test end: $end_hms | Steps: $STEP_COUNT | Failed steps: $fails"
    echo "Total elapsed: $(fmt_duration "$total") | Declared RTO: ${RTO_MINUTES}m 0s"
    if (( total <= rto_secs )); then
        result="PASS"
        echo "RTO RESULT: PASS ($(fmt_duration "$total") <= ${RTO_MINUTES}m 0s)"
    else
        result="FAIL"
        echo "RTO RESULT: FAIL ($(fmt_duration "$total") > ${RTO_MINUTES}m 0s, exceeded by $(fmt_duration $((total - rto_secs))))"
    fi
    [[ "$result" == "PASS" ]]
}

cmd_reset() {
    local stamp
    stamp=$(date '+%Y%m%dT%H%M%S')
    # Archive, never delete: earlier runs are evidence too.
    [[ -f "$LOG_FILE" ]] && mv "$LOG_FILE" "${LOG_FILE%.txt}_archived_${stamp}.txt"
    [[ -f "$STATE_FILE" ]] && mv "$STATE_FILE" "${STATE_FILE}_archived_${stamp}"
    echo "Timer reset; previous log and state archived with suffix _archived_${stamp}"
}

case $# in
    1)
        case "$1" in
            SUMMARY) cmd_summary ;;
            RESET) cmd_reset ;;
            *) usage ;;
        esac
        ;;
    2)
        [[ -z "$1" ]] && usage
        case "$2" in
            START) cmd_start "$1" ;;
            PASS|FAIL) cmd_end "$1" "$2" ;;
            *) usage ;;
        esac
        ;;
    *) usage ;;
esac
