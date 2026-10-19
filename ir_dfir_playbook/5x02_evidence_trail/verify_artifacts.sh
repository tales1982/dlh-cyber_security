#!/usr/bin/env bash
# verify_artifacts.sh - integrity gate for case LH-2026-0414-01 / IR-2026-0414-01
#
# Run before EVERY analysis session. If any artifact fails, the session does not start.
#
#   First run  : hashes.txt does not exist -> compute SHA-256 of all three artifacts,
#                write hashes.txt (read-only), status BASELINE_SET.
#   Next runs  : recompute SHA-256, compare with hashes.txt, print [PASS]/[FAIL].
#   Every run  : append one event per artifact to verification_log.txt.
#
# Exit codes: 0 = all PASS (or baseline written), 1 = at least one FAIL, 2 = setup error.
#
# Environment (optional):
#   ARTIFACT_DIR  directory holding the artifacts   (default: current directory)
#   HASH_FILE     baseline manifest                 (default: hashes.txt)
#   LOG_FILE      append-only verification log      (default: verification_log.txt)
#   ACTOR         investigator name for the log     (default: $USER)

set -u

ARTIFACT_DIR="${ARTIFACT_DIR:-.}"
HASH_FILE="${HASH_FILE:-hashes.txt}"
LOG_FILE="${LOG_FILE:-verification_log.txt}"
ACTOR="${ACTOR:-${USER:-$(id -un 2>/dev/null || echo unknown)}}"

# Artifact registry: same IDs as chain_of_custody.md
IDS=("ART-001" "ART-002" "ART-003")
NAMES=("wst-ws-031.dd" "wst-ws-031.mem" "wst-ws-017.mem")

if ! command -v sha256sum >/dev/null 2>&1; then
    echo "ERROR: sha256sum not found" >&2
    exit 2
fi

utc_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

log_event() {
    # timestamp | actor | artifact_id | artifact | result | expected | computed
    printf '%s | actor=%s | %s | %s | %s | expected=%s | computed=%s\n' \
        "$(utc_now)" "$ACTOR" "$1" "$2" "$3" "$4" "$5" >> "$LOG_FILE"
}

compute_hash() {
    local f="$ARTIFACT_DIR/$1"
    if [[ -f "$f" && -r "$f" ]]; then
        sha256sum -- "$f" | awk '{print $1}'
    else
        echo "MISSING"
    fi
}

# ---------------------------------------------------------------------------
# First run: establish the baseline
# ---------------------------------------------------------------------------
if [[ ! -f "$HASH_FILE" ]]; then
    declare -a HASHES
    for i in "${!NAMES[@]}"; do
        h="$(compute_hash "${NAMES[$i]}")"
        if [[ "$h" == "MISSING" ]]; then
            echo "[ERROR] ${IDS[$i]} ${NAMES[$i]} not found in $ARTIFACT_DIR; baseline NOT written" >&2
            log_event "${IDS[$i]}" "${NAMES[$i]}" "BASELINE_ERROR" "none" "MISSING"
            exit 2
        fi
        HASHES[i]="$h"
    done

    {
        echo "# Baseline SHA-256 - case LH-2026-0414-01 - set $(utc_now) by $ACTOR"
        for i in "${!NAMES[@]}"; do
            printf '%s  %s\n' "${HASHES[$i]}" "${NAMES[$i]}"
        done
    } > "$HASH_FILE"
    chmod 0444 "$HASH_FILE" 2>/dev/null

    for i in "${!NAMES[@]}"; do
        echo "[BASELINE_SET] ${IDS[$i]} ${NAMES[$i]} sha256=${HASHES[$i]}"
        log_event "${IDS[$i]}" "${NAMES[$i]}" "BASELINE_SET" "none" "${HASHES[$i]}"
    done
    echo "Baseline written to $HASH_FILE. Run again to verify."
    exit 0
fi

# ---------------------------------------------------------------------------
# Verification run
# ---------------------------------------------------------------------------
fail=0
for i in "${!NAMES[@]}"; do
    id="${IDS[$i]}"
    name="${NAMES[$i]}"
    expected="$(awk -v n="$name" '$0 !~ /^#/ && $2 == n {print $1; exit}' "$HASH_FILE")"
    computed="$(compute_hash "$name")"

    if [[ -z "$expected" ]]; then
        expected="NOT_IN_BASELINE"
    fi

    if [[ "$expected" == "$computed" && "$computed" != "MISSING" ]]; then
        result="PASS"
    else
        result="FAIL"
        fail=1
    fi

    echo "[$result] $id $name expected=$expected computed=$computed"
    log_event "$id" "$name" "$result" "$expected" "$computed"
done

if [[ $fail -ne 0 ]]; then
    echo "VERIFICATION FAILED - do not start analysis; append a DEVIATION entry to chain_of_custody.md" >&2
    exit 1
fi

echo "ALL ARTIFACTS VERIFIED"
exit 0
