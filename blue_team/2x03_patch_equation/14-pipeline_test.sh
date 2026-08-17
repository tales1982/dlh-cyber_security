#!/bin/bash
#
# 14-pipeline_test.sh
#
# MedDefense Health Systems - The Patch Equation (2x03)
#
# The pipeline worked against today's data. Will it work against tomorrow's
# advisory? This swaps in a simulated CVE feed, runs the full pipeline in
# dry-run mode and checks that the plan it produces matches what is
# expected - proving the pipeline reacts correctly to new input without
# any code change, not just that it ran without crashing.
#
# Usage: sudo ./14-pipeline_test.sh [output.json]

set -uo pipefail

OUT_JSON="${1:-pipeline_test_results.json}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

resolve_input() {
    local name="$1" candidate
    for candidate in "./${name}" "${SCRIPT_DIR}/${name}" "${SCRIPT_DIR}/../${name}"; do
        [ -f "$candidate" ] && { echo "$candidate"; return 0; }
    done
    echo "$name"
}

CVE_FEED="$(resolve_input cve_feed.json)"
CVE_FEED_SIM="$(resolve_input cve_feed.simulated.json)"
PIPELINE_SCRIPT="$(resolve_input 13-patch_pipeline.sh)"
EXPECTED_PLAN="$(resolve_input patch_plan.expected.json)"

if [ ! -f "$CVE_FEED_SIM" ]; then
    echo "error: cannot find cve_feed.simulated.json" >&2
    exit 1
fi
if [ ! -f "$PIPELINE_SCRIPT" ]; then
    echo "error: cannot find 13-patch_pipeline.sh" >&2
    exit 1
fi

STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "[*] Scenario: simulated CVE advisory"

# Saves the current cve_feed.json to cve_feed.json.bak, restored on exit.
BACKUP="${CVE_FEED}.bak"
# shellcheck disable=SC2329  # invoked indirectly via `trap ... EXIT` below
restore_feed() {
    if [ -f "$BACKUP" ]; then
        mv -f "$BACKUP" "$CVE_FEED"
        echo "[*] Restoring cve_feed.json...                OK"
    fi
}
trap restore_feed EXIT

if [ -f "$CVE_FEED" ]; then
    cp -f "$CVE_FEED" "$BACKUP"
    echo "[*] Backing up cve_feed.json...              OK"
fi
cp -f "$CVE_FEED_SIM" "$CVE_FEED"
echo "[*] Injecting cve_feed.simulated.json...     OK"

echo "[*] Running pipeline (PIPELINE_TEST=1)..."
PIPELINE_TEST=1 bash "$PIPELINE_SCRIPT" pipeline_run.json
PIPELINE_EXIT=$?

STAGES_OK="false"
if [ -f pipeline_run.json ]; then
    status="$(jq -r '.pipeline_status' pipeline_run.json 2>/dev/null)"
    all_stages_have_artifacts="true"
    if [[ "$status" == "ok" || "$status" == "deferred" ]]; then
        while IFS= read -r art; do
            [ -z "$art" ] && continue
            [ -s "$art" ] || all_stages_have_artifacts="false"
        done < <(jq -r '.artifacts // {} | .[]' pipeline_run.json 2>/dev/null)
        [ "$all_stages_have_artifacts" = "true" ] && STAGES_OK="true"
    fi
fi

# --- Compare patch_plan.json to the frozen expected baseline ---------------
echo "[*] Comparing patch_plan.json to expected..."
PLAN_MATCHES="false"
DIFF_JSON="[]"
if [ -f patch_plan.json ] && [ -f "$EXPECTED_PLAN" ]; then
    # Normalize the one genuinely time-varying field (generated_at, a
    # timestamp) to a fixed placeholder before comparing, rather than
    # dropping it, so a real mismatch still shows the field in the diff.
    TIMESTAMP_PLACEHOLDER="NORMALIZED_TIMESTAMP"
    NORM_ACTUAL="$(jq --arg ts "$TIMESTAMP_PLACEHOLDER" '.generated_at = $ts' patch_plan.json)"
    NORM_EXPECTED="$(jq --arg ts "$TIMESTAMP_PLACEHOLDER" '.generated_at = $ts' "$EXPECTED_PLAN")"
    if [ "$NORM_ACTUAL" = "$NORM_EXPECTED" ]; then
        PLAN_MATCHES="true"
        echo "  match"
    else
        DIFF_TEXT="$(diff -u <(jq -S . <<<"$NORM_EXPECTED") <(jq -S . <<<"$NORM_ACTUAL"))"
        DIFF_JSON="$(jq -R -s 'split("\n") | map(select(length>0))' <<<"$DIFF_TEXT")"
        echo "  DIFFERS"
    fi
else
    echo "  (no expected baseline found at $EXPECTED_PLAN - cannot compare)"
fi

FINISHED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
VERDICT="fail"
[ "$PIPELINE_EXIT" -eq 0 ] && [ "$STAGES_OK" = "true" ] && [ "$PLAN_MATCHES" = "true" ] && VERDICT="pass"

jq -n \
    --arg scenario "simulated_cve_advisory" --arg started "$STARTED_AT" --arg finished "$FINISHED_AT" \
    --argjson stages_ok "$STAGES_OK" --argjson plan_matches "$PLAN_MATCHES" \
    --argjson diff "$DIFF_JSON" --arg verdict "$VERDICT" \
    '{scenario: $scenario, started_at: $started, finished_at: $finished,
      stages_ok: $stages_ok, plan_matches_expected: $plan_matches, diff: $diff, verdict: $verdict}' > "$OUT_JSON"

echo "VERDICT: $VERDICT"
echo "Report saved to: $OUT_JSON"

# Exit 0 on pass, exit 1 on fail.
if [ "$VERDICT" = "pass" ]; then
    exit 0
else
    exit 1
fi
