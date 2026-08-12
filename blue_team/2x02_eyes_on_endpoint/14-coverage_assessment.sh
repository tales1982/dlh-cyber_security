#!/bin/bash
#
# 14-coverage_assessment.sh
#
# MedDefense Health Systems - Eyes on the Endpoint (2x02), Task 14.
#
# The single metadata file that travels with the telemetry handoff
# package - total events by platform/source/category, the detection
# matrix summary (Tasks 10 and 12), ATT&CK coverage pulled straight from
# 1-sysmon_coverage_matrix.json (which already carries covered/partial/
# blind and a tuning recommendation per technique), a Known Gaps list
# built from every partial/blind technique and every [MISSED] detection
# matrix entry, and a Quality Summary. The confidence rating is
# deliberately capped at "acceptable" whenever any ATT&CK technique is
# blind - a real, undetected gap outweighs a high average quality score,
# and the SOC reading this file needs to know that, not a rounded-up
# average.
#
# Read-only. Uses jq for all JSON processing. Makes no configuration changes.
#
# Usage: ./14-coverage_assessment.sh

set -euo pipefail

# Reads the handoff package Task 13 built: telemetry_handoff/windows_events.json,
# telemetry_handoff/linux_events.json and telemetry_handoff/attack_ground_truth.json.
HANDOFF_DIR="${HANDOFF_DIR:-telemetry_handoff}"
WINDOWS_EVENTS="$HANDOFF_DIR/windows_events.json"
LINUX_EVENTS="$HANDOFF_DIR/linux_events.json"
GROUND_TRUTH="$HANDOFF_DIR/attack_ground_truth.json"
WINDOWS_MATRIX="${WINDOWS_MATRIX:-windows_detection_matrix.json}"
LINUX_MATRIX="${LINUX_MATRIX:-linux_detection_matrix.json}"
WINDOWS_QUALITY="${WINDOWS_QUALITY:-windows_telemetry_quality.json}"
LINUX_QUALITY="${LINUX_QUALITY:-linux_telemetry_quality.json}"
SYSMON_COVERAGE="${SYSMON_COVERAGE:-sysmon_coverage_matrix.json}"
OUT_JSON="${1:-telemetry_coverage_assessment.json}"

for f in "$WINDOWS_EVENTS" "$LINUX_EVENTS" "$GROUND_TRUTH" "$WINDOWS_MATRIX" "$LINUX_MATRIX" \
         "$WINDOWS_QUALITY" "$LINUX_QUALITY" "$SYSMON_COVERAGE"; do
    if [ ! -r "$f" ]; then
        echo "Error: required input not found: $f" >&2
        exit 1
    fi
done

echo "[*] Loading telemetry handoff package..."

WINDOWS_COUNT=$(jq '.events | length' "$WINDOWS_EVENTS")
LINUX_COUNT=$(jq '.events | length' "$LINUX_EVENTS")
GROUND_TRUTH_ACTIONS=$(jq '.total_actions' "$GROUND_TRUTH")

echo "Windows events: $WINDOWS_COUNT"
echo "Linux events: $LINUX_COUNT"
echo "Ground truth actions: $GROUND_TRUTH_ACTIONS"

# --- Total events: by platform / source type / event category --------------------------------------
BY_SOURCE_TYPE=$(jq -s '
  (.[0].events + .[1].events) | group_by(.source_type) | map({key: .[0].source_type, count: length})
' "$WINDOWS_EVENTS" "$LINUX_EVENTS")
BY_EVENT_CATEGORY=$(jq -s '
  (.[0].events + .[1].events) | group_by(.event_category) | map({key: .[0].event_category, count: length})
' "$WINDOWS_EVENTS" "$LINUX_EVENTS")

# --- Detection matrix summary: total simulated actions, captured, missed, and multi-source detections, combining Task 10 (Windows) + Task 12 (Linux) -------------------------
WIN_ACTIONS_TOTAL=$(jq '.actions_total' "$WINDOWS_MATRIX")
WIN_ACTIONS_CAPTURED=$(jq '.actions_captured' "$WINDOWS_MATRIX")
WIN_MULTI_SOURCE=$(jq '.multi_source_actions' "$WINDOWS_MATRIX")
LIN_ACTIONS_TOTAL=$(jq '.actions_total' "$LINUX_MATRIX")
LIN_ACTIONS_CAPTURED=$(jq '.actions_captured' "$LINUX_MATRIX")
LIN_MULTI_SOURCE=$(jq '.multi_source_actions' "$LINUX_MATRIX")

TOTAL_SIMULATED=$((WIN_ACTIONS_TOTAL + LIN_ACTIONS_TOTAL))
TOTAL_CAPTURED=$((WIN_ACTIONS_CAPTURED + LIN_ACTIONS_CAPTURED))
TOTAL_MISSED=$((TOTAL_SIMULATED - TOTAL_CAPTURED))
TOTAL_MULTI_SOURCE=$((WIN_MULTI_SOURCE + LIN_MULTI_SOURCE))

echo "Detection matrix: $TOTAL_CAPTURED/$TOTAL_SIMULATED captured"

# --- ATT&CK coverage: pulled directly from 1-sysmon_coverage_matrix.json ---------------------------
ATTACK_COVERED=$(jq '.covered_count' "$SYSMON_COVERAGE")
ATTACK_PARTIAL=$(jq '.partial_count' "$SYSMON_COVERAGE")
ATTACK_BLIND=$(jq '.blind_count' "$SYSMON_COVERAGE")
ATTACK_BY_TECHNIQUE=$(jq '[.matrix[] | {technique_id, technique_name, coverage_status, source: "Sysmon", enabled_event_ids}]' "$SYSMON_COVERAGE")

echo "ATT&CK covered: $ATTACK_COVERED"
echo "ATT&CK partial: $ATTACK_PARTIAL"
echo "ATT&CK blind: $ATTACK_BLIND"

# --- Known gaps: every non-covered ATT&CK technique + every [MISSED] detection matrix entry --------
GAPS_FROM_ATTACK=$(jq '
  [.matrix[] | select(.coverage_status != "covered") |
    { description: ("ATT&CK " + .technique_id + " (" + .technique_name + ") is " + .coverage_status),
      impacted_platform: "windows",
      impacted_technique: .technique_id,
      reason: .status_reason,
      recommended_instrumentation_improvement: .recommendation }]
' "$SYSMON_COVERAGE")

GAPS_FROM_WINDOWS_MATRIX=$(jq '
  [.detection_matrix[] | select(.status == "[MISSED]") |
    { description: ("Action not captured: " + .action),
      impacted_platform: "windows",
      impacted_technique: (.source + " EID " + (.event_id | tostring)),
      reason: "No matching event found in the expected source within the search window.",
      recommended_instrumentation_improvement: "Review whether the expected Event ID is actually enabled/unfiltered for the trigger conditions this action exercised." }]
' "$WINDOWS_MATRIX")

GAPS_FROM_LINUX_MATRIX=$(jq '
  [.detection_matrix[] | select(.status == "[MISSED]") |
    { description: ("Action not captured: " + .action),
      impacted_platform: "linux",
      impacted_technique: (.source + " key=" + .audit_key),
      reason: "No matching ausearch/log event found in the expected source within the search window.",
      recommended_instrumentation_improvement: "Review whether the auditd rule for this key watches the syscall/permission actually exercised (e.g. reads are not caught by a write-only -p wa watch)." }]
' "$LINUX_MATRIX")

KNOWN_GAPS=$(jq -s '.[0] + .[1] + .[2]' \
    <(echo "$GAPS_FROM_ATTACK") <(echo "$GAPS_FROM_WINDOWS_MATRIX") <(echo "$GAPS_FROM_LINUX_MATRIX"))

# --- Quality summary + final handoff confidence -----------------------------------------------------
WINDOWS_SCORE=$(jq '.quality_score' "$WINDOWS_QUALITY")
LINUX_SCORE=$(jq '.quality_score' "$LINUX_QUALITY")

# A blind ATT&CK technique is a real, undetected gap - it caps confidence
# at "acceptable" regardless of how high the two quality scores are, since
# an average score can hide a total absence of visibility for one
# technique. Only when nothing is blind does the average-of-scores
# threshold apply.
AVERAGE_SCORE=$(echo "$WINDOWS_SCORE $LINUX_SCORE" | awk '{printf "%.1f", ($1 + $2) / 2}')
if [ "$ATTACK_BLIND" -gt 0 ]; then
    if awk -v s="$AVERAGE_SCORE" 'BEGIN{exit !(s < 70)}'; then
        CONFIDENCE="poor"
    else
        CONFIDENCE="acceptable"
    fi
elif awk -v s="$AVERAGE_SCORE" 'BEGIN{exit !(s >= 90)}'; then
    CONFIDENCE="good"
elif awk -v s="$AVERAGE_SCORE" 'BEGIN{exit !(s >= 70)}'; then
    CONFIDENCE="acceptable"
else
    CONFIDENCE="poor"
fi

echo "Windows quality: $WINDOWS_SCORE"
echo "Linux quality: $LINUX_SCORE"
echo "Confidence: $CONFIDENCE"

jq -n \
  --arg generated "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson windows_events "$WINDOWS_COUNT" --argjson linux_events "$LINUX_COUNT" \
  --argjson by_source_type "$BY_SOURCE_TYPE" --argjson by_event_category "$BY_EVENT_CATEGORY" \
  --argjson total_simulated "$TOTAL_SIMULATED" --argjson total_captured "$TOTAL_CAPTURED" \
  --argjson total_missed "$TOTAL_MISSED" --argjson total_multi_source "$TOTAL_MULTI_SOURCE" \
  --argjson attack_covered "$ATTACK_COVERED" --argjson attack_partial "$ATTACK_PARTIAL" \
  --argjson attack_blind "$ATTACK_BLIND" --argjson attack_by_technique "$ATTACK_BY_TECHNIQUE" \
  --argjson known_gaps "$KNOWN_GAPS" \
  --argjson windows_score "$WINDOWS_SCORE" --argjson linux_score "$LINUX_SCORE" \
  --arg confidence "$CONFIDENCE" \
  '{
    generated: $generated,
    total_events: {
      by_platform: { windows: $windows_events, linux: $linux_events, total: ($windows_events + $linux_events) },
      by_source_type: $by_source_type,
      by_event_category: $by_event_category
    },
    detection_matrix_summary: {
      total_simulated_actions: $total_simulated,
      captured_actions: $total_captured,
      missed_actions: $total_missed,
      multi_source_detections: $total_multi_source
    },
    attack_coverage: {
      covered_techniques: $attack_covered,
      partially_covered_techniques: $attack_partial,
      blind_techniques: $attack_blind,
      by_technique: $attack_by_technique
    },
    known_gaps: $known_gaps,
    quality_summary: {
      windows_score: $windows_score,
      linux_score: $linux_score,
      final_handoff_confidence: $confidence
    }
  }' > "$OUT_JSON"

echo "Report saved to: $OUT_JSON"
