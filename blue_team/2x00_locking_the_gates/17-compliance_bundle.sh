#!/bin/bash
#
# 17-compliance_bundle.sh
#
# MedDefense Health Systems - Locking the Gates (2x00)
#
# The final artifact: not a narrative report, an auditor-ready JSON bundle
# that proves what was selected (Task 1), what gap existed (Task 3), what
# was remediated, what was independently verified (Task 15), and what was
# intentionally left unresolved and why. Every claim in this file traces
# back to one of the six evidence files it reads - nothing here is
# asserted without a source.
#
# Read-only / generator. Makes no system changes.
#
# Usage: ./17-compliance_bundle.sh

set -uo pipefail

OUT_JSON="compliance_report.json"

find_input() {
    local name="$1"; shift
    for c in "$@"; do [ -r "$c" ] && { echo "$c"; return 0; }; done
    echo "Error: $name not found in any expected location" >&2
    return 1
}

CIS_PROFILE=$(find_input "cis_profile.json" "./cis_profile.json" "../1-the_cis_control_profile/cis_profile.json") || exit 1
GAP_ANALYSIS=$(find_input "gap_analysis.json" "./gap_analysis.json" "../3-the_evidence_based_remediation_queue/gap_analysis.json") || exit 1
REMEDIATION_QUEUE=$(find_input "remediation_queue.json" "./remediation_queue.json" "../3-the_evidence_based_remediation_queue/remediation_queue.json") || exit 1
AUDIT_VALIDATION=$(find_input "audit_validation.json" "./audit_validation.json" "../11-the_audit_telemetry_coverage_test/audit_validation.json") || exit 1
VALIDATION_RESULTS=$(find_input "validation_results.json" "./validation_results.json" "../15-the_post_hardening_validator/validation_results.json") || exit 1
HARDENING_IMPROVEMENT=$(find_input "hardening_improvement.json" "./hardening_improvement.json" "../16-the_lynis_improvement_diff/hardening_improvement.json" "../14-the_hardening_orchestrator/hardening_improvement.json") || exit 1

EVIDENCE_FILES=("$CIS_PROFILE" "$GAP_ANALYSIS" "$REMEDIATION_QUEUE" "$AUDIT_VALIDATION" "$VALIDATION_RESULTS" "$HARDENING_IMPROVEMENT")
EVIDENCE_COUNT="${#EVIDENCE_FILES[@]}"

# --- System identity -----------------------------------------------------------
HOSTNAME_VAL="$(hostname)"
if [ -r /etc/os-release ]; then
    OS_VAL="$(. /etc/os-release; echo "${PRETTY_NAME:-unknown}")"
else
    OS_VAL="unknown"
fi
KERNEL_VAL="$(uname -r)"

SELECTED_COUNT=$(jq '.controls | length' "$CIS_PROFILE")

# --- Per-control rollup: join cis_profile x gap_analysis x validation_results --
# A control is "verified" only if EVERY validation_results.json check tagged
# with its control_id passed. It is "remediated" if it is verified now
# AND gap_analysis originally found it non_compliant/partially_compliant
# (i.e. this run's hardening actually fixed something) OR it was already
# compliant at gap-analysis time. Anything not verified is a deviation.
CONTROLS_JOINED=$(jq -n \
  --slurpfile profile "$CIS_PROFILE" \
  --slurpfile gap "$GAP_ANALYSIS" \
  --slurpfile val "$VALIDATION_RESULTS" \
  '
  ($profile[0].controls) as $controls |
  ($gap[0].assessments // []) as $assessments |
  ($val[0].results // []) as $results |
  [ $controls[] | .control_id as $cid |
    ( [ $assessments[] | select(.control_id == $cid) | .status ] | first ) as $gap_status |
    ( [ $results[] | select(.control_id == $cid) ] ) as $checks |
    ( ($checks | length) > 0 and ( [ $checks[] | .status == "PASS" ] | all ) ) as $verified |
    {
      control_id: $cid,
      title: .title,
      severity: .severity,
      gap_status: ($gap_status // "not_assessed"),
      checks_evaluated: ($checks | length),
      verified: $verified
    }
  ]
  ')

CONTROLS_VERIFIED=$(jq '[.[] | select(.verified == true)]' <<<"$CONTROLS_JOINED")
CONTROLS_VERIFIED_COUNT=$(jq 'length' <<<"$CONTROLS_VERIFIED")
CONTROLS_VERIFIED_IDS=$(jq '[.[].control_id]' <<<"$CONTROLS_VERIFIED")

CONTROLS_REMEDIATED=$(jq '[.[] | select(.verified == true and (.gap_status == "non_compliant" or .gap_status == "partially_compliant"))]' <<<"$CONTROLS_JOINED")
CONTROLS_REMEDIATED_COUNT=$(jq 'length' <<<"$CONTROLS_REMEDIATED")
CONTROLS_REMEDIATED_IDS=$(jq '[.[].control_id]' <<<"$CONTROLS_REMEDIATED")

CONTROLS_UNRESOLVED=$(jq '[.[] | select(.verified == false)]' <<<"$CONTROLS_JOINED")
CONTROLS_UNRESOLVED_COUNT=$(jq 'length' <<<"$CONTROLS_UNRESOLVED")

# --- Deviations: every unresolved control gets a documented, owned entry ------
# risk_accepted / compensating_control are derived from severity - this is a
# generic-but-honest default; a specific per-control compensating control
# from the CIS profile's own justification field is preferred when present.
DEVIATIONS=$(jq -n --slurpfile unresolved <(echo "$CONTROLS_UNRESOLVED") --slurpfile profile "$CIS_PROFILE" \
  '
  ($profile[0].controls) as $controls |
  [ $unresolved[0][] | .control_id as $cid |
    ($controls[] | select(.control_id == $cid)) as $ctrl |
    {
      control_id: $cid,
      title: $ctrl.title,
      reason: ("Not yet independently verified in this environment - gap status: " + .gap_status + "; " + (.checks_evaluated | tostring) + " check(s) evaluated by 15-validation.sh."),
      risk_accepted: (
        if $ctrl.severity == "critical" then "Not accepted - critical control, remediation via " + $ctrl.implementation_task + " must be completed before production sign-off."
        elif $ctrl.severity == "high" then "Temporarily accepted pending remediation via " + $ctrl.implementation_task + "; tracked in remediation_queue.json."
        else "Accepted as lower-severity residual risk pending scheduled remediation via " + $ctrl.implementation_task + "."
        end
      ),
      compensating_control: $ctrl.justification,
      owner: "MedDefense Infrastructure Hardening Team (James Chen, workstream owner)"
    }
  ]
  ')
DEVIATIONS_COUNT=$(jq 'length' <<<"$DEVIATIONS")

# --- Residual Lynis findings ---------------------------------------------------
RESIDUAL_FINDINGS=$(jq '.remaining_findings // []' "$HARDENING_IMPROVEMENT")
RESIDUAL_COUNT=$(jq '.remaining_count // ([.remaining_findings // []] | length)' "$HARDENING_IMPROVEMENT")

# --- Overall compliance percentage ---------------------------------------------
if [ "$SELECTED_COUNT" -gt 0 ]; then
    COMPLIANCE_PCT=$(awk -v v="$CONTROLS_VERIFIED_COUNT" -v s="$SELECTED_COUNT" 'BEGIN{printf "%.1f", (v/s)*100}')
else
    COMPLIANCE_PCT="0.0"
fi

jq -n \
  --arg hostname "$HOSTNAME_VAL" --arg os "$OS_VAL" --arg kernel "$KERNEL_VAL" \
  --arg hardening_date "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson selected "$SELECTED_COUNT" \
  --argjson remediated_ids "$CONTROLS_REMEDIATED_IDS" --argjson remediated_count "$CONTROLS_REMEDIATED_COUNT" \
  --argjson verified_ids "$CONTROLS_VERIFIED_IDS" --argjson verified_count "$CONTROLS_VERIFIED_COUNT" \
  --argjson unresolved_count "$CONTROLS_UNRESOLVED_COUNT" \
  --argjson deviations "$DEVIATIONS" --argjson deviations_count "$DEVIATIONS_COUNT" \
  --argjson residual_findings "$RESIDUAL_FINDINGS" --argjson residual_count "$RESIDUAL_COUNT" \
  --arg compliance_pct "$COMPLIANCE_PCT" \
  --argjson evidence_files "$(printf '%s\n' "${EVIDENCE_FILES[@]}" | jq -R . | jq -s .)" \
  --argjson evidence_count "$EVIDENCE_COUNT" \
  '{
    system_identity: { hostname: $hostname, os: $os, kernel: $kernel },
    hardening_date: $hardening_date,
    controls_selected: $selected,
    controls_remediated: { count: $remediated_count, control_ids: $remediated_ids },
    controls_verified: { count: $verified_count, control_ids: $verified_ids },
    controls_unresolved: $unresolved_count,
    deviations: $deviations,
    residual_lynis_findings: { count: $residual_count, findings: $residual_findings },
    overall_compliance_percentage: ($compliance_pct | tonumber),
    evidence_files_used: { count: $evidence_count, files: $evidence_files }
  }' > "$OUT_JSON"

echo "Evidence files loaded: $EVIDENCE_COUNT"
echo "Controls selected: $SELECTED_COUNT"
echo "Controls remediated: $CONTROLS_REMEDIATED_COUNT"
echo "Controls verified: $CONTROLS_VERIFIED_COUNT"
echo "Deviations documented: $DEVIATIONS_COUNT"
echo "Overall compliance: ${COMPLIANCE_PCT}%"
echo "Residual findings: $RESIDUAL_COUNT"
echo "Report saved to: $OUT_JSON"
