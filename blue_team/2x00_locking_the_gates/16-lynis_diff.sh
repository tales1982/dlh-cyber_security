#!/bin/bash
#
# 16-lynis_diff.sh
#
# MedDefense Health Systems - Locking the Gates (2x00)
#
# Sarah Park needs a report that shows which findings disappeared, which
# remain, and whether hardening introduced new issues - not a claim of
# "the score went up," but the itemized evidence behind that claim.
#
# Read-only / generator: compares two already-captured Lynis JSON findings
# files (Task 2's output, before and after hardening) and writes
# hardening_improvement.json. If no post-hardening file is available yet,
# it will generate one itself by running Lynis again and parsing it with
# 2-lynis_parse.sh - this is the same safe, non-destructive Lynis audit
# used in Task 2, just run a second time.
#
# Findings are matched by test_id. A finding present before but not after is
# "resolved"; present in both is "remaining"; present only after is "new"
# (hardening should not introduce new findings - any that show up here need
# explanation, e.g. a newly-installed tool Lynis now has an opinion about).
#
# Usage: ./16-lynis_diff.sh [before_findings.json] [after_findings.json]
#        BEFORE_FINDINGS / AFTER_FINDINGS env vars are equivalent overrides
#        (used by the Task 14 orchestrator to point at its own run's files).

set -uo pipefail

BEFORE_FINDINGS="${BEFORE_FINDINGS:-${1:-}}"
AFTER_FINDINGS="${AFTER_FINDINGS:-${2:-}}"
OUT_JSON="hardening_improvement.json"

find_input() {
    local explicit="$1"; shift
    if [ -n "$explicit" ] && [ -r "$explicit" ]; then echo "$explicit"; return 0; fi
    for c in "$@"; do [ -r "$c" ] && { echo "$c"; return 0; }; done
    return 1
}

BEFORE_FINDINGS="$(find_input "$BEFORE_FINDINGS" "./lynis_findings.json" "../2-the_lynis_audit_parser/lynis_findings.json")" \
    || { echo "Error: pre-hardening lynis_findings.json not found" >&2; exit 1; }

LYNIS_PARSER="../2-the_lynis_audit_parser/2-lynis_parse.sh"
[ -x "$LYNIS_PARSER" ] || LYNIS_PARSER="$(dirname "${BASH_SOURCE[0]}")/../2-the_lynis_audit_parser/2-lynis_parse.sh"

if AFTER_FINDINGS="$(find_input "$AFTER_FINDINGS" "./lynis_post_findings.json" "../2-the_lynis_audit_parser/lynis_post_findings.json")"; then
    : # found an existing post-hardening file
else
    echo "[*] No post-hardening findings file found - running a fresh Lynis audit now..." >&2
    if command -v lynis >/dev/null 2>&1 && [ -x "$LYNIS_PARSER" ]; then
        lynis audit system --quick --no-colors >/dev/null 2>&1 || true
        report="/var/log/lynis-report.dat"
        [ -r "$report" ] || report="$HOME/lynis-report.dat"
        if [ -r "$report" ]; then
            "$LYNIS_PARSER" "$report" > lynis_post_findings.json 2>/dev/null
            AFTER_FINDINGS="lynis_post_findings.json"
        fi
    fi
fi

if [ -z "${AFTER_FINDINGS:-}" ] || [ ! -r "${AFTER_FINDINGS:-/nonexistent}" ]; then
    echo "Error: no post-hardening lynis findings available and none could be generated" >&2
    exit 1
fi

BEFORE_SCORE=$(jq -r '.hardening_index // 0' "$BEFORE_FINDINGS")
AFTER_SCORE=$(jq -r '.hardening_index // 0' "$AFTER_FINDINGS")
DELTA=$((AFTER_SCORE - BEFORE_SCORE))

RESOLVED=$(jq -n --slurpfile b "$BEFORE_FINDINGS" --slurpfile a "$AFTER_FINDINGS" \
    '($b[0].findings // []) as $before | ($a[0].findings // []) as $after |
     ($after | map(.test_id)) as $after_ids |
     [ $before[] | select(.test_id as $t | ($after_ids | index($t)) | not) ]')

REMAINING=$(jq -n --slurpfile b "$BEFORE_FINDINGS" --slurpfile a "$AFTER_FINDINGS" \
    '($b[0].findings // []) as $before | ($a[0].findings // []) as $after |
     ($after | map(.test_id)) as $after_ids |
     [ $before[] | select(.test_id as $t | ($after_ids | index($t))) ]')

NEW=$(jq -n --slurpfile b "$BEFORE_FINDINGS" --slurpfile a "$AFTER_FINDINGS" \
    '($b[0].findings // []) as $before | ($a[0].findings // []) as $after |
     ($before | map(.test_id)) as $before_ids |
     [ $after[] | select(.test_id as $t | ($before_ids | index($t)) | not) ]')

RESOLVED_COUNT=$(jq 'length' <<<"$RESOLVED")
REMAINING_COUNT=$(jq 'length' <<<"$REMAINING")
NEW_COUNT=$(jq 'length' <<<"$NEW")

if [ "$REMAINING_COUNT" -eq 0 ] && [ "$NEW_COUNT" -eq 0 ]; then
    RESIDUAL_SUMMARY="No residual Lynis findings remain outstanding after hardening."
else
    RESIDUAL_SUMMARY="$REMAINING_COUNT finding(s) remain outstanding and $NEW_COUNT new finding(s) appeared post-hardening; see remaining_findings/new_findings for the itemized list and route each through Task 3's remediation queue or an explicit documented deviation."
fi

jq -n \
  --argjson before "$BEFORE_SCORE" --argjson after "$AFTER_SCORE" --argjson delta "$DELTA" \
  --argjson resolved "$RESOLVED" --argjson remaining "$REMAINING" --argjson new "$NEW" \
  --argjson resolved_count "$RESOLVED_COUNT" --argjson remaining_count "$REMAINING_COUNT" \
  --argjson new_count "$NEW_COUNT" --arg residual "$RESIDUAL_SUMMARY" \
  --arg generated "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{
    generated: $generated,
    before_score: $before,
    after_score: $after,
    delta: $delta,
    resolved_findings: $resolved,
    remaining_findings: $remaining,
    new_findings: $new,
    resolved_count: $resolved_count,
    remaining_count: $remaining_count,
    new_count: $new_count,
    residual_risk_summary: $residual
  }' > "$OUT_JSON"

echo "Before: $BEFORE_SCORE"
echo "After: $AFTER_SCORE"
printf 'Delta: %+d\n' "$DELTA"
echo "Findings resolved: $RESOLVED_COUNT"
echo "Findings remaining: $REMAINING_COUNT"
echo "New findings: $NEW_COUNT"
echo "Report saved to: $OUT_JSON"
