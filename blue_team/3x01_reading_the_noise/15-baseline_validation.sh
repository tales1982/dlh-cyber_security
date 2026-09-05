#!/bin/bash

set -euo pipefail

SELF_CHECK_THRESHOLD="${SELF_CHECK_THRESHOLD:-5}"
MIN_SIGNAL_TO_NOISE="${MIN_SIGNAL_TO_NOISE:-3.0}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUMMARY_FILE="$SCRIPT_DIR/baseline_summary.json"
OUT_FILE="$SCRIPT_DIR/baseline_validation.json"

for f in "$SCRIPT_DIR/10-anomalies_auth.sh" "$SCRIPT_DIR/11-anomalies_process.sh" "$SCRIPT_DIR/12-anomalies_network.sh" "$SUMMARY_FILE"; do
  if [[ ! -f "$f" ]]; then
    echo "missing required input: $f" >&2
    exit 1
  fi
done

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

SELF_SUMMARY="$WORKDIR/self_check_summary.json"
jq '.evaluation_window = {
      start: .baseline_window.start,
      end: .baseline_window.end,
      duration_hours: (.baseline_window.duration_days * 24)
    }' "$SUMMARY_FILE" > "$SELF_SUMMARY"

# self-check: scan the baseline window itself with the same detectors/thresholds
SUMMARY_FILE="$SELF_SUMMARY" OUT_FILE="$SCRIPT_DIR/self_check_auth.json" "$SCRIPT_DIR/10-anomalies_auth.sh" >/dev/null
SUMMARY_FILE="$SELF_SUMMARY" OUT_FILE="$SCRIPT_DIR/self_check_process.json" "$SCRIPT_DIR/11-anomalies_process.sh" >/dev/null
SUMMARY_FILE="$SELF_SUMMARY" OUT_FILE="$SCRIPT_DIR/self_check_network.json" "$SCRIPT_DIR/12-anomalies_network.sh" >/dev/null

# live-check: scan the real evaluation window (day 8)
OUT_FILE="$SCRIPT_DIR/live_check_auth.json" "$SCRIPT_DIR/10-anomalies_auth.sh" >/dev/null
OUT_FILE="$SCRIPT_DIR/live_check_process.json" "$SCRIPT_DIR/11-anomalies_process.sh" >/dev/null
OUT_FILE="$SCRIPT_DIR/live_check_network.json" "$SCRIPT_DIR/12-anomalies_network.sh" >/dev/null

jq -n \
  --argjson self_threshold "$SELF_CHECK_THRESHOLD" \
  --argjson min_ratio "$MIN_SIGNAL_TO_NOISE" \
  --slurpfile self_auth "$SCRIPT_DIR/self_check_auth.json" \
  --slurpfile self_process "$SCRIPT_DIR/self_check_process.json" \
  --slurpfile self_network "$SCRIPT_DIR/self_check_network.json" \
  --slurpfile live_auth "$SCRIPT_DIR/live_check_auth.json" \
  --slurpfile live_process "$SCRIPT_DIR/live_check_process.json" \
  --slurpfile live_network "$SCRIPT_DIR/live_check_network.json" '
  def by_type: group_by(.anomaly_type) | map({key: .[0].anomaly_type, value: length}) | from_entries;

  (($self_auth[0]) + ($self_process[0]) + ($self_network[0])) as $self_all
  | (($live_auth[0]) + ($live_process[0]) + ($live_network[0])) as $live_all
  | ($self_all | length) as $self_total
  | ($live_all | length) as $live_total
  | (($live_total | tonumber) / ([$self_total, 1] | max)) as $ratio
  | (($self_total <= $self_threshold) and ($ratio >= $min_ratio)) as $pass
  | {
      self_check_total: $self_total,
      live_check_total: $live_total,
      signal_to_noise_ratio: (($ratio * 100 | round) / 100),
      self_check_by_type: ($self_all | by_type),
      live_check_by_type: ($live_all | by_type),
      thresholds: {
        self_check_max: $self_threshold,
        min_signal_to_noise_ratio: $min_ratio
      },
      verdict: (if $pass then "pass" else "fail" end)
    }
' > "$OUT_FILE"

self_total=$(jq '.self_check_total' "$OUT_FILE")
live_total=$(jq '.live_check_total' "$OUT_FILE")
ratio=$(jq '.signal_to_noise_ratio' "$OUT_FILE")
verdict=$(jq -r '.verdict' "$OUT_FILE")

printf 'self-check anomalies (baseline window): %s\n' "$self_total"
printf 'live-check anomalies (evaluation win ): %s\n' "$live_total"
printf 'signal-to-noise ratio                : %s\n' "$ratio"
printf 'verdict                              : %s\n' "$verdict"
echo "baseline_validation.json written"

if [[ "$verdict" == "pass" ]]; then
  exit 0
else
  exit 1
fi
