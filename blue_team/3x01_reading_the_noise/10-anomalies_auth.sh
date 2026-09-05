#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUMMARY_FILE="$SCRIPT_DIR/baseline_summary.json"
LABELED_FILE="$SCRIPT_DIR/labeled_events.json"
OUT_FILE="$SCRIPT_DIR/anomalies_auth.json"

BSTART=$(jq -r '.baseline_window.start' "$SUMMARY_FILE")
BEND=$(jq -r '.baseline_window.end' "$SUMMARY_FILE")
ESTART=$(jq -r '.evaluation_window.start' "$SUMMARY_FILE")
EEND=$(jq -r '.evaluation_window.end' "$SUMMARY_FILE")
KNOWN_ACCOUNTS=$(jq -c '.auth.known_accounts // []' "$SUMMARY_FILE")
MAX_1H=$(jq -r '.auth.max_failures_1h_window // 0' "$SUMMARY_FILE")
FAIL_MULT=$(jq -r '.thresholds.failure_rate_multiplier.value // 3' "$SUMMARY_FILE")
SURGE_N=$(jq -r '.thresholds.privilege_escalation_surge_threshold.value // 2' "$SUMMARY_FILE")
PRIV_BASELINE=$(jq -c '.auth.per_host // {} | map_values(.privilege_escalation // 0)' "$SUMMARY_FILE")

# users whose baseline login_success events were exclusively during business hours (06:00-17:59)
BIZONLY=$(jq -n --arg bstart "$BSTART" --arg bend "$BEND" '
  reduce (inputs | select(.timestamp >= $bstart and .timestamp < $bend and .canonical_label == "login_success" and .user != null)) as $e
    ({biz: {}, off: {}};
      ($e.timestamp[11:13] | tonumber) as $h
      | if $h >= 6 and $h < 18 then .biz[$e.user] = true else .off[$e.user] = true end
    )
  | [(.biz | keys[]) as $u | select(.off[$u] | not) | $u]
' "$LABELED_FILE")

jq -n \
  --arg estart "$ESTART" --arg eend "$EEND" \
  --argjson known "$KNOWN_ACCOUNTS" \
  --argjson bizonly "$BIZONLY" \
  --argjson max1h "$MAX_1H" \
  --argjson mult "$FAIL_MULT" \
  --argjson surge_n "$SURGE_N" \
  --argjson priv_baseline "$PRIV_BASELINE" '
  def sevrank: {critical: 3, high: 2, medium: 1, low: 0}[.];

  reduce (inputs | select(.timestamp >= $estart and .timestamp < $eend)) as $e
    (
      {unknown: {}, burst: {}, offhours: {}, surge: {}};
      (["login_success","login_failure","logout","privilege_escalation","account_lockout"]) as $auth_labels
      | (if ($e.user != null and ($auth_labels | index($e.canonical_label)) and ($known | index($e.user) | not)) then
           .unknown[$e.user].events = ((.unknown[$e.user].events // []) + [$e.timestamp])
           | .unknown[$e.user].host = (.unknown[$e.user].host // $e.hostname)
           | .unknown[$e.user].src_ip = (.unknown[$e.user].src_ip // $e.src_ip)
         else . end)
      | (if ($e.canonical_label == "login_failure" and $e.src_ip != null) then
           ($e.src_ip + "|" + $e.timestamp[0:13]) as $k
           | .burst[$k].events = ((.burst[$k].events // []) + [$e.timestamp])
           | .burst[$k].src_ip = $e.src_ip
           | .burst[$k].host = (.burst[$k].host // $e.hostname)
         else . end)
      | (if ($e.canonical_label == "login_success" and $e.user != null and ($bizonly | index($e.user))) then
           ($e.timestamp[11:13] | tonumber) as $h
           | (if ($h < 6 or $h >= 18) then
                .offhours[$e.user].events = ((.offhours[$e.user].events // []) + [$e.timestamp])
                | .offhours[$e.user].host = (.offhours[$e.user].host // $e.hostname)
              else . end)
         else . end)
      | (if ($e.canonical_label == "privilege_escalation") then
           .surge[$e.hostname].events = ((.surge[$e.hostname].events // []) + [$e.timestamp])
         else . end)
    )
  | . as $r
  | (
      [
        ($r.unknown | to_entries | map(
           {
             timestamp: (.value.events | sort | .[0]),
             host: .value.host,
             user: .key,
             src_ip: .value.src_ip,
             anomaly_type: "unknown_account",
             baseline_value: 0,
             observed_value: (.value.events | length),
             severity: "medium",
             event_refs: (.value.events | sort)
           }
        )),
        ($r.burst | to_entries | map(select((.value.events | length) > ($max1h * $mult))) | map(
           {
             timestamp: (.value.events | sort | .[0]),
             host: .value.host,
             user: null,
             src_ip: .value.src_ip,
             anomaly_type: "failure_rate_burst",
             baseline_value: $max1h,
             observed_value: (.value.events | length),
             severity: "high",
             event_refs: (.value.events | sort)
           }
        )),
        ($r.offhours | to_entries | map(
           {
             timestamp: (.value.events | sort | .[0]),
             host: .value.host,
             user: .key,
             src_ip: null,
             anomaly_type: "offhours_login",
             baseline_value: "business_hours_only",
             observed_value: (.value.events | length),
             severity: "medium",
             event_refs: (.value.events | sort)
           }
        )),
        ($r.surge | to_entries
          | map(select((($priv_baseline[.key] // 0) == 0) and ((.value.events | length) > $surge_n)))
          | map(
           {
             timestamp: (.value.events | sort | .[0]),
             host: .key,
             user: null,
             src_ip: null,
             anomaly_type: "privilege_escalation_surge",
             baseline_value: 0,
             observed_value: (.value.events | length),
             severity: "critical",
             event_refs: (.value.events | sort)
           }
        ))
      ] | flatten
    )
  | sort_by([-(.severity | sevrank), .timestamp])
' "$LABELED_FILE" > "$OUT_FILE"

total=$(jq 'length' "$OUT_FILE")
unknown_c=$(jq '[.[] | select(.anomaly_type=="unknown_account")] | length' "$OUT_FILE")
burst_c=$(jq '[.[] | select(.anomaly_type=="failure_rate_burst")] | length' "$OUT_FILE")
offhours_c=$(jq '[.[] | select(.anomaly_type=="offhours_login")] | length' "$OUT_FILE")
surge_c=$(jq '[.[] | select(.anomaly_type=="privilege_escalation_surge")] | length' "$OUT_FILE")

printf 'evaluation window  : %s -> %s\n' "$ESTART" "$EEND"
printf 'unknown_account           : %s\n' "$unknown_c"
printf 'failure_rate_burst        : %s\n' "$burst_c"
printf 'offhours_login            : %s\n' "$offhours_c"
printf 'privilege_escalation_surge: %s\n' "$surge_c"
printf 'total anomalies           : %s\n' "$total"
echo "anomalies_auth.json written"
