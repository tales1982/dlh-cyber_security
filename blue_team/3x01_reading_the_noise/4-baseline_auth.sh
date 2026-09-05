#!/bin/bash

set -euo pipefail

BASELINE_DAYS="${BASELINE_DAYS:-7}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LABELED_FILE="$SCRIPT_DIR/labeled_events.json"
OUT_FILE="$SCRIPT_DIR/baseline_auth.json"

set +o pipefail
WSTART=$(jq -r '.timestamp' "$LABELED_FILE" | sort | head -n 1)
set -o pipefail
WEND=$(date -u -d "$WSTART + ${BASELINE_DAYS} days" +"%Y-%m-%dT%H:%M:%SZ")

jq -n --arg wstart "$WSTART" --arg wend "$WEND" '
  def hour_of: .[11:13] | tonumber;

  reduce (inputs | select(.timestamp >= $wstart and .timestamp < $wend)) as $e
    (
      {
        per_host: {}, per_user: {}, accounts: {},
        biz_hours: {}, off_hours: {},
        biz_succ: 0, biz_fail: 0, off_succ: 0, off_fail: 0,
        fail_by_ip_hour: {}
      };
      ($e.canonical_label) as $label
      | ($e.hostname) as $host
      | ($e.user) as $user
      | ($e.timestamp | hour_of) as $h
      | ($h >= 6 and $h < 18) as $biz
      | ($e.timestamp[0:13]) as $hbucket
      | (if $host != null and (["login_success","login_failure","logout","account_lockout","privilege_escalation"] | index($label)) then
            .per_host[$host][$label] = ((.per_host[$host][$label] // 0) + 1)
          else . end)
      | (if $user != null then
            .accounts[$user] = true
            | (if $label == "login_success" then .per_user[$user].success = ((.per_user[$user].success // 0) + 1) else . end)
            | (if $label == "login_failure" then .per_user[$user].failure = ((.per_user[$user].failure // 0) + 1) else . end)
          else . end)
      | (if $biz then
           .biz_hours[$hbucket] = true
           | (if $label == "login_success" then .biz_succ += 1 else . end)
           | (if $label == "login_failure" then .biz_fail += 1 else . end)
         else
           .off_hours[$hbucket] = true
           | (if $label == "login_success" then .off_succ += 1 else . end)
           | (if $label == "login_failure" then .off_fail += 1 else . end)
         end)
      | (if $label == "login_failure" and $e.src_ip != null then
           ($e.src_ip + "|" + $hbucket) as $key
           | .fail_by_ip_hour[$key] = ((.fail_by_ip_hour[$key] // 0) + 1)
         else . end)
    )
  | . as $r
  | def avg_round($n; $d): (if $d > 0 then (($n / $d) * 100 | round) / 100 else 0 end);
  {
    window: {start: $wstart, end: $wend},
    per_host: $r.per_host,
    per_user: ($r.per_user | to_entries | map({user: .key, success: (.value.success // 0), failure: (.value.failure // 0)}) | sort_by(.user)),
    known_accounts: ($r.accounts | keys | sort),
    business_hours_avg: {
      success: avg_round($r.biz_succ; ($r.biz_hours | length)),
      failure: avg_round($r.biz_fail; ($r.biz_hours | length))
    },
    offhours_avg: {
      success: avg_round($r.off_succ; ($r.off_hours | length)),
      failure: avg_round($r.off_fail; ($r.off_hours | length))
    },
    max_failures_1h_window: ([$r.fail_by_ip_hour[]] | if length > 0 then max else 0 end)
  }
' "$LABELED_FILE" > "$OUT_FILE"

host_count=$(jq '.per_host | length' "$OUT_FILE")
account_count=$(jq '.known_accounts | length' "$OUT_FILE")
biz_success=$(jq '.business_hours_avg.success' "$OUT_FILE")
biz_failure=$(jq '.business_hours_avg.failure' "$OUT_FILE")
off_success=$(jq '.offhours_avg.success' "$OUT_FILE")
off_failure=$(jq '.offhours_avg.failure' "$OUT_FILE")
max_1h=$(jq '.max_failures_1h_window' "$OUT_FILE")

printf 'baseline window : %s -> %s\n' "$WSTART" "$WEND"
printf 'hosts           : %s\n' "$host_count"
printf 'known accounts  : %s\n' "$account_count"
printf 'business hours  : %s success/h  |  %s failure/h\n' "$biz_success" "$biz_failure"
printf 'off hours       : %s success/h  |  %s failure/h\n' "$off_success" "$off_failure"
printf 'max 1h src_ip failures : %s\n' "$max_1h"
echo "baseline_auth.json written"
