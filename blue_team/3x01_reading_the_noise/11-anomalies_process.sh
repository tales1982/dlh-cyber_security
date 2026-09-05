#!/bin/bash

set -euo pipefail

# --- severity rubric ---
SEV_UNKNOWN_PROCESS="low"
SEV_UNKNOWN_PARENT_CHILD="medium"
SEV_RARE_SPIKE="medium"
SEV_HIGH_RISK="high"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUMMARY_FILE="$SCRIPT_DIR/baseline_summary.json"
LABELED_FILE="$SCRIPT_DIR/labeled_events.json"
OUT_FILE="$SCRIPT_DIR/anomalies_process.json"

ESTART=$(jq -r '.evaluation_window.start' "$SUMMARY_FILE")
EEND=$(jq -r '.evaluation_window.end' "$SUMMARY_FILE")

jq -n \
  --arg estart "$ESTART" --arg eend "$EEND" \
  --arg sev_unknown "$SEV_UNKNOWN_PROCESS" \
  --arg sev_pc "$SEV_UNKNOWN_PARENT_CHILD" \
  --arg sev_rare "$SEV_RARE_SPIKE" \
  --arg sev_risk "$SEV_HIGH_RISK" \
  --slurpfile summary "$SUMMARY_FILE" '
  ($summary[0]) as $s
  | (["powershell.exe","cmd.exe","wscript.exe","mshta.exe","nc","nmap","wget","curl","python3","bash"]) as $watchlist
  | def is_process_label: . == "process_start" or . == "process_stop" or . == "child_process_spawn";
  def basename: (. // "") | (split("\\") | last) | (split("/") | last) | ascii_downcase;
  def host_processes($h): ($s.process.per_host[$h] // [] | map(.process_name));
  def host_pairs($h): ($s.process.parent_child_pairs[$h] // [] | map(.parent + "||" + .child));
  (($s.process.rare_processes // []) | map(select(.total_count < 5)) | map(.process_name)) as $rare_names

  | reduce (inputs | select(.timestamp >= $estart and .timestamp < $eend and (.canonical_label | is_process_label))) as $e
      (
        {unknown: {}, pairs: {}, rare: {}, risk: {}};
        ($e.hostname) as $host
        | ($e.process_name) as $pname
        | ($e.raw_message // "") as $rmsg
        | (if ($rmsg | test("^Process Create: .+ (spawned by|by) .+$")) then
             ($rmsg | capture("^Process Create: (?<child>.+?) (spawned by|by) (?<parent>.+)$"))
           else null end) as $cap
        | (if $host != null and $pname != null then
             (if (host_processes($host) | index($pname) | not) then
                .unknown[$host + "||" + $pname].events = ((.unknown[$host + "||" + $pname].events // []) + [$e.timestamp])
                | .unknown[$host + "||" + $pname].user = (.unknown[$host + "||" + $pname].user // $e.user)
              else . end)
             | (if ($rare_names | index($pname)) then
                  .rare[$host + "||" + $pname].events = ((.rare[$host + "||" + $pname].events // []) + [$e.timestamp])
                  | .rare[$host + "||" + $pname].user = (.rare[$host + "||" + $pname].user // $e.user)
                else . end)
             | (if (($pname | basename) as $b | $watchlist | index($b)) and (host_processes($host) | index($pname) | not) then
                  .risk[$host + "||" + $pname].events = ((.risk[$host + "||" + $pname].events // []) + [$e.timestamp])
                  | .risk[$host + "||" + $pname].user = (.risk[$host + "||" + $pname].user // $e.user)
                else . end)
           else . end)
        | (if $host != null and $cap != null then
             ($cap.parent + "||" + $cap.child) as $pk
             | (if (host_pairs($host) | index($pk) | not) then
                  .pairs[$host + "||" + $pk].events = ((.pairs[$host + "||" + $pk].events // []) + [$e.timestamp])
                  | .pairs[$host + "||" + $pk].parent = $cap.parent
                  | .pairs[$host + "||" + $pk].child = $cap.child
                  | .pairs[$host + "||" + $pk].host = $host
                else . end)
           else . end)
      )
  | . as $r
  | (
      [
        ($r.unknown | to_entries | map(
           (.key | split("||")) as $hk
           | {
               timestamp: (.value.events | sort | .[0]),
               host: $hk[0],
               user: .value.user,
               process_name: $hk[1],
               parent_process_name: null,
               anomaly_type: "unknown_process_for_host",
               severity: $sev_unknown,
               event_refs: (.value.events | sort)
             }
        )),
        ($r.pairs | to_entries | map(
           {
             timestamp: (.value.events | sort | .[0]),
             host: .value.host,
             user: null,
             process_name: .value.child,
             parent_process_name: .value.parent,
             anomaly_type: "unknown_parent_child",
             severity: $sev_pc,
             event_refs: (.value.events | sort)
           }
        )),
        ($r.rare | to_entries | map(select((.value.events | length) > 10)) | map(
           (.key | split("||")) as $hk
           | {
               timestamp: (.value.events | sort | .[0]),
               host: $hk[0],
               user: .value.user,
               process_name: $hk[1],
               parent_process_name: null,
               anomaly_type: "rare_process_spike",
               severity: $sev_rare,
               event_refs: (.value.events | sort)
             }
        )),
        ($r.risk | to_entries | map(
           (.key | split("||")) as $hk
           | {
               timestamp: (.value.events | sort | .[0]),
               host: $hk[0],
               user: .value.user,
               process_name: $hk[1],
               parent_process_name: null,
               anomaly_type: "high_risk_process",
               severity: $sev_risk,
               event_refs: (.value.events | sort)
             }
        ))
      ] | flatten
    )
  | sort_by(.timestamp)
' "$LABELED_FILE" > "$OUT_FILE"

total=$(jq 'length' "$OUT_FILE")
c_unknown=$(jq '[.[] | select(.anomaly_type=="unknown_process_for_host")] | length' "$OUT_FILE")
c_pair=$(jq '[.[] | select(.anomaly_type=="unknown_parent_child")] | length' "$OUT_FILE")
c_rare=$(jq '[.[] | select(.anomaly_type=="rare_process_spike")] | length' "$OUT_FILE")
c_risk=$(jq '[.[] | select(.anomaly_type=="high_risk_process")] | length' "$OUT_FILE")

printf 'evaluation window : %s -> %s\n' "$ESTART" "$EEND"
printf 'unknown_process_for_host : %s\n' "$c_unknown"
printf 'unknown_parent_child     : %s\n' "$c_pair"
printf 'rare_process_spike       : %s\n' "$c_rare"
printf 'high_risk_process        : %s\n' "$c_risk"
printf 'total anomalies          : %s\n' "$total"
echo "anomalies_process.json written"
