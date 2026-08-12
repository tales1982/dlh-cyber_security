#!/bin/bash
#
# 8-linux_telemetry_quality.sh
#
# MedDefense Health Systems - Eyes on the Endpoint (2x02), Task 8.
#
# This project is cross-platform - if Windows telemetry (Task 4) is
# measured strictly but Linux telemetry (Task 7) is only exported, the
# handoff becomes uneven. This script applies the exact same standard to
# linux_events_export.json: Event Distribution by category and source
# type, hour-by-hour Time Coverage, Gap Detection (>30 minutes silent),
# Field Completeness on the fields analysts actually triage (command
# line for execve, source IP/user for SSH events, path for auditd file
# events), and a single weighted 0-100 Quality Score with a
# good/acceptable/poor assessment.
#
# Read-only. Uses jq for all JSON parsing. Makes no configuration changes.
#
# Usage: ./8-linux_telemetry_quality.sh

set -euo pipefail

IN_JSON="${1:-linux_events_export.json}"
OUT_JSON="${2:-linux_telemetry_quality.json}"
GAP_THRESHOLD_MINUTES=30

if [ ! -r "$IN_JSON" ]; then
    echo "Error: $IN_JSON not found - run 7-linux_export.sh first." >&2
    exit 1
fi

echo "[*] Analyzing $IN_JSON..."

jq -n --slurpfile export "$IN_JSON" \
  --arg generated "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson gap_threshold "$GAP_THRESHOLD_MINUTES" '
  ($export[0].events // []) as $events |
  ($events | length) as $total |

  # --- Event Distribution: count and percentage per event_category and per source_type ------------
  ([$events[].event_category] | group_by(.) | map({
      key: .[0], count: length,
      percentage: (if $total > 0 then ((length / $total) * 10000 | round) / 100 else 0 end)
    })) as $event_distribution |
  ([$events[].source_type] | group_by(.) | map({
      key: .[0], count: length,
      percentage: (if $total > 0 then ((length / $total) * 10000 | round) / 100 else 0 end)
    })) as $source_distribution |

  # --- Time Coverage: events per hour, hours with/without events -----------------------------------
  ([$events[].timestamp | select(. != null and . != "") | .[0:13] + ":00:00Z"] | sort) as $hour_buckets |
  ($hour_buckets | unique) as $distinct_hours |
  ([$events[].timestamp | select(. != null and . != "")] | sort) as $sorted_ts |
  # Hour-bucket count spanned by the range, inclusive of both ends - NOT
  # the raw elapsed duration in hours. A range like 14:46-16:32 touches 3
  # calendar-hour buckets (14, 15, 16) despite being under 2 hours of
  # actual elapsed time; comparing hours_with_events (a bucket count)
  # against an elapsed-duration total_hours let the "with" side exceed
  # the "total" side whenever events cluster near an hour boundary.
  ( if ($distinct_hours | length) > 0 then
      (($distinct_hours[-1] | strptime("%Y-%m-%dT%H:%M:%SZ") | mktime) -
       ($distinct_hours[0]  | strptime("%Y-%m-%dT%H:%M:%SZ") | mktime)) / 3600 | floor + 1
    else 0 end
  ) as $total_hours_raw |
  ([$total_hours_raw, 1] | max) as $total_hours |
  ($distinct_hours | length) as $hours_with_events |
  ($total_hours - $hours_with_events) as $hours_without_events |
  ($hour_buckets | group_by(.) | map({key: .[0], count: length})) as $events_per_hour |

  # --- Gap Detection: consecutive-event gaps longer than the threshold ------------------------------
  ( [ range(0; ($sorted_ts | length) - 1) as $i |
      ( ($sorted_ts[$i+1] | strptime("%Y-%m-%dT%H:%M:%SZ") | mktime) -
        ($sorted_ts[$i]   | strptime("%Y-%m-%dT%H:%M:%SZ") | mktime) ) as $delta_s |
      ($delta_s / 60) as $delta_m |
      select($delta_m > $gap_threshold) |
      { gap_start: $sorted_ts[$i], gap_end: $sorted_ts[$i+1], duration_minutes: ((($delta_m * 10) | round) / 10) }
    ]
  ) as $gaps |
  ($gaps | length) as $gap_count |
  ( if $gap_count > 0 then ([$gaps[].duration_minutes] | max) else 0 end ) as $largest_gap_minutes |

  # --- Field Completeness -------------------------------------------------------------------------
  # Measures: timestamp/hostname/source_type/event_category on every event,
  # command line completeness for execve, source IP/user for SSH events,
  # and path + operation (the nametype - CREATE/DELETE/NORMAL/PARENT -
  # 7-linux_export.sh captures alongside the path) completeness for
  # auditd file events.
  def pct($n; $d): if $d > 0 then ((($n / $d) * 10000) | round) / 100 else 100.0 end;
  ([$events[] | select(.timestamp != null and .timestamp != "")] | length) as $ts_ok |
  ([$events[] | select(.hostname != null and .hostname != "")] | length) as $host_ok |
  ([$events[] | select(.source_type != null and .source_type != "")] | length) as $st_ok |
  ([$events[] | select(.event_category != null and .event_category != "")] | length) as $ec_ok |
  ([$events[] | select(.event_category == "execve")]) as $execve_events |
  ([$execve_events[] | select((.field1 // "") != "" or (.field2 // "") != "")] | length) as $execve_cmdline_ok |
  ([$events[] | select(.source_type == "auth.log" and (.event_category | test("^ssh_login")))]) as $ssh_events |
  ([$ssh_events[] | select((.source_ip // "") != "" and (.user // "") != "")] | length) as $ssh_ok |
  ([$events[] | select(.source_type == "audit.log" and .event_category == "file_access")]) as $file_events |
  ([$file_events[] | select((.field1 // "") != "")] | length) as $file_path_ok |
  ([$file_events[] | select((.field2 // "") != "")] | length) as $file_operation_ok |

  pct($ts_ok; $total) as $timestamp_pct |
  pct($host_ok; $total) as $hostname_pct |
  pct($st_ok; $total) as $source_type_pct |
  pct($ec_ok; $total) as $event_category_pct |
  pct($execve_cmdline_ok; ($execve_events | length)) as $execve_cmdline_pct |
  pct($ssh_ok; ($ssh_events | length)) as $ssh_source_ip_pct |
  pct($file_path_ok; ($file_events | length)) as $file_path_pct |
  pct($file_operation_ok; ($file_events | length)) as $file_operation_pct |

  # --- Quality Score: weighted 0-100 ----------------------------------------------------------------
  (if $total_hours > 0 then ($hours_with_events / $total_hours) * 100 else 0 end) as $time_coverage_score |
  ([100 - ($gap_count * 10), 0] | max) as $gap_score |
  ( ($time_coverage_score * 0.20) + ($gap_score * 0.15) +
    ($execve_cmdline_pct * 0.20) + ($ssh_source_ip_pct * 0.20) + ($file_path_pct * 0.15) +
    ($event_category_pct * 0.10)
  ) as $weighted_score |
  ((($weighted_score * 10) | round) / 10) as $quality_score |
  ( if $quality_score >= 90 then "good" elif $quality_score >= 70 then "acceptable" else "poor" end ) as $assessment |

  {
    generated: $generated,
    source_export: "'"$IN_JSON"'",
    total_events: $total,
    event_distribution: $event_distribution,
    source_type_distribution: $source_distribution,
    time_coverage: {
      total_hours: $total_hours,
      hours_with_events: $hours_with_events,
      hours_without_events: $hours_without_events,
      events_per_hour: $events_per_hour
    },
    gap_detection: {
      threshold_minutes: $gap_threshold,
      gap_count: $gap_count,
      largest_gap_minutes: $largest_gap_minutes,
      gaps: $gaps
    },
    field_completeness: {
      timestamp_pct: $timestamp_pct,
      hostname_pct: $hostname_pct,
      source_type_pct: $source_type_pct,
      event_category_pct: $event_category_pct,
      execve_command_line_pct: $execve_cmdline_pct,
      ssh_source_ip_user_pct: $ssh_source_ip_pct,
      auditd_file_path_pct: $file_path_pct,
      auditd_file_operation_pct: $file_operation_pct
    },
    quality_score: $quality_score,
    assessment: $assessment
  }
' > "$OUT_JSON"

TOTAL_EVENTS=$(jq -r '.total_events' "$OUT_JSON")
HOURS_WITH=$(jq -r '.time_coverage.hours_with_events' "$OUT_JSON")
HOURS_TOTAL=$(jq -r '.time_coverage.total_hours' "$OUT_JSON")
GAP_COUNT=$(jq -r '.gap_detection.gap_count' "$OUT_JSON")
LARGEST_GAP=$(jq -r '.gap_detection.largest_gap_minutes' "$OUT_JSON")
EXECVE_PCT=$(jq -r '.field_completeness.execve_command_line_pct' "$OUT_JSON")
SSH_PCT=$(jq -r '.field_completeness.ssh_source_ip_user_pct' "$OUT_JSON")
FILE_PCT=$(jq -r '.field_completeness.auditd_file_path_pct' "$OUT_JSON")
FILE_OP_PCT=$(jq -r '.field_completeness.auditd_file_operation_pct' "$OUT_JSON")
SCORE=$(jq -r '.quality_score' "$OUT_JSON")
ASSESSMENT=$(jq -r '.assessment' "$OUT_JSON")

echo "Total events: $TOTAL_EVENTS"
echo "Hours with events: $HOURS_WITH/$HOURS_TOTAL"
if [ "$GAP_COUNT" -eq 0 ]; then
    echo "No gaps detected"
else
    echo "Gaps detected: $GAP_COUNT (largest: ${LARGEST_GAP} minutes)"
fi
echo "execve command_line completeness: ${EXECVE_PCT}%"
echo "SSH source_ip completeness: ${SSH_PCT}%"
echo "auditd file path completeness: ${FILE_PCT}%"
echo "auditd file operation completeness: ${FILE_OP_PCT}%"
echo "Quality score: ${SCORE}% ($ASSESSMENT)"
echo "Report saved to: $OUT_JSON"
