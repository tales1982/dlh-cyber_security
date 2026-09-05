#!/bin/bash

set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
DATA_FILE="$HANDOFF_DIR/data/enriched_events.json"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TAXONOMY_FILE="$SCRIPT_DIR/event_taxonomy.json"
LABELED_FILE="$SCRIPT_DIR/labeled_events.json"

cat > "$TAXONOMY_FILE" <<'EOF'
[
  {"source_type": "windows_json", "match": {"event_category": "privilege_escalation"}, "label": "privilege_escalation"},
  {"source_type": "windows_json", "match": {"event_category": "authentication", "action": "success"}, "label": "login_success"},
  {"source_type": "windows_json", "match": {"event_category": "authentication", "action": "failure"}, "label": "login_failure"},
  {"source_type": "windows_json", "match": {"event_category": "audit", "raw_message": "An account was logged off.*"}, "label": "logout"},
  {"source_type": "windows_json", "match": {"event_category": "audit", "raw_message": "A user account was locked out.*"}, "label": "account_lockout"},
  {"source_type": "windows_json", "match": {"event_category": "audit", "raw_message": "Audit event 4688"}, "label": "process_start"},
  {"source_type": "windows_json", "match": {"event_category": "audit", "raw_message": "Audit event 4689"}, "label": "process_stop"},
  {"source_type": "windows_json", "match": {"event_category": "audit", "raw_message": "Audit event 5140"}, "label": "file_read_sensitive"},
  {"source_type": "windows_json", "match": {"event_category": "audit", "raw_message": "Process Create:*"}, "label": "child_process_spawn"},
  {"source_type": "windows_json", "match": {"event_category": "audit", "raw_message": "Network connection:*"}, "label": "network_connection_outbound"},
  {"source_type": "windows_json", "match": {"event_category": "audit", "raw_message": "Sysmon Event 11"}, "label": "file_write_sensitive"},
  {"source_type": "windows_json", "match": {"event_category": "audit", "raw_message": "Sysmon Event 23"}, "label": "file_write_sensitive"},
  {"source_type": "windows_json", "match": {"event_category": "audit", "raw_message": "Sysmon Event 22"}, "label": "network_connection_outbound"},
  {"source_type": "windows_json", "match": {"event_category": "audit", "raw_message": "Audit event 4670"}, "label": "file_permission_change"},
  {"source_type": "windows_json", "match": {"event_category": "process", "process_name": "Microsoft-Windows-PowerShell"}, "label": "child_process_spawn"},
  {"source_type": "windows_json", "match": {"event_category": "process", "raw_message": "Module 2 test action: sc.exe create TestSvcM2 binPath=C:\\test\\svc.exe"}, "label": "process_start"},
  {"source_type": "windows_json", "match": {"event_category": "process", "raw_message": "Module 2 test action: Get-Process | Export-Csv C:\\Temp\\procs.csv"}, "label": "file_write_sensitive"},
  {"source_type": "windows_json", "match": {"event_category": "file", "raw_message": "Module 2 test action: copy C:\\Users\\analyst\\test_file.txt C:\\Temp\\"}, "label": "file_write_sensitive"},
  {"source_type": "windows_json", "match": {"event_category": "network", "raw_message": "Module 2 test action: Test-NetConnection -ComputerName srv-dc-01 -Port 445"}, "label": "network_connection_outbound"},

  {"source_type": "linux_text", "match": {"event_category": "authentication", "process_name": "sudo"}, "label": "privilege_escalation"},
  {"source_type": "linux_text", "match": {"event_category": "authentication", "process_name": "sshd", "action": "success"}, "label": "login_success"},
  {"source_type": "linux_text", "match": {"event_category": "authentication", "process_name": "sshd", "action": "failure"}, "label": "login_failure"},
  {"source_type": "linux_text", "match": {"event_category": "authentication", "process_name": "sshd", "action": null}, "label": "logout"},
  {"source_type": "linux_text", "match": {"event_category": "authentication", "process_name": "su", "action": "success"}, "label": "login_success"},
  {"source_type": "linux_text", "match": {"event_category": "authentication", "process_name": "su", "action": null}, "label": "logout"},
  {"source_type": "linux_text", "match": {"event_category": "authentication", "process_name": "login", "action": "success"}, "label": "login_success"},
  {"source_type": "linux_text", "match": {"event_category": "authentication", "process_name": "login", "action": null}, "label": "logout"},
  {"source_type": "linux_text", "match": {"event_category": "authentication", "process_name": "polkitd", "action": "success"}, "label": "login_success"},
  {"source_type": "linux_text", "match": {"event_category": "authentication", "process_name": "polkitd", "action": null}, "label": "logout"},
  {"source_type": "linux_text", "match": {"event_category": "authentication", "action": "success"}, "label": "login_success"},
  {"source_type": "linux_text", "match": {"event_category": "authentication", "action": "failure"}, "label": "login_failure"},

  {"source_type": "linux_text", "match": {"event_category": "audit", "action": "success"}, "label": "login_success"},
  {"source_type": "linux_text", "match": {"event_category": "audit", "action": "failure"}, "label": "login_failure"},

  {"source_type": "linux_text", "match": {"event_category": "process", "process_name": "execve"}, "label": "child_process_spawn"},
  {"source_type": "linux_text", "match": {"event_category": "process", "process_name": "open"}, "label": "file_read_sensitive"},
  {"source_type": "linux_text", "match": {"event_category": "process", "process_name": "read"}, "label": "file_read_sensitive"},
  {"source_type": "linux_text", "match": {"event_category": "process", "process_name": "write"}, "label": "file_write_sensitive"},
  {"source_type": "linux_text", "match": {"event_category": "process", "process_name": "bind"}, "label": "network_connection_inbound"},
  {"source_type": "linux_text", "match": {"event_category": "process", "process_name": "connect"}, "label": "network_connection_outbound"},
  {"source_type": "linux_text", "match": {"event_category": "process", "process_name": "CRON"}, "label": "process_start"},
  {"source_type": "linux_text", "match": {"event_category": "process", "process_name": "cron"}, "label": "process_start"},
  {"source_type": "linux_text", "match": {"event_category": "process", "raw_message": "type=SERVICE_START*"}, "label": "process_start"},
  {"source_type": "linux_text", "match": {"event_category": "process", "raw_message": "type=SERVICE_STOP*"}, "label": "process_stop"},

  {"source_type": "firewall", "match": {"action": "BLOCK"}, "label": "network_blocked"},
  {"source_type": "firewall", "match": {"action": "ALLOW", "src_zone": "INTERNET"}, "label": "network_connection_inbound"},
  {"source_type": "firewall", "match": {"action": "ALLOW"}, "label": "network_connection_outbound"},

  {"source_type": "pcap", "match": {"event_category": "network_flow", "src_zone": "INTERNET"}, "label": "network_connection_inbound"},
  {"source_type": "pcap", "match": {"event_category": "network_flow"}, "label": "network_connection_outbound"},

  {"source_type": "suricata", "match": {"event_category": "network_alert"}, "label": "network_alert"}
]
EOF

jq -c --slurpfile rules "$TAXONOMY_FILE" '
  ($rules[0]) as $taxonomy
  | . as $ev
  | (
      $taxonomy
      | map(select(
          $ev.source_type == .source_type
          and (.match | to_entries | all(
            . as $e
            | $ev[$e.key] as $v
            | if ($e.value | type) == "string" and ($e.value | endswith("*"))
              then ($v != null and ($v | tostring | startswith($e.value[0:-1])))
              else $v == $e.value
              end
          ))
        ))
      | .[0].label // "unlabeled"
    ) as $label
  | $ev + {canonical_label: $label}
' "$DATA_FILE" > "$LABELED_FILE"

rule_count=$(jq 'length' "$TAXONOMY_FILE")
total=$(wc -l < "$LABELED_FILE")
unlabeled=$(jq -c 'select(.canonical_label=="unlabeled")' "$LABELED_FILE" | wc -l)
labeled=$((total - unlabeled))

printf 'taxonomy rules         : %s\n' "$rule_count"
printf 'records labeled        : %s\n' "$labeled"
printf 'records unlabeled      : %s\n' "$unlabeled"
printf 'canonical label distribution (top 10):\n'
jq -r '.canonical_label' "$LABELED_FILE" \
  | sort \
  | uniq -c \
  | sort -k1,1rn \
  | head -n 10 \
  | awk '{c=$1; $1=""; sub(/^ /,""); printf "  %-25s %s\n", $0, c}'

echo "event_taxonomy.json written"
echo "labeled_events.json written"
