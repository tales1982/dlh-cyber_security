# MedDefense SOC Triage Methodology

## Classification Taxonomy
- **true_positive**: the rule fired on activity that is unauthorized, malicious, or otherwise real adversary behavior against a MedDefense asset. Example: `001_ssh_brute_force` firing on repeated SSH auth failures from an external IP with no matching change ticket.
- **false_positive**: the rule fired correctly, but the specific instance is authorized or expected; the detection logic is sound, the instance is not a threat. Example: `002_windows_offhours_privileged_logon` firing on a scheduled patch-management service account logon.
- **benign**: the activity never carried any risk and needs no tuning action, unlike a false_positive. Example: `004_recon_tool_execution` firing on a vulnerability-scanner host IT already excluded from the asset inventory, but the exclusion has not reached the rule yet.
- **escalated**: a true_positive packaged into an incident record (timeline, IOCs, affected assets, ATT&CK mapping, containment recommendation) for Tier 2. Example: `003_interpreter_abuse` chained into the RR-02 off-hours PHI scenario becomes an escalated incident, not a standalone alert.

## Priority Ordering Rule
Work the queue in descending `priority_score` order. Break ties by `rule_level` (critical > high > medium > low), then by asset criticality. Override: any alert on a CRITICAL asset or PHI/PCI `data_classification` jumps to the front regardless of score; any alert with a malicious IOC hit is worked before any alert without one at the same band.

## Evidence Requirement
Every classification must cite the specific enriched event fields that drove it: `event_category`, `process_name`/`command_line`, `user`, `src_ip`/`dst_ip`, and `asset.criticality`. A justification that names no field and value is not acceptable documentation.

## Escalation Criteria
Escalate to Tier 2 when any of the following is true:
- `classification == true_positive` AND `asset.criticality == CRITICAL`
- at least one `ioc_hit.reputation == malicious`
- the rule maps to an ATT&CK tactic in {TA0006 credential access, TA0008 lateral movement, TA0010 exfiltration}
- two or more alerts correlate to the same host or user inside the rule's timeframe

## SLA
- critical: 15 minutes
- high: 30 minutes
- medium: 60 minutes
- low: same shift (end of day)

## Documentation Standard
Every ticket must include:
- [ ] `ticket_id`, `alert_id`
- [ ] `classification`
- [ ] `justification` citing a specific field and value
- [ ] `evidence_refs` (at least one `event_ref`)
- [ ] `ioc_hits`
- [ ] `attack_techniques`
- [ ] `recommended_action`
- [ ] `analyst_time_seconds`
- [ ] `created_at` (ISO 8601 UTC)
