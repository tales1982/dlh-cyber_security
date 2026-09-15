# MedDefense Tool-Agnostic Investigation Playbook v1

## Purpose

This playbook encodes the SOC's investigation workflow as a sequence of steps that survives a change of SIEM vendor. Any Tier 1 analyst should be able to follow it against a CLI pipeline, a live dashboard, or a pre-exported evidence set and reach the same finding.

## Scope

Covers host- and network-centric alert triage: credential access, off-hours privileged logon, and anomalous network egress from a known or suspected asset. It does not cover malware reverse engineering, packet-level forensics, or vendor procurement mechanics — those are separate playbooks.

## Inputs

The analyst must have access to: enriched events (normalized host/network log), asset inventory (criticality, data classification, owner), network baseline/zone map, the detection catalog (Sigma rules), the triage package (prior classifications), and IOC context (threat intel enrichment). Missing any of these turns an investigation into guesswork.

## Workflow Steps

| # | Step | CLI Action | Dashboard / Export Action |
|---|------|-----------|---------------------------|
| 1 | Verify toolkit and inputs | Run tool_check script; confirm jq/yq/sigma-cli and handoff dirs exist | Confirm dashboard reachable, or export files staged and non-empty |
| 2 | Load the scenario manifest | `jq` the manifest for host, time window, IOCs | Same manifest; note the equivalent KQL/Lucene filter |
| 3 | Scope events | `jq select(hostname==H and timestamp in window)` | Type KQL/Lucene query, set time range in Discover |
| 4 | Resolve missing structured fields | Pattern-match `raw_message` when a field (src_ip, event_id) is null | Expand the document; the same field is often already structured |
| 5 | Cross-reference context | Join asset_inventory / network_zones / ioc_context by hand | Check `agent.labels`; fall back to context files if a label is absent |
| 6 | Reconstruct the sequence | Sort matched events by timestamp; compute intervals | Sort by `@timestamp` in Discover; note gaps between hits |
| 7 | Record and write the finding | Track actions/fields/elapsed time; write JSON against the locked schema | Same — click path substitutes for the command list |

## Field Name Translation Table

| Normalized | Wazuh |
|---|---|
| timestamp | @timestamp |
| event_ref | _id |
| hostname | agent.name |
| src_ip | source.ip |
| dst_ip | destination.ip |
| src_port | source.port |
| dst_port | destination.port |
| user | user.name |
| process_name | process.name |
| event_id | winlog.event_id |

## Query Decomposition Rule

Every investigative question decomposes into three parts: **filter** (which records), **aggregation** (how they're counted or grouped), and **time window** (over what period).

| Part | jq | Sigma | KQL | Lucene |
|---|---|---|---|---|
| Filter | `select(.hostname==$h)` | `selection: {hostname: H}` | `hostname:"H"` | `hostname:H` |
| Aggregation | `group_by(.src_ip)\|map(length)` | `condition: selection \| count() by src_ip > 5` | (visualize/Lens count) | `facet` (via aggregations API) |
| Time window | `select(.timestamp>=$s and .timestamp<=$e)` | `timeframe: 120s` | `timestamp:[S TO E]` | `timestamp:[S TO E]` |

## Finding Schema (short form)

`finding_id, scenario_id, interface, investigation_start, investigation_end, time_to_first_answer_seconds, actions[], fields_touched[], event_refs[], attack_techniques[], hypothesis (≤2 sentences), confidence, created_at`.

## Exit Criteria

An investigation is complete when: every key field in the finding schema is populated (no placeholder values), `event_refs` is non-empty and traceable back to the source file, the hypothesis names a verdict the analyst can defend in one breath, and the finding JSON validates against the locked schema before it is filed.

## Known Pitfalls

- A field being present in the schema does not mean it is populated: `src_ip` was null on every `linux_text` auth record this week, with the real IP recoverable only from `raw_message` — always sample real records before trusting a field name.
- The normalized CLI schema carries no `event_id` field, even though scenario manifests' own example queries assume one; Windows/Sysmon event type must instead be inferred from `raw_message` phrasing conventions (e.g., "File created:", "Network connection:").
- A Wazuh document's `agent.labels` is not guaranteed to carry every asset attribute (it lacked `data_classification` in this export); always keep the asset inventory as a fallback join, not an afterthought.
- Dashboard-export Markdown files may use CRLF line endings, which silently defeats blank-line filters in `awk`/`sed` unless stripped with `tr -d '\r'` first.
- `jq` reserves words like `end`, `if`, and `then`; passing `--arg end ...` produces a cryptic "expecting IDENT" parse error — never name a `--arg` after a `jq` keyword.
