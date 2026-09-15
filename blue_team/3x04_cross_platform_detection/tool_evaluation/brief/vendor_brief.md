# SIEM Vendor Evaluation Brief — CLI Pipeline vs. Wazuh Dashboard/Export

## Purpose

This brief answers whether MedDefense's SOC should standardize on the existing CLI pipeline or the Wazuh dashboard as the primary analyst interface. It is grounded in eight structured findings produced by investigating the same four incidents through both interfaces this week, not in vendor literature.

## Evaluation Methodology

Four incidents (one known anchor and three fresh scenarios — credential theft, off-hours PHI logon, medical-IoT egress) were each investigated twice: once via `jq`/`sigma-cli` against the 3x00-3x03 evidence handoff, once via pre-exported Wazuh search results and dashboard-workflow traces covering the same 339,882-event index. Each investigation produced a locked-schema finding recording elapsed time, actions taken, fields touched, and event references. Two caveats bound this data: `time_to_first_answer_seconds` measures script wall-clock, not a human's dashboard click-through time, and the two interfaces' `actions` arrays differ in granularity (CLI records command-level steps; export records the finer-grained click path prescribed by the task). Neither number should be read as a precise productivity multiplier — the qualitative findings below are the load-bearing evidence.

## Findings Summary

Across the 8 findings (`comparison/workflow_comparison.json`): CLI totaled 70s / 19 actions across 4 investigations (avg 17.5s, median 21s); Wazuh export totaled 3s / 26 actions (avg 0.75s, median 1s). Confidence distribution was identical between interfaces (high=3, medium=1, low=0) — neither interface changed the analyst's verdict, only the path to it. Per-scenario deltas (`comparison/tradeoff_table.json`) favored the export in all four cases, by 5-22 seconds.

## Strengths and Weaknesses per Interface

**CLI pipeline.** Fully scriptable, version-controlled, and reproducible — the same command run twice gives the same answer, and nothing depends on a running container or license seat. Its weakness surfaced directly in the data: the anchor and scenario_a trade-off rows are both attributed to `native_field_surface` — the CLI's flat schema had a null `src_ip` on every `linux_text` record and no `event_id` field at all, forcing brittle `raw_message` pattern-matching that a schema change would silently break.

**Wazuh dashboard/export.** Structured fields (`winlog.event_id`, `source.ip`) were reliably present where the CLI schema dropped them, which is exactly the advantage the `native_field_surface` attribution captures in 3 of 4 scenarios. But its indexing is not uniformly complete either: the scenario_b trade-off row is attributed to `context_join_ergonomics` because `agent.labels` lacked `data_classification`, forcing the same fallback join to `asset_inventory.json` that the CLI needed anyway.

## Recommendation

Standardize on the Wazuh dashboard as the primary analyst interface, since it consistently exposed structured fields the current CLI pipeline drops and introduced no timing disadvantage in this sample. Keep the CLI pipeline as the supported secondary path for maintenance windows, bulk/batch re-investigation, and any period where dashboard access or licensing is unavailable — the export-mode workflow proven this week is exactly that fallback.

## Operational Risks of Being Wrong

- **Over-trusting dashboard field completeness**: if analysts stop maintaining the asset-inventory fallback because "Wazuh has it," the scenario_b gap (missing `data_classification`) repeats at scale — estimated 1-2 analyst-hours/week re-deriving asset context under time pressure.
- **CLI schema drift going unnoticed**: the `raw_message`-parsing workaround for `src_ip`/`event_id` is fragile; a pipeline change that reformats log lines breaks detections silently — estimated 2-4 analyst-hours/week of triage rework if undetected for a shift.
- **Single-vendor lock-in**: if Wazuh becomes primary with no maintained CLI fallback, a licensing lapse or outage removes the SOC's only investigation path — unbounded cost, mitigated only by keeping this week's export-mode workflow current.

## Security+ 4.7 Considerations

Automation and orchestration favor the interface with the lower long-term technical debt, not the lower single-session time: the CLI's brittleness under schema drift is a recurring cost that a one-time timing sample does not capture, while Wazuh's structured fields reduce per-investigation complexity at the cost of vendor dependency. Scaling to more analysts favors Wazuh's shallower learning curve; scaling to more log sources favors the CLI's transparent, diffable pipeline.

## Next Steps

1. **Detection engineering**: normalize `src_ip` extraction and add an `event_id` field to the 3x00 pipeline so the CLI schema stops requiring `raw_message` regex workarounds.
2. **Compliance**: confirm `agent.labels` will be extended to carry `data_classification` before the Wazuh dashboard is declared primary, or document the asset-inventory fallback as a permanent step.
3. **SOC manager**: schedule a quarterly re-run of this same 4-scenario comparison so the recommendation is re-validated against real dashboard latency, not export-mode wall-clock, before the next platform decision.
