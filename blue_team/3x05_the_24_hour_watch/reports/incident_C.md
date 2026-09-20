## Incident Identifier

INC-20260920-NONE

## Executive Summary

The provided Wazuh export for incident C (med-mri-02 medical IoT egress) is 3x04 primary-pack reference data, not data generated from this capstone's evidence_pack_secondary, so it cannot be used to seed or confirm a CLI investigation for this shift. Confidence in this finding is low. $WAZUH_EXPORTS/incident_A_search_results.json, incident_B_search_results.json, and incident_C_search_results.json all query index 'meddefense-evidence-2026-03' over March 2026-03-25 windows and reference hosts (clin-ws-12, clin-ws-07, med-mri-02) from the 3x04 Cross-Platform Detection project's primary evidence pack, not this capstone's hosts (ctr-*/sth-*/wst-*) or April window. hits_total is 0 in every one of the three files, confirming the export never matched this shift's actual data. This looks like a packaging/generation bug in the lab platform's wazuh_exports for this capstone, not a gap this shift's own work could close.

## Timeline

_No events are attributable to a confirmed incident._

## Affected Assets

| HOST | CRITICALITY | DATA_CLASS | ZONE |
|------|-------------|------------|------|
| — | — | — | — |

## Indicators of Compromise

| TYPE | VALUE | CONFIDENCE | SOURCE |
|------|-------|------------|--------|
| — | — | — | — |

## ATT&CK Mapping

| TECHNIQUE | NAME | EVIDENCE |
|-----------|------|----------|
| — | — | — |

## Detection Performance

- See runtime/catalog_run.json and alerts/triage_log.jsonl for this shift's full detection performance (1 rule fired, 1014 alerts, 0 TP).

## Recommended Actions

1. Review the catalog-coverage gap documented in response/tuning_recommendations.json.
2. Confirm whether hc_red7_advisory.md / change_tickets.json / prior_shift_notes.md were generated against this evidence pack.
3. Re-run this investigation once the catalog and/or context files are corrected.

## Evidence References

_None — no event_refs are attributable to a confirmed incident._
