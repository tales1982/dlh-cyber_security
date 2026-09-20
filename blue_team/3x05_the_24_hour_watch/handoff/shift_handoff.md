# Shift Handoff — SHIFT-20260920-0656

## Shift Identifier

Shift ID: SHIFT-20260920-0656. Analyst host: ip-10-42-175-199.ec2.internal. Started: 2026-09-20T06:56:28Z. Ended: 2026-09-20T10:10:44Z. Duration: 3.24 hours.

## Situation

MedDefense activated heightened monitoring after an H-ISAC advisory tied the HC-RED7 activity cluster to three confirmed regional hospital intrusions over the prior six weeks. This shift ran the full detection chain (pipeline, baseline, catalog, triage) against an 8-day, ~339,287-event evidence pack (2026-04-01 to 2026-04-08) covering 16 hosts across three sites, with a 12-entry IOC feed cross-referenced throughout. The catalog produced 1014 alerts from one rule; triage classified 0 of them as true positive.

## Incidents

No incident reached true-positive status this shift (0 confirmed TPs out of 1014 alerts), so no incident IDs are logged in alerts/incidents.json. The "A", "B", and "C" investigation slots were each still worked and documented: reports/incident_A.md, reports/incident_B.md, and reports/incident_C.md each record a null-result investigation with the specific searches performed and their evidence. Slot A ruled out an SSH/RDP brute-force cluster and the advisory's named C2/service indicators (none present in the raw evidence). Slot B ruled out the expected change-ticket ambiguity case because the ticketed host (rad-srv-02) does not exist in this pack's technical evidence. Slot C found that the Wazuh export artifacts for this incident reference the wrong evidence pack entirely (3x04's primary pack, not this capstone's data).

## Campaign Assessment

campaign_linked is false, cluster_id is unknown, per campaign/campaign_assessment.json. With zero confirmed TP incidents, there is no pairwise IOC, tactic, or temporal overlap to evaluate, so no campaign linkage can be asserted from this shift's own evidence. The Wazuh export view (campaign_dashboard_summary.md) separately claims campaign_linked=true with high confidence, but that verdict is built on search results with hits_total=0 against hosts absent from this pack — it is not corroborating evidence and should not be relied on until the export is regenerated correctly.

## Open Items for Next Shift

- Add a Sigma rule for Windows service installation (event_id 7045) to cover T1543.003 persistence — see response/tuning_recommendations.json TUNE-001.
- Add a Sigma rule for irregular-interval outbound beaconing to cover T1071.001 C2 — see TUNE-002; a manual firewall.csv sweep for 8-15 minute beacon pairs found none.
- Re-tune rule 002 (off-hours privileged logon) to require privileged group membership — it produced 1014 noisy alerts this shift with no differentiating signal — see TUNE-003.
- Recover the LogonType field in the 3x00 pipeline's normalized schema — dropped during normalization, which broke rule 002's original selection — see TUNE-004.
- Request regeneration of hc_red7_advisory.md, change_tickets.json, prior_shift_notes.md, and wazuh_exports/* against evidence_pack_secondary — every named host and IOC in the current versions is absent from the actual pack — see TUNE-005.
- Confirm whether the H-ISAC advisory's HC-RED7 activity is present in this specific evidence window at all, given no technical indicator for it was found despite systematic search.

## Artifact Index

See MANIFEST.json for the complete file list with sha256 hashes and sizes.
