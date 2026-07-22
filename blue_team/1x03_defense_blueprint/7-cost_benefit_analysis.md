# 7. The Cost-Benefit Analysis MedDefense Health Systems

**Analyst:** Security Analyst
**Date:** Current

## Control 1: Network Segmentation (VLAN Implementation)

```
Control 1: Network segmentation (server, workstation, medical device
  and guest zones)
CIS Control Reference: 12 (Network Infrastructure Management)
Annual Cost: $45,000 (hardware/licensing $15,000 + implementation
  labor $25,000 + ongoing maintenance $5,000)
Risk(s) Addressed: Risk 4 (medical device compromise) directly; Risk 1
  (ransomware) indirectly, by limiting lateral-movement blast radius
  even when initial access succeeds
ALE Reduction: $31,750 (Risk 4's segmentation-specific reduction, per
  Task 6) + an estimated $50,000 additional reduction to Risk 1 (a
  conservative fraction of its $300,000 baseline, reflecting contained
  blast radius rather than full domain-wide reach even if phishing
  succeeds) = $81,750
Net Value: $81,750 - $45,000 = $36,750
Verdict: Justified
Recommendation: Implement — 1x02's own Task 14 already quantified
  segmentation as the single architecture change with the broadest
  amplifying effect across every other vulnerability in the environment.
```

## Control 2: MFA Deployment (VPN + Administrative Accounts)

```
Control 2: MFA deployment on VPN and administrative accounts
CIS Control Reference: 6 (Access Control Management)
Annual Cost: $4,000 (labor/configuration only, using existing O365 E3
  licensing — no new procurement)
Risk(s) Addressed: Risk 1 (ransomware, domain-wide)
ALE Reduction: $300,000 - $96,000 = $204,000 (per Task 6's full
  calculation)
Net Value: $204,000 - $4,000 = $200,000
Verdict: Justified
Recommendation: Implement immediately — the single highest net-value
  control in this entire analysis, at the lowest cost of any control
  evaluated.
```

## Control 3: Enterprise SIEM Deployment (Wazuh)

```
Control 3: Enterprise SIEM deployment (Wazuh, open-source)
CIS Control Reference: 8 (Audit Log Management) / 13 (Network
  Monitoring and Defense)
Annual Cost: $28,000 (Phase 1 labor: deployment, rule tuning, and daily
  alert review covering critical servers and the firewall — software
  itself is free, matching the estimate already scoped in 1x00's own
  Risk Decisions for GAP-002)
Risk(s) Addressed: Risk 1 (earlier detection reduces the odds of full
  domain-wide escalation), Risk 3 (Ghostcat would very likely be
  flagged automatically rather than requiring manual follow-up), Risk 5
  (export-volume anomaly detection)
ALE Reduction: $150,000 (a conservative, blended estimate reflecting
  meaningfully faster containment across these three risks — not
  crediting the SIEM with fully solving any one of them, since
  detection reduces exposure, it does not eliminate the underlying
  vulnerability)
Net Value: $150,000 - $28,000 = $122,000
Verdict: Justified
Recommendation: Implement — this directly closes GAP-002, the single
  most systemic and most frequently cited gap across all three prior
  projects (7 of 8 possible kill-chain/scenario appearances, 1x01 T15).
```

## Control 4: Offsite Backup Replication (Cloud Immutable Storage)

```
Control 4: Offsite backup replication (AWS S3 Glacier, immutable
  storage)
CIS Control Reference: 11 (Data Recovery)
Annual Cost: $14,400 (already priced in 1x00's Risk Decisions for
  GAP-003)
Risk(s) Addressed: Risk 1 (specifically the recovery-cost and
  downtime-duration components of AV, which assume backups may be
  destroyed alongside production per Kill Chain #1's documented outcome)
ALE Reduction: Isolated, immutable backups cut Risk 1's recovery cost
  component from $300,000 to $100,000 and downtime from 25 to 12 days
  (13 fewer days x $40,000/day = $520,000), reducing AV by $720,000
  (from $2,000,000 to $1,280,000). At baseline EF (60%) and ARO (0.25,
  evaluated standalone): New ALE = $1,280,000 x 0.6 x 0.25 = $192,000.
  ALE Reduction = $300,000 - $192,000 = $108,000
Net Value: $108,000 - $14,400 = $93,600
Verdict: Justified
Recommendation: Implement — one of the cheapest controls evaluated,
  directly targeting GAP-003 (rated Critical in 1x00 and confirmed
  still open by 1x02 Finding 015).
```

## Control 5: EDR Upgrade (Sophos Basic → Intercept X, All Endpoints)

```
Control 5: Endpoint Detection and Response upgrade, extended to
  servers
CIS Control Reference: 10 (Malware Defenses)
Annual Cost: $30,000 (licensing for ~387 endpoints at roughly
  $65/endpoint/year, plus implementation labor)
Risk(s) Addressed: Risk 2 (billing server — prevents a third
  malware-based compromise following the same pattern as the prior
  cryptominer incident), and general endpoint-level malware risk not
  separately captured in the five named risks
ALE Reduction: $40,000 (a conservative, blended estimate — this
  control catches post-exploitation malware behavior rather than
  preventing initial access, so its contribution is real but narrower
  than the controls above)
Net Value: $40,000 - $30,000 = $10,000
Verdict: Marginal
Recommendation: Defer — positive but thin net value; GAP-005 (endpoint
  AV excluding servers) is real, but this is a lower-leverage fix than
  the four controls above given a constrained budget.
```

## Control 6: Dedicated Firewall for Westside Clinic

```
Control 6: Dedicated firewall for Westside Clinic (replacing the
  consumer router)
CIS Control Reference: 12 (Network Infrastructure Management)
Annual Cost: $6,000 (hardware ~$3,500 + installation/configuration
  labor ~$2,500)
Risk(s) Addressed: No risk in the Task 6 top-5 centers on Westside
  specifically — this is an honest gap in this analysis, not an
  omission. A standalone estimate: the consumer router terminates the
  site-to-site VPN into Central, so a compromise here is a lower-
  likelihood variant of Risk 1's entry path. AV ~$150,000 (a discounted
  fraction of a full domain-compromise event via this specific,
  less-preferred path), EF 100%, ARO 0.1 -> SLE/ALE = $15,000. After
  control, ARO drops to 0.02 (an enterprise-grade device closes the
  low-hanging-fruit exposure): New ALE = $3,000.
ALE Reduction: $15,000 - $3,000 = $12,000
Net Value: $12,000 - $6,000 = $6,000
Verdict: Marginal
Recommendation: Implement anyway — the absolute cost is low enough
  that even a thin margin is worth taking; this closes GAP-015 (1x01
  T15, rated High) at minimal budget risk.
```

## Control 7: 24/7 Security Operations Center Staffing (Outsourced)

```
Control 7: 24/7 SOC staffing (outsourced managed SOC)
CIS Control Reference: 13 (Network Monitoring and Defense) / 17
  (Incident Response Management)
Annual Cost: $120,000 ($10,000/month for continuous, human-monitored
  coverage)
Risk(s) Addressed: Same risk set as Control 3 (Risk 1, Risk 3, Risk 5),
  but with continuous human monitoring layered on top of tooling rather
  than periodic review by a two-person internal team
ALE Reduction: $180,000 (broader and faster than Control 3 alone,
  since 24/7 human coverage catches what an occasionally-reviewed SIEM
  would miss between checks — but not dramatically higher, since
  Control 3 already captures most of the achievable detection value at
  a quarter of the cost)
Net Value: $180,000 - $120,000 = $60,000
Verdict: Marginal
Recommendation: Defer — the net value is positive in isolation, but
  this single control would consume the entire $120,000 annual budget,
  leaving nothing for the four higher-net-value, lower-cost controls
  above. Revisit once the program has grown beyond what Control 3 can
  cover.
```

## Control 8: Full Medical Device Network Isolation with Dedicated Monitoring

```
Control 8: Full medical device network isolation with dedicated
  monitoring
CIS Control Reference: 12 (Network Infrastructure Management) / 13
  (Network Monitoring and Defense)
Annual Cost: $55,000 ($30,000 segmentation, same scope as Control 1's
  medical-device component + $25,000 for dedicated medical-protocol-
  aware monitoring tooling/service, since generic IT monitoring tools
  do not properly parse HL7/DICOM traffic)
Risk(s) Addressed: Risk 4 (medical device compromise) — the same risk
  Control 1 already addresses, but pursued as a standalone "premium"
  version
ALE Reduction: With dedicated monitoring added on top of segmentation,
  ARO(DoS) drops to 0.01 and ARO(patient safety) to 0.002: New
  ALE(DoS) = $1,000, New ALE(patient safety) = $3,300, combined =
  $4,300. ALE Reduction = $43,000 - $4,300 = $38,700
Net Value: $38,700 - $55,000 = -$16,300
Verdict: Not Justified
Recommendation: Reject this standalone version. The marginal
  improvement dedicated monitoring adds over segmentation alone
  (Control 1) does not justify its additional cost — Control 1 already
  captures the large majority of Risk 4's addressable ALE at a lower
  price. This is the clearest example in this analysis of a control
  that costs more than the risk it removes.
```

## Cost-Benefit Summary Table (Ranked by Net Value)

| Rank | Control                                   | Annual Cost         | ALE Reduction      | Net Value     | Verdict                            | Fits in $120,000? |
| ---- | ----------------------------------------- | ------------------- | ------------------ | ------------- | ---------------------------------- | ----------------- |
| 1    | Control 2 - MFA                           | $4,000 | $204,000   | **$200,000** | Justified     | Yes                                |                   |
| 2    | Control 3 - SIEM (Wazuh)                  | $28,000 | $150,000  | **$122,000** | Justified     | Yes                                |                   |
| 3    | Control 4 - Backup replication            | $14,400 | $108,000  | **$93,600**  | Justified     | Yes                                |                   |
| 4    | Control 7 - 24/7 outsourced SOC           | $120,000 | $180,000 | $60,000            | Marginal      | No (exceeds budget alone)          |                   |
| 5    | Control 1 - Network segmentation          | $45,000 | $81,750   | $36,750            | Justified     | Yes (if 5+ selected together)      |                   |
| 6    | Control 5 -  EDR upgrade                 | $30,000 | $40,000   | $10,000            | Marginal      | Depends on remaining budget        |                   |
| 7    | Control 6 - Westside firewall             | $6,000 | $12,000    | $6,000             | Marginal      | Yes                                |                   |
| 8    | Control 8 - Full medical device isolation | $55,000 | $38,700   | **-$16,300** | Not Justified | N/A — reject regardless of budget |                   |

**Controls that fit within $120,000 without exceeding budget, selected greedily by net value:** Controls 2, 3, 4, 1 and 6 together cost $4,000 + $28,000 + $14,400 + $45,000 + $6,000 = **$97,400**, leaving $22,600 unspent not quite enough to also add Control 5 ($30,000). Control 7 alone would consume the entire budget and is deferred; Control 8 is rejected outright regardless of remaining funds. This greedy selection is a starting point, not the final answer Task 8 works through the full allocation decision, including whether a different combination outperforms this one.
