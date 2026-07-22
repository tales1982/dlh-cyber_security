# 6. The ALE Workshop MedDefense Health Systems

**Analyst:** Security Analyst
**Date:** Current

## Risk 1: Ransomware Encrypts Domain-Joined Systems (Including EHR)

```
Risk: Ransomware Groups encrypt domain-joined systems and exfiltrate
  patient data via the full Kill Chain #1 sequence
Source: GAP-002 (no detection), GAP-003 (backup unprotected), GAP-014
  (no MFA), GAP-017 (no AD tiering); Threat Actor: Ransomware Groups
  (#1 priority, 1x01 T6); Kill Chain #1 (1x01 T10) / Scenario 1
  "Operation Flatline" (1x01 T14)

Asset: ehr-db-01, ad-dc-01/02, NAS-01, billing-srv-01 (domain-wide)
Asset Value (AV): $2,000,000
  Replacement/recovery cost: $300,000 (multi-system forensics, rebuild,
    incident-response firm engagement across several servers, not one)
  Revenue loss during downtime: $40,000/day x 25 days = $1,000,000
    (blended clinical + billing daily impact during a domain-wide
    outage, longer than a single-server incident because paper-record
    fallback covers only partial operations)
  Regulatory penalties: $200,000 (combined financial-data and
    patient-data HIPAA exposure, both categories breached at once)
  Reputation/patient trust impact: $500,000

Exposure Factor (EF): 60%
  Reasoning: Not every successful initial-access event escalates to the
    full domain-wide worst case. MedDefense's own prior ransomware
    incident (1x00, Task 1) was contained to the billing server, not
    domain-wide — history suggests a realistic blend of contained and
    catastrophic outcomes, not a guaranteed full realization every time.

SLE: AV x EF = $2,000,000 x 0.60 = $1,200,000

ARO: 0.25 (once every 4 years)
  Reasoning: Matches the sector rate for ransomware against
  similar-profile hospitals (1x01 intelligence dossier, 1 attack per
  3-4 years), using the more conservative end since this specific
  domain-wide worst case requires the full gap chain (GAP-002/003/014/
  017) to all remain open simultaneously, not just any ransomware
  contact.

ALE: SLE x ARO = $1,200,000 x 0.25 = $300,000

Proposed Control: MFA on VPN remote access and all administrative
  accounts (CIS Control 6), using existing O365 E3 licensing
Control Annual Cost: $4,000 (labor/configuration only — no new
  licensing required)
Estimated ALE After Control: MFA does not stop Kill Chain #1's initial
  phishing step, but it closes the pass-the-hash/credential-based
  escalation to Domain Admin (Step 4) that converts a single
  workstation compromise into the domain-wide outcome, and independently
  closes Kill Chain #2 entirely. ARO reduced to 0.08. New ALE =
  $1,200,000 x 0.08 = $96,000
Net Benefit: $300,000 - $96,000 - $4,000 = $200,000
```

## Risk 2: Unauthenticated RCE-to-Root on `billing-srv-01`

```
Risk: An Unskilled/Opportunistic Attacker achieves full root
  compromise of billing-srv-01 via the unpatched Apache chain — the
  same pattern already realized twice
Source: GAP-008 (billing server weak coverage), GAP-011 (Ubuntu 18.04
  EOL); 1x02 Findings 001, 002, 006, 009, 011, 026; Threat Actor:
  Unskilled/Opportunistic Attacker (#2 priority, 1x01 T6); Kill Chain
  #4, Step 1

Asset: billing-srv-01 (A-004)
Asset Value (AV): $473,000
  Replacement/recovery cost: $85,000
  Revenue loss during downtime: $16,000/day x 18 days = $288,000
  Regulatory penalties: $100,000
  Reputation/patient trust impact: not separately counted — this is a
    financial-data incident, not a patient-data one, so the reputational
    channel is materially smaller and already reflected in the downtime
    figure

Exposure Factor (EF): 100%
  Reasoning: A successful RCE-to-root chain is not a partial-loss
    event — once achieved, the full downtime, recovery and penalty
    costs all occur together, exactly as they did in the real January
    incident.

SLE: AV x EF = $473,000 x 1.00 = $473,000

ARO: 0.4 (once every 2.5 years)
  Reasoning: Above the generic sector rate because this is not a
  theoretical target profile — it is a proven, repeat target (ransomware,
  then a cryptominer, both via this exact unpatched Apache instance),
  and the vulnerable configuration remains open today.

ALE: SLE x ARO = $473,000 x 0.4 = $189,200

Proposed Control: Ubuntu Pro/ESM enrollment + emergency Apache patch
  (CIS Control 2 and 7)
Control Annual Cost: $3,000 (ESM subscription for the affected servers)
Estimated ALE After Control: Patching eliminates the specific CVE
  chain and restores an ongoing patch channel, ending the "same door"
  pattern. ARO reduced to 0.05 (residual risk of a different,
  not-yet-disclosed vulnerability). New ALE = $473,000 x 0.05 = $23,650
Net Benefit: $189,200 - $23,650 - $3,000 = $162,550
```

## Risk 3: Ghostcat RCE Exposes EHR Database Credentials

```
Risk: A confirmed-active, KEV-listed Ghostcat exploit against
  ehr-srv-01 exposes ehr-db-01 credentials, enabling direct patient
  database exfiltration
Source: GAP-001 (EHR database reachable network-wide); 1x02 Finding
  031 (CVE-2020-1938, CVSS 9.8); Threat Actor: Ransomware Groups /
  Unskilled-Opportunistic; structurally equivalent to Kill Chain #2
  Step 3 (no dedicated kill chain names this finding directly — a gap
  flagged in 1x02 Task 10)

Asset: ehr-srv-01, ehr-db-01 (A-001, A-002)
Asset Value (AV): $825,000
  Replacement/recovery cost: not separately counted — folded into the
    notification/litigation figures below, since this risk's primary
    cost driver is data exposure, not system rebuild
  Regulatory penalties (HIPAA breach notification): $25,000
  Litigation exposure: $200,000
  Reputation/patient trust impact: $600,000

Exposure Factor (EF): 100%
  Reasoning: Once database credentials are exposed and used, the
    breach notification, litigation and reputational costs are all
    triggered in full — there is no partial version of a confirmed
    patient data exfiltration event.

SLE: AV x EF = $825,000 x 1.00 = $825,000

ARO: 0.6 (more likely than not within any given year)
  Reasoning: Unlike a generic breach-probability estimate, this is a
  specific, confirmed-active, CISA KEV-listed, Exploitability-5
  vulnerability with a public Metasploit module (1x02, Task 4) sitting
  unpatched today — this is meaningfully higher-likelihood than an
  undefined future breach vector.

ALE: SLE x ARO = $825,000 x 0.6 = $495,000

Proposed Control: Disable/restrict the Tomcat AJP connector
  (configuration change, effectively free)
Control Annual Cost: $500 (labor only)
Estimated ALE After Control: This specific exploit path is closed
  entirely; residual risk reflects only the small chance of a different,
  not-yet-known vulnerability in the same service. ARO reduced to 0.03.
  New ALE = $825,000 x 0.03 = $24,750
Net Benefit: $495,000 - $24,750 - $500 = $469,750
```

## Risk 4: Medical Device Compromise (DoS + Patient Safety)

```
Risk: An Unskilled/Opportunistic Attacker reaches the BD Alaris and
  Philips medical device fleets via default credentials and the flat
  network, causing either a denial-of-service or, in the rare
  worst case, a patient safety incident
Source: GAP-004 (Alaris fleet no controls), GAP-007 (medical IoT flat
  network); 1x02 Findings 010, 016; Threat Actor: Unskilled/
  Opportunistic (direct), Ransomware Groups (secondary); Kill Chain #4

Asset: BD Alaris pump fleet, Philips IntelliVue monitor fleet (A-016,
  A-015)
Asset Value (AV) — two components, not combined into one blended
  figure, since they represent different severity classes:
  DoS component: $20,000/day x 5 days = $100,000 (operational
    disruption while devices are quarantined)
  Patient safety component: $1,500,000 (liability, reasoned point
    estimate within the $500K-$5M range) + $150,000 (FDA investigation)
    = $1,650,000

Exposure Factor (EF): 100% for both components
  Reasoning: Both are binary — either the DoS/quarantine event happens
    in full, or the patient safety event happens in full; there is no
    fractional version of either.

SLE (DoS): $100,000 x 1.00 = $100,000
SLE (patient safety): $1,650,000 x 1.00 = $1,650,000

ARO (DoS): 0.1 (once every 10 years)
ARO (patient safety): 0.02 (once every 50 years)
  Reasoning: Low for a targeted attack on medical devices specifically,
  but the flat network and confirmed unchanged default credentials
  (7 of 7 pumps) make opportunistic compromise plausible even without
  deliberate targeting.

ALE (DoS): $100,000 x 0.1 = $10,000
ALE (patient safety): $1,650,000 x 0.02 = $33,000
ALE (combined): $10,000 + $33,000 = $43,000

Proposed Control: Dedicated medical-device VLAN segmentation extending
  to both fleets (CIS Control 12; builds on the pump-only Phase 1
  already funded in 1x00's Risk Decisions)
Control Annual Cost: $30,000
Estimated ALE After Control: Segmentation reduces reachability by
  orders of magnitude (matches 1x02 Task 14's own quantified finding).
  ARO(DoS) reduced to 0.03; ARO(patient safety) reduced to 0.005.
  New ALE(DoS) = $100,000 x 0.03 = $3,000
  New ALE(patient safety) = $1,650,000 x 0.005 = $8,250
  New ALE (combined) = $11,250
Net Benefit: $43,000 - $11,250 - $30,000 = $1,750
```

*Note on Risk 4's thin net benefit:* this is the one risk in this workshop where the pure financial math produces a modest number, not a dramatic one segmentation is comparatively expensive relative to the (mercifully low-probability) patient-safety ALE it protects against. This is an honest result, not a miscalculation, and it does not mean the control is a bad idea: patient-safety findings are categorical, not purely financial (1x02, Task 15) the case for this control rests as much on the ethical and clinical-harm dimension as on the net-benefit figure above.

## Risk 5: Insider Data Exfiltration via Unrestricted Export + No Deprovisioning

```
Risk: A malicious departing employee exports patient records using
  legitimate, unmonitored access before termination and re-enters
  after departure using still-active credentials
Source: GAP-001 (no anomalous-access detection on export function),
  GAP-018 (no automated deprovisioning tied to HR termination), GAP-016
  (no change management, enabling credential exposure); Threat Actor:
  Insider (Malicious); Kill Chain #3 / Scenario 2 "The Quiet Departure"
  (1x01 T14)

Asset: ehr-db-01 (patient records, ~3,200 records per the modeled
  scenario)
Asset Value (AV): $140,000
  Regulatory penalties (HIPAA notification, smaller-scale incident):
    $15,000
  Litigation exposure: $75,000
  Reputation/patient trust impact: $50,000 (a quieter, less publicized
    insider case causes less attrition than a headline breach)

Exposure Factor (EF): 100%
  Reasoning: Once the exfiltration is discovered and confirmed as a
    breach, notification, litigation and reputational costs are all
    triggered in full.

SLE: AV x EF = $140,000 x 1.00 = $140,000

ARO: 0.5 (once every 2 years)
  Reasoning: Malicious insider departures with actual data-theft intent
  are less frequent than generic negligent incidents (1x01 T6 rates
  Insider Malicious likelihood as Medium, versus Negligent's High), but
  real — GAP-018 directly enables the specific re-entry-after-
  termination step this risk depends on.

ALE: SLE x ARO = $140,000 x 0.5 = $70,000

Proposed Control: Automated deprovisioning tied to HR termination
  events + export-volume/DLP alerting on the EHR export function
Control Annual Cost: $8,000 (HR-IT integration and basic export
  monitoring, largely built on existing AD/O365 tooling)
Estimated ALE After Control: Automated deprovisioning closes the
  re-entry step entirely; export monitoring flags bulk-export behavior
  during employment. ARO reduced to 0.15.
  New ALE = $140,000 x 0.15 = $21,000
Net Benefit: $70,000 - $21,000 - $8,000 = $41,000
```

## Risk Prioritization by ALE

| Rank | Risk                                                       | ALE (Before Control) | Net Benefit of Proposed Control |
| ---- | ---------------------------------------------------------- | -------------------- | ------------------------------- |
| 1    | Risk 3 — Ghostcat exposes EHR database credentials        | $495,000 | $469,750  |                                 |
| 2    | Risk 1 — Ransomware encrypts domain-joined systems        | $300,000 | $200,000  |                                 |
| 3    | Risk 2 — Billing server RCE-to-root (repeat compromise)   | $189,200 | $162,550  |                                 |
| 4    | Risk 5 — Insider data exfiltration (malicious departure)  | $70,000 | $41,000    |                                 |
| 5    | Risk 4 — Medical device compromise (DoS + patient safety) | $43,000 | $1,750     |                                 |

The ranking by ALE alone (Risk 3 highest) does not match a ranking by "which asset matters most" (which would put the domain-wide ransomware risk or the medical device patient-safety risk first) this is intentional and matches the pattern already established across this entire engagement: raw likelihood x impact math and categorical severity are two different lenses, and a mature risk program needs both, not just one.
