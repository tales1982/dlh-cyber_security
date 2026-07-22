# 11. The Control Selection — MedDefense Health Systems

**Analyst:** Security Analyst
**Date:** Current

*All 10 risks in the Register (Task 10) carry a Treatment Decision of Mitigate, so all 10 are covered below. Several risks share a control (noted explicitly to avoid double-counting cost across entries).*

## RISK-001 — Ghostcat Exposes EHR Database Credentials

```
Selected Control: Disable/restrict the Tomcat AJP connector on ehr-srv-01
CIS Control Mapping: CIS 4 (Secure Configuration), Safeguard 4.6
NIST CSF Mapping: PR.PS (Platform Security)
Control Type: Preventive
Control Category: Technical
Implementation Cost: $500 (labor only)
Expected Risk Reduction: ALE $495,000 -> $24,750 (Task 6)
Dependencies: None — can be implemented immediately, independent of
  every other control in this list.
```

## RISK-002 — Ransomware Encrypts Domain-Joined Systems

*Three controls, each addressing a different step of Kill Chain #1.*

```
Selected Control (a): MFA on VPN and administrative accounts
CIS Control Mapping: CIS 6 (Access Control Management), Safeguards
  6.3/6.4/6.5
NIST CSF Mapping: PR.AA (Identity Management, Authentication and
  Access Control)
Control Type: Preventive
Control Category: Technical
Implementation Cost: $4,000 (existing O365 E3 licensing)
Expected Risk Reduction: ALE $300,000 -> $96,000 (Task 6)
Dependencies: None — requires only O365/Azure AD tenant
  administration access already held by IT.

Selected Control (b): SIEM deployment (Wazuh), Phase 1
CIS Control Mapping: CIS 8 (Audit Log Management), Safeguard 8.1; CIS
  13 (Network Monitoring and Defense), Safeguard 13.1
NIST CSF Mapping: DE.CM (Continuous Monitoring)
Control Type: Detective
Control Category: Technical
Implementation Cost: $28,000
Expected Risk Reduction: Contributes to the same $300,000 -> $96,000
  reduction above by shortening dwell time and enabling containment
  before full domain-wide escalation.
Dependencies: Requires a current, accurate asset inventory (already
  established, 1x00 Task 7) to correctly configure log sources for
  every critical server and the firewall.

Selected Control (c): Offsite immutable backup replication
CIS Control Mapping: CIS 11 (Data Recovery), Safeguards 11.3/11.4
NIST CSF Mapping: RC.RP (Incident Recovery Plan Execution)
Control Type: Corrective (with a Compensating element, since it
  protects the recovery path rather than preventing the initial event)
Control Category: Technical
Implementation Cost: $14,400/year
Expected Risk Reduction: Reduces the AV component of this risk by an
  estimated $720,000 (Task 7, Control 4), reducing ALE from $300,000
  to approximately $192,000 on this component alone.
Dependencies: None direct, though should be validated against the
  current NAS-01 backup configuration before cutover.
```

## RISK-003 — Billing Server Repeat RCE-to-Root

```
Selected Control: Ubuntu Pro/ESM enrollment + emergency Apache patch
CIS Control Mapping: CIS 7 (Continuous Vulnerability Management),
  Safeguards 7.3/7.4; CIS 2 (Software Assets), Safeguard 2.2
NIST CSF Mapping: PR.PS (Platform Security) / ID.AM (Asset Management)
Control Type: Preventive
Control Category: Technical
Implementation Cost: $3,000/year
Expected Risk Reduction: ALE $189,200 -> $23,650 (Task 6)
Dependencies: None — can be implemented immediately.
```

## RISK-004 — Insider Data Exfiltration (Departing Employee)

```
Selected Control (a): Automated deprovisioning tied to HR termination
CIS Control Mapping: CIS 6 (Access Control Management), Safeguard 6.2;
  CIS 5 (Account Management), Safeguard 5.3
NIST CSF Mapping: PR.AA
Control Type: Preventive
Control Category: Technical (mechanism) / Administrative (the HR-IT
  process behind it)
Implementation Cost: $8,000 (shared cost with Control (b) below,
  per Task 6's combined estimate)
Expected Risk Reduction: ALE $70,000 -> $21,000 (Task 6)
Dependencies: Requires an accurate, current account inventory (CIS
  Safeguard 5.1) as a prerequisite — deprovisioning is only reliable if
  the account list it acts against is complete.

Selected Control (b): Export-volume/DLP alerting on the EHR export
  function
CIS Control Mapping: CIS 3 (Data Protection), Safeguard 3.3; CIS 13,
  Safeguard 13.1
NIST CSF Mapping: DE.CM
Control Type: Detective
Control Category: Technical
Implementation Cost: (included in the $8,000 above)
Dependencies: Benefits from the SIEM deployment (RISK-002, Control b)
  being in place to centralize the alerting, though it can function as
  a standalone alert rule if implemented first.
```

## RISK-005 — Medical Device Compromise

```
Selected Control (a): Reset default credentials on the BD Alaris fleet
CIS Control Mapping: CIS 4 (Secure Configuration), Safeguard 4.7
NIST CSF Mapping: PR.PS
Control Type: Preventive
Control Category: Technical
Implementation Cost: $500 (labor only — 7 devices)
Expected Risk Reduction: Removes the specific default-credential
  vector entirely; contributes to the combined ALE reduction below.
Dependencies: None — can be done in a single afternoon.

Selected Control (b): Medical device VLAN segmentation (both fleets)
CIS Control Mapping: CIS 12 (Network Infrastructure Management),
  Safeguard 12.2
NIST CSF Mapping: PR.IR (Technology Infrastructure Resilience)
Control Type: Compensating (the underlying device vulnerabilities are
  not eliminated, only made unreachable)
Control Category: Technical
Implementation Cost: $0 incremental — shared funding with Control 1
  from Task 7/8, already counted under this project's segmentation
  budget line
Expected Risk Reduction: Combined ALE $43,000 -> $11,250 (Task 6)
Dependencies: Requires the network segmentation design (Task 14) to be
  finalized first, and depends on an accurate device inventory to
  correctly assign each device to its zone.
```

## RISK-006 — Shared PACS Login

```
Selected Control: Proximity/smart-card authentication for PACS
  workstations
CIS Control Mapping: CIS 6 (Access Control Management), Safeguard 6.1;
  CIS 5, Safeguard 5.2 (unique credentials per user)
NIST CSF Mapping: PR.AA
Control Type: Preventive
Control Category: Technical (badge hardware) / Administrative (policy
  requiring individual login going forward)
Implementation Cost: $5,000 (already approved, 1x00 Risk Decisions)
Expected Risk Reduction: Qualitative — restores individual
  accountability, moving this risk from Critical to Low per the
  original 1x00 Gap Analysis reasoning.
Dependencies: Requires radiology department-head sign-off before
  rollout — a people/change-management dependency, not a technical one,
  since an earlier attempt at this exact fix was rejected on workflow
  grounds.
```

## RISK-007 — Westside Consumer Router

```
Selected Control: Dedicated enterprise-grade firewall
CIS Control Mapping: CIS 12 (Network Infrastructure Management),
  Safeguards 12.1/12.4
NIST CSF Mapping: PR.IR
Control Type: Preventive
Control Category: Technical
Implementation Cost: $6,000
Expected Risk Reduction: ALE $15,000 -> $3,000 (Task 7)
Dependencies: None — standalone hardware replacement.
```

## RISK-008 — Westside Shadow IT (Grafana)

```
Selected Control: Immediate network block, pending ownership
  investigation
CIS Control Mapping: CIS 1 (Inventory and Control of Enterprise
  Assets), Safeguard 1.2
NIST CSF Mapping: ID.AM (Asset Management)
Control Type: Preventive (the block) / Corrective (eventual
  decommission or onboarding, pending investigation outcome)
Control Category: Technical (the block) / Administrative (the
  investigation process)
Implementation Cost: $0-500 (labor only for the block; final
  disposition cost unknown pending investigation)
Expected Risk Reduction: Not yet quantifiable — explicitly flagged in
  the Risk Register as pending, not assumed resolved.
Dependencies: None to start the block immediately; the final treatment
  decision depends on completing the ownership investigation first.
```

## RISK-009 — No CISO / Governance Vacancy

```
Selected Control: Engage a virtual CISO (vCISO)
CIS Control Mapping: No direct mapping — this is an organizational/
  staffing decision outside the 18 Controls' technical safeguard scope.
  The closest conceptual ties are CIS 17 (Incident Response Management)
  and CIS 14 (Security Awareness Training), since a vCISO would own
  establishing and maturing both programs.
NIST CSF Mapping: GV.RR (Roles, Responsibilities, and Authorities)
Control Type: Administrative (by definition — this is a governance
  function, not a technical safeguard)
Control Category: Administrative
Implementation Cost: $48,000/year (a $4,000/month retainer) — this
  cost is explicitly NOT part of the $120,000 technical security budget
  evaluated in Tasks 7-8; it requires a separate governance/staffing
  budget line, consistent with the recommendation in Task 4.
Expected Risk Reduction: Not quantifiable in ALE terms — its value is
  every other risk in this register being treated with consistent,
  accountable executive ownership rather than ad hoc decision-making.
Dependencies: Requires CEO approval and a hiring/engagement process —
  an organizational dependency, not a technical one.
```

## RISK-010 — Unmanaged Vendor Risk (Supply Chain)

```
Selected Control (a): Vendor risk inventory and assessment process
CIS Control Mapping: CIS 15 (Service Provider Management), Safeguards
  15.1/15.2
NIST CSF Mapping: GV.SC (Cybersecurity Supply Chain Risk Management)
Control Type: Preventive
Control Category: Administrative
Implementation Cost: $2,000 (Security Analyst labor to build and
  maintain the inventory)
Dependencies: None to begin the inventory itself.

Selected Control (b): Extend MFA to vendor remote-access accounts
CIS Control Mapping: CIS 6, Safeguard 6.3
NIST CSF Mapping: PR.AA
Control Type: Preventive
Control Category: Technical
Implementation Cost: $500 (incremental configuration only)
Expected Risk Reduction: Not separately quantified (Task 10 flagged
  insufficient data for a confident ALE on this risk); qualitatively
  closes Kill Chain #5's Step 1 (stolen vendor credential, no MFA
  required).
Dependencies: Requires the MFA deployment under RISK-002 (Control a) to
  already be live — this is a direct technical dependency, not just a
  sequencing preference.
```

## Control Dependency Map

```
LAYER 0 — No prerequisites, can begin immediately (Week 1)
  |
  |-- Disable AJP connector (RISK-001)
  |-- Ubuntu Pro/ESM enrollment + Apache patch (RISK-003)
  |-- Reset BD Alaris default credentials (RISK-005a)
  |-- Network block on Westside shadow IT device (RISK-008)
  |-- Westside dedicated firewall swap (RISK-007)
  |-- MFA deployment on VPN/admin accounts (RISK-002a)  ****
  |-- Offsite immutable backup replication (RISK-002c)
  |-- vCISO engagement (RISK-009) -- organizational track, runs in
  |     parallel to all technical work
  |-- PACS badge authentication (RISK-006) -- pending department
  |     sign-off, otherwise independent
  |
  v
LAYER 1 — Depends on a Layer 0 control being live first
  |
  |-- SIEM deployment, Phase 1 (RISK-002b)
  |     depends on: accurate asset inventory (already done, 1x00)
  |-- Export-volume/DLP alerting (RISK-004b)
  |     depends on: SIEM (RISK-002b) for centralized alerting
  |-- Automated deprovisioning (RISK-004a)
  |     depends on: accurate account inventory (CIS 5.1)
  |-- Extend MFA to vendor accounts (RISK-010b)
  |     depends on: MFA deployment already live (RISK-002a) ****
  |
  v
LAYER 2 — Depends on design work + Layer 0/1 controls
  |
  |-- Network segmentation design (Task 14, produced next)
  |     depends on: accurate asset inventory + device classification
  |-- Medical device VLAN segmentation (RISK-005b)
  |     depends on: segmentation design (Task 14) being finalized
  |
  v
LAYER 3 — Ongoing / continuous, depends on Layer 1-2 being operational
  |
  |-- 24/7 monitoring (deferred per Task 8, but noted here for future
        sequencing) depends on: SIEM (Layer 1) already tuned and
        producing reliable alerts — a SOC cannot monitor a feed that
        does not exist yet
```

**Key dependency to highlight (marked \*\*\*\* above):** MFA (RISK-002a) is the single control with the most downstream dependents in this map — it is a direct prerequisite for extending MFA to vendor accounts (RISK-010b) and materially improves the value of the SIEM (fewer credential-based alerts to triage once MFA is live). This reinforces the same conclusion Task 7's cost-benefit analysis reached independently: MFA is not just the highest net-value control in isolation, it is also the architectural foundation several other controls build on.

## Repo

- **GitHub repository:** `dlh-cyber_security`
- **Directory:** `blue_team/1x03_defense_blueprint`
- **File:** `11-control_selection.md`
