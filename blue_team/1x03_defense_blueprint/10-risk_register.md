# 10. The Risk Register — MedDefense Health Systems

**Analyst:** Security Analyst
**Date:** Current

*Likelihood scale: 1=Rare (>10 yrs) · 2=Unlikely (5-10 yrs) · 3=Possible (2-5 yrs) · 4=Likely (1-2 yrs) · 5=Almost Certain (<1 yr or already ongoing)*
*Impact scale: 1=Negligible · 2=Minor · 3=Moderate · 4=Major · 5=Severe/Catastrophic (patient safety or existential financial/regulatory exposure)*

## RISK-001

- **Risk Description:** An unauthenticated attacker exploits the confirmed-active Ghostcat vulnerability on `ehr-srv-01` to read `ehr-db-01`'s credentials and exfiltrate the patient database.
- **Risk Category:** Compliance
- **Threat Source:** Ransomware Groups / Unskilled-Opportunistic Attacker (1x01 T6)
- **Vulnerability:** 1x02 Finding 031 (CVE-2020-1938, CVSS 9.8)
- **Affected Asset(s):** `ehr-srv-01` (A-001), `ehr-db-01` (A-002)
- **Likelihood:** 4 (Likely) — confirmed active, CISA KEV-listed, weaponized public exploit
- **Impact:** 5 (Severe) — full patient database exposure, 50,000+ records
- **Inherent Risk Score:** 4 × 5 = **20**
- **ALE:** $495,000 (Task 6, Risk 3)
- **Risk Owner:** Deputy CISO (James Chen)
- **Treatment Decision:** Mitigate
- **Treatment Justification:** A near-zero-cost configuration change eliminates this specific exploit path entirely; there is no reason to accept, transfer or avoid a risk this cheap to close.
- **Planned Control(s):** Disable/restrict the Tomcat AJP connector (Task 7-adjacent, effectively free)
- **Residual Risk:** Low — ALE reduces to $24,750 after the connector is disabled
- **KRI:** Any inbound connection attempt to port 8009 on `ehr-srv-01` logged by the SIEM (Task 7, Control 3) once deployed
- **Review Date:** 30 days

## RISK-002

- **Risk Description:** A ransomware affiliate gains initial access via phishing or a purchased credential and escalates to domain-wide encryption plus patient data exfiltration, following Kill Chain #1.
- **Risk Category:** Strategic
- **Threat Source:** Ransomware Groups, #1-priority actor (1x01 T6)
- **Vulnerability:** No single 1x02 finding; enabled by the combined gap chain (GAP-002, GAP-003, GAP-014, GAP-017)
- **Affected Asset(s):** `ehr-db-01`, `ad-dc-01`/`02`, `NAS-01`, `billing-srv-01` (domain-wide)
- **Likelihood:** 3 (Possible) — matches sector rate (1 attack per 3-4 years) for this specific worst-case chain
- **Impact:** 5 (Severe) — organization-wide clinical and financial disruption, patient data exposure
- **Inherent Risk Score:** 3 × 5 = **15**
- **ALE:** $300,000 (Task 6, Risk 1)
- **Risk Owner:** Deputy CISO (James Chen)
- **Treatment Decision:** Mitigate
- **Treatment Justification:** The two lowest-cost controls in this entire program (MFA and SIEM) directly break this chain's most critical steps; accepting this risk unmitigated would mean tolerating MedDefense's single highest-priority documented threat pattern indefinitely.
- **Planned Control(s):** MFA on VPN/admin accounts (Task 7, Control 2); SIEM deployment (Control 3); offsite immutable backup replication (Control 4)
- **Residual Risk:** Medium — ALE reduces to approximately $96,000 after MFA alone; further reduced by SIEM and backup controls layered on top
- **KRI:** Number of failed MFA challenge attempts on VPN/admin accounts per week (a spike indicates active credential-stuffing or phishing follow-through)
- **Review Date:** 30 days

## RISK-003

- **Risk Description:** An Unskilled/Opportunistic Attacker achieves full root compromise of `billing-srv-01` via the unpatched Apache chain — the same pattern already realized twice in real incidents.
- **Risk Category:** Financial
- **Threat Source:** Unskilled/Opportunistic Attacker, #2-priority actor (1x01 T6)
- **Vulnerability:** 1x02 Findings 001, 002, 006, 009, 011, 026
- **Affected Asset(s):** `billing-srv-01` (A-004)
- **Likelihood:** 4 (Likely) — proven, repeat target with the vulnerable configuration still open
- **Impact:** 3 (Moderate) — financial/billing data exposure and operational disruption, not patient-safety or full-EHR scale
- **Inherent Risk Score:** 4 × 3 = **12**
- **ALE:** $189,200 (Task 6, Risk 2)
- **Risk Owner:** IT Director (Sarah Park)
- **Treatment Decision:** Mitigate
- **Treatment Justification:** ESM enrollment and patching cost a fraction of the ALE and end a pattern that has already cost MedDefense two real incidents.
- **Planned Control(s):** Ubuntu Pro/ESM enrollment + emergency Apache patch
- **Residual Risk:** Low — ALE reduces to $23,650 once patched and enrolled
- **KRI:** Days since last successful `apt` security update on `billing-srv-01` (should never exceed 30 once ESM is active)
- **Review Date:** 7 days

## RISK-004

- **Risk Description:** A malicious departing employee exports patient records via the EHR's unrestricted export function before termination, then re-enters using still-active credentials.
- **Risk Category:** Compliance
- **Threat Source:** Insider (Malicious) (1x01 T6); Kill Chain #3 / Scenario 2 "The Quiet Departure" (1x01 T14)
- **Vulnerability:** No direct 1x02 finding (this is a process/detection gap, not a scanned vulnerability); sourced from GAP-001, GAP-018, GAP-016
- **Affected Asset(s):** `ehr-db-01` (A-002)
- **Likelihood:** 4 (Likely) — GAP-018 directly enables the specific re-entry step this risk depends on, and no control currently interrupts it
- **Impact:** 3 (Moderate) — a bounded-scale breach (~3,200 records), not organization-wide
- **Inherent Risk Score:** 4 × 3 = **12**
- **ALE:** $70,000 (Task 6, Risk 5)
- **Risk Owner:** IT Director (Sarah Park), jointly with HR
- **Treatment Decision:** Mitigate
- **Treatment Justification:** Automated deprovisioning is a process fix, not a technology purchase, and directly closes the exact step that makes this scenario possible after termination.
- **Planned Control(s):** Automated deprovisioning tied to HR termination events; export-volume/DLP alerting on the EHR export function
- **Residual Risk:** Low — ALE reduces to $21,000 once deprovisioning and export monitoring are active
- **KRI:** Number of active accounts for employees whose termination date has passed by more than 24 hours (should be zero)
- **Review Date:** 30 days

## RISK-005

- **Risk Description:** An Unskilled/Opportunistic Attacker reaches the BD Alaris and Philips medical device fleets via default credentials and the flat network, causing a denial-of-service or, rarely, a patient safety incident.
- **Risk Category:** Operational
- **Threat Source:** Unskilled/Opportunistic Attacker (direct); Ransomware Groups (secondary); Kill Chain #4
- **Vulnerability:** 1x02 Findings 010, 016
- **Affected Asset(s):** BD Alaris pump fleet (A-016), Philips IntelliVue monitor fleet (A-015)
- **Likelihood:** 2 (Unlikely) — low probability of a targeted attack on medical devices specifically, though opportunistic compromise is plausible
- **Impact:** 5 (Severe) — scored on the patient-safety worst case regardless of its low probability, consistent with 1x02's categorical treatment of patient-safety findings
- **Inherent Risk Score:** 2 × 5 = **10**
- **ALE:** $43,000 combined (Task 6, Risk 4: $10,000 DoS + $33,000 patient safety)
- **Risk Owner:** IT Director (Sarah Park), jointly with Clinical Engineering
- **Treatment Decision:** Mitigate
- **Treatment Justification:** Segmentation is comparatively expensive relative to this risk's ALE alone, but the categorical patient-safety dimension overrides a pure net-value calculation (1x02, Task 15).
- **Planned Control(s):** Network segmentation extended to both device fleets (Task 7, Control 1)
- **Residual Risk:** Low — combined ALE reduces to approximately $11,250 post-segmentation
- **KRI:** Number of medical devices observed communicating outside their assigned VLAN (should be zero once segmentation is enforced)
- **Review Date:** 90 days

## RISK-006

- **Risk Description:** Unauthorized viewing or manipulation of medical imaging occurs through the PACS system's shared login, with no way to attribute the access to an individual.
- **Risk Category:** Compliance
- **Threat Source:** Insider (Malicious), Insider (Negligent) (1x01 T6)
- **Vulnerability:** No direct 1x02 finding — the unauthenticated PACS scan did not assess authentication practices; evidence is from the 1x00 Gap Analysis (GAP-010) only. This is an honest gap in scan coverage, not evidence the risk is smaller.
- **Affected Asset(s):** `pacs-srv-01` (A-003)
- **Likelihood:** 3 (Possible)
- **Impact:** 3 (Moderate) — imaging confidentiality/integrity concern, serious but not immediately life-threatening
- **Inherent Risk Score:** 3 × 3 = **9**
- **ALE:** Not separately quantified in T5/T6; qualitative Critical rating carried forward from the 1x00 Gap Analysis
- **Risk Owner:** IT Director (Sarah Park)
- **Treatment Decision:** Mitigate
- **Treatment Justification:** A workflow-friendly fix (badge authentication) is already funded in the 1x00 Risk Decisions and resolves the accountability problem without reintroducing the login-speed complaint that blocked an earlier fix attempt.
- **Planned Control(s):** Proximity/smart-card authentication for PACS workstations (already approved, 1x00 Task 14, ~$5,000)
- **Residual Risk:** Low, once individual login attribution is restored
- **KRI:** Number of PACS logins under the shared/generic account per month (should trend to zero)
- **Review Date:** 90 days

## RISK-007

- **Risk Description:** The Westside Clinic's consumer-grade router, which also terminates the site-to-site VPN into Central, is compromised, providing a lower-effort entry point into the internal network.
- **Risk Category:** Operational
- **Threat Source:** Unskilled/Opportunistic Attacker (general; no dedicated Westside threat model exists in 1x01, an honest documentation gap)
- **Vulnerability:** 1x02 Finding 014
- **Affected Asset(s):** Westside Netgear router, `ws-srv-01` (A-024)
- **Likelihood:** 2 (Unlikely)
- **Impact:** 3 (Moderate) — a contained satellite-site compromise relative to Central, but a real path into the shared VPN
- **Inherent Risk Score:** 2 × 3 = **6**
- **ALE:** $15,000 (Task 7, Control 6 standalone estimate)
- **Risk Owner:** IT Director (Sarah Park)
- **Treatment Decision:** Mitigate
- **Treatment Justification:** Low absolute cost ($6,000) with positive net value already approved in the Task 8 budget allocation.
- **Planned Control(s):** Dedicated enterprise-grade firewall (Task 7, Control 6)
- **Residual Risk:** Low — ALE reduces to approximately $3,000
- **KRI:** Number of unauthorized connection attempts logged at the Westside perimeter device per month
- **Review Date:** 30 days

## RISK-008

- **Risk Description:** An undocumented device at Westside Clinic running a vulnerable, unpatched Grafana instance is exploited via a trivial public path-traversal exploit, with no monitoring to detect it.
- **Risk Category:** Operational
- **Threat Source:** Unskilled/Opportunistic Attacker
- **Vulnerability:** 1x02 Finding 029 (CVE-2021-43798, CVSS 7.5)
- **Affected Asset(s):** A-025 (unidentified device, Westside)
- **Likelihood:** 4 (Likely) — trivial, public, unauthenticated exploit against a completely unmonitored device
- **Impact:** 3 (Moderate) — scored conservatively given the device's true purpose and blast radius remain unknown
- **Inherent Risk Score:** 4 × 3 = **12**
- **ALE:** Not separately quantified — this asset's true scope is still unknown, consistent with the gap flagged in 1x02 Tasks 17-18
- **Risk Owner:** Security Analyst (initial investigation), transitioning to IT Director (Sarah Park) for final disposition
- **Treatment Decision:** Mitigate (containment first; formal treatment decision pending investigation)
- **Treatment Justification:** A risk cannot be formally accepted, transferred or avoided for an asset that is not even inventoried — containment must precede any longer-term decision.
- **Planned Control(s):** Immediate network block pending ownership investigation; formal onboarding or decommission within 30 days
- **Residual Risk:** Unknown until investigation completes — explicitly flagged as open, not assumed Low
- **KRI:** Any traffic observed to/from 10.10.10.200 after the block is implemented (would indicate the block failed, or a related device exists elsewhere)
- **Review Date:** 30 days

## RISK-009

- **Risk Description:** The vacant CISO position means no single accountable executive owns security strategy, producing inconsistent, ad hoc risk decisions across the organization.
- **Risk Category:** Strategic
- **Threat Source:** Not applicable — this is a structural governance risk, not an actor-driven one
- **Vulnerability:** Not applicable — sourced from Task 4's governance analysis, not a scanned finding
- **Affected Asset(s):** The security program as a whole (organization-wide)
- **Likelihood:** 5 (Almost Certain) — this is a present, ongoing condition, not a future probabilistic event
- **Impact:** 4 (Major) — undermines consistent execution of every other risk treatment decision in this register, though not itself a single catastrophic event
- **Inherent Risk Score:** 5 × 4 = **20**
- **ALE:** Not quantifiable in the SLE/ARO/ALE framework — its cost is better expressed as every other risk in this register being harder to treat consistently without an accountable executive owner
- **Risk Owner:** CEO (Dr. Morales) — only she can create or fill the position
- **Treatment Decision:** Mitigate
- **Treatment Justification:** A vCISO engagement (Task 4) closes this gap immediately within the existing budget constraint, at a fraction of a full-time hire's cost.
- **Planned Control(s):** Engage a virtual CISO (vCISO)
- **Residual Risk:** Medium — a fractional/part-time executive still leaves some governance thinness until the program matures enough to justify a full-time hire
- **KRI:** Number of security decisions made without a documented risk-acceptance sign-off (should trend to zero once the Task 4 RACI is enforced)
- **Review Date:** 180 days

## RISK-010

- **Risk Description:** A third-party vendor (e.g., MedTech Solutions) with legitimate remote maintenance access to `ehr-srv-01` is compromised, and the attacker uses that trusted access to reach and exfiltrate patient data.
- **Risk Category:** Compliance
- **Threat Source:** External attacker via compromised vendor (Supply Chain Compromise); Kill Chain #5 / Scenario 3 "The MedTech Backdoor" (1x01 T14)
- **Vulnerability:** No direct 1x02 finding — vendor remote access was outside the scan's technical scope; consistent with CIS Control 15 scoring Not Implemented (Task 2)
- **Affected Asset(s):** `ehr-srv-01` (A-001), `ehr-db-01` (A-002), reached via vendor access
- **Likelihood:** 2 (Unlikely) — no evidence this has been attempted; requires a supply-chain compromise outside MedDefense's direct control
- **Impact:** 5 (Severe) — identical worst-case outcome to RISK-001, via a completely ungoverned path
- **Inherent Risk Score:** 2 × 5 = **10**
- **ALE:** Not separately quantified — insufficient data to construct a confident AV/EF/ARO estimate; flagged explicitly as a research gap for the next assessment cycle rather than a guessed number
- **Risk Owner:** Deputy CISO (James Chen) — vendor risk assessment owner per the Task 4 RACI
- **Treatment Decision:** Mitigate
- **Treatment Justification:** A vendor inventory and MFA requirement on vendor remote access is low-cost relative to the severity of what an ungoverned vendor credential can reach.
- **Planned Control(s):** Vendor risk inventory and assessment process (CIS Control 15); extend MFA (Task 7, Control 2) to cover vendor remote-access accounts specifically, not only internal admin accounts
- **Residual Risk:** Medium — governance reduces likelihood further, but MedDefense cannot directly control MedTech's own internal security practices
- **KRI:** Number of third-party vendors with remote access not yet inventoried or assessed (should trend to zero)
- **Review Date:** 90 days

## Register Summary

| Risk ID | Description (short) | Category | Inherent Score | ALE | Treatment | Residual |
|---|---|---|---|---|---|---|
| RISK-001 | Ghostcat exposes EHR DB credentials | Compliance | 20 | $495,000 | Mitigate | Low |
| RISK-002 | Domain-wide ransomware (Kill Chain #1) | Strategic | 15 | $300,000 | Mitigate | Medium |
| RISK-003 | Billing server repeat RCE-to-root | Financial | 12 | $189,200 | Mitigate | Low |
| RISK-004 | Insider exfiltration, departing employee | Compliance | 12 | $70,000 | Mitigate | Low |
| RISK-005 | Medical device compromise | Operational | 10 | $43,000 | Mitigate | Low |
| RISK-006 | Shared PACS login | Compliance | 9 | Not quantified | Mitigate | Low |
| RISK-007 | Westside consumer router | Operational | 6 | $15,000 | Mitigate | Low |
| RISK-008 | Westside shadow IT (Grafana) | Operational | 12 | Not quantified | Mitigate (contain) | Unknown |
| RISK-009 | No CISO / governance vacancy | Strategic | 20 | Not applicable | Mitigate | Medium |
| RISK-010 | Unmanaged vendor risk (supply chain) | Compliance | 10 | Not quantified | Mitigate | Medium |

## Risk Register Governance Note

This register is maintained by the Deputy CISO (James Chen), with the Security Analyst responsible for updating individual entries whenever new scan data, threat intelligence or control deployments change a risk's status — the same division of labor established in the Task 4 RACI matrix, where James is Accountable for the security program's ongoing risk posture and the analyst is Responsible for the underlying analysis. The register is formally reviewed monthly by James and Sarah Park together, with each entry's stated Review Date acting as a minimum cadence, not a maximum — any risk can be pulled forward for reassessment sooner. An out-of-cycle review is triggered by any of three events: a new CVE or CISA KEV addition affecting an asset in the 1x00 Asset Registry, a security incident (confirmed or suspected) touching any listed asset, or a KRI breaching its implied threshold (for example, RISK-003's KRI crossing 30 days since the last successful patch, or RISK-004's KRI showing any active account past its termination date). When a KRI threshold is breached, the affected risk is escalated immediately to James for a documented treatment-decision review, rather than waiting for the next scheduled monthly cycle — the entire purpose of tracking a KRI is to catch a risk drifting toward its next incident before the calendar does.

## Repo

- **GitHub repository:** `dlh-cyber_security`
- **Directory:** `blue_team/1x03_defense_blueprint`
- **File:** `10-risk_register.md`
