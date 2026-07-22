# 5. The Risk Equation MedDefense Health Systems

**Analyst:** Security Analyst
**Date:** Current

## Scenario 1: Ransomware Attack on Billing Server

**AV (Asset Value):** Rather than valuing the server itself, I valued the *incident* the realistic bundle of costs a successful ransomware event produces: lost billing revenue during downtime, recovery cost, and regulatory penalty.

- Downtime cost: 18 days × $16,000/day = **$288,000**
- Recovery cost: **$85,000**
- HIPAA penalty (mid-range): **$100,000**
- **AV = $288,000 + $85,000 + $100,000 = $473,000**

**EF (Exposure Factor): 100%.** A successful ransomware encryption event is not a partial-loss scenario once the server is encrypted, the full 18 days of downtime, the full recovery effort, and the regulatory exposure all materialize together. There is no realistic version of "we only lost half the revenue."

**SLE = AV × EF = $473,000 × 1.0 = $473,000**

**ARO:** The sector rate given is roughly 1 attack every 3-4 years (≈0.29). I adjusted this **upward to 0.4** (once every 2.5 years) because MedDefense is not an average hospital for this specific risk `billing-srv-01` has already been successfully compromised by ransomware once (1x00, Task 1), the exact vulnerable Apache instance remains unpatched (1x02, Findings 001/002), and the organization is therefore a proven repeat target rather than a theoretical statistical case.

**ALE = SLE × ARO = $473,000 × 0.4 = $189,200**

**Confidence: Medium.** The assumption most likely to change this number dramatically is the 18-day downtime figure, which is a CISA *average* assuming a working recovery process. GAP-003 (1x00) confirms MedDefense's backup has never been tested at full scale and NAS-01 itself is exposed (1x02, Finding 015) if the backup fails during a real event, downtime could run well beyond 18 days, pushing the SLE (and ALE) substantially higher than this estimate.

## Scenario 2: Patient Data Breach via EHR System

**AV (Asset Value):** The scenario provides two different ways to size this loss, and using both together would double-count: the Ponemon $165/record figure is explicitly described as *already including* detection, notification, legal and lost business. Applying it to 50,000 records ($8,250,000) and *also* adding the itemized notification/litigation/reputational figures would count the same costs twice. I chose the **itemized, MedDefense-specific bottom-up figures** as the primary basis, since they are sized to this organization rather than a generic industry average that may reflect breaches of very different scale:

- HIPAA breach notification: **$25,000**
- Litigation exposure: **$200,000**
- Reputational impact (patient attrition): **$600,000**
- **AV = $25,000 + $200,000 + $600,000 = $825,000**
- *(Sanity check: the Ponemon per-record method gives $8.25M nearly 10x higher. I judged the bottom-up estimate more defensible for a single mid-size regional hospital breach, but flag this as the single largest judgment call in this scenario.)*

**EF: 100%.** A confirmed breach triggers mandatory notification, opens litigation exposure, and sets the reputational-attrition clock running these are binary consequences of the breach occurring, not something that happens "60% as much."

**SLE = AV × EF = $825,000 × 1.0 = $825,000**

**ARO:** The baseline sector estimate (~1 in 3 years, ≈0.33) is explicitly flagged as a floor, since "MedDefense is higher risk than average." I adjusted to **0.4** (once every 2.5 years), reflecting the three specific aggravating factors named in the data and independently confirmed elsewhere in this engagement: no SIEM (1x00 GAP-002), a flat network (1x00 GAP-012, quantified in 1x02 Task 14), and unpatched systems (1x02, across nearly every finding).

**ALE = SLE × ARO = $825,000 × 0.4 = $330,000**

**Confidence: Low-Medium.** The reputational/attrition estimate ($600,000) is the single largest and softest number in this calculation it is a behavioral prediction (how many patients leave, and for how long) that could easily swing 2-3x in either direction depending on how transparently and quickly MedDefense communicates after a breach, a factor this scenario has no data to estimate.

## Scenario 3: Insider Data Theft (Negligent)

**AV:** The given average incident cost is already a fully-loaded, per-incident figure (investigation + containment + remediation + regulatory reporting), so it serves directly as the value at risk per event, not a total needing further decomposition.

- **AV = $120,000** (investigation $30,000 + containment $25,000 + remediation $40,000 + regulatory reporting $25,000)

**EF: 100%.** This figure already represents the full realized cost of one incident; there is no partial version of "investigation + containment + remediation" for a negligent data-handling event once it occurs.

**SLE = AV × EF = $120,000 × 1.0 = $120,000**

**ARO: 2.5** (midpoint of the given 2-3 incidents/year estimate). The hint that ARO can exceed 1 applies directly here: with 280 uncontrolled clinical workstations, no DLP, no USB restriction (1x02, Finding 023) and negligent incidents accounting for 60% of healthcare insider events sector-wide, multiple incidents per year is the realistic baseline, not the exception.

**ALE = SLE × ARO = $120,000 × 2.5 = $300,000**

**Confidence: Medium-High relative to the other scenarios**, since this rests on well-documented sector statistics (Ponemon, Verizon DBIR) applied to a specific, reasoned local ARO. The assumption most likely to change this number is the ARO itself and specifically, it is likely **understated**: GAP-002 (no detection capability) means negligent incidents that never get discovered are never counted, so the "true" ARO could be meaningfully higher than 2-3/year, not lower.

## Scenario 4: Medical Device Compromise

The hint correctly flags that this needs two separate ALE calculations a Denial-of-Service scenario and a much rarer, much more severe Patient Safety scenario. Device replacement cost ($105,000) is deliberately excluded from both, per the scenario's own framing that destruction is not the primary risk.

**DoS Scenario:**

- **AV:** Operational disruption while devices are quarantined and dosing reverts to manual: $20,000/day × 5 days = **$100,000**
- **EF: 100%** (a DoS event fully triggers the 5-day manual-operation disruption; there's no partial quarantine)
- **SLE = $100,000 × 1.0 = $100,000**
- **ARO: 0.1** (given: 1 in 10 years)
- **ALE(DoS) = $100,000 × 0.1 = $10,000**

**Patient Safety Scenario:**

- **AV:** The liability range given is wide ($500,000-$5,000,000). I chose **$1,500,000** as a reasoned point estimate weighted toward the lower-middle of the range, since a catastrophic maximum-liability event is less probable than a serious-but-contained one within this band plus the FDA investigation cost, which applies regardless of the liability outcome: $1,500,000 + $150,000 = **$1,650,000**
- **EF: 100%** (a confirmed patient safety event triggers both the liability exposure and the FDA investigation in full)
- **SLE = $1,650,000 × 1.0 = $1,650,000**
- **ARO: 0.02** (given: 1 in 50 years)
- **ALE(patient safety) = $1,650,000 × 0.02 = $33,000**

**Combined ALE for Finding 010: $10,000 + $33,000 = $43,000**

**Confidence: Low, specifically for the patient safety component.** The single assumption most likely to change this number dramatically is where the actual liability lands within the given $500,000-$5,000,000 range had I chosen $5,000,000 instead of $1,500,000, the patient-safety ALE alone would be $100,000, more than double this scenario's entire combined total. This is the widest, least-constrained input in this entire task.

## Scenario 5: VPN Compromise Leading to Full Network Access

**AV:** Per the scenario's own guidance, this risk represents the aggregate outcome of a successful campaign that achieves both the ransomware impact (Scenario 1) and the data-exfiltration impact (Scenario 2) simultaneously which matches Kill Chain #1's actual documented sequence (1x01, Task 10): domain compromise, patient data exfiltration, *and* ransomware deployment together, not separately.

- **AV = Scenario 1 SLE + Scenario 2 SLE = $473,000 + $825,000 = $1,298,000**
- *(This is likely a conservative floor, not a ceiling: Kill Chain #1's documented outcome also includes backup destruction, meaning recovery would likely extend well beyond Scenario 1's 18-day CISA-average assumption, which itself assumes a working backup GAP-003 confirms MedDefense's backup has never been tested at scale. Neither Scenario 1 nor Scenario 2 individually prices in this compounding effect.)*

**EF: 100%.** If the VPN is compromised and the attacker executes the described campaign, both loss categories occur together by definition that is what "full ransomware + data exfiltration campaign" means.

**SLE = AV × EF = $1,298,000 × 1.0 = $1,298,000**

**ARO: 0.3** (given directly: once every ~3 years, based on VPN/credential compromise being the #1 initial access vector at 38% of healthcare ransomware attacks).

**ALE = SLE × ARO = $1,298,000 × 0.3 = $389,400**

**Confidence: Low the lowest of all five scenarios.** This risk inherits every soft assumption from Scenarios 1 and 2 (downtime days, reputational attrition) *and* adds a new one: the scenario data itself states MedDefense's FortiGate patching cadence is "unknown." This is not a minor caveat 1x02's own OSINT research (Task 9) found a critical, actively-exploited FortiOS authentication-bypass vulnerability (CVE-2026-24858) affecting the exact FortiGate model MedDefense runs. If that patch has not been applied, the realistic ARO could be far higher than 0.3 potentially "likely within 1-2 years" rather than "once every 3" which would push this scenario's ALE well past every other risk calculated in this task, including Scenario 2. The FortiGate's actual patch status is the single highest-value fact MedDefense could confirm to sharpen this entire risk register.
