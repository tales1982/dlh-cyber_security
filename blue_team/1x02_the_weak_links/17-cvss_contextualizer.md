# 17. The CVSS Contextualizer — MedDefense Vulnerability Scan

**Analyst:** Threat Intelligence Analyst
**Date:** Current

**Scope note:** The 8 findings analyzed here are the same 8 carried through the rest of this project's synthesis tasks: 031, 003, 001/002 (analyzed as one chain), 004, 015, 016, 007, and 029 — the top of the Actionable Critical list from Task 16, selected for maximum diversity of host, asset type and threat pattern.

**Data-integrity note before recalculating:** While preparing this task, I re-verified Finding 031's CVSS vector directly against NVD rather than trusting the scan report's transcription. The scan report lists CVE-2020-1938 as `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` scored 9.8 — but that exact vector mathematically computes to 9.1, not 9.8 (Impact 5.18 + Exploitability 3.89 = 9.06 → 9.1). NVD's actual published vector is `.../C:H/I:H/A:H` (full triad), which correctly computes to 9.8. This is a transcription error in the scan report itself, not a scoring dispute — I used the correct, NVD-verified vector (`A:H`) as the basis for all recalculation below.

## Finding 031 — Ghostcat (CVE-2020-1938), `ehr-srv-01`

```
CVSS Base Score: 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H, NVD-verified)

Factor 1 - Asset Criticality:
  Asset: ehr-srv-01 (A-001), EHR application server
  CIA Rating: EHR System -- Confidentiality/Integrity/Availability all Critical
    (1x00 Task 8)
  Criticality Impact on Priority: Raises urgency to maximum -- this is the
    application server for the single highest-value asset pairing in the
    environment.

Factor 2 - Kill Chain Position:
  Appears in Kill Chain(s): None named explicitly (a documentation gap
    flagged in Task 10), but structurally equivalent to Kill Chain #2's
    Step 3 pattern (flat network exposing a critical server to any internal
    session).
  Chain Role: Lateral-movement enabler / near-final target -- a direct path
    to ehr-db-01's credentials.
  Kill Chain Impact on Priority: Raises urgency -- functions as the
    connective step between "any foothold" and "full patient database
    access," even without a named chain citing it directly.

Factor 3 - Exploitability:
  Exploitability Score: 5/5 (Task 4)
  CISA KEV: Yes (added 2022-03-03, due 2022-03-17)
  Exploit Impact on Priority: Raises urgency to maximum -- weaponized,
    default-on configuration, confirmed active on this exact host.

Factor 4 - Compensating Controls:
  Existing Controls: C-004 (SSH key-only auth) and C-005 (SSH logging) apply
    to ehr-srv-01, but both protect the SSH surface -- neither touches
    Tomcat or the AJP connector at all. C-002 (VPN-restricted server subnet)
    blocks direct internet access but does nothing against an attacker
    already on the internal flat network. No control in the 1x00 inventory
    addresses this specific service.
  Control Impact on Priority: Does not lower urgency -- every documented
    control protects a different attack surface on this same host.

Environmental CVSS (recalculated):
  Environmental Metrics Applied: CR=High, IR=High, AR=High (matching the
    EHR System's all-Critical CIA rating).
  Adjusted Score: 9.8 (unchanged) -- the base vector's Impact submetrics
    (C:H/I:H/A:H) were already at maximum, so the Modified Impact
    calculation hits CVSS's 0.915 Impact-subscore cap regardless of how
    high the environmental requirements are set. The environmental
    adjustment doesn't raise the number further because there is nowhere
    higher for it to go -- it confirms the base score was already
    appropriately severe for this asset, rather than revealing new severity.

Final Priority: Critical
Final Justification: Every one of the four factors points the same
  direction with no offsetting force: maximum asset criticality, a direct
  (if undocumented) kill-chain role, a weaponized KEV-listed exploit
  confirmed active on this exact host, and zero compensating controls that
  touch the vulnerable service. This is the least ambiguous Critical
  priority call in the entire report.
```

## Finding 003 — PostgreSQL Unrestricted Network Access, `ehr-db-01`

```
CVSS Base Score: N/A (no CVE). For this exercise, I constructed an
  equivalent vector reflecting direct, unauthenticated-barrier network
  access to a database (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` ≈ 9.1) --
  explicitly labeled as an analyst estimate, not an authoritative score,
  since misconfigurations don't receive official CVSS scoring.

Factor 1 - Asset Criticality:
  Asset: ehr-db-01 (A-002), EHR database -- the #1 Top-5 Most Critical
    Asset in the entire environment (1x00 Task 8)
  CIA Rating: EHR System -- all Critical.
  Criticality Impact on Priority: Raises urgency to maximum -- this is the
    single highest-value target MedDefense has.

Factor 2 - Kill Chain Position:
  Appears in Kill Chain(s): Kill Chain #5 ("Vendor Compromise to Direct
    Patient Data Access"), Step 3, named explicitly by Gap ID (GAP-001).
  Chain Role: Final target -- the objective-execution point of the chain.
  Kill Chain Impact on Priority: Raises urgency -- this is not a
    speculative connection, it is a documented, named step in an existing
    1x01 kill chain.

Factor 3 - Exploitability:
  Exploitability Score: Not scored on the 1-5 scale (Task 4) -- behaves as
    maximally exploitable in practice, since no exploit code is required at
    all, only network reachability and a password.
  CISA KEV: N/A (no CVE to list).
  Exploit Impact on Priority: Raises urgency -- "no exploit needed" is not
    a mitigating factor here, it removes the one variable (exploit
    reliability) that might otherwise introduce uncertainty.

Factor 4 - Compensating Controls:
  Existing Controls: C-002 (VPN-restricted server subnet) blocks direct
    internet access, but provides zero protection against lateral traffic
    from any already-compromised internal host -- which is exactly the
    threat model this finding describes. C-009 (nightly backup) is
    Corrective, not Preventive, and does nothing to stop unauthorized reads.
  Control Impact on Priority: Does not lower urgency -- this is precisely
    the gap GAP-001 already names: "no detection of anomalous access,"
    confirmed still open in this scan.

Environmental CVSS (recalculated):
  Environmental Metrics Applied: CR=High, IR=High, AR=High.
  Adjusted Score: 9.8 -- same capping effect as Finding 031; the
    Confidentiality and Integrity submetrics being maximal on a Critical
    asset alone is sufficient to hit the 0.915 Impact cap even without an
    Availability component.

Final Priority: Critical
Final Justification: This finding requires no exploit development, sits on
  the organization's single most valuable asset, and is named by Gap ID in
  an already-documented kill chain -- the environmental recalculation
  doesn't change the number, but it confirms there is no scenario in which
  this finding is anything less than Critical.
```

## Finding 001/002 — Apache RCE-to-Root Chain, `billing-srv-01`

```
CVSS Base Score: 9.8 (Finding 001, CVE-2021-44790) chaining into 7.8
  (Finding 002, CVE-2019-0211) -- analyzed together as the combined
  end-state impact (full root compromise), using 9.8 as the representative
  base.

Factor 1 - Asset Criticality:
  Asset: billing-srv-01 (A-004), Billing/claims server
  CIA Rating: Billing & Financial Infrastructure -- Confidentiality:
    Medium, Integrity: Medium, Availability: High, Overall: High (1x00
    Task 8) -- notably the only one of these 8 findings NOT on a
    Critical-rated asset.
  Criticality Impact on Priority: Lowers the asset-criticality contribution
    relative to the other 7 findings -- but does not lower overall
    priority, because this factor is outweighed by the other three below.

Factor 2 - Kill Chain Position:
  Appears in Kill Chain(s): Kill Chain #4 ("Unpatched Web Server to Medical
    Device Exposure"), Step 1.
  Chain Role: Initial access point -- the documented opening move of an
    entire chain that continues into the medical IoT fleet.
  Kill Chain Impact on Priority: Raises urgency -- being the *initial
    access step* of a chain matters independent of the target host's own
    criticality, because it is the gateway to everything downstream.

Factor 3 - Exploitability:
  Exploitability Score: 4/5 (Finding 001, Task 4)
  CISA KEV: No (confirmed absent, Task 4)
  Exploit Impact on Priority: Raises urgency moderately -- a public PoC
    exists and this exact vulnerability class has already been exploited
    against MedDefense twice in real incidents, which is stronger evidence
    than KEV listing alone would provide.

Factor 4 - Compensating Controls:
  Existing Controls: C-002 lists billing-srv-01 among assets "protected" by
    VPN-restricted server-subnet access -- but this is contradicted by
    confirmed reality: this exact Apache instance has been reached and
    exploited directly from the internet twice (1x00 Tasks 1-2), meaning
    C-002 either has an undocumented carve-out for this host's web port or
    is not functioning as described. This discrepancy itself is worth
    escalating, not just noting. C-009 (nightly backup) is Corrective only.
  Control Impact on Priority: Does not lower urgency -- if anything, the
    discovery that a documented "protective" control doesn't match observed
    reality is itself a reason for more urgency, not less.

Environmental CVSS (recalculated):
  Environmental Metrics Applied: CR=Medium, IR=Medium, AR=High (matching
    the asset's actual Medium/Medium/High rating).
  Adjusted Score: 9.8 (unchanged) -- even with only Medium Confidentiality/
    Integrity requirements, the combination still exceeds the 0.915 Impact
    cap once Availability is set to High, so the score does not move
    numerically despite the lower-than-Critical asset rating.

Final Priority: Critical
Final Justification: This is the one finding in the set where asset
  criticality alone would argue for a slightly lower priority than the
  others -- but it is overridden by a documented kill-chain role as the
  entry point to a larger chain, by a proven (not theoretical) exploitation
  history unique among all 31 findings, and by a compensating control
  whose real-world reliability is now in question. Priority stays Critical
  despite the lower asset tier, precisely because this task's whole purpose
  is to show that base severity and asset value are not the only inputs
  that matter.
```

## Finding 004 — Windows XP EOL Bundle, `WS-RAD-01`

```
CVSS Base Score: 10.0 (worst of the three bundled CVEs, MS08-067)

Factor 1 - Asset Criticality:
  Asset: WS-RAD-01 (A-014), MRI imaging control workstation
  CIA Rating: Medical IoT -- Integrity: Critical, Availability: Critical,
    Confidentiality: Medium, Overall: Critical (1x00 Task 8)
  Criticality Impact on Priority: Raises urgency to maximum -- direct
    patient-safety asset.

Factor 2 - Kill Chain Position:
  Appears in Kill Chain(s): None named explicitly (flagged as a gap in
    Task 10 and Task 14) -- structurally matches Kill Chain #4's general
    "flat-network pivot to medical IoT" pattern, but this specific device
    is never named.
  Chain Role: Would function as a lateral-movement/worm-propagation target
    given the self-spreading nature of the bundled exploits.
  Kill Chain Impact on Priority: Raises urgency independent of formal
    documentation -- the wormable nature of these exploits means this
    device doesn't need to be a deliberate target to be reached.

Factor 3 - Exploitability:
  Exploitability Score: 5/5 for all three bundled CVEs (Task 4)
  CISA KEV: Yes, all three listed.
  Exploit Impact on Priority: Raises urgency to maximum -- fully weaponized,
    self-propagating, historically responsible for two of the most
    destructive malware outbreaks ever recorded (Conficker, WannaCry).

Factor 4 - Compensating Controls:
  Existing Controls: None from the 1x00 Control Inventory apply to this
    device at all -- it is entirely absent from every control's
    "Asset(s) Protected" list. The only relevant controls are the three
    proposed specifically for this device in 1x00 Task 6, which Task 12 of
    this project already confirmed remain unimplemented.
  Control Impact on Priority: Does not lower urgency at all -- zero
    effective mitigation exists in practice, proposed or otherwise.

Environmental CVSS (recalculated):
  Environmental Metrics Applied: CR=Medium, IR=High, AR=High.
  Adjusted Score: 10.0 (unchanged) -- already at the maximum possible CVSS
    value; there is no environmental adjustment that can exceed it.

Final Priority: Critical
Final Justification: Every factor reinforces maximum priority with literally
  no room left in the scoring scale to express additional severity. The
  environmental exercise here doesn't change a number -- it demonstrates
  that this finding was already priced at its ceiling, and that the correct
  response is architectural (segmentation, per Task 12) rather than
  score-driven, since the score has nothing left to say.
```

## Finding 015 — NAS-01 Exposed Management Interface

```
CVSS Base Score: N/A (no CVE); constructed estimate `AV:N/AC:L/PR:N/UI:N/
  S:U/C:H/I:L/A:H` ≈ 9.4, reflecting primarily confidentiality (backup data
  exposure) and availability (backup destruction) impact, with lesser
  integrity impact.

Factor 1 - Asset Criticality:
  Asset: NAS-01 (A-010), Backup storage -- #3 Top-5 Most Critical Asset
  CIA Rating: File/Print/Backup Infrastructure -- Confidentiality: High,
    Integrity: Medium, Availability: Critical, Overall: Critical (1x00
    Task 8)
  Criticality Impact on Priority: Raises urgency to maximum -- this is
    MedDefense's only backup copy.

Factor 2 - Kill Chain Position:
  Appears in Kill Chain(s): Kill Chain #1 ("Phishing to Domain-Wide
    Ransomware"), Step 6, and named again as "Scenario 1 (Operation
    Flatline)" Step 6 in 1x01 Task 14.
  Chain Role: Final target / objective execution -- the decisive step that
    removes MedDefense's ability to recover.
  Kill Chain Impact on Priority: Raises urgency significantly -- this is
    the step that converts a contained ransomware event into an
    unrecoverable one.

Factor 3 - Exploitability:
  Exploitability Score: Not scored on the 1-5 scale (Task 4, misconfig) --
    behaves as maximally exploitable, no exploit code required.
  CISA KEV: N/A.
  Exploit Impact on Priority: Raises urgency -- identical reasoning to
    Finding 003.

Factor 4 - Compensating Controls:
  Existing Controls: NAS-01 is conspicuously absent from C-002's documented
    "Asset(s) Protected" list, despite sitting on the same physical subnet
    as the five servers C-002 does name -- either a documentation gap or a
    genuine, uncorrected omission. C-009 (nightly backup) does not apply to
    NAS-01 itself, since NAS-01 is the backup target, not something
    separately backed up.
  Control Impact on Priority: Does not lower urgency -- directly matches
    GAP-003's own finding that "nothing backs it up... nothing monitors
    NAS-01 for tampering."

Environmental CVSS (recalculated):
  Environmental Metrics Applied: CR=High, IR=Medium, AR=High.
  Adjusted Score: 9.8 -- rises slightly from the constructed 9.4 baseline
    and hits the same 0.915 Impact cap as the other Critical-asset findings.

Final Priority: Critical
Final Justification: Named explicitly, by two separate 1x01 deliverables
  (the kill chain and the named scenario), as the specific mechanism that
  turns a recoverable incident into an unrecoverable one -- combined with a
  documented control gap (GAP-003) that is already rated Critical in 1x00
  and a complete absence of any control from the general inventory. This is
  as close to unconditionally Critical as an uncredentialed finding gets.
```

## Finding 016 — Medical Device HTTP Interfaces, Philips Fleet

```
CVSS Base Score: N/A (no CVE for this specific finding); constructed
  estimate using the documented real-world capability for this device
  family (Task 15: unauthenticated memory read/write) -- `AV:N/AC:L/PR:N/
  UI:N/S:U/C:H/I:H/A:H` ≈ 9.8.

Factor 1 - Asset Criticality:
  Asset: Philips IntelliVue Monitor Fleet (A-015)
  CIA Rating: Medical IoT -- Confidentiality: Medium, Integrity: Critical,
    Availability: Critical, Overall: Critical (1x00 Task 8)
  Criticality Impact on Priority: Raises urgency to maximum -- direct
    patient-safety category.

Factor 2 - Kill Chain Position:
  Appears in Kill Chain(s): Kill Chain #4, Step 3-4 (medical IoT reached via
    flat-network pivot) -- the fleet category is named, though this
    specific finding ID is not cited by number.
  Chain Role: Final target -- the objective of the chain once a foothold
    reaches the medical device subnet.
  Kill Chain Impact on Priority: Raises urgency -- this is the destination,
    not a step along the way, of a documented chain.

Factor 3 - Exploitability:
  Exploitability Score: Not scored on the 1-5 scale in Task 4 (misconfig,
    not among the five CVEs analyzed there); the documented CVE family for
    this device (Task 15) has public advisories describing unauthenticated
    read/write, which suggests high real-world exploitability without a
    project-specific exploit search having been performed.
  CISA KEV: Not checked in this project.
  Exploit Impact on Priority: Raises urgency, cautiously -- based on
    documented capability rather than a project-verified PoC search.

Factor 4 - Compensating Controls:
  Existing Controls: None -- matches GAP-007 exactly ("Medical IoT devices
    share a flat network with no isolation... What is Missing: Preventive
    and Detective").
  Control Impact on Priority: Does not lower urgency -- zero controls exist.

Environmental CVSS (recalculated):
  Environmental Metrics Applied: CR=Medium, IR=High, AR=High.
  Adjusted Score: 9.8 -- hits the Impact cap given the Critical
    Integrity/Availability requirements.

Final Priority: Critical
Final Justification: A patient-safety asset category with zero compensating
  controls of any kind, a documented (if not project-verified) real-world
  exploitation capability, and a named role as the destination of an
  existing kill chain. The main honest caveat here, compared to Finding
  031 or 015, is that this project did not independently verify exploit
  availability for this specific finding the way Task 4 did for the top 5
  CVEs -- that gap should be closed before this priority is finalized in a
  real engagement.
```

## Finding 007 — LDAP Signing / SMBv1, `ad-dc-01`

```
CVSS Base Score: N/A (no CVE); constructed estimate `AV:N/AC:H/PR:N/UI:N/
  S:U/C:H/I:H/A:N` ≈ 7.4 -- Attack Complexity rated High to reflect that an
  LDAP relay attack requires positioning (a man-in-the-middle or relay
  setup), not a single direct request.

Factor 1 - Asset Criticality:
  Asset: ad-dc-01 (A-005), Primary domain controller -- #2 Top-5 Most
    Critical Asset
  CIA Rating: Identity & Directory Services -- Confidentiality: High,
    Integrity: Critical, Availability: Critical, Overall: Critical (1x00
    Task 8)
  Criticality Impact on Priority: Raises urgency significantly -- this is
    the trust anchor for nearly every login in the organization.

Factor 2 - Kill Chain Position:
  Appears in Kill Chain(s): Kill Chain #1, Step 4 (credential dumping and
    pass-the-hash against ad-dc-01) and Scenario 1 ("Operation Flatline"),
    Step 4 -- both name this exact host as the point where Domain Admin is
    obtained, via a related but not identical technique (pass-the-hash
    rather than LDAP relay specifically).
  Chain Role: Lateral movement / escalation -- the step that converts a
    single compromised workstation into domain-wide authority.
  Kill Chain Impact on Priority: Raises urgency -- this finding adds a
    second, independent path to the same devastating outcome (Domain
    Admin) that Kill Chain #1 already documents via a different technique.

Factor 3 - Exploitability:
  Exploitability Score: Not scored on the 1-5 scale (Task 4, misconfig).
  CISA KEV: N/A.
  Exploit Impact on Priority: Raises urgency moderately -- LDAP relay and
    SMBv1 abuse are well-documented, tool-supported techniques (e.g.,
    ntlmrelayx), not exotic research, even without a project-specific
    exploit search.

Factor 4 - Compensating Controls:
  Existing Controls: C-002 (VPN-restricted subnet, same reliability caveat
    as Finding 001/002) and C-013 (FortiGate local traffic logging --
    Detective, 30-day retention). C-013 is the only detective control
    touching this host's traffic at all, but GAP-002 already establishes
    that nothing reviews these logs in practice.
  Control Impact on Priority: Minimal -- a detective control exists on
    paper but is functionally inert without review, so it does not
    meaningfully lower urgency.

Environmental CVSS (recalculated):
  Environmental Metrics Applied: CR=High, IR=High, AR=High (matching the
    domain controller's High/Critical/Critical rating).
  Adjusted Score: 8.1 -- up from the constructed base of 7.4. Unlike the
    fully-maxed findings above, this vector's High Attack Complexity keeps
    Exploitability lower, so the environmental Impact increase (driven by
    the Critical asset rating) produces a visible, meaningful score
    increase rather than hitting an already-saturated cap.

Final Priority: Critical
Final Justification: This is the clearest example in the set of an
  environmental recalculation actually changing the number in a way that
  matters for decision-making: a misconfiguration that might read as
  "High, not urgent" in isolation becomes Critical once the domain
  controller's own criticality and its second, independent path to the
  exact outcome Kill Chain #1 already fears are both factored in.
```

## Finding 029 — Grafana Path Traversal (CVE-2021-43798), Westside Shadow IT

```
CVSS Base Score: 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N, NVD-verified)

Factor 1 - Asset Criticality:
  Asset: A-025, unidentified device at Westside Clinic
  CIA Rating: Shadow IT / Undocumented Assets -- Confidentiality: High,
    Integrity: Medium, Availability: Low, Overall: High (1x00 Task 8)
  Criticality Impact on Priority: Raises urgency more than the "High"
    category label suggests at first glance -- the High Confidentiality
    rating specifically reflects the fact that no one knows what this
    device can see or touch, which is itself a reason for elevated concern,
    not reduced.

Factor 2 - Kill Chain Position:
  Appears in Kill Chain(s): None identified -- this device does not appear
    in any of the five 1x01 Task 10 kill chains or the three Task 14
    scenarios.
  Chain Role: Unknown / undetermined -- genuinely unclear, since no one has
    mapped what this device can reach or why it exists.
  Kill Chain Impact on Priority: Raises urgency through absence, not
    presence -- a vulnerability with no documented blast-radius mapping on
    an unmonitored device is a bigger unknown than one whose worst case is
    already understood.

Factor 3 - Exploitability:
  Exploitability Score: Not independently scored in Task 4 (outside the
    five CVEs analyzed there), but the CVE is described in the scan report
    itself as "publicly available, trivial to execute" -- functionally a
    4-5 by this project's own scale.
  CISA KEV: Not checked in this project.
  Exploit Impact on Priority: Raises urgency -- trivial exploitation
    combined with zero monitoring is a dangerous combination regardless of
    formal KEV status.

Factor 4 - Compensating Controls:
  Existing Controls: None -- by definition, an undocumented device cannot
    appear in any control's "Asset(s) Protected" list.
  Control Impact on Priority: Does not lower urgency -- no control exists
    or could exist for an asset no one has formally acknowledged.

Environmental CVSS (recalculated):
  Environmental Metrics Applied: CR=High, IR=Medium, AR=Low (matching the
    Shadow IT category's own rating).
  Adjusted Score: 9.3 -- a substantial rise from the base 7.5. Unlike the
    already-maxed findings above, this vector's Confidentiality-only impact
    (I:N/A:N) was well below the 0.915 cap at baseline, leaving real room
    for the environmental adjustment to move the number -- and the High
    Confidentiality requirement moves it a full 1.8 points.

Final Priority: Critical
Final Justification: This is the single most counter-intuitive result in
  the set. An "Informational" scanner-severity finding, on a device no one
  formally owns, with a base CVSS of only 7.5, recalculates to 9.3 once the
  actual risk driver -- total absence of visibility into a device with
  documented high-confidentiality exposure -- is properly weighted. This is
  exactly the kind of finding a purely CVSS-driven, unweighted triage
  process would deprioritize into irrelevance.
```

## Priority Comparison Table

| Finding | CVSS Base | Adjusted (Environmental) | Final Priority | Change Direction |
|---|---|---|---|---|
| 031 (Ghostcat) | 9.8 | 9.8 | Critical | Same (already at cap) |
| 003 (PostgreSQL) | ~9.1 (estimated) | 9.8 | Critical | Higher |
| 001/002 (Apache chain) | 9.8 | 9.8 | Critical | Same (already at cap) |
| 004 (Windows XP) | 10.0 | 10.0 | Critical | Same (already at ceiling) |
| 015 (NAS-01) | ~9.4 (estimated) | 9.8 | Critical | Higher |
| 016 (Philips fleet) | ~9.8 (estimated) | 9.8 | Critical | Same (already at cap) |
| 007 (LDAP/SMBv1) | ~7.4 (estimated) | **8.1** | Critical | **Higher — meaningful shift** |
| 029 (Grafana shadow IT) | 7.5 | **9.3** | Critical | **Higher — most significant shift** |

**Findings where the adjusted priority differs most significantly from base CVSS:** **Finding 029** is the standout case — a base score of 7.5 on a scanner-labeled "Informational" finding recalculates to 9.3 once the shadow-IT confidentiality exposure is weighted, a 1.8-point swing that would be invisible to any triage process relying on the scan's own severity label. **Finding 007** shows the same pattern at smaller scale (7.4 → 8.1): a misconfiguration with no CVE and no CVSS score at all only becomes visibly urgent once the domain controller's criticality is factored in explicitly. Every other finding in this set was already scored at or near CVSS's mathematical ceiling at the base level, meaning the environmental exercise mostly *confirmed* rather than *changed* their priority — the real value of this task is precisely in catching the two findings where that wasn't true.

## Repo

- **GitHub repository:** `dlh-cyber_security`
- **Directory:** `blue_team/1x02_the_weak_links`
- **File:** `17-cvss_contextualizer.md`
