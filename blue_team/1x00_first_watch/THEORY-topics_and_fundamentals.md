# Theory and Topics — 1x00 First Watch

Study guide with theory + practical examples from the MedDefense scenario, for every exercise in this module. This is the **first** module in the track: the central question is **"what does MedDefense have, and where are the control failures?"** — an internal posture assessment, without yet discussing who wants to attack (that's 1x01) or scanned technical vulnerabilities (that's 1x02).

---

## 0. Environment Summary

**What it is:** the raw, structured survey of the environment — sites, infrastructure, data, and critically the **Known Unknowns** (what still isn't known). This is the starting point of any assessment: you can't protect what hasn't been mapped.

**Structure used:** Organization Overview (sites, headcount, reporting structure) → IT Infrastructure (servers, network, endpoints, medical devices) → Data and Services (what each system holds and its criticality) → **Known Unknowns** (knowledge gaps explicitly documented, by category: network, servers, authentication, physical, compliance, medical devices).

**Why "Known Unknowns" is a formal section, not an afterthought:** explicitly documenting "we don't know if X" is as valuable as documenting a confirmed fact — it turns a silent blind spot into a trackable item someone can decide to investigate. An assessment that only lists certainties hides exactly the most dangerous risks (whatever no one has verified yet).

**A governance detail that already appears here and echoes through the whole module:** the CISO seat is vacant (James Chen is only Deputy), and James has authority over security policy but **not** over IT operations (controlled by Sarah Park, a peer, not a subordinate) — this organizational friction resurfaces in nearly every governance exercise in later modules.

**Example:** Central's network is completely flat (`10.10.0.0/16`) — medical devices, workstations and servers share the same broadcast domain. This single fact, recorded here as a "Known Unknown/planned with no timeline," becomes the repeated root cause behind nearly every Critical gap documented in the items that follow.

---

## 1. Incident Classification

**What it is:** classifying historical incidents using the **CIA Triad** (Confidentiality, Integrity, Availability) — the most fundamental vocabulary in information security, used to name *what kind* of damage an event caused.

**Correct methodology:** identify the **primary pillar** (the direct, explicit impact described in the record) and only list a **secondary pillar** if there is explicit textual evidence for it — never by speculation. This prevents inflating an incident's severity with hypothetical impacts the record doesn't actually support.

**Classic mistake to avoid:** confusing "the most visible symptom" with "the pillar actually violated." Ransomware that encrypts a server looks, at first glance, like an **Availability** problem (the server went down) — but the encryption itself is an unauthorized modification of the data, which is also **Integrity**. Meanwhile, an IDOR exposing another patient's lab result is purely **Confidentiality** — nothing was altered, nothing went down.

**Example:** an unmanaged personal laptop on the network for 3 weeks → primary **Confidentiality** (bypasses segmentation and reaches the same segment as the HR share), secondary **Availability** (a torrent client generates sustained heavy traffic, potentially degrading the clinical/administrative network sharing that same link).

---

## 2. Root Cause Analysis

**What it is:** going beyond the obvious symptom ("CPU is saturated") to the **real root cause** of a technical incident — here, a cryptojacking process disguised as a legitimate Linux kernel process.

**Core technique: recognizing process disguise.** A real `kworker` runs as `root` and appears as `[kworker]` in brackets; the malicious process here runs as `www-data`, from a file path (`/var/www/html/.cache/kworker`) — a name deliberately chosen to blend into the process list.

**The real compromise chain (in the correct order):** first **Confidentiality** was broken (unauthorized access through the web application itself), then **Integrity** (a foreign binary was uploaded and executed), and only **last**, as the visible symptom, came CPU saturation (**Availability**). The core lesson: the pillar that trips the alarm isn't always the first pillar actually violated.

**Why the sysadmin's "fix" (hardware upgrade) fails:** the miner is configured to use whatever CPU it's given — a bigger VM just hands the attacker more mining capacity, without touching how they got in. Swapping the symptom for bigger hardware doesn't close the entry door.

**Connecting two seemingly unrelated incidents:** two different compromises on the same server, after a full rebuild, means the rebuild reset the **symptom**, not the **cause** — the same vulnerability (Apache 2.4.29 with known RCEs) very likely survived the rebuild.

**Example:** the final recommendation isn't "upgrade the VM" — it's confirming the Apache version against known CVEs and auditing other servers running the same vulnerable version, treating the cause, not the symptom.

---

## 3. Physical Assessment

**What it is:** assessing **physical** security risk — how someone with access to the building can cause harm without touching any system remotely.

**Decomposition framework used for every observation (4 formal components):**
- **Vulnerability:** the concrete physical weakness (unlocked door, exposed credential, no session timeout).
- **Threat:** who would benefit from exploiting this weakness, and how.
- **Impact:** which CIA pillar(s) would be broken.
- **Severity:** justified in one sentence, weighing ease of exploitation against impact.

**Why this formal decomposition matters:** it turns a generic observation ("the door stays open") into a defensible risk analysis, using the same structure applied to technical vulnerabilities — physical security isn't a separate category, it's risk with the same anatomy.

**Pattern that repeats across all 5 observations:** most require **zero technical skill** to exploit (a generic badge, a password taped to a wall, a fire exit wedged open) — the barrier to a successful physical attack here is nearly zero, which raises severity even when the "attack" itself is trivial.

**Example:** the network closet (Observation 2) has no lock, the door sits ajar, and a sheet taped to the wall lists the switch's management username and password — severity **Critical**, because it requires no skill at all and compromises connectivity/traffic for an entire floor.

---

## 4. Control Inventory

**What it is:** formally cataloging **every existing security control** — the inventory that becomes the foundation for every subsequent gap analysis (you can't find what's missing without first listing what already exists).

**Two classification dimensions used for every control (used throughout the rest of the module):**
- **Category:** Technical / Administrative / Physical — *where* the control lives.
- **Function:** Preventive / Detective / Corrective / Compensating / Deterrent — *what* the control does.

**Why cross these two dimensions into a matrix:** a Category × Function matrix reveals **investment patterns** visually — empty cells jump out in a way a flat control list never does.

**A pattern that already appears here (and gets confirmed in later items):** the Task 4 matrix shows controls concentrated almost entirely in **Preventive**, with very thin **Detective** coverage and almost no **Corrective/Compensating/Deterrent** — the same "prevention yes, detection and response almost zero" pattern that becomes the entire module's central theme.

**Example:** C-009 (nightly Veeam backup) is Technical/**Corrective** — it exists, but it's the only corrective control in the entire inventory, and alone it doesn't compensate for the absence of any Detective or Compensating control.

---

## 5. Control Gaps

**What it is:** starting from item 4's inventory, formally identifying **where coverage is missing** — crossing Category × Function and asking "what combination should exist and doesn't?"

**Methodological discipline:** a gap of "no Detective AND Corrective control" is only classified that way if **both** functions are genuinely absent — if a Corrective control (e.g., backup) exists but Detective is missing, the gap is downgraded from Critical to High. This discipline prevents artificially inflating severity.

**The core pattern this item formalizes:** MedDefense is heavily prevention-oriented; detective coverage is thin and unmonitored; corrective/compensating/deterrent are almost entirely absent. This means that once an attacker gets past a preventive control — which has **already happened twice** on `billing-srv-01` — the organization has very little ability to notice, contain, or recover quickly: incidents are discovered by accident, not by design.

**Example:** G-002 (logs exist — SSH, firewall — but nothing reviews or alerts on them) is rated **Critical**, because the only detection mechanism is "we check manually when something breaks" — exactly what let the cryptominer from item 2 run unnoticed for two weeks.

---

## 6. Compensating Controls

**What it is:** designing a mitigation strategy for a risk that **cannot be fixed at the source** — the classic case is a legacy system that can't be updated, replaced, or disconnected (the MRI control workstation, running Windows XP).

**Why "compensating" is different from "correcting":** a compensating control doesn't touch the underlying vulnerability — it reduces the **reach** or **likelihood of exploitation** without eliminating the flaw itself. It's the right answer when direct correction (patch, upgrade, replacement) is impossible due to a business constraint, not a lack of technical will.

**The 3 categories of compensating strategy (they appear together, reinforcing each other):**
- **Technical/Compensating:** network isolation (segmentation, a dedicated VLAN) — doesn't touch the OS, only changes where the device "lives" on the network.
- **Administrative/Compensating:** a formal risk-acceptance and review process — protects nothing technically, but ensures the risk stays *actively tracked* instead of forgotten.
- **Physical/Preventive:** restricting physical access and locking USB ports — closes the one path no network control can close (someone physically touching the equipment).

**How to prioritize among the three when only one can be implemented immediately:** network segmentation (Technical/Compensating) wins because it attacks the root architectural exposure (flat network) instead of managing the problem administratively, it's a one-time technical change that doesn't depend on ongoing human compliance (unlike the administrative process), and it protects against the most likely, most scalable attack path (network) rather than the least likely one (physical access, which already requires the attacker to be inside the building).

**Example:** even with all 3 layers implemented, residual risk still exists — if the one remaining permitted host (PACS) is ever compromised, or if there's direct physical access, none of the 3 controls offer protection. This is stated explicitly, not hidden.

---

## 7. Asset Registry

**What it is:** the single, formal inventory of **every asset** in the environment — servers, endpoints, medical devices, applications, network and physical infrastructure — each with an ID, location, owner, criticality and status.

**Why this is the foundation for everything that follows:** you can't assess criticality (item 8), map data (item 9), or calculate financial risk (module 1x03) on an asset that isn't listed. The Asset Registry is the "master database" every other curriculum artifact references by ID (A-001, A-002...).

**A crucial reconciliation step: cross documentation against an independent network scan.** This reveals three types of discrepancy, each with a different implication:
- **Asset in the scan but not in documentation (Shadow IT):** no one knows it exists — the most dangerous kind of risk, because it sits outside any control.
- **Asset in documentation but not in the scan:** it may no longer exist, may be powered off, or may live on a system the scan doesn't cover (cloud, for instance).
- **Contradiction between sources:** a repeated claim (e.g., "the Apache version is X") needs direct verification, not confident repetition.

**Example:** A-012 (`UNKNOWN-01`, 10.10.2.99) is an undocumented Linux host with two web services, on the same subnet as core servers — Sarah has no record of it. This is exactly the kind of finding that only surfaces by cross-checking the scan against documentation, never trusting a single source.

---

## 8. Criticality Assessment

**What it is:** for each asset category in the registry (item 7), assigning a formal criticality rating using the **CIA Triad** — not "this seems important," but a justified C/I/A score backed by evidence.

**How a medical asset's criticality differs from an ordinary IT asset:** an Integrity/Availability failure on a medical device isn't "a data problem" — it's a **patient-safety problem** (a wrong vitals reading, interrupted dosing). This raises the entire medical IoT category to Critical, regardless of how "simple" the device seems technically.

**How the flat network affects the criticality of a seemingly ordinary asset:** a single workstation has moderate direct impact — but the absence of segmentation (tracked separately as an amplification risk) turns any one of them into a pivot point toward much more critical assets. An asset's "isolated" criticality and its real role in the environment's risk can diverge.

**Example:** `ehr-db-01` is the #1 Top-5 asset — not just for holding PHI for 50,000+ patients, but because, **at the time of assessment**, it's already reachable from the entire `/16` instead of being restricted to the application server — its real exposure is broader than its isolated criticality alone would suggest, a combination that recurs in module 1x02 as Finding 003.

---

## 9. Data Map

**What it is:** mapping **each data category** (not each system) through its full lifecycle — at rest, in transit, and in use — along with current protection and the specific gap at each stage.

**Why separating into 3 states matters:** data can be well-protected at rest (encrypted on disk) and completely exposed in transit (flat network, no TLS) — protecting only one state gives a false sense of complete security.

**Classification used:** **Restricted** (patient data, system credentials) vs. **Confidential** (financial, HR) — MedDefense uses these two levels, and every row in the map inherits the highest level among everything it contains.

**The most important discovery of this exercise:** the most critical data category at risk isn't the medical record itself — it's **system credentials**, because credentials are "Restricted" by definition (they unlock access to every other category), and yet the switch management password is physically written on a sheet taped to a wall, and no system in the environment requires a second authentication factor. A failure in the "master key" category takes down the protection of every other category at once.

**Example:** Dr. Patel's clinical research data, stored on an unmanaged personal NAS, is completely **invisible** to any control in item 4's inventory — no backup, no access policy, no monitoring, because it was never formally recognized as an organizational asset (see item 11).

---

## 10. Complete Control Matrix

**What it is:** updating item 4's control matrix by adding a new dimension — **Effectiveness** (Strong / Adequate / Weak) — and then crossing that matrix against item 8's Top 5 critical assets, to see *where protection actually fails in the places that matter most*.

**Why "exists" isn't the same question as "works well":** a control can appear present in item 4's matrix and still be rated **Weak** here — for example, C-004 (SSH key-only) is strong on the host it's implemented on, but only **Adequate**, not Strong, because it was never rolled out to the rest of the organization. A control that is "correct but isolated" isn't the same as a control that is "correct and comprehensive."

**The most revealing cross-reference in the exercise: the Top 5 Asset Control Coverage Map.** It shows, asset by asset, exactly which control function is missing — and the pattern is consistent: **almost every one of the most critical assets has zero Detective control**, even when it has some Preventive/Corrective.

**Example:** the BD Alaris infusion pump fleet appears as **completely unprotected** ("Unprotected") in the matrix — no control of any category protects it directly, and the vendor-recommended isolation was never implemented — the worst possible outcome when crossing maximum criticality (patient safety) with zero coverage.

---

## 11. Shadow Systems Assessment

**What it is:** formally investigating every **Shadow IT** system (technology used without formal IT approval/governance) discovered throughout the assessment, and deciding the correct response for each — not every instance of Shadow IT deserves the same response.

**The 3 possible responses, and when each applies:**
- **Legitimize and Secure:** when there's a real, legitimate need behind the Shadow IT (e.g., the shared drive was too slow) — decommissioning without an alternative just pushes the same behavior somewhere even less visible.
- **Migrate:** when a sanctioned, already-paid-for, functionally equivalent alternative already exists (e.g., already-licensed O365/SharePoint, instead of a personal Google Drive) — the clearest case of "why are we paying for something we already own, just in the shadows."
- **Decommission:** when there's no longer an active business owner for the system (the original project ended when its owner left) — there's no current legitimate need to legitimize.

**The most important policy lesson of the exercise:** the common root cause across all 3 cases is the **absence of a fast, low-friction intake process** for new tools — every instance of Shadow IT was born from a real need with no fast sanctioned path to address it. A formal process with a committed response time (e.g., 48h) removes the incentive to quietly solve problems outside IT's visibility — a more durable fix than any amount of after-the-fact detection.

**Example:** the "network monitor" Raspberry Pi on the 2nd floor is very likely the same unidentified host (A-012) from item 7's network scan — cross-referencing two independent sources of evidence (the helpdesk conversation and the technical scan) confirms it's the same device, not a fourth unknown one.

---

## 12. Prioritized Gap Analysis

**What it is:** consolidating everything from items 4-11 into a single, prioritized list of **control gaps**, each with a formal ID (GAP-XXX), risk level, and specific evidence — the central artifact that feeds the rest of the curriculum (1x01 and 1x02 constantly cite these GAP-IDs).

**Explicit methodological rule (same discipline as item 5, now formalized):** "no detective or corrective control" only justifies **Critical** if both functions are genuinely absent — if one of them exists (even weakly), the gap drops to **High**. This rule prevents severity inflation and makes the rating defensible.

**Distribution pattern discovered:** the overwhelming majority of gaps concentrate on **missing Detective and Corrective** functions, never a total absence of Preventive — confirming, with consolidated data, the pattern already emerging since item 5: MedDefense never lacked the will to block known threats; it lacks the ability to notice or recover from the ones that get through anyway.

**Example:** GAP-004 (infusion pump fleet with zero dedicated controls) is Critical because it combines a patient-safety asset with total absence (Preventive, Detective and Corrective) and a known, vendor-flagged vulnerability that was never mitigated.

---

## 13. Reality Check

**What it is:** validating (or refuting) the gap analysis itself against **real breach cases at other hospitals** — testing whether the documented gaps match how real attacks actually unfolded at similar organizations.

**Per-breach methodology:** for each real case, (1) identify the exact attack vector, (2) correlate each step against MedDefense's already-documented GAPs, and (3) run a **Blind Spot Check** — explicitly asking "is there anything in this breach that MedDefense hasn't documented anywhere yet?"

**Why this exercise is valuable beyond simply "confirming" the gaps:** it often reveals **new** gaps that went unnoticed because no one yet had the concrete case that made them obvious — three new GAPs (017, 018, 019) are born exactly from this process, not from the original internal audit.

**How an external breach can raise an existing gap's priority:** if a real case shows a single gap, alone, causing a full notifiable breach, that's stronger evidence than the original theoretical analysis — GAP-014 (no MFA) rises from High to **Critical** for exactly this reason.

**Example of a discovered blind spot:** no gap documented before addressed **privileged access tiering in Active Directory** — Breach 1 shows a single compromised domain-admin credential being used to push ransomware via GPO across the entire organization at once, revealing GAP-017 as a real, previously unnamed gap.

---

## 14. Risk Treatment Decisions

**What it is:** for the highest-priority gaps (the 6 Critical + the top-ranked High), formally deciding the **treatment strategy** and proposing a concrete control with an estimated cost — turning "we know this is bad" into "here's the plan and the price."

**Structure of each decision:** risk level → treatment strategy (here, always Mitigate) → justification → proposed control(s) → estimated cost → implementation effort → expected risk reduction → **trade-offs** (what this control does *not* fix, stated explicitly).

**Why stating trade-offs is mandatory, not optional:** every control has a limit — a SIEM only works if someone actually monitors the alerts; segmenting only the infusion pumps (not the rest of medical IoT) leaves explicit residual risk on the monitors, not an accidental oversight. Naming the trade-off prevents a false sense of "fully solved."

**How to allocate a fixed budget across multiple Critical gaps:** rank by cost-benefit ratio, and use the "best deal" (a trivially cheap, extremely high-impact gap, like the unlocked network closet) as a quick win that doesn't genuinely compete with the expensive items — then reserve the remaining balance for the next-highest-value gap, not leave it sitting unused without purpose.

**Example:** GAP-006 (unlocked network closet, exposed credentials) is the "best deal" on the entire list — trivially exploitable, Critical, and fixable for under $1,000 — it should be done immediately, independent of the rest of the budget cycle.

---

## 15. Predecessor Review

**What it is:** formally comparing your own analysis against an **incomplete** draft left by a previous analyst (Marcus Webb) — a real security-program handoff/transition practice, not an adversarial audit.

**Comparison structure, finding by finding:** Agree (same conclusion, independent evidence) / Disagree (a specific reason your own classification diverges) / "Marcus caught something I missed" (acknowledging when the predecessor saw something you hadn't formalized).

**Why "disagreeing" requires explicit justification, not just a different note:** every disagreement in this exercise is resolved with a concrete reason — for example, disagreeing with Marcus's "Medium" rating for the shared PACS credential because "on-site-only access" reduces the **pool of possible actors**, but adds no detective/corrective control and doesn't change the data's classification.

**The most honest part of the exercise: acknowledging what the predecessor saw that you didn't.** This includes informal findings (a sticky note saying "critical" that never made it into the formal document) — evidence that Marcus himself was capturing findings in scattered places and ran out of time to consolidate them, not evidence of incompetence.

**Example:** Marcus discounted the shared PACS login's risk because it's "on-site-only access" — but non-reduced local access doesn't change the absence of a detective/corrective control nor the data's Restricted classification; reducing the pool of actors isn't the same as reducing severity if the event occurs.

---

## 16. Security Posture Assessment

**What it is:** the **consolidated report** for the entire 1x00 module — bringing together assets, controls, gaps, treatment decisions, and the predecessor review into a single document with an Executive Summary, Scope and Methodology, and Conclusion.

**Why this document isn't "just stapling the prior ones together":** a security posture report needs to **translate** technical artifacts into a coherent executive narrative — the same technical-to-executive translation discipline that reappears in the Threat Landscape Report (1x01) and the Security Strategy Document (1x03).

**The sentence that sums up the entire posture, and why it's the right formulation:** "**prevention-only and effectively blind**" — the organization has reasonable controls stopping *some* attacks from starting, but almost no ability to notice one that succeeds, and almost no tested way to recover afterward. It's the conclusion that ties items 4, 5, 10 and 12 into a single executive sentence.

**Structure of the final report (a template reused across the whole curriculum):** Executive Summary (most critical finding + top 3 actions) → Scope/Methodology (what was and wasn't assessed, with stated limitations) → Asset Landscape → Current Controls → Gap Analysis → Treatment Recommendations → Conclusion and Next Steps.

**Example of the report's closing:** it explicitly ends by pointing out that this assessment answered the internal question ("what do we have, and where are the gaps"), but not the external one ("who is actually targeting organizations like MedDefense, and how") — the direct bridge to the next module, 1x01.

---

## 17. CISO Briefing

**What it is:** the most compressed version of everything — a single-page executive communication for a Board meeting, with no technical jargon.

**Structure of an effective Board briefing:** Current State (the problem, in plain language) → Critical Finding (a single concrete fact, not a list) → Priority Actions (a few, named, with cost and timeline) → Business Case (comparing the program's cost against the real cost of a comparable incident) → Closing.

**Why anchoring on a real example from another hospital is more persuasive than any abstract statistic:** citing the recovery cost and ambulance-diversion days from a comparable real breach makes the requested budget concrete and comparable, not a hypothetical estimate the Board can mentally discount.

**Style rule, same as 1x03's Board Pitch:** every sentence needs to stand on its own if read aloud in a meeting room — zero untranslated technical jargon.

**Example:** "if a more serious attacker got in the same way, we would likely find out only after patient care was already disrupted" — translates the absence of detection (GAP-002) into a concrete clinical consequence, without using the word "SIEM" even once.

---

## Dependency order across the files

```
0 raw environment survey (Known Unknowns)
 └─ 1 CIA incident classification · 2 technical root cause · 3 physical assessment
     └─ 4 control inventory (Category × Function)
         └─ 5 control gaps (what's missing from the matrix)
             └─ 6 compensating controls (legacy case with no direct fix possible)
                 └─ 7 asset registry (single inventory, reconciled against a scan)
                     └─ 8 CIA criticality per asset · 9 data map (3 states)
                         └─ 10 complete control matrix (+ effectiveness, crossed with Top 5)
                             └─ 11 shadow IT (case-by-case response)
                                 └─ 12 prioritized gap analysis (formal GAP-IDs)
                                     └─ 13 reality check (validation against real breaches)
                                         └─ 14 risk treatment decisions (cost + strategy)
                                             └─ 15 predecessor review (comparison with Marcus)
                                                 └─ 16 security posture assessment (consolidated report)
                                                     └─ 17 CISO briefing (final communication, 1 page)
```

## Framework reference table (quick review before repeating the module)

| Concept | Used in | Core idea |
|---|---|---|
| CIA Triad | Items 1, 3, 8, 9 | Confidentiality, Integrity, Availability — the base vocabulary of the whole curriculum |
| Known Unknowns | Item 0 | Explicitly documenting what isn't known, not just what is |
| Control Category × Function | Items 4, 5, 10 | Technical/Administrative/Physical × Preventive/Detective/Corrective/Compensating/Deterrent |
| Compensating Control Strategy | Item 6 | Mitigating without fixing the cause, when direct correction is impossible |
| Asset Registry + reconciliation | Item 7 | Single inventory by ID, cross-checked against an independent scan to find Shadow IT |
| Shadow IT Triage | Item 11 | Legitimize and Secure / Migrate / Decommission — the right response per case |
| Formal GAP-ID | Item 12 | Rule: Critical requires the absence of BOTH Detective and Corrective, not just one |
| Reality Check / Breach Validation | Item 13 | Validating theoretical gaps against real cases; finds new blind spots |
| Risk Treatment (Mitigate) | Item 14 | Strategy + cost + explicit trade-off, never "solved" without a caveat |
| Predecessor Review | Item 15 | Agree/Disagree with justification; acknowledging what the other analyst saw |
| Executive Report Structure | Items 16, 17 | Summary → Scope → Findings → Recommendation, translated for non-technical readers |

---

*Study guide — not part of the deliverable. Use as a theory checklist before reviewing or expanding any exercise in this module.*
