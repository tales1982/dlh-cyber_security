
# 15. The Gap-Threat Correlation

**Analyst:** Threat Intelligence Analyst
**Date:** Current

## Methodology Note

Kill Chains referenced (T10): **KC1** Phishing to Domain-Wide Ransomware, **KC2** VPN Credential Compromise to Domain Takeover, **KC3** Insider Data Exfiltration, **KC4** Unpatched Web Server to Medical Device Exposure, **KC5** Vendor Compromise to Direct Patient Data Access.
Scenarios referenced (T14): **S1** BlackReef Ransomware Campaign, **S2** Insider Data Exfiltration, **S3** MedTech Supply Chain Compromise.

## Gap Correlations

### GAP-001 — EHR database reachable network-wide, no anomalous-access detection

- Original Risk Level: High
- Threat Actors: Ransomware Groups, Insider (Malicious), Insider (Negligent), Unskilled/Opportunistic — effectively every actor type once any foothold exists.
- Kill Chains: KC1, KC3, KC5
- Scenarios: S1, S2, S3 — the only gap appearing in all three built scenarios.
- Updated Risk Level: **Upgraded → Critical**
- Justification: The original High rating assumed the corrective backup control offset the missing detective control. Threat evidence shows this gap is the connective tissue of literally every attack path built in 1x01 regardless of actor type — that universality is itself Critical-level evidence.

### GAP-002 — No functioning detection or incident-response capability

- Original Risk Level: Critical
- Threat Actors: All 6 actor types — the single most universal enabler of undetected dwell time.
- Kill Chains: KC1, KC2, KC3, KC5 (4 of 5)
- Scenarios: S1, S2, S3 (all 3)
- Updated Risk Level: **Same — Confirmed Critical**
- Justification: Already Critical in 1x00; threat analysis strongly reinforces rather than changes it — this is the single most-cited gap across the entire correlation (7 total appearances), the clearest possible independent validation.

### GAP-003 — Sole backup repository (NAS-01) unprotected

- Original Risk Level: Critical
- Threat Actors: Ransomware Groups specifically — backup neutralization is BlackReef's own documented, written playbook step.
- Kill Chains: KC1
- Scenarios: S1
- Updated Risk Level: **Same — Confirmed Critical**
- Justification: Narrower footprint than GAP-001/002, but the #1-priority actor type (T6) targets this gap explicitly and by name in its own operational doctrine, sustaining the Critical rating on likelihood grounds alone.

### GAP-004 — Infusion pump fleet has zero dedicated security controls

- Original Risk Level: Critical
- Threat Actors: Unskilled/Opportunistic (direct), Ransomware Groups (secondary, post-lateral-movement)
- Kill Chains: KC4
- Scenarios: None of the 3 built scenarios directly.
- Updated Risk Level: **Same — Confirmed Critical**
- Justification: Appears in only one kill chain and zero scenarios, but patient-safety severity is categorical, not frequency-dependent — a gap with direct clinical-harm potential does not get downgraded simply because fewer threat paths were modeled through it.

### GAP-005 — Endpoint antivirus excludes every server

- Original Risk Level: High
- Threat Actors: Unskilled/Opportunistic, Ransomware Groups (persistence stage)
- Kill Chains: None of the 5 name it directly, though it is a supporting factor in the STRIDE Denial-of-Service analysis of the EHR (T11, EHR-D2).
- Scenarios: None directly.
- Updated Risk Level: **Same**
- Justification: Not a primary step in any built kill chain or scenario, but real clinical relevance via the STRIDE cross-reference keeps it from downgrading — insufficient new frequency evidence to move it in either direction.

### GAP-006 — Network closet has no lock, exposed credentials

- Original Risk Level: Critical
- Threat Actors: None of the 6 T6 actor profiles list Physical Access as a preferred/primary vector.
- Kill Chains: None of the 5.
- Scenarios: None of the 3.
- Updated Risk Level: **Downgraded → High**
- Justification: Rated Critical in 1x00 purely on inward-looking criteria (critical asset, complete control absence). Threat evidence tells a different story: zero of the 6 profiled actor types and zero of the 5 kill chains or 3 scenarios route through physical access — credential- and network-based paths dominate every actual attack path modeled, making this a real but comparatively lower-priority gap once threat likelihood is factored in.

### GAP-007 — Medical IoT devices share a flat network with no isolation

- Original Risk Level: Critical
- Threat Actors: Unskilled/Opportunistic
- Kill Chains: KC4
- Scenarios: None of the 3 directly.
- Updated Risk Level: **Same — Confirmed Critical**
- Justification: Same reasoning as GAP-004 — patient-safety category, and KC4 is built on MedDefense's own proven pattern (the `billing-srv-01` double-compromise), making the likelihood component concrete rather than theoretical.

### GAP-008 — Billing server has weak coverage despite two prior compromises

- Original Risk Level: High
- Threat Actors: Unskilled/Opportunistic — ranked #2 in T6's Top 3 Priority Ranking.
- Kill Chains: KC4
- Scenarios: None of the 3 built directly, though thematically adjacent to S1.
- Updated Risk Level: **Upgraded → Critical**
- Justification: This gap is attached to an actor type independently confirmed as a top-3 priority specifically *because* it already caused two real incidents here — this is not a theoretical High risk, it is an actively and repeatedly exploited one, which the original assessment could not fully weigh without the T6 actor-likelihood analysis.

### GAP-009 — HR file share reachable by unmanaged devices

- Original Risk Level: High
- Threat Actors: Insider (Negligent) — matches the shadow-IT pattern (T3 Scenario 3, T1 Report F).
- Kill Chains: None of the 5.
- Scenarios: None of the 3.
- Updated Risk Level: **Same**
- Justification: Confirmed relevant to a High-likelihood actor type via the shadow-IT connection, but does not appear as a primary step in any built kill chain or scenario — sustains its original rating without evidence to move it either direction.

### GAP-010 — Shared PACS login removes individual accountability

- Original Risk Level: Critical
- Threat Actors: Insider (Malicious), Insider (Negligent)
- Kill Chains: None of the 5 directly, though EHR-R2 (T11) draws a direct structural parallel.
- Scenarios: None of the 3.
- Updated Risk Level: **Same — Confirmed Critical**
- Justification: 1x00 already fought to keep this Critical against Marcus's Medium rating; T6's independent Insider actor-likelihood analysis (both Malicious and Negligent rated Medium-High) reinforces the original Critical call even without a dedicated kill chain built around PACS.

### GAP-011 — Three confirmed shadow IT systems sit outside governance

- Original Risk Level: High
- Threat Actors: Insider (Negligent) primarily; Nation-State secondarily (the only current research-adjacent foothold, T6).
- Kill Chains: None of the 5.
- Scenarios: None of the 3.
- Updated Risk Level: **Same**
- Justification: Confirmed relevant to two distinct actor types, but impact stays bounded per 1x00's own original reasoning — no new evidence pushes it toward Critical.

### GAP-012 — Flat network turns every endpoint into a pivot point

- Original Risk Level: Medium
- Threat Actors: Ransomware Groups — the #1-priority actor type.
- Kill Chains: KC2
- Scenarios: S1
- Updated Risk Level: **Upgraded → High**
- Justification: 1x00 rated this Medium because partial controls (C-006/008/012) reduce the risk. Threat evidence shows this exact gap is a named, explicit step in the #1-priority actor's kill chain and the #1-priority scenario — the partial controls that justified Medium do not meaningfully stop the specific actor type most likely to exploit it.

### GAP-013 — Print server past end-of-life

- Original Risk Level: Low
- Threat Actors: None of the 6 primary actor types target this asset in any T6-T14 material.
- Kill Chains: None.
- Scenarios: None.
- Updated Risk Level: **Same — Confirmed Low**
- Justification: Zero threat-actor association across the entire 1x01 analysis — the clearest possible case of a gap that stays low priority because no one is actually likely to target it.

### GAP-014 — No MFA anywhere in the environment

- Original Risk Level: Critical *(already upgraded from High within 1x00 itself, Task 13, following Breach 2 evidence)*
- Threat Actors: Ransomware Groups — the #1-priority actor type.
- Kill Chains: KC1, KC2, KC5 (3 of 5 — tied for the most of any gap)
- Scenarios: S1, S3
- Updated Risk Level: **Same — Confirmed Critical**
- Justification: Already elevated to Critical inside 1x00 itself. The 1x01 threat analysis arrives at the same conclusion from a completely independent angle — appearing in 3 of 5 kill chains and 2 of 3 scenarios — which is strong cross-validation rather than new information.

### GAP-015 — Westside Clinic lacks basic network and physical security

- Original Risk Level: High
- Threat Actors: No dedicated actor/kill chain/scenario was built targeting Westside specifically in 1x01.
- Kill Chains: None of the 5.
- Scenarios: None of the 3.
- Updated Risk Level: **Same**
- Justification: An analysis gap worth flagging for the next cycle — Westside was never modeled as a dedicated attack path in 1x01, so there is no new threat evidence to move this rating in either direction; it remains High on inward-looking criteria alone.

### GAP-016 — No formal change management process

- Original Risk Level: High
- Threat Actors: Insider (Negligent) — T3 Scenario 5 (the overworked admin) is a direct instance.
- Kill Chains: None tagged directly, though KC1 Step 9's plaintext-credential file is the same structural pattern.
- Scenarios: S2
- Updated Risk Level: **Upgraded → Critical**
- Justification: This gap directly enabled the plaintext-credential exposure at the root of the Insider Exfiltration scenario (S2), and the same pattern independently extended the Ransomware scenario's blast radius to the Linux servers in KC1 — sitting at the root of two independent, high-priority threat paths pushes it above its original High rating.

### GAP-017 — No privileged access tiering for Active Directory

- Original Risk Level: Critical
- Threat Actors: Ransomware Groups — the #1-priority actor type.
- Kill Chains: KC1, KC2
- Scenarios: S1
- Updated Risk Level: **Same — Confirmed Critical**
- Justification: Already Critical in 1x00; threat evidence directly reinforces it by showing this gap is the specific mechanism converting a single phished or purchased credential into full domain compromise in the #1-priority actor's two most direct kill chains.

### GAP-018 — No automated account deprovisioning tied to HR termination

- Original Risk Level: High
- Threat Actors: Insider — the departing-employee pattern spans both the Malicious and Negligent categories.
- Kill Chains: KC3
- Scenarios: S2
- Updated Risk Level: **Upgraded → Critical**
- Justification: 1x00 rated this High by analogy to GAP-010's credential-culture pattern. T14's dedicated Insider scenario shows this single gap is the sole enabler of that scenario's final and most damaging step (post-termination re-entry) — a gap that is the last link in an otherwise-complete kill chain deserves the same urgency as the chain's other, already-Critical links.

### GAP-019 — Medical device management interfaces not verified for default credentials

- Original Risk Level: Critical
- Threat Actors: Unskilled/Opportunistic
- Kill Chains: KC4
- Scenarios: None of the 3 directly.
- Updated Risk Level: **Same — Confirmed Critical**
- Justification: Same reasoning as GAP-004/007 — the actor type most directly tied to this gap is independently confirmed High-to-Critical likelihood in T6, and patient-safety severity sustains the rating regardless of kill-chain frequency.

---

## Re-Prioritized Gap List

**Critical (11):** GAP-001 *(↑ from High)*, GAP-002, GAP-003, GAP-004, GAP-007, GAP-008 *(↑ from High)*, GAP-010, GAP-014, GAP-016 *(↑ from High)*, GAP-017, GAP-018 *(↑ from High)*, GAP-019 — *(12 total; note this list is longer than 1x00's original 6 Critical gaps because four gaps moved up)*

**High (6):** GAP-005, GAP-006 *(↓ from Critical)*, GAP-009, GAP-011, GAP-012 *(↑ from Medium)*, GAP-015

**Medium (0):** *(GAP-012 was the only Medium gap and has moved to High)*

**Low (1):** GAP-013

**Movers:**

- ⬆ Upgraded: GAP-001 (High→Critical), GAP-008 (High→Critical), GAP-012 (Medium→High), GAP-016 (High→Critical), GAP-018 (High→Critical)
- ⬇ Downgraded: GAP-006 (Critical→High)
- Confirmed at original level: GAP-002, GAP-003, GAP-004, GAP-005, GAP-007, GAP-009, GAP-010, GAP-011, GAP-013, GAP-014, GAP-015, GAP-017, GAP-019

## The Critical Three

Ranked by total appearances across the 5 kill chains + 3 scenarios (8 possible mentions):

1. **GAP-002** (No detection/IR capability) — 7 of 8 possible appearances (4 kill chains, all 3 scenarios). Closing this single gap would give MedDefense visibility into every attack path modeled in this project, regardless of actor type.
2. **GAP-001** (EHR reachable network-wide, no anomalous-access detection) — 6 of 8 (3 kill chains, all 3 scenarios). The only gap present in literally every scenario built.
3. **GAP-014** (No MFA anywhere) — 5 of 8 (3 kill chains, 2 scenarios). Tied for the most kill-chain appearances of any single gap, and the initial-access gap for the #1-priority actor type.

Closing these three would disrupt the greatest number of attack paths of any combination of gaps in this analysis — together they touch every kill chain except KC4 (the medical-device path, which runs on a structurally different set of gaps entirely).

## The Surprise

**GAP-012** (flat network turns every endpoint into a potential pivot point) was rated **Medium** in 1x00 — the only Medium-rated gap in the entire original 13-gap list — because partial preventive controls (C-006, C-008, C-012) were judged to meaningfully reduce the risk. Threat analysis overturns that judgment: GAP-012 is a named, explicit step in Kill Chain #2 and Scenario 1, both built around the #1-priority threat actor (Ransomware Groups). What changed is the frame of reference — the 1x00 rating asked "how much does this partial control help in general," while the 1x01 analysis asks "does this partial control stop the specific actor most likely to attack us," and the answer for BlackReef-style affiliates is no: none of C-006/008/012 meaningfully impede network discovery or lateral movement once any foothold exists. This is the clearest example in the entire correlation of why an inward-only gap analysis is incomplete without threat context.
