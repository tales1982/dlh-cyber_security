
# 17. The What-If — Threat Evolution Analysis

**Analyst:** Threat Intelligence Analyst
**Date:** Current

## Instructions Recap

For each of the 3 hypothetical scenarios below, answer: New Threat Actors, Changed Vectors, Shifted Priorities, New Gaps, Net Assessment.

---

## Scenario A — University Clinical Trial Partnership

```
New Threat Actors: Nation-State APT moves from Low to genuinely relevant.
  Every prior assessment (T0, T6) rated this actor type Low specifically
  because "we don't do research" (Marcus's own annotation) — this
  scenario removes that exact caveat. Proprietary research protocols and
  3 international research institutions are precisely the profile that
  attracts espionage-motivated actors (T1 Report A is the direct model:
  a 14-month, zero-day-enabled theft of Phase III trial data).

Changed Vectors: A brand-new dedicated server is added to the environment
  with no evidence it would be treated differently from any other new
  asset — meaning it likely joins the same flat network (GAP-012) by
  default. Spear phishing targeting research staff and international
  collaborators becomes newly relevant (matching the nation-state pattern
  in T1). The 3 partner institutions become new third-party relationships
  functionally identical in risk shape to the 5 vendors assessed in T5,
  but never evaluated.

Shifted Priorities: Nation-State APT enters Top-5-adjacent consideration
  for the first time — not yet displacing Rank 5 in T16, but no longer
  negligible. The existing Top 5 (Ransomware, Opportunistic, Insider,
  Vendor, Medical IoT) does not reorder internally, since none of their
  underlying gaps are touched by this change — a new target is added
  without removing any existing exposure.

New Gaps: (1) The new clinical-trial server has no documented governance,
  access policy or network placement decision — an assessment gap, not
  just a technical one. (2) The 3 international research institutions
  represent an entirely new third-party risk category, structurally
  identical to T5's vendor analysis but never performed for this
  relationship, including cross-border data-transfer exposure T5 never
  had to consider.

Net Assessment: Increases. A new, high-value, internationally-exposed
  target is added to an environment whose default behavior (per every
  prior task) is to absorb new assets into the same unsegmented flat
  network — and it activates the one actor type MedDefense was least
  prepared to face, since Nation-State APT never appeared as a live
  consideration anywhere in the Top 5 (T16).
```

---

## Scenario B — EHR Migration to Cloud SaaS (MedTech Solutions)

```
New Threat Actors: No entirely new actor type is introduced, but the
  *effective* population able to reach patient data changes shape —
  internal actors (flat-network-based lateral movement) lose their most
  direct path, while MedTech Solutions' own security posture becomes, for
  the first time, functionally equivalent to MedDefense's own security
  posture for this one asset.

Changed Vectors: GAP-001 (EHR reachable network-wide via 10.10.2.0/24)
  becomes moot — `ehr-srv-01`/`ehr-db-01` no longer exist on MedDefense's
  network to be reached that way. In its place, the dominant vector
  becomes authentication to the SaaS platform itself (phishing/credential
  compromise targeting cloud logins) and, far more significantly, Supply
  Chain Compromise: T10's Kill Chain #5 already showed MedTech access as
  a direct, unmitigated path to `ehr-db-01` when they were only a
  maintenance vendor — after migration, they are not *a* path to the
  data, they are effectively the *only* path to the data.

Shifted Priorities: Rank 4 (Vendor/Supply Chain Compromise, T16) should
  move to Rank 1 or 2 — MedTech's own security now *is* MedDefense's EHR
  security in a way it never was before. Rank 1 (internal-network
  ransomware) drops specifically for EHR data (though ransomware remains
  just as severe against everything still on-premises: billing, AD,
  workstations). Rank 2 (billing-srv-01 exploitation) and Rank 5 (medical
  IoT) are unaffected, since neither depends on where the EHR is hosted.

New Gaps: (1) MedDefense would have no visibility into or audit rights
  over MedTech's own cloud security controls — a gap T5's original vendor
  assessment never had to consider, because MedTech was a *maintenance*
  vendor with *local* access, not the sole infrastructure custodian. (2)
  Cloud-specific authentication policy (MFA, session management, IP
  allow-listing for the SaaS platform) becomes an explicit contractual
  requirement rather than an internal configuration choice — closing
  GAP-014 for this one path can no longer be done unilaterally by
  MedDefense's own IT team.

Net Assessment: Shifts rather than simply increases or decreases. Broad,
  diffuse internal-network risk to the EHR (GAP-001, GAP-012) drops
  sharply, since the data is no longer reachable via the flat network at
  all — but that risk concentrates into a narrow, deep dependency on a
  single third party whose security MedDefense cannot directly verify or
  control, trading a wide attack surface for a smaller one with far less
  visibility into it.
```

---

## Scenario C — Media Coverage of the January Ransomware Attack

```
New Threat Actors: Hacktivists move from Low to a live consideration for
  the first time. T0/T6 rated this actor type Low specifically because
  "MedDefense has no political profile, no controversy" (Marcus's own
  annotation) — patient quotes expressing concern in a national story is
  exactly the kind of controversy that removes that reasoning, and
  matches the defacement/DDoS pattern already seen in T1 Report C.
  Separately, Unskilled/Opportunistic attackers become *more* likely, not
  less: publicized breaches are known to attract "kick them while they're
  down" scanning, on the working assumption that a recently-breached
  organization is still vulnerable.

Changed Vectors: DDoS against the patient portal becomes a newly credible
  hacktivist vector (low sophistication, high visibility, matching the
  profile in T1 Report C). The breach narrative itself becomes usable
  social-engineering material — a BEC or phishing pretext referencing
  "verify whether your data was affected" gains new plausibility that it
  did not have before the story broke (an evolution of the T4 Scenario 2
  pattern, now with real public context to borrow credibility from).

Shifted Priorities: Hacktivist activity becomes worth tracking for the
  first time, though its low technical ceiling likely keeps it below
  Rank 5 in T16 rather than displacing any existing threat. More
  significantly, Rank 2 (Unskilled/Opportunistic exploitation of
  unpatched services) becomes even more urgent — the same publicity that
  attracts hacktivists to the portal also attracts more automated
  scanning attention to every other exposed MedDefense service.

New Gaps: A new, non-technical gap emerges that does not fit anywhere in
  the original 19-gap 1x00 analysis: **no public-facing incident-response
  communication plan**. Every gap in 1x00 addresses a technical,
  administrative or physical security control — none address how
  MedDefense manages a public narrative during and after disclosure,
  which this scenario shows is itself a live risk factor (an unmanaged
  narrative amplifies both reputational damage and attacker interest).

Net Assessment: Increases. Public disclosure does not close a single
  existing gap, while it simultaneously activates a previously-dormant
  actor type (Hacktivist) and intensifies attention from the actor type
  already causing MedDefense's proven, repeated damage
  (Unskilled/Opportunistic) — the organization becomes a more visible
  target at the exact moment it can least afford one.
```

---
