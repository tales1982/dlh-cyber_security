# 15. Red Team Your Blueprint — MedDefense Health Systems

**Analyst:** Security Analyst (writing as a BlackReef affiliate for this exercise)
**Date:** Current

## Part 1: The Attacker's Perspective

### Which kill chain is still viable?

**Kill Chain #3 (Insider Data Exfiltration via Legitimate Access) is completely untouched.** Walking back through this project's own funding history proves it: the dedicated fix for this exact risk — automated deprovisioning tied to HR termination, plus export-volume/DLP alerting on the EHR export function (RISK-004, quantified in Task 6 at $8,000) — was **never actually selected in the Task 8 budget allocation.** Task 7's cost-benefit analysis only evaluated the 8 named architectural controls (segmentation, MFA, SIEM, backup, EDR, Westside firewall, 24/7 SOC, medical device isolation); RISK-004's own control never competed for funding at all, despite $16,600 sitting unspent after Task 8's primary selection — money that could have covered it twice over. As the attacker, I don't need a zero-day. I need a billing employee facing termination and the same unrestricted export function that has been sitting open since 1x00.

### Alternative attack path exploiting what the budget could not close

1. **Compromise MedTech Solutions** (the EHR maintenance vendor) rather than MedDefense directly — RISK-010 (vendor risk program) was identified in Task 6/11 but, like RISK-004, was never funded through the Task 7/8 process. Nobody has actually confirmed whether MedTech's specific maintenance account was brought into the MFA rollout's scope, even though MFA itself was funded (Task 8).
2. **Authenticate to `ehr-srv-01` using MedTech's legitimate, pre-authorized maintenance session** — this is not a segmentation bypass; it is the segmentation working exactly as designed, because `ehr-srv-01` *is* the one host Rule 7 explicitly permits to reach `ehr-db-01`. The new architecture assumed the threat came from *outside* the app server. Kill Chain #5's entire premise is a threat that already has legitimate standing *on* the app server — segmentation was never designed to stop that, and it doesn't.
3. **Query and export patient records through the already-permitted `ehr-srv-01` → `ehr-db-01` path**, blending in with routine vendor maintenance traffic.
4. **Rely on the SIEM's Phase 1 scope not covering this** — 1x00's own GAP-002 remediation was explicitly scoped to "critical servers and the firewall first," and behavioral, query-volume-based database monitoring for a legitimate application-to-database path is a materially more mature detection capability than a Phase 1 deployment provides. Task 7 itself only credited the SIEM with a "conservative, blended" ALE reduction for exactly this reason — it does not claim to catch everything.
5. **Exfiltrate over the same maintenance channel repeatedly**, since nothing distinguishes this session from a routine MedTech visit without a behavioral baseline that has not yet been built.

**This is the sharpest finding in this entire red-team exercise:** the fix for Finding 003 (Quick Win #2, Rule 7) closes the "reachable from the whole network" problem, but it does not and cannot close the "reachable from whoever legitimately controls the one permitted host" problem — those are different threats that look identical in a network diagram.

### Insider threat scenario that remains dangerous

The same one named above under Kill Chain #3: **a malicious employee facing termination exports patient records via the EHR's own built-in bulk-export function during their remaining employment, then, per 1x01 T3's documented pattern, potentially re-enters after departure using still-active credentials.** MFA does not stop someone already logged in with valid credentials during active employment; segmentation does not apply, since this uses access the person is already authorized to have within their own zone; and the one control that would have specifically stopped it (RISK-004) was never funded.

## Part 2: The Honest Assessment

**Overall residual risk after the proposed controls: Medium.**

**Justification:** This is not a Low rating, because two real, working attack paths remain — one (insider exfiltration) with zero technical controls in place at all, and one (vendor-mediated access) that the segmentation design's own logic cannot reach by construction, not by oversight. It is not a High or Critical rating either, because the paths that were previously the most probable and the most proven — the Ghostcat exploit, the open PostgreSQL database, the billing server's internet-facing RCE chain, and domain-wide ransomware via workstation-to-domain-controller discovery — are now genuinely and substantially disrupted, not just documented. The residual risk that remains is concentrated in exactly the two categories a purely technical, network-and-authentication-focused budget round was always going to under-fund: access governance (insider) and third-party trust (vendor).

**The single biggest remaining gap:** RISK-004, the unfunded insider deprovisioning and export-monitoring control. It is the only one of the top-5 risks from Task 6 with **zero** technical mitigation in place after this entire budget cycle, it requires no sophistication whatsoever from the threat actor, and — most damning from a program-management standpoint — it was identified, quantified, and costed at only $8,000 in this very engagement, and simply never made it into the funded list because it was never entered into the same competition as the other 8 controls.

**Recommendation for next year's budget — and one item that shouldn't wait that long:** Fund RISK-004's $8,000 control immediately, out of the $16,600 that Task 8 left unspent this cycle — there is no reason for this fix to wait for a "next fiscal year" conversation at all, and this red-team exercise should not have been necessary to catch it. For the actual next-year priority, mature the SIEM beyond its Phase 1 scope to include application- and database-layer behavioral monitoring for the EHR's own data paths and third-party vendor sessions specifically — this is the only remaining control that can close the vendor-mediated Kill Chain #5 bypass identified above, since that gap is structurally immune to both segmentation and MFA by design, and can only be closed by detecting *what a legitimately-authenticated session does*, not by restricting *where it can come from*.

## Repo

- **GitHub repository:** `dlh-cyber_security`
- **Directory:** `blue_team/1x03_defense_blueprint`
- **File:** `15-red_team_blueprint.md`
