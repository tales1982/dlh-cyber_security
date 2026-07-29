# 9. The Board Presentation — MedDefense Health Systems

**To:** The Board of Directors
**For:** Emergency Meeting, 9:00 AM
**Prepared by:** Security Analyst

---

## Part 1 — Board Security Brief (One Page)

**Current threat status.** CISA issued an emergency advisory two days ago describing "Crimson Tide," a ransomware campaign that has compromised 5 regional hospitals in 10 days — 3 within our own region, one 45 miles away — through an unpatched firewall vulnerability, a flat internal network, and unencrypted backups. Our own environment matches that profile exactly: we are currently exposed to 6 of the 7 documented phases of their attack.

**Security posture verdict.** Five weeks of independent assessment found real gaps in prevention and a near-total absence of detection, and a $120,000 remediation plan was approved to fix them. As of tonight, the plan is funded but not yet built — the firewall in question is still unpatched, the network is still flat, and the backups are still unencrypted, exactly as they were when the plan was designed.

**Emergency response summary.** We began remediation the moment this advisory landed. Tonight: isolating our backup storage from the production network and verifying our firewall's exposure. Tomorrow, pending Board approval: renewing a lapsed $2,400 support contract to patch the firewall, removing a weak legacy authentication setting domain-wide, and completing multi-factor authentication rollout. This week: beginning network segmentation and accelerating our detection system deployment. A full 72-hour, tier-by-tier plan with named owners exists behind this brief.

**Investment summary.** Of the $120,000 already approved, $103,400 is allocated to five controls projected to remove $587,750 in annual risk — none of which are live yet. Tonight's threat intelligence quadrupled our single largest quantified risk, from $300,000 to $1,275,000 in expected annual loss, purely because a real, active campaign now exists where only a generic estimate did before. We are requesting **$36,500 in new emergency spending** beyond the original $120,000 — a small fraction of the risk it removes, including a $2,400 firewall patch alone worth an estimated $813,600 in avoided expected loss.

**Recommendation.** Approve the $36,500 emergency request in full today, and treat the underlying lesson as permanent, not a one-time crisis response: our risk numbers are only as good as the actions taken on them, and this week we are still exposed to the exact chain we identified and priced five weeks ago. Fund it, then finish it.

---

## Part 2 — Stakeholder Talking Points

**Dr. Morales (CEO) — Patient safety and reputation.** This campaign has already caused ambulance diversions and week-long paper-record fallbacks at a hospital 45 miles from us; it is a clinical continuity emergency before it is a financial one. Our own posture assessment shows we are exposed to 6 of the 7 phases that produced those outcomes elsewhere — approving tomorrow's actions is what keeps this from becoming our story instead of theirs.

**Robert Kim (CFO) — Financial exposure and ROI.** New intelligence just moved our single largest quantified risk from $300,000 to $1,275,000 in expected annual loss — a 4.25x jump without spending a dollar, purely from confirming the threat is real and active. The $2,400 firewall patch alone returns an estimated $813,600 in avoided loss; the full $36,500 emergency ask is the highest-return spending decision on this Board's table today, by a wide margin.

**Dr. Reeves (Board Chair) — Professional recommendation and confidence.** My recommendation is to approve the emergency request in full and treat this as the moment the existing $120,000 plan gets executed with urgency, not replaced. I have high confidence in the technical plan — it is built on five weeks of our own verified data, not speculation — and equally high confidence that the plan alone, even fully funded, does not eliminate risk; two of the seven attack phases have no funded control at all, and I want the Board to approve those eyes-open, not by omission.

**Thomas Wright (Former banker) — Industry comparison.** A financial institution operating with no multi-factor authentication, no network segmentation, and no detection capability would not pass a single regulatory exam cycle; healthcare has historically been permitted to lag that standard, and Crimson Tide is precisely the market correcting for it. Every control on tomorrow's list is one your prior industry adopted as baseline a decade ago.

**Maria Santos (Legal counsel) — HIPAA liability and insurance.** We could not pass a HIPAA security audit today — the complete absence of encryption on our patient database is the single finding an auditor would cite first, and it has sat open and documented across five weeks of our own assessments, which enforcement actions treat more harshly than a gap nobody had yet found. I need this Board's decision this morning on our cyber insurance carrier's breach-response resources and our own crisis-communication authority before, not during, a 96-hour ransom clock.

## Repo

- **GitHub repository:** `dlh-cyber_security`
- **Directory:** `blue_team/1x05_board_briefing`
- **File:** `9-board_presentation.md`
