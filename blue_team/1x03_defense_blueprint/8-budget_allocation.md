# 8. The Budget Game MedDefense Health Systems

**Analyst:** Security Analyst
**Date:** Current

## Part 1: The Selection

**Funded this fiscal year ($120,000 budget):**

Selection method: controls were ranked by ALE reduction per dollar spent (cost-benefit ratio from Task 7), and funded in that order until the $120,000 budget was exhausted. This maximizes total risk reduction for the money available rather than picking controls by arbitrary preference or convenience — the two highest-value controls (MFA and SIEM) were funded first because they deliver the largest ALE reduction per dollar, and lower-ratio items (like the Westside firewall) were only funded because budget remained after the higher-value controls were covered.

| Control                                                 | Cost                                    | ALE Reduction |
| ------------------------------------------------------- | --------------------------------------- | ------------- |
| Control 2 - MFA (VPN + admin accounts)                  | $4,000 | $204,000                       |               |
| Control 3 - Enterprise SIEM (Wazuh, Phase 1)            | $28,000 | $150,000                      |               |
| Control 4 - Offsite backup replication                  | $14,400 | $108,000                      |               |
| Control 1 - Network segmentation (all zones)            | $45,000 | $81,750                       |               |
| Control 6 - Westside dedicated firewall                 | $6,000 | $12,000                        |               |
| Control 5 (scoped) - EDR upgrade,**servers only** | $6,000 | $32,000                        |               |
| **Total**                                         | **$103,400** | **$587,750** |               |

**Note on the scoped Control 5:** Task 7 evaluated EDR upgrade across all ~387 endpoints for $30,000. But GAP-005 specifically excludes *servers* from antivirus coverage workstations already have baseline Sophos protection. Scoping the upgrade to the ~15 servers alone costs a fraction of the full rollout ($6,000 vs. $30,000) while capturing an estimated 80% of the value ($32,000 of the original $40,000 ALE reduction), since the unprotected servers are the actual documented gap, not the already-covered workstations. This is a better buy than the full version priced in Task 7 a scoped fix aimed precisely at the gap outperforms a broader fix that partly pays for coverage that already exists.

**Total spend: $103,400. Budget remaining: $16,600.**

Budget summary: total budget 120000, total spend 103400, budget remaining 16600.

**Deferred to next fiscal year:**

- **Control 7 (24/7 outsourced SOC, $120,000):** Positive net value in isolation ($60,000), but funding it alone would consume the entire annual budget, leaving zero funding for five other justified controls that together deliver more total risk reduction for less money. Revisit once Control 3 (SIEM) has been operating long enough to show what detection gaps remain unaddressed by internal review alone.
- **Control 5, full version (remaining ~372 workstations, incremental $24,000):** The servers-only scope above is funded now; extending EDR to the full workstation fleet is deferred, since workstations already carry baseline Sophos protection and represent the lower-urgency half of GAP-005.

**Rejected outright:**

- **Control 8 (full medical device isolation with dedicated monitoring, $55,000):** Negative net value (-$16,300). Control 1 already includes medical-device segmentation as part of its scope the incremental cost of dedicated protocol-aware monitoring on top of that does not clear its own bar. Rejecting this loses no unique protection, since Control 1 already covers the segmentation component.

## Part 2: The Opportunity Cost

**By deferring the 24/7 outsourced SOC (Control 7), MedDefense accepts an estimated $30,000 in annual risk exposure** specifically, the incremental detection value a continuously-staffed SOC would add beyond what Control 3's internally-reviewed SIEM already provides ($180,000 total value for Control 7 minus the $150,000 already captured by Control 3 = $30,000 in detection gap during hours or events an internal, non-24/7 review cadence would miss).

**By deferring the full workstation EDR rollout beyond the funded servers-only scope, MedDefense accepts an estimated $8,000 in annual risk exposure** the incremental ALE reduction the full $30,000 version would have captured ($40,000) beyond what the $6,000 servers-only scope already delivers ($32,000).

**By rejecting Control 8 entirely, there is no meaningful opportunity cost to report** its negative net value means the "cost" of not doing it is that MedDefense avoids overspending on a control that would not have paid for itself.

## Part 3: The Alternative

**Alternative allocation: fund only the medical-device-specific portion of segmentation (matching Task 6's original Risk 4 scope, $30,000) instead of the full four-zone Control 1 ($45,000), keeping everything else the same.**

| Control                          | Cost                                   | ALE Reduction |
| -------------------------------- | -------------------------------------- | ------------- |
| Control 2 - MFA                  | $4,000 | $204,000                      |               |
| Control 3 - SIEM                 | $28,000 | $150,000                     |               |
| Control 4 - Backup replication   | $14,400 | $108,000                     |               |
| Medical-device-only segmentation | $30,000 | $31,750                      |               |
| Control 6 - Westside firewall    | $6,000 | $12,000                       |               |
| Control 5 (scoped, servers only) | $6,000 | $32,000                       |               |
| **Total**                  | **$88,400** | **$537,750** |               |

**Comparison to the primary recommendation:** when we compare the two portfolios side by side, the alternative has a lower cost but also delivers less protection. This alternative costs **$15,000 less** than the primary recommendation ($88,400 vs. $103,400) and leaves $31,600 unspent rather than $16,600 but it delivers **$50,000 less total risk reduction** ($537,750 vs. $587,750), because it gives up the broader segmentation project's contribution to Risk 1 (the ransomware/domain-wide scenario), keeping only the narrower medical-device VLAN work. Trading $50,000 in foregone risk reduction to save $15,000 in spend is a worse deal on a pure dollars-per-risk-reduced basis the primary recommendation remains the stronger choice, despite its lower cost the alternative is not the better option. **This alternative would only make sense if MedDefense specifically needed to preserve additional budget headroom for an unforeseen need this fiscal year** (e.g., an emergency response to a newly disclosed critical vulnerability); absent that specific reason, the primary allocation in Part 1 delivers more protection per dollar spent.
