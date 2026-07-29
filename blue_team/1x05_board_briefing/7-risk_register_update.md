# 7. The Risk Register Update — MedDefense Health Systems

**Analyst:** Security Analyst
**Date:** Current

## Part 1 — Update to RISK-002

**Original entry (1x03 Task 10):** "A ransomware affiliate gains initial access via phishing or a purchased credential and escalates to domain-wide encryption plus patient data exfiltration, following Kill Chain #1." Likelihood 3 (Possible), Impact 5 (Severe), Inherent Score 15, ALE $300,000, Residual ~$96,000 after MFA.

**Updated RISK-002:**

- **Risk Description:** A Crimson Tide (CT) affiliate — or an imitator using the now-publicly-disclosed TTPs — gains initial access via the FortiGate SSL-VPN (CVE-2023-27997, see RISK-NEW-001) or a purchased/phished credential, and escalates to domain-wide encryption plus double-extortion data exfiltration, following the confirmed 7-phase Crimson Tide chain overlaid onto Kill Chain #1 (Task 2, this module).
- **Risk Category:** Strategic
- **New Threat Source:** Crimson Tide (CT), a RaaS affiliate network running a modified BlackSuit variant, first observed 8 months ago, with 5 confirmed hospital compromises in the last 10 days (3 in MedDefense's own region). This supersedes the prior generic "Ransomware Groups (Organized Crime)" threat source with a named, currently-active, regionally-confirmed actor.
- **Vulnerability:** Combined gap chain unchanged in substance (GAP-002, GAP-003, GAP-014, GAP-017), now confirmed to be the exact chain a real, named campaign is executing against peer hospitals, not a theoretical worst case.
- **Affected Asset(s):** `ehr-db-01`, `ad-dc-01`/`02`, `NAS-01`, `billing-srv-01` (unchanged — domain-wide).
- **Updated Likelihood: 5 (Almost Certain)** — up from 3 (Possible), using the updated ARO of 0.75 (Task 5), which itself reflects an active, geographically-clustered campaign already confirmed against 3 regional peers, not a generic sector base rate.
- **Impact:** 5 (Severe) — unchanged.
- **Updated Inherent Risk Score:** 5 × 5 = **25** (up from 15).
- **Updated ALE: $1,275,000** (Task 5), up from $300,000.
- **Updated Treatment Decision:** Mitigate — unchanged.
- **Updated Treatment Justification:** The treatment *decision* still holds, but the treatment as originally scoped no longer holds by itself. The original three controls (MFA, SIEM, offsite backup replication) were priced and justified against a $300,000 ALE and did not include patching the specific initial-access vector this advisory reveals. The plan must be extended, not replaced: RISK-NEW-001 (below) is the missing piece.
- **New KRI:** Any inbound connection to the FortiGate SSL-VPN portal matching the advisory's documented exploitation signature (oversized `/remote/logincheck` payloads), or any unusual FortiGate CLI command (e.g., `show system interface`) logged outside scheduled administrative activity — both pulled directly from CISA AA26-077A's own IOC list, monitorable today via FortiGate logs and, once deployed, the Wazuh SIEM.
- **Residual Risk:** Remains **High** until the FortiGate is patched and the Kerberos/segmentation work lands (Task 3); returns to the originally-planned Medium once the emergency actions and the existing 1x03 controls are both complete.
- **Review Date:** Changed from 30 days to **7 days**, reflecting the out-of-cycle trigger below.

## Part 2 — New Entry: RISK-NEW-001

- **Risk Description:** A Crimson Tide affiliate, or any opportunistic actor using the same now-public TTP, exploits CVE-2023-27997 on MedDefense's unpatched FortiGate 100F to gain full remote code execution on the sole perimeter/VPN device, enabling the entire downstream 7-phase attack chain. This entry decomposes RISK-002's combined-gap-chain ARO into its most concrete, currently-confirmed component — it does not duplicate RISK-002; it is the first CVE-specific pin to a vector RISK-002 previously described only in general terms.
- **Risk Category:** Compliance / Strategic (perimeter access control)
- **Threat Source:** Crimson Tide (CT) / any actor exploiting a CISA KEV-listed, actively-weaponized CVE
- **Vulnerability:** CVE-2023-27997 (this module, Task 1) — CVSS 9.8, CWE-122, CISA KEV-listed
- **Affected Asset(s):** FortiGate 100F (perimeter firewall/VPN, all 3 site tunnels)
- **Likelihood: 5 (Almost Certain)** — CISA KEV-listed, confirmed active exploitation against 5 hospitals in 10 days, 3 in-region
- **Impact: 5 (Severe)** — this vector is the confirmed entry point for the same domain-wide outcome RISK-002 quantifies
- **Inherent Risk Score:** 5 × 5 = **25**
- **ALE (unpatched):** SLE $1,700,000 (Task 5's updated Risk 1 SLE — this vector's realistic worst case is the same catastrophic outcome) × ARO 0.5 (this vector's own share of the blended 0.75 RISK-002 ARO, being the primary but not sole entry path) = **$850,000**
- **Risk Owner:** IT Director (Sarah Park) for execution; Deputy CISO (James Chen) Accountable
- **Treatment Decision:** Mitigate
- **Treatment Justification — patching cost vs. ALE:**
  ```
  Cost to renew FortiGate support contract: $2,400
  ALE before patch: $1,700,000 x 0.5 = $850,000
  ALE after patch: $1,700,000 x 0.02 (residual, matching this register's own precedent
    for point-fix ARO reduction, e.g. RISK-001's Ghostcat fix to 0.03) = $34,000
  Net Benefit: $850,000 - $34,000 - $2,400 = $813,600
  ```
  A $2,400 cost against an $813,600 net benefit is not a marginal call — it is among the highest single-dollar-return actions in MedDefense's entire risk program, comparable in scale to 1x03's own highest-return item (Ghostcat, $469,750 net benefit), and clears its cost by a wider margin than any control evaluated to date.
- **Planned Control(s):** Renew the FortiGate support contract ($2,400, funded from the existing $16,600 budget reserve — no new Board approval required for this specific line item); apply the firmware patch (7.0.12+/7.2.5+ or later); disable SSL-VPN in the interim if same-day patching is not possible (Task 3, Tier 1).
- **Residual Risk:** Low once patched (~$34,000 ALE).
- **KRI:** Days since the FortiGate support contract status shows Active AND the firmware version is confirmed patched — mirroring RISK-003's existing KRI structure ("days since last successful patch").
- **Review Date:** 7 days (elevated cadence), reverting to 30 days once patched and validated.

## Part 3 — Register Governance Test

The 1x03 Risk Register Governance Note states: *"An out-of-cycle review is triggered by any of three events: a new CVE or CISA KEV addition affecting an asset in the 1x00 Asset Registry, a security incident (confirmed or suspected) touching any listed asset, or a KRI breaching its implied threshold."*

**Does Crimson Tide qualify?** Yes — cleanly on the first trigger alone, since the governance note's three triggers are joined by "any," not "all." CVE-2023-27997 is a new CVE, added to the CISA KEV catalog, directly affecting the FortiGate 100F — a device already implicitly covered by the 1x00 Asset Registry as MedDefense's perimeter/VPN infrastructure and named directly in 1x01 Kill Chain #2's initial-access step, even though it never previously carried its own dedicated finding or CVE. Trigger #1 is satisfied outright, and satisfying any one of the three triggers is sufficient to mandate this out-of-cycle review.

The second trigger — "a security incident (confirmed or suspected) touching any listed asset" — is a closer call, and it would be dishonest to overclaim it: the 5 confirmed Crimson Tide compromises are incidents at *other* hospitals, not a confirmed or suspected incident against a MedDefense asset specifically. Trigger #2 does not strictly apply yet. It would apply immediately and without ambiguity the moment the Tier 1 FortiGate log review (Task 3) turns up any of the advisory's listed IOCs — a possibility this document does not currently rule out. Trigger #1 alone is sufficient to justify everything in this update; trigger #2 remains a live, not-yet-triggered possibility worth tracking through the same review, not a settled fact.

## Repo

- **GitHub repository:** `dlh-cyber_security`
- **Directory:** `blue_team/1x05_board_briefing`
- **File:** `7-risk_register_update.md`
