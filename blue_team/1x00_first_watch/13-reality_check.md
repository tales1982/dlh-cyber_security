# Reality Check MedDefense Health Systems

## Breach 1: "Regional Hospital Alpha" Ransomware via VPN

**Attack Vector Identification:** Initial entry was an unpatched VPN appliance with a known CVE (patch available 4 months prior). From there, the flat network let the attacker reach the domain controller in 3 hours, and a compromised domain admin account was used to push ransomware to every Windows system via Group Policy simultaneously.

**MedDefense Correlation:**

- Flat network with unrestricted lateral movement → **GAP-004/GAP-007** (medical IoT/flat network) and the underlying M-01 finding the exact same architecture.
- Zero network monitoring, hours of invisible dwell time → **GAP-002**.
- Backup NAS on the same network, encrypted along with production, most recent viable copy 5 weeks old → **GAP-003**, almost identical in shape to `NAS-01`'s situation, down to the "same network as production" detail.
- No incident response plan, improvised 11-day response → part of **GAP-002**'s corrective gap.
- Unpatched, internet-facing perimeter device as entry point → parallels **GAP-008** (`billing-srv-01`'s unpatched Apache 2.4.29, already exploited twice).

**Blind Spot Check:** Yes. The domain admin credential being usable to push ransomware org-wide via GPO reveals a gap not documented anywhere in Task 12: MedDefense has no tiered/privileged access model for AD any compromised admin credential can act with full domain authority. Added as **GAP-017** below.

## Breach 2: "Health Network Beta" Insider + Credential Abuse

**Attack Vector Identification:** A terminated employee's VPN and EHR credentials stayed active for 47 days because offboarding depended entirely on a manager remembering to file a ticket. No MFA meant the original password alone was sufficient; access happened at unusual hours from a new IP with no alert generated.

**MedDefense Correlation:**

- No MFA on remote/clinical access → **GAP-014** (added in Task 15 from Marcus's M-05) this breach is close to a direct demonstration of that exact gap causing a real, notifiable incident.
- Audit logs existed but were never reviewed until after the fact → **GAP-002**.
- No DLP on data export (3,211 records downloaded without triggering anything) → flagged as valid-but-undocumented in Task 15 from Marcus's Section 2.

**Blind Spot Check:** Yes. Nothing in the gap analysis addresses account lifecycle management whether access is automatically disabled when someone leaves. MedDefense has never documented an HR-to-IT termination process at all. Added as **GAP-018** below.

## Breach 3: "Community Hospital Gamma" Medical Device Pivot

**Attack Vector Identification:** An unpatched, internet-facing patient portal (patch available 2 months) was compromised; a DMZ misconfiguration allowed outbound connections back into the internal network. From there, attackers found medical IoT devices reachable on the same network, discovered infusion pump management interfaces still using **default vendor credentials**, and accessed patient names and dosage data through them. Detection took 23 days and came from a human noticing unusual traffic, not a monitoring system.

**MedDefense Correlation:**

- Cryptomining deployed on a compromised, internet-facing, unpatched web server → an almost exact structural match to Task 2 (`billing-srv-01`, Apache 2.4.29, undetected for two weeks).
- Medical IoT reachable from the general network, firmware CVE with vendor-recommended isolation never implemented → **GAP-004**, matching the BD Alaris situation detail-for-detail (known CVE, vendor bulletin, isolation not done).
- 23-day dwell time, detected by chance rather than by design → **GAP-002**.

**Blind Spot Check:** Yes, and this one is concrete and actionable. Nothing in MedDefense's assessment has verified whether the Philips monitors or BD Alaris pump management interfaces still use default/vendor credentials this breach shows that's exactly the kind of detail that turns a contained compromise into a patient-data exposure. Added as **GAP-019** below.

## New Gaps Identified

**GAP-017 No privileged access tiering for Active Directory.** Any compromised admin-level credential can push changes (including malicious software) domain-wide via Group Policy, with no separation between routine sysadmin access and true domain admin authority. Category/Function missing: Technical Preventive. Risk Level: **Critical** directly enables the single-event, organization-wide ransomware pattern in Breach 1, against `ad-dc-01`/`ad-dc-02`, MedDefense's own Critical-rated identity infrastructure.

**GAP-018 No automated account deprovisioning tied to HR termination.** Account lifecycle depends entirely on manual manager action, exactly as in Breach 2. Category/Function missing: Administrative Preventive. Risk Level: **High** MedDefense has the same shared/weak-accountability credential culture already noted in GAP-010, making a similar dormant-account scenario plausible.

**GAP-019 Medical device management interfaces not verified for default credentials.** No evidence in any prior task confirms whether Philips monitor or BD Alaris pump management interfaces have had default vendor credentials changed. Category/Function missing: Technical Preventive. Risk Level: **Critical**  Breach 3 shows this exact unverified assumption is what converted a contained web-server compromise into patient data exposure through medical devices.

## Priority Reassessment

**GAP-014 (No MFA anywhere) is upgraded from High to Critical.** Breach 2 is close to a direct demonstration of this single gap, on its own, producing a full notifiable breach, HHS investigation, and class-action lawsuit the real-world evidence shows this gap alone is sufficient to cause Critical-level harm, not merely contributing to it.

**GAP-003 (NAS-01 unprotected) and GAP-002 (no detection) are confirmed at Critical, no change.** Breach 1 plays out almost exactly as GAP-003 describes (same-network backup destroyed alongside production, weeks-old recovery point), and all three breaches cite detection failure as a root enabler strong independent validation of the existing ratings rather than new information requiring a change.

**GAP-010 (shared PACS credentials) is confirmed at Critical, reinforcing the earlier disagreement with Marcus (Task 15).** Both the insider case (Breach 2) and the default-credential case (Breach 3) show credential-based accountability gaps causing real breaches regardless of whether access is remote or on-site supporting the Critical rating over Marcus's Medium.

## Pattern Analysis

All three breaches, despite very different attack styles (external ransomware, insider abuse, IoT pivot), share the same four ingredients: a known-but-unpatched vulnerability or default credential as the entry point, a flat network that let the attacker go anywhere once inside, an effective absence of monitoring that let the compromise run for hours to weeks unnoticed, and a credential-related weakness (no MFA, no offboarding, defaults never changed) as either the primary or secondary cause. None of these are exotic they are the same four foundational gaps MedDefense already carries. This strongly suggests the limited security budget should prioritize these boring-but-structural fixes (patch cadence, segmentation, detection, credential hygiene) over any single point solution, since it was exactly this combination, not a sophisticated or novel technique, that took down three otherwise very different healthcare organizations.
