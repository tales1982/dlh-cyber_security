# MedDefense Health Systems Security Posture Assessment

## 1. Executive Summary

MedDefense's security posture today is **prevention-only and effectively blind**: the organization has reasonable controls stopping some attacks from starting, but almost no ability to notice one that succeeds, and almost no tested way to recover once it does. This is not theoretical two separate systems have already been compromised twice each in the past year, both discovered by accident rather than by any security tool.

**The single most critical finding:** there is no functioning detection capability anywhere in the environment. Logs exist but nobody reviews them, and there is no alerting of any kind. A cryptocurrency-mining infection ran undetected on our billing server for at least two weeks the same blind spot that, in three real-world hospital breaches we reviewed, allowed attackers to operate for hours to over three weeks before anyone noticed.

**Top 3 recommended actions:**

1. Deploy basic detection and monitoring (a modern SIEM tool) starting with our most critical systems roughly $30,000.
2. Move our only backup copy off the same network as the servers it protects, and add offsite cloud replication roughly $14,400/year, already quoted and previously denied on cost grounds alone.
3. Isolate our highest-risk medical devices (infusion pumps) onto their own protected network segment roughly $30,000.

**Budget implication:** These and four other priority fixes fit within **$80,400 of our $120,000 annual security budget**, leaving reserve capacity for the next tier of improvements.

## 2. Scope and Methodology

**What was assessed:** All three MedDefense sites (Central Hospital, Westside Clinic, Corporate HQ), covering servers, endpoints, network infrastructure, medical IoT devices, applications, and the data they hold.

**Sources used:** The onboarding documentation package; six months of incident history; a physical walk-through of Central; configuration artifacts for the firewall, servers, and endpoints; a full internal network scan; three real-world healthcare breach reports used to validate our findings; and a partially completed assessment left by the previous security analyst.

**Limitations and assumptions:** Corporate HQ's individual endpoints are covered by the network scan but were not itemized in the asset registry to the same depth as Central. Some findings (e.g., whether medical device management interfaces still use default credentials) are flagged as needing direct verification rather than confirmed fact. All financial figures are order-of-magnitude estimates, not vendor quotes, except where a specific quote is cited.

## 3. Asset Landscape

**Inventory summary:** 27 distinct assets documented across 7 categories: 13 servers, 4 medical IoT device groups (~200 individual devices), 3 applications, 2 network devices, 2 data stores, 2 endpoint groups (~450+ individual devices), and 1 physical infrastructure zone. Three of these 27 are confirmed **Shadow IT** systems operating with no official oversight.

**Top 5 Critical Assets:**

1. **`ehr-db-01`** the database holding protected health information for 50,000+ patients.
2. **`ad-dc-01`** the domain controller anchoring nearly every login in the organization.
3. **`NAS-01`** the sole backup copy of every critical system, with no offsite copy.
4. **FortiGate 100F** the single perimeter device for the entire Central site.
5. **BD Alaris infusion pump fleet** devices directly controlling patient medication dosing, with a known, unmitigated vulnerability.

**Data classification summary:** Of 8 major data categories identified, 5 are classified **Restricted** (patient records, medical imaging, real-time clinical data, system credentials, research data) and 3 **Confidential** (financial data, HR records, audit logs). The most significant protection weakness is at the Restricted level: system credentials, including a network switch password physically taped to a wall.

## 4. Current Security Controls

**Control inventory:** 16 documented controls 10 Technical, 3 Administrative, 3 Physical. By function: 10 Preventive, 3 Detective, 1 Corrective, 2 Compensating (both still proposed, not yet implemented), 0 Deterrent.

**Maturity assessment:** MedDefense is **moderately mature in prevention** (firewall rules, password policy, antivirus, access lockout) and **critically immature everywhere else**. Detection exists on paper but not in practice. Only one corrective control exists (nightly backup), and it has never been tested at full scale. No control category has any deterrent function at all.

**Key effectiveness findings:** Of the 16 controls, only 3 are rated fully "Strong." Antivirus excludes every server in the environment. The guard service covers one entrance, one shift, at one site. Camera coverage excludes the server room, network closet, and administrative wing entirely.

## 5. Gap Analysis

19 gaps were identified and validated, including 3 confirmed against real-world breach patterns at other hospitals. **Distribution: 9 Critical, 8 High, 1 Medium, 1 Low.**

| Gap                                        | Level    | Description                                                                                                            | Affected Assets | Potential Impact                                              | Recommended Treatment                     |
| ------------------------------------------ | -------- | ---------------------------------------------------------------------------------------------------------------------- | --------------- | ------------------------------------------------------------- | ----------------------------------------- |
| GAP-002                                    | Critical | No functioning detection or incident response                                                                          | Network-wide    | Repeat of the 2-week undetected cryptominer                   | Mitigate: deploy SIEM + IR plan           |
| GAP-003                                    | Critical | Sole backup shares network/room with production                                                                        | `NAS-01`      | Simultaneous loss of production and recovery data             | Mitigate: cloud backup replication        |
| GAP-004                                    | Critical | Infusion pumps have zero controls                                                                                      | BD Alaris fleet | Direct patient harm via dosage manipulation                   | Mitigate: dedicated VLAN                  |
| GAP-006                                    | Critical | Network closet unlocked, credentials exposed                                                                           | Network Core    | Full network compromise, undetected                           | Mitigate: lock + credential rotation      |
| GAP-007                                    | Critical | Medical IoT fleet-wide flat network                                                                                    | All medical IoT | Same as GAP-004, broader scope                                | Mitigate: phased VLAN rollout             |
| GAP-010                                    | Critical | Shared PACS login, no accountability                                                                                   | `pacs-srv-01` | Untraceable unauthorized imaging access                       | Mitigate: badge authentication            |
| GAP-014                                    | Critical | No MFA anywhere (upgraded post Task 13)                                                                                | Org-wide        | Proven pattern: enabled a real insider breach elsewhere       | Mitigate: MFA via existing O365 licensing |
| GAP-017                                    | Critical | No privileged access tiering on AD                                                                                     | `ad-dc-01/02` | One compromised admin account = domain-wide ransomware        | Mitigate: tiered admin model              |
| GAP-019                                    | Critical | Medical device default credentials unverified                                                                          | Medical IoT     | Proven pattern: converted a breach into patient data exposure | Mitigate: audit and rotate credentials    |
| GAP-001, 005, 008, 009, 011, 015, 016, 018 | High     | Incomplete coverage across EHR access, AV, billing, HR share, shadow IT, Westside site, change management, offboarding | Multiple        | Varies see Task 12/13/15 for detail                          | Mostly Mitigate; see Task 14              |

**Gap distribution analysis:** Gaps concentrate overwhelmingly in **Detective and Corrective** functions, not Preventive — MedDefense has never lacked the will to block known threats, it lacks the ability to notice or recover from the ones that get through anyway.

## 6. Risk Treatment Recommendations

The 7 priority recommendations (full detail in Task 14):

| Priority | Gap                               | Strategy | Cost        | Timeline                      |
| -------- | --------------------------------- | -------- | ----------- | ----------------------------- |
| 1        | GAP-006 (closet lock/credentials) | Mitigate | $0-1K       | Quick Win (<1 wk)             |
| 2        | GAP-001 (EHR DB firewall rule)    | Mitigate | $0-1K       | Quick Win (<1 wk)             |
| 3        | GAP-010 (PACS badge auth)         | Mitigate | $1-10K      | Short-term (<1 mo)            |
| 4        | GAP-003 (cloud backup)            | Mitigate | ~$14,400/yr | Short-term (<1 mo)            |
| 5        | GAP-002 (SIEM + IR plan, Phase 1) | Mitigate | $10-50K     | Short-term (<1 mo)            |
| 6        | GAP-004 (pump VLAN, Phase 1)      | Mitigate | $10-50K     | Long-term (>1 mo)             |
| 7        | GAP-007 (remaining IoT VLAN)      | Mitigate | $10-50K     | **Deferred to next FY** |

**Budget allocation:** ~$80,400 of $120,000 committed this fiscal year; ~$39,600 reserved, recommended for GAP-005 (server antivirus coverage) as the next-highest-value item.

- **Quick wins (<1 week):** GAP-006, GAP-001 both near-zero cost, should start immediately regardless of budget approval timing.
- **Short-term (<1 month):** GAP-010, GAP-003, GAP-002 Phase 1.
- **Long-term roadmap:** GAP-004 this year; GAP-007 Phase 2, GAP-017 (AD access tiering), and GAP-019 (device credential audit) proposed for next fiscal year.

## 7. Conclusion and Next Steps

In business terms: MedDefense currently spends its security effort almost entirely on locking doors, with very little spent on noticing when a door has been forced or recovering afterward. Three real-world hospital breaches reviewed in this assessment were caused by this exact combination — not sophisticated attacks, but ordinary gaps like these left unaddressed. If these recommendations are not implemented, the most likely outcome is not a hypothetical future risk but a repeat of what has already happened twice on our own billing server, at a scale that could affect clinical operations directly, as it already has once (Task 1, Incident E).

This assessment answers the internal question what do we have, and where are the gaps. It does not yet answer the external question the previous analyst, Marcus Webb, had begun but never finished: **who is actually targeting organizations like MedDefense, and how.** The next phase of this program should be a formal External Threat Landscape Assessment, mapping our now-documented gaps against real attacker techniques (as Marcus began outlining using MITRE ATT&CK and CISA healthcare advisories) turning "here is what's wrong" into "here is who would exploit it, and how we'd know."
