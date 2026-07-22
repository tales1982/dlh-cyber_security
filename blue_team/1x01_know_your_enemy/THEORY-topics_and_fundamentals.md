# Theory and Topics — 1x01 Know Your Enemy

Study guide with theory + practical examples from the MedDefense scenario, for every exercise in this module.

---

## 0. Threat Landscape Summary

**What it is:** the big-picture view of who could attack your organization, why, and with what capability — the starting point before detailing each threat individually.

**Core concepts:**
- **Threat:** someone or something with intent and capability to cause harm (e.g., a ransomware group).
- **Vulnerability:** a weakness that can be exploited (e.g., an unpatched server).
- **Risk:** the combination of both, together with the impact if it happens. Mental formula: `Risk = Threat × Vulnerability × Impact`. Without one of the three parts, there is no real risk (a vulnerability nobody is interested in exploiting is low risk).

**Why hospitals are a specific target:**
1. Patient data is worth a lot on the black market.
2. Legacy systems (medical devices that can't be updated).
3. Clinical urgency — you can't "wait" to resolve an incident, which increases pressure to pay ransom.
4. Regulation (HIPAA) — a breach triggers fines and mandatory public disclosure.

**Example:** MedDefense has an EHR with thousands of patient records + a firewall exposed without MFA + 3 hospitals in the region already hit by ransomware → real threat, real vulnerability, high impact = critical risk.

---

## 1. Threat Actor Taxonomy

**What it is:** the process of classifying a threat actor from technical evidence (not guesswork) — like a profiler building a picture from clues.

**Formal classification criteria:**
- **Actor Type:** Nation-State/APT, Organized Crime, Insider, Hacktivist, Unskilled/Opportunistic.
- **Internal vs External:** did the attack originate from inside (employee) or outside?
- **Resources:** expensive custom tooling (sign of a well-funded group) vs public/free tools (sign of a casual attacker).
- **Sophistication:** low (uses a ready-made exploit), medium (adapts existing tools), high (develops its own exploit), very high (zero-day + operating undetected for months).
- **Motivation:** financial, espionage (theft of IP/research), ideological (hacktivism), personal revenge, curiosity.
- **Confidence Level:** how certain you are of the attribution, and why — always backed by evidence (e.g., "stolen code-signing certificate + encrypted DNS C2 + 14 months undetected" points to a nation-state, not common crime, because common crime wants fast profit, not 14 months of patience).

**Practical example:** a report shows zero-day exploitation, custom malware, no ransom demand, and the target was clinical research data (not money). Conclusion: Nation-State/APT, motivation espionage, high confidence — because organized crime doesn't invest that much effort without demanding a ransom.

**Supporting framework — Diamond Model:** every intrusion can be described by 4 connected points: **Adversary** (who) — **Capability** (tools/technique) — **Infrastructure** (servers/domains used) — **Victim** (target). Helps structure attribution reasoning.

---

## 2. Ransomware Assessment

**What it is:** understanding ransomware as a **criminal business model**, not just "a virus that encrypts files."

**RaaS (Ransomware-as-a-Service) — the roles:**
| Role | Function | Cut |
|---|---|---|
| Developers | build and maintain the malware, run the leak site | 20-30% of ransom |
| Affiliates | carry out the actual intrusion | 70-80% of ransom |
| Initial Access Brokers (IAB) | sell already-compromised access (VPN, RDP) | US$500 to US$10,000 per access |
| Negotiators | run the extortion conversation with the victim | commission |

**Double extortion:** the attacker steals the data **before** encrypting it. That way, even if the victim has backups and recovers on its own, there's still the threat of "pay or we publish your data." That's why destroying the backup also became a standard step of the attack — without that second lever, the victim simply restores and ignores the ransom demand.

**Typical attack timeline (useful reference when building kill chains):**
1. Days -30 to 0: initial access (bought from an IAB, phishing, or direct exploitation).
2. Days 1-2: mapping the network, Active Directory, and critically **where the backup lives**.
3. Days 2-3: privilege escalation up to Domain Admin.
4. Days 3-5: data exfiltration (15-50GB is typical for a hospital target).
5. Day 5+: simultaneous ransomware deployment across the network, usually via a GPO (Group Policy Object) pushed from a compromised Domain Controller.

**Why hospitals are a logical target (4 reasons):**
1. Clinical urgency = pressure to pay quickly.
2. A medical record is worth US$250-1,000 on the black market (a credit card is worth US$5-50, because it can be cancelled; medical data can't).
3. Legacy technology = easier to breach and move laterally.
4. Cyber insurance frequently pays the ransom, which attackers already know and factor into the amount they demand.

**Example:** an affiliate buys VPN access for US$5,000 from an IAB, spends 2 days mapping the network, finds and deletes the NAS backup job, exfiltrates the patient database, and only then triggers the ransomware via GPO — hitting every server at once.

---

## 3. Insider Threat Assessment

**What it is:** a threat that originates from someone with legitimate access — not every insider threat is intentional, and getting the classification right completely changes the mitigation.

**The 3 classifications:**
- **Malicious:** clear intent to cause harm or profit (e.g., an employee sells patient data).
- **Negligent:** no intent, it's a process or culture failure (e.g., a shared account because "it's always been that way").
- **Compromised:** the account is legitimate, but is being used by a third party who stole the credential (the person did nothing wrong, but the effect is the same).

**Indicators that help tell them apart:**
- **Behavioral:** unusual access hours, abnormal data volume, access outside the scope of the role.
- **Technical:** multiple simultaneous sessions on the same account, logins from already-terminated accounts, absence of individual logging.

**Controls associated with each type:**
- Malicious → behavior monitoring (UEBA), DLP (Data Loss Prevention), segregation of duties.
- Negligent → training, individual (non-shared) logins, automatic session timeout.
- Compromised → MFA, login anomaly detection.

**Example 1:** shared login among PACS technicians, no session timeout → classified as **negligent** (process failure, not individual malicious intent). Mitigation: individual logins + automatic timeout.

**Example 2:** a former contractor's account authenticating 3 times after hours, 2 months after termination, with no open ticket → classified as **negligent (systemic)**, root cause is an offboarding failure — but it still requires individual investigation, since it could also indicate malicious use of the credential by a third party.

---

## 4. Social Engineering Analysis

**What it is:** an attack that manipulates a **person**, not a system, to gain access or information.

**Vectors (official CompTIA Security+ 2.2 terminology):**
| Vector | Description | Example |
|---|---|---|
| Phishing | mass fraudulent email | fake "password reset" link |
| Spear phishing | phishing targeted at a specific person | email naming the IT director |
| Whaling | spear phishing aimed at a senior executive | fake email to the CFO requesting a wire transfer |
| Vishing | voice/phone-based scam | call impersonating technical support |
| Smishing | SMS-based scam | text: "your package is held, click here" |
| Pretexting | fabricating a false story to gain trust | "I'm from audit, I need your password" |
| Baiting | physical or digital lure | a USB drive "forgotten" in the parking lot |
| Tailgating/Piggybacking | following someone through a door without badging in | walking in right behind an employee |
| Watering hole | compromising a site the victim regularly visits | an infected medical association website |

**Psychological triggers (Cialdini) that make the scam effective:**
- **Authority** ("I'm from official tech support").
- **Urgency** ("your account will be locked in 1 hour").
- **Fear** ("we detected suspicious activity on your account").
- **Social proof** ("every other department already updated").
- **Curiosity/liking** (generic bait, e.g., "see who viewed your profile").

**How to solve each exercise scenario:** identify the exact vector (table above) + the dominant psychological trigger + 3 concrete red flags from the text (odd sender, artificial urgency, link that doesn't match the official domain) + 1 technical control + 1 administrative control.

**Example:** an email "urgent FortiGate firmware update" signed as technical support, asking to click an external link → vector: spear phishing; trigger: authority + urgency; technical control: "external email" banner + link blocking; administrative control: training to verify by phone before clicking.

---

## 5. Supply Chain / Third-Party Risk Assessment

**What it is:** any vendor with access to your network is, in practice, an extension of your attack surface — the organization's security is only as strong as the weakest link among its partners.

**Key concepts:**
- **TPRM (Third-Party Risk Management):** the formal process of assessing and monitoring the risk of each vendor.
- **BAA (Business Associate Agreement):** in a healthcare environment (HIPAA), a mandatory contract defining a vendor's responsibility over patient data.
- **Right to audit:** a contractual clause allowing you to audit the vendor's security.
- **Least privilege for third parties:** a vendor should only have access to what it truly needs, nothing more.

**What to assess for each vendor:**
1. Scope of access granted (what it can see/touch).
2. Type of connection (dedicated VPN, remote access, API).
3. Whether MFA exists on the vendor's account.
4. Compromise path: if the vendor is hacked, what does the attacker gain inside your network?

**Real-world reference example (outside the exercise, but instructive):** the SolarWinds attack (2020) compromised a single software vendor and, because of that, reached thousands of customers — proof of how one weak link in the supply chain becomes a mass entry point.

**MedDefense example:** the EHR maintenance vendor (MedTech Solutions) has remote-access VPN with no MFA and no time restriction → if that vendor is compromised, the attacker walks straight into the hospital's EHR as if it were a legitimate user.

---

## 6. Threat Actor Matrix

**What it is:** a single table comparing all 6 actor types side by side — not new theory, it's a consolidation of what was gathered in items 1 through 5.

**Expected structure per actor:** motivation, technical capability, typical TTPs (Tactics, Techniques, Procedures), and which MedDefense asset that actor is most likely to target.

**Example matrix row:**
| Actor | Motivation | Sophistication | Preferred target |
|---|---|---|---|
| Ransomware (RaaS) | Financial | Medium-High | EHR + backup (double extortion) |
| Nation-State APT | Espionage | Very High | Clinical research data |
| Malicious Insider | Financial/revenge | Low-Medium | Data they already have access to |
| Hacktivist | Ideological | Low-Medium | Public website, leak for exposure |
| Opportunistic | Curiosity/easy profit | Low | Any exposed, unpatched system |

---

## 7. Attack Surface Map

**What it is:** listing **every possible entry point** into the organization, organized by layer.

**The 4 classic layers:**
- **External:** anything reachable from the internet (VPN, email, website, patient portal, DNS).
- **Internal:** local network, segmentation (or lack thereof), Active Directory.
- **Human:** employees, third parties — anyone who can be tricked.
- **Physical:** physical access to the datacenter, a medical device, a server room.

**For each entry point, document:** the asset behind it, the control already in place, and the gap (if any) that leaves it exposed.

**Related concepts:**
- **Attack Surface Reduction (ASR):** eliminating or disabling anything not strictly necessary, reducing entry points.
- **Zero Trust:** the principle of never automatically trusting anything, not even internal traffic — always verify.

**Example:** a FortiGate 100F VPN exposed to the internet, without MFA (GAP-014) → a high-risk external entry point, because a single leaked credential is enough to get into the network.

---

## 8. Technical Vectors Assessment

**What it is:** technical intrusion vectors — unlike the human vector in item 4, here the target is the system itself.

**Main categories:**
- **Vulnerable/outdated software:** version with a known CVE, past end-of-support (EOL).
- **Misconfiguration:** an unnecessary open port, excessive permissions, a service running with admin privilege it doesn't need.
- **Weak or default credentials:** never-changed factory default password, simple password.
- **Insecure legacy protocol:** SMBv1, Telnet, or in a hospital's case, the DICOM protocol without authentication on a medical device.
- **Zero-day vs known exploit:** a zero-day requires a sophisticated attacker (nation-state); a public exploit for an old CVE can be used even by a beginner.

**Link to the taxonomy (item 1/6):** the vector type indicates the most likely attacker type — an old, public CVE attracts opportunists; a zero-day indicates an advanced actor.

**Example:** Apache 2.4.29 running on billing-srv-01, unsupported since June 2023, with a known, public RCE (Remote Code Execution) → any opportunistic attacker with an exploit downloaded from the internet can compromise the server, no advanced skill required.

---

## 9. Vector-to-Asset Matrix

**What it is:** a matrix crossing **attack vector (rows) × critical asset (columns)**, to visualize where exposure concentrates.

**How to pick critical assets:** use the CIA Triad (Confidentiality, Integrity, Availability) — which asset, if compromised, causes the most damage along one of those three dimensions. E.g., EHR = high confidentiality (patient data) + high availability (must always be accessible for care).

**How to fill in a matrix cell:** "can this vector reach this asset? How, specifically?" — not just yes/no, explain the path.

**Example:** the "VPN without MFA" row crossing the "Active Directory" column → a critical-risk cell, because a stolen VPN credential allows direct network login, and from there escalation up to the Domain Controller.

**Why it matters:** this matrix is the direct foundation for building the Kill Chains in the next item — every high-risk cell becomes the starting point of a full attack chain.

---

## 10. Kill Chains

**What it is:** the **Cyber Kill Chain** (Lockheed Martin model) describes the sequential phases of a complete attack, from reconnaissance to final objective.

**The 7 phases:**
1. **Reconnaissance:** gathering information about the target (employees on LinkedIn, technology exposed via scan).
2. **Weaponization:** preparing the payload (malware, exploit, malicious email).
3. **Delivery:** delivering the payload (sending the email, exploiting the exposed service).
4. **Exploitation:** the vulnerability is actually exploited (the click happens, the exploit runs).
5. **Installation:** the attacker installs persistence (backdoor, resident malware).
6. **Command & Control (C2):** the remote communication channel between attacker and compromised machine.
7. **Actions on Objectives:** the final objective is executed (data exfiltration, encryption, sabotage).

**Complementary concepts:**
- **MITRE ATT&CK** (item 13) is a more granular evolution of the kill chain.
- **Unified Kill Chain** (Paul Pols) combines both models into a single chain.

**Full kill chain example:** phishing the IT director (Delivery) → stolen credential used on the VPN (Exploitation) → malware installed on the machine (Installation) → attacker communicates over encrypted C2 (C2) → GPO distributes ransomware across the entire network (Actions on Objectives).

---

## 11 and 12. STRIDE (on the EHR and Across the Architecture)

**What it is:** a Microsoft *threat modeling* framework with 6 fixed threat categories, applied system by system.

| Letter | Category | Key question | Example |
|---|---|---|---|
| S | Spoofing | Can someone pretend to be another person/system? | login with a stolen credential, no MFA |
| T | Tampering | Can someone alter data without permission? | editing a patient record without authorization |
| R | Repudiation | Can someone deny an action for lack of proof? | no logs, nobody can prove who accessed what |
| I | Information Disclosure | Can someone see data they shouldn't? | unauthorized export of the patient database |
| D | Denial of Service | Can someone take the service down? | ransomware locks up a medical infusion pump |
| E | Elevation of Privilege | Can someone become admin without being one? | a permission bug becomes a path to Domain Admin |

**How to apply it:** for each category, document a Threat ID, description, associated attack vector (tying back to items 4 and 8), and business impact.

**Difference between the two exercises:** item 11 applies STRIDE only to the EHR system (single focus); item 12 repeats the process for each system in the architecture (PACS, medical devices, network) — same methodology, broader scope.

**Complementary frameworks (context, not directly used here):**
- **DREAD:** a risk scoring method (Damage, Reproducibility, Exploitability, Affected users, Discoverability).
- **PASTA / VAST:** other threat modeling methodologies, more focused on business risk or agile scale.

**Example (EHR):** login without MFA on the EHR system (GAP-014) → **Spoofing** category → attacker authenticates as if they were a legitimate physician → impact: full access to patient records with no real identity verification.

---

## 13. ATT&CK Mapping

**What it is:** a MITRE matrix documenting real adversary behavior, observed in real campaigns (not theoretical), with standardized naming.

**Structure:**
- **Tactic:** the "why" — the phase of the attacker's objective (Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, Impact).
- **Technique:** the "how" — the specific action, with a code in the format T#### (e.g., T1190) or a sub-technique T####.### (e.g., T1566.001 = phishing via attachment).

**Difference from the Kill Chain:** ATT&CK is more granular (dozens of techniques per tactic) and doesn't need to follow a linear order — an attacker can return to "Discovery" multiple times during the attack.

**Mapping example:**
| Attack step | Tactic | Technique |
|---|---|---|
| Buying access from an IAB | Resource Development | Acquire Access (T1650) |
| Exploiting the exposed FortiGate | Initial Access | Exploit Public-Facing Application (T1190) |
| Dumping credentials from memory | Credential Access | OS Credential Dumping (T1003) |
| Ransomware via GPO | Impact | Data Encrypted for Impact (T1486) |

**How to solve the exercise:** for each step of the scenario, identify the Tactic, the matching Technique/code, and the "MedDefense factor" — the specific organizational reason that makes that technique viable there (e.g., "FortiGate exposed to the internet" is what enables T1190).

---

## 14. Threat Scenarios

**What it is:** consolidating actor + vector + kill chain + STRIDE + ATT&CK into a **single, plausible narrative**, told from start to finish.

**The three scenario axes to cover:**
- **External:** e.g., a ransomware campaign (outside actor exploiting a technical or human vector).
- **Internal:** e.g., data exfiltration by an insider.
- **Third-party/supply chain:** e.g., a compromised vendor used as a bridge.

**Structure of a well-written scenario:** title, actor, motivation, initial vector, attack surface exploited, step-by-step progression, final impact.

**Example:** "Operation Flatline" — a ransomware affiliate (actor) sends phishing impersonating Fortinet support (initial vector, human vector) to the IT director; the credential is stolen; the attacker logs into the VPN (external surface); maps the network and deletes the backup; exfiltrates the patient database; triggers encryption via GPO across every domain-joined system (final impact: total shutdown + data breach).

---

## 15. Gap-Threat Correlation

**What it is:** linking each **control gap** identified in the prior assessment (1x00) to the specific threats that exploit exactly that gap — a traceability matrix.

**Correlation logic:** a gap is never abstract — it always enables one or more concrete attack chains. Document: `GAP-XXX → which Kill Chain uses this gap → which Scenario it appears in → which control closes the gap`.

**Why this correlation matters in practice:** it's what turns "I recommend buying MFA" (opinion) into "GAP-014 enables Kill Chain 2, which leads to full domain takeover, so MFA is mandatory" (evidence-based justification) — this is the logic used in GRC (Governance, Risk & Compliance) to approve security budget.

**Example:** GAP-014 (no MFA on the VPN) → enables Kill Chain 2 (a compromised VPN credential leads to full domain takeover) → appears in Scenario 1 (ransomware) → recommended control: mandatory MFA on every VPN and administrative account.

---

## 16. Threat Priority Assessment

**What it is:** ranking the Top 5 threats using the formal risk criterion: **Likelihood × Impact**.

**What increases Likelihood:**
- An exposed, easy-to-find attack surface (public scan).
- Technical ease of exploitation (a ready-made exploit available).
- Evidence of real activity in the sector (contextual threat intel: "3 hospitals in the region have been hit by the same group in the last 8 months").

**What increases Impact:**
- Asset criticality (use the CIA Triad from item 9).
- Presence of regulated data (PHI under HIPAA = fines and legal obligation).
- Critical operational dependency (a compromised medical device can cost a life, not just money).

**Golden rule:** every position in the ranking must cite concrete evidence from prior artifacts (kill chain, STRIDE, correlated gap) — never a loose opinion like "I think it's the most dangerous."

**Example:** ransomware ranks #1 because it has high Likelihood (an active group in the region, an entry vector already mapped and without MFA) and very high Impact (shuts down the whole hospital, including patient care, plus a breach of regulated data).

---

## 17. Threat Evolution — What-If Analysis

**What it is:** prospective analysis (scenario planning) — testing how the entire threat landscape changes if a business factor changes.

**5 mandatory questions per hypothetical scenario:**
1. **New Threat Actors:** what type of actor becomes interested?
2. **Changed Vectors:** what new vector becomes available or more attractive?
3. **Shifted Priorities:** how does the ranking from item 16 reorder?
4. **New Gaps:** what control now becomes necessary that wasn't before?
5. **Net Assessment:** executive conclusion — did net risk increase, decrease, or change in nature?

**Why this is a valuable skill:** business decisions (a new partnership, expansion, new technology) change the entire *threat model*, not just one isolated point — thinking about this ahead of time avoids being caught off guard.

**Example:** MedDefense signs a partnership with a university for clinical research → now attracts nation-state interest (previously only organized crime cared) → the vector shifts from "generic phishing" to "targeted espionage against a researcher"; priority shifts; new gap: research data previously had no confidentiality classification.

---

## 18. Threat Landscape Report

**What it is:** the final document — translating all the technical analysis into executive communication, for the people who decide (leadership/board), who have neither the time nor the technical vocabulary.

**Recommended structure:**
1. **Executive Summary:** 3-5 sentences, straight to the point, no jargon, stating the most critical threat and the top 3 recommendations.
2. **Report body:** organized into logical sections reusing prior artifacts (actors → surface → scenarios → gaps → prioritization).
3. **Recommendations:** specific, prioritized, and tied to a concrete gap — never generic.

**Best practices for threat intelligence reporting:**
- Separate **observed fact** from **inference/assumption**.
- State a **confidence level** for each claim.
- Be specific: "enable MFA on the VPN by 09/30" instead of "improve security."

**Example of a well-written executive summary:** "MedDefense matches the ideal ransomware target profile: valuable patient data, a thin security team, and gaps that have already been exploited at 3 regional hospitals in the last 8 months. The most critical threat is a ransomware attack that encrypts the entire EHR and destroys the backup before demanding payment. Top 3 priorities: functioning intrusion detection, MFA everywhere (including vendors), and closing the 4 gaps that let a single phishing email turn into full compromise."

---

## Dependency order across the files

```
0 landscape overview
 └─ 1,2,3,4,5 threat profiles by category (actor, ransomware, insider, human, vendor)
     └─ 6 consolidated actor matrix
         └─ 7,8,9 attack surface, technical vectors, vector×asset matrix
             └─ 10 kill chains · 11,12 STRIDE · 13 ATT&CK  (same layer, feed off the previous step)
                 └─ 14 consolidated threat scenarios
                     └─ 15 gap × threat correlation
                         └─ 16 risk prioritization
                             └─ 17 what-if analysis
                                 └─ 18 final report
```

## Framework reference table (quick review before repeating the module)

| Framework | Used in | Core idea |
|---|---|---|
| Diamond Model | Item 1 | Adversary – Infrastructure – Capability – Victim |
| CIA Triad | Items 0, 9, 16 | Confidentiality, Integrity, Availability |
| RaaS / Double Extortion | Item 2 | Ransomware is a role-split business, with 2 forms of pressure |
| Insider classification | Item 3 | Malicious vs Negligent vs Compromised |
| Sec+ 2.2 (Social Engineering) | Item 4 | Standard vocabulary for scams + psychological triggers |
| TPRM / BAA | Item 5 | Formal vendor risk management in a regulated environment |
| Cyber Kill Chain (Lockheed Martin) | Item 10 | 7 phases, from reconnaissance to final objective |
| STRIDE | Items 11, 12 | 6 threat categories, applied per system |
| MITRE ATT&CK | Item 13 | Tactics (why) + Techniques (how), with standardized codes |
| Risk Matrix | Item 16 | Likelihood × Impact = risk priority |
| Scenario Planning | Item 17 | Anticipating how a context change shifts the threat model |
| Threat Intel Reporting | Item 18 | Fact vs inference, confidence level, specific recommendation |

---

*Study guide — not part of the deliverable. Use as a theory checklist before reviewing or expanding any exercise in this module.*
