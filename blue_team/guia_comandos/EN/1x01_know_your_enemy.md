# 1x01 – Know Your Enemy

## Task - 0-threat_landscape_summary.md
Concept: Threat actor profiling is the practice of categorizing who might attack an organization by type (organized crime, nation-state, insider, hacktivist, opportunistic), motivation, technical sophistication, and available resources. This profile is not generic — it is cross-referenced with sector-specific targeting logic (e.g., why hospitals are attractive targets) to estimate how likely each actor type is to actually target the organization being assessed.

## Task - 1-threat_actor_taxonomy.md
Concept: Threat attribution is the process of classifying an observed incident into an actor type based on indirect evidence — technique sophistication, apparent motivation, resources used, behavioral pattern — rather than identifying the exact individual. The exercise also teaches that attribution carries confidence levels (high, medium, low), and that ambiguous evidence can point equally well to more than one actor type.

## Task - 2-ransomware_assessment.md
Concept: Ransomware-as-a-Service (RaaS) is an operational model in which developers, affiliates, and Initial Access Brokers split roles and profit within an industrialized crime supply chain. The core concept of "double extortion" is combining data encryption with the threat of public leak, creating two independent pressure tracks on the victim — which is why simply restoring from backup is no longer enough to neutralize the attack.

## Task - 3-insider_assessment.md
Concept: Insider threat is the risk posed by people who already hold legitimate access to systems, split into two categories: negligent (mistake or shortcut with no malicious intent) and malicious (deliberate abuse of access for revenge, financial gain, or curiosity). Correct classification depends on specific behavioral indicators, not just the resulting damage.

## Task - 4-social_engineering_analysis.md
Concept: Social engineering is the manipulation of people — rather than systems — to gain access or information, exploiting psychological levers such as urgency, authority, familiarity, and helpfulness. The exercise covers the specific vectors named in the Security+ 2.2 objective (phishing, vishing, smishing, BEC, watering hole, typosquatting, tailgating), reinforcing that each vector carries its own red flags and matching technical/administrative controls.

## Task - 5-supply_chain_assessment.md
Concept: Supply chain / third-party risk recognizes that access granted to vendors and service providers extends an organization's attack surface beyond its own perimeter. Assessing this risk requires mapping each vendor's exact access scope and the specific "compromise path" an attacker would follow if that particular vendor were breached.

## Task - 6-threat_actor_matrix.md
Concept: A threat actor matrix consolidates, for each actor type, its likelihood, capability, motivation, preferred vector, and likely target, allowing threats to be compared and ranked side by side. This is the step that turns individual actor profiles into an ordered list of defensive priorities.

## Task - 7-attack_surface_map.md
Concept: Attack surface mapping is the systematic identification of every point where an attacker could attempt entry, typically organized into three layers — external (internet-facing), internal (network), and human (people). The exercise reinforces that in a flat, unsegmented network, any single entry point can become a direct shortcut to the most critical assets.

## Task - 8-technical_vectors.md
Concept: Technical attack vectors are recurring categories of weakness an attacker exploits — vulnerable software, unsupported (EOL) systems, open service ports, default credentials, unsecured networks, and unmanaged removable devices. Each category is paired with the actor type most likely to exploit it, tying the technical weakness back to a real adversary.

## Task - 8-threat_landscape_report.md
Concept: A threat landscape report is the consolidated document that synthesizes actors, vectors, attack surface, kill chains, STRIDE, scenarios, and gap correlation into a single narrative aimed at executive decision-making. It represents the final step of threat intelligence work, translating scattered technical analysis into prioritized, actionable recommendations.

## Task - 9-vector_asset_matrix.md
Concept: A vector-to-asset matrix cross-references every possible attack vector against every critical asset, mapping the exploitation path (or lack thereof) cell by cell. This surfaces the "most connected assets" (reachable via multiple vectors) and the "most versatile vectors" (that reach multiple assets), revealing where defensive investment has the greatest leverage.

## Task - 10-kill_chains.md
Concept: The Cyber Kill Chain is a model that describes an attack as a sequence of stages — initial access, establishing a foothold, lateral movement/escalation, objective execution, and impact. Mapping an attack onto these stages allows "break points" to be identified: specific stages where a security control could have stopped the entire chain before final impact.

## Task - 11-stride_ehr.md
Concept: STRIDE is a threat modeling framework that categorizes risks into six types — Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege. Applying STRIDE in depth to a single critical system produces a systematic list of threats per category, rather than relying on ad-hoc brainstorming.

## Task - 12-stride_architecture.md
Concept: STRIDE can also be applied at the architecture level, covering multiple systems more shallowly (survey level) to quickly identify each component's dominant threat category. This shows how the same framework scales from a deep dive on one asset to a broad sweep across several systems.

## Task - 13-attck_mapping.md
Concept: MITRE ATT&CK is a matrix of tactics (the "why" of each step, such as Initial Access or Lateral Movement) and techniques (the specific "how," such as Pass-the-Hash or Spearphishing Attachment) used by real attackers. Mapping an attack narrative to ATT&CK techniques creates a common, comparable vocabulary across different attack scenarios, revealing recurring tactics where defenses should be prioritized.

## Task - 14-threat_scenarios.md
Concept: A threat scenario is a complete narrative that ties actor, motivation, initial vector, attack sequence, STRIDE categories, impacted assets, and business impact together into one coherent story. Building realistic scenarios — rather than abstract risk lists — helps communicate concrete consequences to non-technical stakeholders.

## Task - 15-gap_threat_correlation.md
Concept: Gap-threat correlation is the process of recalibrating the priority of already-identified vulnerabilities (from an internal assessment) by cross-referencing them against external evidence of who would actually exploit them and how. A gap's priority can rise or fall once it's discovered whether it is (or isn't) a central step in multiple real-world kill chains and attack scenarios.

## Task - 16-threat_priority_assessment.md
Concept: Threat prioritization combines likelihood and impact into a composite risk ranking, ordering threats from most to least critical. The core idea is that the most severe impact alone doesn't determine first place — it's the combination of high likelihood and high impact together that sets the final priority.

## Task - 17-threat_evolution.md
Concept: What-if / threat evolution analysis evaluates how the threat landscape would change under hypothetical future events — a new partnership, a cloud migration, media exposure. The concept teaches that environmental changes don't just shift risk levels; they can activate previously irrelevant threat actors and create entirely new categories of gaps.

## Task - 18-threat_landscape_report.md
Concept: A threat landscape report is the consolidated document that synthesizes actors, vectors, attack surface, kill chains, STRIDE, scenarios, and gap correlation into a single narrative aimed at executive decision-making. It represents the final step of threat intelligence work, translating scattered technical analysis into prioritized, actionable recommendations.
