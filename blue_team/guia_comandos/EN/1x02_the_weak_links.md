# 1x02 – The Weak Links

## Task - 0-first_impressions.md
Concept: A vulnerability scan report is a document produced by humans and tools, and as such it can contain inconsistencies (header vs. body mismatches, miscounts, findings appended manually without updating the summary). The discipline of reading and counting every individual finding, rather than trusting the executive summary alone, is a core vulnerability-analysis skill. It also introduces the difference between authenticated and unauthenticated scanning: devices scanned without credentials only reveal what is exposed on the network, not what is misconfigured underneath, which should lower confidence in those specific findings.

## Task - 1-cve_ecosystem.md
Concept: CVE (Common Vulnerabilities and Exposures) is a system of unique, standardized identifiers for known vulnerabilities, maintained by CNAs (CVE Numbering Authorities) under the MITRE/CISA CVE Program. Each CVE has a lifecycle (Reserved, Published, Rejected) and an ID structure (CVE-YYYY-NNNN) where the year reflects assignment, not necessarily discovery. Understanding this decentralized ecosystem explains why not every CVE gets a CWE mapping, why CVEs can be rejected (duplicates), and why a "last modified" date does not mean a vulnerability is still under active analysis.

## Task - 2-cvss_analysis.md
Concept: CVSS (Common Vulnerability Scoring System) is a standardized framework for scoring the technical severity of a vulnerability, combining Exploitability metrics (Attack Vector, Attack Complexity, Privileges Required, User Interaction, Scope) and Impact metrics (Confidentiality, Integrity, Availability) into a 0-10 score. Manually deconstructing a CVSS vector and recalculating the formula teaches which metrics carry the most weight in the final score - the Impact triad (C/I/A) is usually what separates High from Critical, while Attack Vector and Privileges Required gate who can even attempt the attack in the first place.

## Task - 3-cwe_analysis.md
Concept: CWE (Common Weakness Enumeration) is a hierarchical taxonomy of software flaw categories (the "root cause" behind a specific CVE), organized from most generic (Class) to most specific (Variant). MITRE's CWE Top 25 ranks the most frequent and dangerous categories across the ecosystem, but frequency is not the same as danger per instance - a rare CWE can produce a CVE just as critical as a common one. Tracing CVEs back to their CWE helps surface repeated root-cause patterns that a list of isolated CVEs would otherwise hide.

## Task - 4-exploit_hunt.md
Concept: Exploit-DB (and the `searchsploit` tool) and the CISA KEV (Known Exploited Vulnerabilities) catalog are sources that measure a vulnerability's exploit maturity and real-world exploitation, complementing CVSS's theoretical severity score. A vulnerability with a high CVSS but no public exploit available represents a different risk than one with a weaponized Metasploit module and confirmed active exploitation on the KEV list - that exploit maturity is an essential axis of prioritization, separate from the severity score.

## Task - 5-exploit_check.sh
What it does: Reads a list of service/version strings from a text file and runs `searchsploit` for each line, counting how many public exploits exist for each service and listing the results.
How to use: `./5-exploit_check.sh <services_file>`
Commands:
- `searchsploit -j <terms>` — searches the local Exploit-DB copy for the given terms (each word acts as an AND filter) and returns the results as JSON.
- `searchsploit --colour=never <terms>` — the same search in plain-text mode (no ANSI colors), used as a fallback when `jq` is not installed.

## Task - 6-misconfiguration_analysis.md
Concept: Not every vulnerability has a CVE - misconfigurations (overly open ports, missing authentication, disabled encryption) are human operational mistakes, not software defects, and therefore never receive an official CVE identifier or CVSS score. Findings without a CVE can be just as dangerous as, or more dangerous than, scored CVEs, since they often require zero technical sophistication to exploit (just network reach). A vulnerability management program built purely around CVE/CVSS counts is blind to this entire risk category.

## Task - 7-vulnerability_taxonomy.md
Concept: Vulnerabilities can be classified into broad categories (Application, OS-based, Misconfiguration, Cryptographic, Hardware/Firmware/EOL, Web-based, Supply Chain, Cloud, Virtualization, Mobile, Zero-day), as in Sec+ 2.3. Building this taxonomy over a real set of findings reveals an organization's security maturity profile - for example, a predominance of misconfiguration indicates a failure of operational discipline, not attacker sophistication. Categories absent from the taxonomy do not mean absence of risk: they may simply reflect a blind spot of the scanning tool (e.g., zero-day can never appear in a signature-based scanner's output).

## Task - 8-lynis_audit.md
Concept: Lynis is a Linux system-hardening audit tool that evaluates dozens of categories (authentication, file permissions, logging, networking, packages) and produces a Hardening Index along with actionable suggestions. Running a self-audit without root privileges demonstrates how access level changes finding visibility - tests that require root (firewall rules, sudo file permissions, disk encryption) become invisible without elevated privilege, the same "reduced access equals reduced visibility" principle observed in unauthenticated scans of medical devices.

## Task - 9-osint_hunt.md
Concept: OSINT (Open Source Intelligence) applied to security means actively searching public sources (NVD, vendor advisories, CISA bulletins) for vulnerabilities that affect an organization's technology stack but that an internal scanner would never detect - either because it falls outside the scan's scope (cloud, mobile devices) or because it lives at a layer the scanner can't reach (a perimeter firewall's own firmware, for example). This reinforces that a scan report is always a partial view, and proactive research is needed to cover its blind spots.

## Task - 10-critical_cves.md
Concept: A complete analysis of a critical vulnerability combines two dimensions: technical analysis (CVSS, CWE, exploit availability, CISA KEV status) and contextual analysis (network exposure, position in a kill chain, relevant threat actor, existing controls). Only combining both lets you arrive at a truly adjusted priority - a finding that is technically "only" High can be the most urgent item in the whole report once the asset's and threat's context is factored in.

## Task - 11-false_positives.md
Concept: False positives are scanner findings that, after manual validation, do not represent real risk in the specific context of the environment - usually because the exploitation precondition doesn't apply (e.g., a CVE that requires a usage pattern the server never actually exhibits). Validating before acting is essential because remediation effort is a finite resource: time spent fixing a false positive is time taken away from a true, currently exploitable finding. A scanning tool's expected false-positive rate (typically 5-10%) serves as a sanity check on the validation process itself.

## Task - 12-legacy_systems.md
Concept: An "End-of-Life" (EOL) system is qualitatively different from a merely "outdated" one - "unpatched" describes a flaw with an available fix that hasn't been applied yet (a temporary, closeable gap), while EOL means no future fix will ever be produced for any new vulnerability, no matter how severe (a permanent, growing exposure). When an EOL system cannot be migrated for technical or regulatory reasons (e.g., a certified medical device), compensating controls like network segmentation become the only viable mitigation, instead of patching.

## Task - 13-web_exposure.md
Concept: Information-disclosure findings (like an error page revealing a version number) look low-severity in isolation, but should be treated as investigative leads rather than conclusions - they point exactly to what should be checked next. Combining multiple findings on the same host (internet exposure, exploit chain, asset criticality) produces a more realistic attack scenario than analyzing each finding in isolation.

## Task - 14-network_posture.md
Concept: A flat network (no segmentation/VLANs) acts as a uniform risk multiplier: it doesn't create any single vulnerability, but it amplifies the blast radius of all of them simultaneously, turning an isolated departmental risk into a full organization-wide one. Unlike applying a patch (which closes exactly one vulnerability), network segmentation reduces the impact of everything not yet discovered - including future vulnerabilities and misconfigurations that will never receive a CVE.

## Task - 15-medical_iot.md
Concept: Medical IoT devices (infusion pumps, patient monitors) require a different risk model than ordinary IT servers, because an integrity or availability failure there is not a data problem - it is a real-time physical patient-safety problem, with no "restore from backup" possible afterward. Fixing these devices is structurally harder than fixing regular IT for three reasons: regulation (FDA re-clearance), operations (continuous clinical use with no maintenance window), and total dependency on the manufacturer for any firmware update.

## Task - 16-triage.md
Concept: Triage is the process of quickly classifying every finding from a scan into action categories (e.g., Actionable Critical, Actionable Standard, Informational, False Positive) before investing deep research time into any single one of them. This initial filter prevents an analyst from spending research effort on noise (false positives, purely informational items) before even knowing which findings actually deserve priority attention.

## Task - 17-cvss_contextualizer.md
Concept: CVSS v3.1's Environmental Metrics allow adjusting a vulnerability's base score by accounting for the real criticality of the affected asset (Confidentiality/Integrity/Availability Requirements), producing an "adjusted score" that's more faithful to real risk than the generic base score. This recalculation is most revealing when the base score isn't already saturated at the top of the scale - that's where factors like asset criticality, position in an attack chain, and absence of compensating controls can dramatically raise the priority of a finding that a CVSS-only triage would have overlooked.

## Task - 18-threat_vuln_correlation.md
Concept: Correlating technical vulnerabilities with threat intelligence (actors, attack vectors, documented kill chains) turns a list of isolated flaws into a view of which ones actually converge on a real, plausible attack path. When the same vulnerability shows up independently in multiple different threat narratives, that is a stronger signal of real-world inevitability than any single CVSS score could express on its own.

## Task - 19-remediation_map.md
Concept: A formal remediation plan specifies not just what to fix, but how (configuration change, patch, or compensating control), along with impact assessment, rollback plan, timeline, owner, and estimated cost. Distinguishing the three response types matters: configuration changes tend to be fast and cheap, patches require testing and a reversal plan, and compensating controls (like segmentation) mitigate access risk without eliminating the underlying vulnerability - leaving a residual risk that must be explicitly acknowledged.

## Task - 20-priority_matrix.md
Concept: A priority matrix organizes all actionable findings by time horizon (immediate, short-, medium- and long-term) with estimated cost, allowing the total remediation effort to be compared against the actual available security budget. This exercise often reveals that the most urgent, highest-impact items cost very little (configuration changes), while the most expensive items (network segmentation, hardware replacement) tend to be longer-term - decisive information for budget decisions and for negotiating supplemental funding.

## Task - 21-vulnerability_assessment.md
Concept: An executive vulnerability assessment report consolidates scope, methodology, critical findings, false positives, vulnerability profile, threat-informed prioritization, and remediation roadmap into a single document aimed at management decision-making. The core skill here is synthesis: translating dozens of individual technical findings into one coherent, prioritized narrative a non-technical executive can use to decide on budget and timelines.

## Task - 22-patch_briefing.md
Concept: Executive security communication requires translating complex technical findings (CVEs, CVSS, CWE) into language a non-technical board or leadership team can understand and act on immediately - focusing on business impact, cost, and timeline rather than technical jargon. An effective briefing is short, concrete, and action-oriented, making clear what happens if nothing is done.

## Task - 23-validation_plan.md
Concept: Remediation is not complete until it has been independently verified - an untested fix is a claim, not a fact. A validation plan defines specific, reproducible tests for each type of fix (a refused reconnection after a configuration change, a version check after a patch, a network-reachability test after a compensating control) and establishes a continuous lifecycle (scan, triage, prioritize, remediate, validate, repeat) instead of treating the scan as a one-time event.
