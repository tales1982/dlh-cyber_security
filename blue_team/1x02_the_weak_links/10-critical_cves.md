# 10. The Critical CVEs — MedDefense Vulnerability Scan

**Analyst:** Threat Intelligence Analyst
**Date:** Current

## 1. Finding 031 — Ghostcat AJP File Read/Inclusion

```
Finding: 031
CVE: CVE-2020-1938
Host: 10.10.2.10 (ehr-srv-01)
Asset Role: A-001, EHR application server (1x00 Asset Registry, Task 7)
Asset Criticality: EHR System — Confidentiality: Critical, Integrity: Critical,
  Availability: Critical, Overall: Critical (1x00 Criticality Matrix, Task 8)

Technical Analysis:
  Vulnerability Description: The Tomcat AJP connector, active by default and
    confirmed active by SecurePoint's manual follow-up on this host, lets an
    unauthenticated attacker read any file on the server through the AJP
    protocol -- including configuration files that may hold database
    credentials for ehr-db-01.
  CVSS Base Score: 9.8
  Exploit Availability: 5/5 (Task 4) -- weaponized Metasploit module (EDB-49039),
    standalone Python PoC (EDB-48143), AJP enabled by default in Tomcat 6-9.
  CISA KEV Status: Listed. Date Added 2022-03-03, Due Date 2022-03-17 (a 14-day
    window).
  CWE: NVD-CWE-Other -- NVD does not map this to a specific numbered weakness
    category (confirmed during Task 1 research); the underlying mechanism is
    functionally a file-read/path-disclosure primitive over a trust-abused
    protocol.

Contextual Analysis:
  Network Exposure: Internal only (port 8009/AJP is not internet-facing), but
    the flat network (GAP-007/GAP-012 pattern, 1x00 Task 12) means any of the
    47 scanned hosts can reach it once compromised by any other means.
  Kill Chain Position: Not explicitly named as a step in any of the five 1x01
    Task 10 kill chains -- this is itself worth flagging as a documentation
    gap. Structurally, it is functionally equivalent to Kill Chain #2's Step 3
    ("the flat network exposes [a critical server] directly to any
    authenticated internal session"), just aimed at ehr-srv-01 instead of
    ad-dc-01.
  Threat Actor: Ransomware Groups (Organized Crime) post-initial-access -- 1x01
    Task 6 names ehr-db-01 as this actor's primary target via exfiltration for
    leverage, and Ghostcat is a direct, trivial path to exactly that once any
    foothold exists anywhere on the flat network. Unskilled/Opportunistic
    Attacker is also plausible given the near-zero skill required to run the
    public Metasploit module.
  Related Findings: Finding 017 (the same Tomcat instance -- info disclosure
    that first suggested AJP might be reachable, which 031 then confirmed);
    Finding 003 (same asset pair, ehr-srv-01/ehr-db-01, different exposure
    mechanism).

Adjusted Priority: Critical
Justification: This is the only Exploitability-5, CISA-KEV-listed,
  confirmed-active finding sitting directly on the application server for
  MedDefense's single highest-value asset. Unlike the Critical-labeled MRI
  workstation (a real but singular device), a compromise here reaches the
  full 50,000+ patient record database. The 14-day KEV due date has already
  expired by a wide margin relative to when this vulnerability was disclosed.
```

## 2. Finding 003 — PostgreSQL Unrestricted Network Access

```
Finding: 003
CVE: N/A (misconfiguration)
Host: 10.10.2.11 (ehr-db-01)
Asset Role: A-002, EHR database (1x00 Asset Registry, Task 7)
Asset Criticality: EHR System -- Overall: Critical (1x00 Criticality Matrix,
  Task 8); ehr-db-01 is explicitly the #1 Top-5 Most Critical Asset.

Technical Analysis:
  Vulnerability Description: pg_hba.conf accepts connections from the entire
    10.10.0.0/16 range instead of only ehr-srv-01; listen_addresses='*' binds
    PostgreSQL to every interface. No exploit is needed -- only network
    reachability and a password.
  CVSS Base Score: N/A -- no CVE exists to score. Practically equivalent to a
    9.8+ finding given the directness of the exposure (Task 6 analysis).
  Exploit Availability: Not applicable on the 1-5 scale (Task 4) -- behaves as
    maximally exploitable in practice, since no exploit code is required at
    all.
  CISA KEV Status: N/A -- no CVE to list.
  CWE: CWE-1327, Binding to an Unrestricted IP Address (Task 3, Pattern 1 --
    shared with Finding 006's MySQL exposure on a different host).

Contextual Analysis:
  Network Exposure: Internal only, but flat-network reachable from all 47
    scanned hosts, including every compromised workstation, medical device,
    and shadow-IT host in the environment.
  Kill Chain Position: Named explicitly in Kill Chain #5 ("Vendor Compromise
    to Direct Patient Data Access"), Step 3: "GAP-001 -- ehr-db-01 is
    reachable network-wide, not restricted to ehr-srv-01 alone." This is a
    direct, word-for-word match, not an inference.
  Threat Actor: External attacker via a compromised vendor (Kill Chain #5's own
    actor); also Insider (Malicious), per 1x01 Task 6's matrix ("Primary
    Target: ehr-db-01... via abuse of legitimate access").
  Related Findings: Finding 031 (same asset pair, different exposure
    mechanism); Finding 006 (identical CWE-1327 root cause, different host);
    every finding rooted in the organization's absence of network
    segmentation.

Adjusted Priority: Critical
Justification: This finding is named by ID in an already-documented kill
  chain (1x01 Task 10) as the specific mechanism enabling total compromise of
  the organization's #1 critical asset. It requires zero exploit
  sophistication, making "when," not "if," the operative question for an
  attacker who reaches the internal network by any means whatsoever.
```

## 3. Findings 001 + 002 — Apache RCE-to-Root Chain

```
Finding: 001 / 002 (analyzed together -- the scan report itself documents them
  as a chain)
CVE: CVE-2021-44790 (001) / CVE-2019-0211 (002)
Host: 10.10.2.15 (billing-srv-01)
Asset Role: A-004, Billing/claims server, already compromised twice before
  this scan (ransomware, 1x00 Task 1; cryptominer, 1x00 Task 2) -- both times
  via this exact Apache instance.
Asset Criticality: Billing & Financial Infrastructure -- Confidentiality:
  Medium, Integrity: Medium, Availability: High, Overall: High (1x00
  Criticality Matrix, Task 8) -- notably not rated Critical, unlike the other
  four findings in this analysis. Its priority here comes from exploitability
  and proven history, not raw asset criticality.

Technical Analysis:
  Vulnerability Description: An unauthenticated attacker sends a crafted
    multipart request to trigger a buffer overflow in mod_lua, achieving code
    execution as www-data (001); a second flaw in Apache's scoreboard handling
    then escalates that shell to root (002) -- full host takeover from a
    single anonymous HTTP request followed by one local step.
  CVSS Base Score: 9.8 (001) / 7.8 (002)
  Exploit Availability: 4/5 (001, Task 4) -- public Python PoC (EDB-51193),
    not weaponized/not KEV-listed. 002 was not scored in Task 4's five; based
    on the same research trail, no independently weaponized public exploit
    was confirmed for it in this project -- stated here as unverified rather
    than assumed.
  CISA KEV Status: CVE-2021-44790 confirmed NOT listed (Task 4). CVE-2019-0211
    KEV status was not independently checked in this project.
  CWE: CWE-787, Out-of-Bounds Write (001) / CWE-416, Use After Free (002) --
    both traced in Task 3, both in the CWE Top 25 (#2 and #8 respectively).

Contextual Analysis:
  Network Exposure: External / internet-facing -- 1x01 Task 6's own Threat
    Actor Matrix states this directly: "Preferred Vector: Exploitation of
    known, unpatched, internet-facing vulnerabilities -- specifically Apache
    2.4.29 on billing-srv-01." This is not a flat-network-only exposure like
    the other findings in this analysis; it is reachable from outside
    MedDefense entirely, which is consistent with both prior real-world
    compromises having been external, opportunistic events.
  Kill Chain Position: Named explicitly as Kill Chain #4's Step 1
    ("Unpatched Web Server to Medical Device Exposure"): "A mass internet
    scanner finds billing-srv-01's exposed, unpatched Apache instance and
    exploits it automatically -- the same vulnerability already used twice
    against MedDefense."
  Threat Actor: Unskilled / Opportunistic Attacker -- both the 1x01 Task 6
    matrix and Kill Chain #4 name this actor type specifically for this exact
    vulnerability, and MedDefense's own incident history (twice already)
    confirms it rather than merely predicting it.
  Related Findings: Findings 006 (MySQL open, same host), 009 (SSH password
    auth, same host), 011 (Ubuntu 18.04 EOL, same host), 026 (47 unpatched
    kernel CVEs, same host) -- six of the report's 31 findings concentrate on
    this single host (Task 0's heat map), and this chain is the one that
    turns any of them into full root compromise.

Adjusted Priority: Critical
Justification: This is the only finding in the report with a confirmed,
  repeated real-world exploitation history against MedDefense specifically --
  not a theoretical risk, a demonstrated pattern about to repeat a third time
  on an internet-facing host, via a named step in an existing kill chain.
```

## 4. Finding 004 — Windows XP End-of-Life (MRI Workstation)

```
Finding: 004
CVE: CVE-2008-4250 (MS08-067) / CVE-2017-0144 (EternalBlue) / CVE-2019-0708
  (BlueKeep)
Host: 10.10.1.70 (WS-RAD-01, MRI scanner control workstation)
Asset Role: A-014, MRI imaging control (1x00 Asset Registry, Task 7) --
  explicitly documented as unable to be patched, upgraded, replaced, or
  disconnected (1x00 Task 6).
Asset Criticality: Medical IoT -- Confidentiality: Medium, Integrity:
  Critical, Availability: Critical, Overall: Critical (1x00 Criticality
  Matrix, Task 8).

Technical Analysis:
  Vulnerability Description: Three independently weaponized remote code
    execution vulnerabilities in an operating system that has received no
    security patch in over a decade -- SMB (MS08-067, EternalBlue) and RDP
    (BlueKeep) services are all reachable and unpatched simultaneously on one
    host.
  CVSS Base Score: 10.0 / 8.1 / 9.8 respectively.
  Exploit Availability: 5/5 for all three (Task 4) -- fully weaponized
    Metasploit modules for each; MS08-067 was the Conficker worm's vector,
    EternalBlue was WannaCry/NotPetya's vector.
  CISA KEV Status: All three listed. EternalBlue added 2022-02-10 (due
    2022-08-10); BlueKeep added 2021-11-03 (due 2022-05-03); MS08-067 added
    2026-05-20 per CISA's own recent bulletin -- notably, this means CISA
    added a 16-year-old vulnerability to an active-exploitation catalog only
    recently, evidence attackers are still finding value in it today.
  CWE: Not independently traced against NVD/CWE in this project for these
    three specific CVEs (Task 3 focused on three different CVEs) -- stated
    honestly rather than assumed; all three are memory-safety/protocol
    trust-boundary failures in the same general family as the CWE-787 pattern
    already established as the environment's highest-frequency dangerous
    weakness category (Task 3).

Contextual Analysis:
  Network Exposure: Internal only, but on the same flat subnet (10.10.1.0/24)
    as roughly 320 general-purpose Windows 10 workstations, with no VLAN
    isolation (confirmed in the finding itself and in 1x00 Task 6).
  Kill Chain Position: Not explicitly named in any of the five 1x01 Task 10
    kill chains -- another real documentation gap worth raising with James,
    since this is arguably the single worst medical-device exposure in the
    environment and has no dedicated walkthrough. It fits the same structural
    position as Kill Chain #4's Step 3 (medical IoT reached after a flat-
    network pivot), just via a different device.
  Threat Actor: Unskilled / Opportunistic Attacker -- these exploits are
    wormable and require no operator skill once released, matching the
    profile 1x01 Task 6 already assigns highest likelihood to; Ransomware
    Groups would also readily use any of the three as a lateral-movement tool
    once inside.
  Related Findings: No other finding shares this host, but it is thematically
    identical in root cause (flat network, no segmentation, GAP-007) to
    Findings 010, 016 and 024, all also medical-device exposures.

Adjusted Priority: Critical
Justification: Unlike every other finding in this report, this one cannot be
  patched, upgraded, or replaced by any remediation strategy other than
  network isolation -- the compensating controls proposed for this exact
  scenario in 1x00 (C-014/015/016) are still only proposed, not implemented
  (1x01 Task 7, Attack Surface Map). Three separately wormable, KEV-listed
  RCEs on a life-safety device with no viable patch path is as close to
  unconditionally Critical as this report gets.
```

## 5. Finding 015 — Synology NAS Exposed Management Interface

```
Finding: 015
CVE: N/A per the scan report itself; CVE-2024-10441 identified via OSINT
  (Task 9) as a plausible, unconfirmed risk behind this same exposed
  interface if the DSM build predates the fix.
Host: 10.10.2.41 (NAS-01)
Asset Role: A-010, Backup storage (1x00 Asset Registry, Task 7) -- the #3
  Top-5 Most Critical Asset (1x00 Task 8): "the only thing standing between
  MedDefense and permanent data loss."
Asset Criticality: File, Print & Backup Infrastructure -- Confidentiality:
  High, Integrity: Medium, Availability: Critical, Overall: Critical (1x00
  Criticality Matrix, Task 8).

Technical Analysis:
  Vulnerability Description: The DSM web management interface (ports
    5000/5001) is reachable from the entire internal network, and backup
    data is stored unencrypted. Per Task 9's OSINT research, if the DSM build
    predates 7.2-64570-4 / 7.2.1-69057-6 / 7.2.2-72806-1, the same exposed
    interface may also carry CVE-2024-10441, a CWE-116 remote code execution
    flaw in DSM's system plugin daemon -- this has not been confirmed against
    the actual device and is flagged here as an open question, not a
    verified finding.
  CVSS Base Score: N/A from the scan itself (misconfiguration); 9.8 if
    CVE-2024-10441 applies and remains unpatched.
  Exploit Availability: Not scored on the 1-5 scale in Task 4 (misconfig, not
    among the five CVEs analyzed there); if CVE-2024-10441 applies, exploit
    maturity was not independently verified in this project.
  CISA KEV Status: N/A for the misconfiguration; CVE-2024-10441's KEV status
    was not checked in this project.
  CWE: Not individually assigned in Task 3; closest categorical fit is
    CWE-284 (Improper Access Control) for the exposure itself, and CWE-116
    specifically if CVE-2024-10441 is confirmed present.

Contextual Analysis:
  Network Exposure: Internal only, flat-network reachable from all 47 scanned
    hosts.
  Kill Chain Position: Named explicitly at Kill Chain #1's Step 4: "NAS-01's
    management interface is used to delete backup jobs and stored backups
    before a GPO pushes the ransomware payload domain-wide." This is the
    decisive, final step of the single highest-impact kill chain documented
    in 1x01 Task 10, not a peripheral finding.
  Threat Actor: Ransomware Groups (Organized Crime) -- Kill Chain #1's own
    actor, using this exact mechanism as its objective-execution step.
  Related Findings: Structurally identical in pattern (open management
    interface, flat network) to Findings 003 and 006; conceptually
    inseparable from GAP-003 (1x00 Task 12, rated Critical): the sole backup
    repository having no protection or redundancy of its own.

Adjusted Priority: Critical
Justification: This finding is the literal final step of the environment's
  #1 documented kill chain -- the point at which a ransomware event stops
  being recoverable. Combined with a real, unconfirmed possibility of an
  unpatched critical RCE (CVE-2024-10441) sitting behind the same exposed
  interface, this is not a "nice to fix" item; it is the single point of
  failure for MedDefense's entire disaster-recovery posture.
```

## Repo

- **GitHub repository:** `dlh-cyber_security`
- **Directory:** `blue_team/1x02_the_weak_links`
- **File:** `10-critical_cves.md`
