
# 6. The MedDefense Threat Actor Matrix

**Analyst:** Threat Intelligence Analyst
**Date:** Current

## Instructions Recap

Cover 6 actor types: Ransomware Groups, Nation-State APT, Insider (Malicious), Insider (Negligent), Hacktivist, Unskilled/Opportunistic Attacker.

---

## Actor Matrix

### Ransomware Groups (Organized Crime)

```
Likelihood: Critical matches BlackReef's stated "Tier 1" target profile
  exactly, and three regional hospitals within 200 miles have been hit in
  the last 8 months (T2).
Capability: Medium-High RaaS platforms buy initial access from brokers,
  use a mix of commercial and custom tools, and operate with business-like
  efficiency rather than improvisation (T2).
Primary Motivation: Financial gain, via double extortion (encryption +
  data-leak threat).
Preferred Vector: Exploitation of public-facing applications/VPN (38% of
  healthcare cases), phishing (31%), purchased or harvested valid
  credentials (22%) T0.
Primary Target: ehr-db-01 (data exfiltration for leverage) and NAS-01
  (backup neutralization, per BlackReef's own playbook) both Top 5
  Critical Assets (1x00 Task 8).
MedDefense Exposure: GAP-014 (no MFA initial access), GAP-002 (no
  detection undetected dwell), GAP-017 (no AD tiering domain-wide
  escalation), GAP-003 (backup unprotected removes recovery option). The
  full 4-gap chain identified in T2.
```

### Nation-State APT

```
Likelihood: Low today MedDefense runs no research programs, so it holds
  little an espionage-motivated actor would prioritize (Marcus's own
  annotation in T0 dossier). This would change immediately with a research
  or clinical-trial partnership.
Capability: Very High custom malware, zero-day exploitation, dwell times
  measured in months to years (T0, Report A pattern).
Primary Motivation: Espionage theft of research/IP, not extortion.
Preferred Vector: Zero-day exploitation of public-facing infrastructure,
  custom tooling with stolen code-signing certificates (Report A, T1).
Primary Target: Research-adjacent data currently only Dr. Patel's
  personal NAS (shadow IT, T3 Scenario 3) holds anything resembling
  research data; this would shift to formal clinical-trial systems if any
  partnership began.
MedDefense Exposure: GAP-011 (shadow IT) is the only current foothold with
  any research-data relevance; overall exposure is low purely because there
  is little of interest to this actor type yet.
```

### Insider (Malicious)

```
Likelihood: Medium plausible but not yet observed at MedDefense; the
  conditions for it (broad access, weak accountability) are present per T3.
Capability: Low-Medium sophistication is institutional knowledge (how
  systems and processes work), not technical skill; no exploit development
  required, since the actor already holds legitimate access.
Primary Motivation: Revenge (termination-driven sabotage), financial gain
  (data theft for resale), or curiosity (VIP/celebrity record snooping)
  T1 Report D and T3 Scenario 4 both fit this actor type.
Preferred Vector: Abuse of legitimate access the shared PACS login, or
  the EHR's unrestricted export function.
Primary Target: ehr-db-01 (patient records via legitimate query/export
  access) and pacs-srv-01 (imaging, via the shared login).
MedDefense Exposure: GAP-001 (EHR reachable with no anomalous-access
  detection), GAP-010 (shared PACS login, no individual accountability),
  GAP-002 (no detection to catch any of it after the fact).
```

### Insider (Negligent)

```
Likelihood: High this is the dominant pattern across the 5 scenarios
  analyzed in T3, four of which were negligent rather than malicious.
Capability: Low no malicious tooling or intent; risk comes from
  convenience-driven shortcuts, not skill.
Primary Motivation: Solving a real work problem (workload backlog,
  clinical convenience) without understanding the risk created.
Preferred Vector: Shadow IT (unmanaged personal devices), plaintext
  credential storage, shared logins, and access left active after
  employment/contract ends.
Primary Target: Whatever system the negligent action happens to touch
  most commonly file-srv-01 (HR data), AD credentials, and PACS.
MedDefense Exposure: GAP-011 (shadow IT), GAP-016 (no change management),
  GAP-018 (no automated deprovisioning), GAP-010 (shared PACS login) the
  broadest gap footprint of any single actor type.
```

### Hacktivist

```
Likelihood: Low MedDefense has no political or controversial public
  profile (T0, Marcus's own annotation).
Capability: Low-Medium — SQL injection, DDoS and defacement rather than
  deep intrusion (T1 Report C).
Primary Motivation: Ideology / political-social activism.
Preferred Vector: Web application vulnerabilities against public-facing
  systems; DDoS against the patient portal.
Primary Target: web-srv-01 / Patient Portal the only symbolically public
  MedDefense asset, and one with a proven prior weakness (the IDOR incident
  documented in 1x00 Task 1, Incident B).
MedDefense Exposure: General web-application hardening gaps on the
  patient-facing portal; no dedicated Gap ID exists for this specifically,
  which is itself a minor gap in the 1x00 analysis.
```

### Unskilled / Opportunistic Attacker

```
Likelihood: High not hypothetical; this exact actor type has already
  compromised MedDefense twice (the January ransomware and the
  cryptominer, both via billing-srv-01, per 1x00 Task 1/2).
Capability: Low automated scanners sweeping the internet for known,
  unpatched CVEs; zero targeting or custom tooling involved (T0, T1
  Report E).
Primary Motivation: Opportunistic financial gain (cryptomining, credential
  resale) or simple availability of an easy target.
Preferred Vector: Exploitation of known, unpatched, internet-facing
  vulnerabilities specifically Apache 2.4.29 on billing-srv-01.
Primary Target: Any internet-facing unpatched service; billing-srv-01 has
  already demonstrated this twice, web-srv-01 is the next most likely.
MedDefense Exposure: GAP-008 (billing server weak coverage despite two
  prior compromises), GAP-005 (endpoint AV excludes all servers).
```

---

## Top 3 Priority Ranking

**1.** Ransomware Groups (Organized Crime) This actor combines Critical likelihood with the highest possible impact (simultaneous encryption of all Windows systems, exfiltration of the full patient database, and destruction of the only backup). It is the only actor type whose entire documented attack lifecycle maps step-for-step onto four currently-open MedDefense gaps (GAP-014, GAP-002, GAP-017, GAP-003), and it is the pattern that has already hit three peer hospitals within 200 miles in the past 8 months.

**2.** Unskilled / Opportunistic Attacker This is not a projection; it is MedDefense's own recent history. The exact same unpatched Apache instance on `billing-srv-01` has already been exploited twice by this actor type (ransomware, then a cryptominer), which means the barrier to a third incident is not "will an opportunistic scan find us" but "has the underlying gap (GAP-008) actually been closed yet."

**3.** Insider (Negligent) While no single negligent scenario is as catastrophic as a full ransomware event, this actor type has the broadest gap footprint of any category (four separate gaps across four different systems) and the highest likelihood after ransomware, because it does not require an external actor to do anything at all the risk is already inside the organization, spread across ordinary daily workflow.

---
