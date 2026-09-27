# ATT&CK Navigator Mapping — HEALTHBANE Campaign

MITRE ATT&CK v15, Enterprise domain. Two-tier classification:

- **OBSERVED** — direct evidence exists in at least one source (a formal
  technique table, a described mechanism with cited evidence such as a
  packet capture or extracted config file, or a directly-named artifact).
- **INFERRED** — a reasonable analytical hypothesis given the observed
  behavior, but not directly evidenced by any source in this package — either
  because a source explicitly flags it as likely-but-unconfirmed, or because
  this analysis adds it based on a named artifact pattern without direct
  behavioral confirmation.

19 OBSERVED, 3 INFERRED — 22 techniques total. See Section 3 for the summary.

## 1. Techniques by Tactic

### Reconnaissance

| Technique | Name | Status | Evidence/Reasoning | Source | Phase |
|---|---|---|---|---|---|
| T1589.002 | Gather Victim Identity: Email | OBSERVED | Attacker possessed target employee email addresses across ≥14 healthcare orgs to phish; a prerequisite the spearphishing operation directly evidences | HC3 | Pre-Stage 1 |

### Resource Development

| Technique | Name | Status | Evidence/Reasoning | Source | Phase |
|---|---|---|---|---|---|
| T1583.001 | Acquire Infrastructure: Domains | OBSERVED | Namecheap-registered lookalike domains (4-10 days pre-use) plus Njalla-registered operator domains; exact registration dates confirmed for 3 domains | HC3, MedDefense, Researcher | Pre-Stage 1 |
| T1585.002 | Establish Accounts: Email | OBSERVED | Attacker-controlled mailbox referenced directly in kit config.php (`ops@healthbane-c2.net`) | HC3, Researcher | Pre-Stage 1 |
| T1587.001 | Develop Capabilities: Malware | OBSERVED | Stage 2 executable (svchost_update.exe) and PowerShell exfiltrator (sync_healthdata.ps1) both attributed to this operator's toolset | HC3, Researcher | Pre-Stage 2 |
| T1608.005 | Stage Capabilities: Link Target | OBSERVED | Kit staged on `portal-secure-meddefense.com` ahead of activation, confirmed via direct researcher access to the staged instance | HC3, MedDefense, Researcher | Pre-Stage 1 |

### Initial Access

| Technique | Name | Status | Evidence/Reasoning | Source | Phase |
|---|---|---|---|---|---|
| T1566.002 | Phishing: Spearphishing Link | OBSERVED | Primary Stage 1 vector at all 6 HC3-visible orgs and at MedDefense (E2/E5/E7) | HC3, MedDefense, Researcher | Stage 1 |
| T1566.001 | Phishing: Spearphishing Attachment | OBSERVED | Stage 2 `.docm` macro document sent from a compromised account | HC3 | Stage 2 |

### Execution

| Technique | Name | Status | Evidence/Reasoning | Source | Phase |
|---|---|---|---|---|---|
| T1204.001 | User Execution: Malicious Link | OBSERVED | dmarsh directly clicked the Stage 1 link (2026-04-14 15:02:33) | HC3, MedDefense | Stage 1 |
| T1204.002 | User Execution: Malicious File | OBSERVED | Macro-enabled `.docm` required user action to enable content | HC3 | Stage 2 |
| T1059.005 | Command and Scripting Interpreter: Visual Basic | OBSERVED | Macro in HEALTHBANE_S2_invoice.docm drops the Stage 2 executable | HC3 | Stage 2 |
| T1059.001 | Command and Scripting Interpreter: PowerShell | OBSERVED | sync_healthdata.ps1 extracted directly from the kit's tools/ directory by the researcher | HC3, Researcher | Stage 2/3 |

### Persistence

| Technique | Name | Status | Evidence/Reasoning | Source | Phase |
|---|---|---|---|---|---|
| T1053.005 | Scheduled Task/Job: Scheduled Task | OBSERVED | Named task "HealthSync Update Service" | HC3 | Stage 2 |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | OBSERVED | Registry Run-key addition confirmed alongside the scheduled task | HC3 | Stage 2 |
| T1078 | Valid Accounts | **INFERRED** | HC3's own advisory states this is "assessed as LIKELY" (Stage 1 credentials reused to authenticate to victim cloud email accounts for Stage 2 delivery) but explicitly **excludes it from the formal OBSERVED table pending confirmation** — this analysis preserves that distinction rather than upgrading it | HC3 (explicit LIKELY, not OBSERVED) | Stage 2 |

### Defense Evasion

| Technique | Name | Status | Evidence/Reasoning | Source | Phase |
|---|---|---|---|---|---|
| T1036 | Masquerading | **INFERRED** | The dropped executable is named `svchost_update.exe`, mimicking the legitimate Windows `svchost.exe` process naming convention — a plausible evasion choice, but no source in this package confirms process-tree, parent-image, or code-signing evidence to verify masquerading was actually attempted rather than just a coincidental/generic filename | Analyst inference from HC3/commercial-feed filename evidence | Stage 2 |

### Credential Access

| Technique | Name | Status | Evidence/Reasoning | Source | Phase |
|---|---|---|---|---|---|
| T1056.003 | Input Capture: Web Portal Capture | OBSERVED | HTML form POST credential capture confirmed via kit's `handlers/post.php`; MedDefense's SIEM shows a 47-second HTTPS session consistent with form submission | HC3, MedDefense | Stage 1 |

### Lateral Movement

| Technique | Name | Status | Evidence/Reasoning | Source | Phase |
|---|---|---|---|---|---|
| T1021 | Remote Services | **INFERRED** | Same HC3 caveat as T1078: assessed LIKELY by HC3 but explicitly excluded from the formal OBSERVED table pending confirmation. No source specifies which remote-service protocol (RDP, SMB, etc.) would be involved | HC3 (explicit LIKELY, not OBSERVED) | Stage 2/3 (unconfirmed) |

### Command and Control

| Technique | Name | Status | Evidence/Reasoning | Source | Phase |
|---|---|---|---|---|---|
| T1071.004 | Application Layer Protocol: DNS | OBSERVED | Stage 3 C2/exfil channel via DNS TXT queries to data-sync.healthbane-c2.net, confirmed via packet capture at 2 orgs | HC3 | Stage 3 |
| T1071.001 | Application Layer Protocol: Web Protocols | OBSERVED | Stage 2 payload download over HTTPS from healthbane-c2.net | HC3 | Stage 2 |
| T1132.001 | Data Encoding: Standard Encoding | OBSERVED | Base32-encoded query labels and base64-encoded TXT response command strings, directly described in HC3's Stage 3 narrative with packet-capture-based HIGH confidence — present in HC3's prose but **not included in HC3's own formatted technique table**, added here from a close reading of their Section 1.3/3 narrative rather than copied from their table | HC3 (narrative, not table) | Stage 3 |

### Exfiltration

| Technique | Name | Status | Evidence/Reasoning | Source | Phase |
|---|---|---|---|---|---|
| T1048.003 | Exfiltration Over Alternative Protocol: Non-C2 Protocol | OBSERVED | DNS tunneling as the exfiltration channel, per HC3's formal table | HC3 | Stage 3 |
| T1041 | Exfiltration Over C2 Channel | OBSERVED | The same DNS channel also carries C2 command responses, per HC3's formal table | HC3 | Stage 3 |

## 2. Data-Quality Note

MedDefense's own 4x00 report states "7 OBSERVED techniques" in its ATT&CK
section but lists exactly 6 technique rows. This mapping uses the 6
enumerable techniques MedDefense actually lists (all cross-confirmed by HC3
independently) rather than inventing a plausible 7th to make the stated
count match — consistent with this project's evidence-based standard: report
what the source actually enumerates, flag the count discrepancy, do not
silently correct or pad it.

## 3. Summary

- **Total techniques identified:** 22
- **Observed vs. inferred ratio:** 19 OBSERVED : 3 INFERRED (≈86% : 14%)
- **Tactics with most coverage:** Resource Development and Execution (4
  techniques each)
- **Tactics with least coverage:** Reconnaissance, Defense Evasion,
  Credential Access, and Lateral Movement (1 technique each) — Discovery,
  Privilege Escalation, Collection, and Impact have **zero** mapped
  techniques, which is itself a notable finding: no source in this package
  provides any evidence of adversary discovery/enumeration activity,
  privilege escalation, or a distinct collection step separate from the
  credential-capture and exfiltration mechanisms already mapped. This is
  either a genuine gap in attacker tradecraft visibility (most likely, given
  how narrow HC3's own visibility already is — see `6-kill_chain.md`
  Section 4) or a real absence of those behaviors in a campaign that may not
  need them (a single-hop DNS-tunnel exfiltration path doesn't require
  extensive internal discovery).
- **Techniques most important for detection planning:**
  1. **T1566.002** (Spearphishing Link) — the universal chokepoint; 100% of
     visible organizations were hit here, making it the highest-leverage
     single detection/prevention point in the entire chain.
  2. **T1078** (Valid Accounts, INFERRED) — important precisely *because*
     it is a detection gap: HC3 itself could not confirm it, meaning
     organizations likely have little to no visibility into
     credential-reuse-based follow-on access, yet it is the pivot that
     turns a single phishing click into Stage 2 malware delivery.
  3. **T1053.005 / T1547.001** (Scheduled Task / Registry Run Key) — high
     fidelity, low false-positive persistence indicators; the specific
     named artifact ("HealthSync Update Service") is a strong, narrow
     detection signature.
  4. **T1071.004 / T1132.001** (DNS C2 / Standard Encoding) — this is the
     actual data-loss chokepoint (Stage 3); detecting the DNS tunneling
     pattern (query rate, label length, character set) is the last
     opportunity to prevent data loss even if every earlier stage is missed.

See `healthbane_layer.json` for the machine-readable ATT&CK Navigator layer
built from this table.
