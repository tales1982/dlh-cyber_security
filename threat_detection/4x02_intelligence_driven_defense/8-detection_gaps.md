# Detection Gap Analysis — HEALTHBANE Campaign

**Scope note:** this analysis uses the detection inventory actually available
at the time of writing: `meddefense_4x00_findings.txt` (Wazuh rules
100080–100082), the 4x01 packet-based detection recommendations
(`7-detection_rules.sh`: C2 beaconing, DNS query-length anomaly, VPN
geo-anomaly, cross-role RDP, DNS-tunneling TXT-query pattern, TLS-to-
lookalike-domain), and this module's own `9-yara_phishing_pdf.yar`. Tasks 5
(indicator database) and 10 (email-header YARA rule) were not produced in
this batch, so their potential detection contributions are **not** reflected
below — this is itself a documented limitation of this gap analysis, not a
claim that no such detection could exist. If/when those tasks are produced,
this file should be re-run against the expanded inventory.

## 1. Technique-by-Technique Detection Assessment

| ATT&CK ID | Technique | Status (Task 7) | Detection Status | Evidence | Gap | Recommendation |
|---|---|---|---|---|---|---|
| T1589.002 | Gather Victim Identity: Email | OBSERVED | **NOT DETECTED** | No documented control covers pre-attack reconnaissance | This happens entirely outside MedDefense's visibility, on attacker-side infrastructure | Not directly closeable by MedDefense; only sector-level intelligence sharing (HC3) surfaces this after the fact |
| T1583.001 | Acquire Infrastructure: Domains | OBSERVED | PARTIALLY DETECTED | Wazuh 100080/100081 block/alert on *known* campaign domains | No detection of newly-registered lookalike domains *before* they appear in a threat feed | Deploy a passive-DNS/certificate-transparency watch for domains matching org-specific naming patterns (`meddefense-*`, `*-benefits`, `med*-supplies`) per the researcher's Section 7 defensive notes |
| T1585.002 | Establish Accounts: Email | OBSERVED | **NOT DETECTED** | No documented control | Attacker's own mailbox setup is outside MedDefense visibility | Not directly closeable; would require attacker-infrastructure-side intelligence (e.g., from the researcher's kit access) |
| T1587.001 | Develop Capabilities: Malware | OBSERVED | **NOT DETECTED** | No documented control | Malware development happens in attacker's environment, before delivery | Not directly closeable by MedDefense controls |
| T1608.005 | Stage Capabilities: Link Target | OBSERVED | PARTIALLY DETECTED | Only detected via the researcher's direct kit access (external, one-off); no MedDefense-side monitoring | MedDefense has no way to detect infrastructure staged but not yet active (e.g. `portal-secure-meddefense.com`) | Subscribe to the researcher's/HC3's ongoing monitoring; add staged domain to a watch-list even while inactive |
| T1566.002 | Spearphishing Link | OBSERVED | **DETECTED** | Wazuh 100080 (known-domain block) + `9-yara_phishing_pdf.yar` (structural PDF-lure pattern, survives domain rotation) | Layered coverage exists; residual gap is the window between a *new* domain's first use and its addition to the Wazuh CDB list | Automate CDB list updates from HC3 advisories; the YARA rule already mitigates this gap for the PDF-lure vector specifically |
| T1566.001 | Spearphishing Attachment | OBSERVED | PARTIALLY DETECTED | Wazuh 100081 could catch outbound traffic *after* macro execution reaches a known C2 domain | No control inspects the `.docm` attachment itself at delivery time | Deploy Task 10's planned email-header/attachment YARA rule (not yet produced) or mail-gateway macro-document sandboxing |
| T1204.001 | User Execution: Malicious Link | OBSERVED | PARTIALLY DETECTED | Domain block (100080) prevents delivery for *known* domains; no technical control stops the click itself for a new domain | Relies on user awareness for unknown domains; no click-time protection (e.g., time-of-click URL rewriting) | Deploy a time-of-click URL protection/rewriting service at the email gateway |
| T1204.002 | User Execution: Malicious File | OBSERVED | **NOT DETECTED** | No documented control for macro-enablement | HC3 recommends disabling Office macros by default; not confirmed deployed at MedDefense | Disable macros by default per HC3 5.3; require attestation for external macro-enabled documents |
| T1059.005 | VBA (macro execution) | OBSERVED | **NOT DETECTED** | No documented Wazuh/EDR rule for macro-triggered process execution | No endpoint telemetry rule covers Office spawning a child process | Deploy an EDR rule alerting on Office applications (WINWORD.EXE etc.) spawning child processes |
| T1059.001 | PowerShell | OBSERVED | PARTIALLY DETECTED | HC3 5.5 recommends hunting for base64-encoded PowerShell payloads >1024 chars — a manual hunt query, not an automated alert | Detection exists only as a documented hunting procedure, not an operationalized real-time rule | Convert HC3's hunting query into an automated Wazuh/EDR alert rule |
| T1053.005 | Scheduled Task | OBSERVED | **NOT DETECTED** | HC3 5.3 recommends alerting on scheduled tasks named "Sync"/"Update"/"Service" by non-admin users; not in MedDefense's deployed rule set (100080–82) | A specific, high-fidelity, ready-made detection recommendation exists but has not been deployed | Deploy HC3's recommended scheduled-task-naming alert as a new Wazuh rule |
| T1547.001 | Registry Run Keys | OBSERVED | **NOT DETECTED** | HC3 5.3 recommends alerting on Registry Run-key additions outside installer context; not deployed | Same pattern as T1053.005 — documented but not operationalized | Deploy HC3's recommended Registry Run-key alert as a new Wazuh rule |
| T1078 | Valid Accounts | INFERRED | PARTIALLY DETECTED | Wazuh 100082 alerts on dmarsh authentication from outside MedDefense networks | Rule is scoped to one specific account (dmarsh), not general credential-reuse detection across all accounts | Generalize 100082 into an org-wide impossible-travel/geo-anomaly authentication rule (HC3 5.4 recommends this generally) |
| T1036 | Masquerading | INFERRED | **NOT DETECTED** | No documented control inspects process-name-vs-hash or code-signing consistency | No signature/behavioral control for filename masquerading | Deploy EDR rule flagging unsigned binaries named after common system processes (svchost, etc.) not running from their expected system directory |
| T1056.003 | Web Portal Capture | OBSERVED | PARTIALLY DETECTED | Wazuh 100081 catches outbound HTTPS to *known* campaign domains at submission time | No detection for credential submission to an *unknown* new phishing domain | The YARA PDF rule (Task 9) provides upstream coverage for the lure itself; a browser-isolation or DLP control at form-submission time would close the remaining gap |
| T1021 | Remote Services | INFERRED | PARTIALLY DETECTED | 4x01's Cross-Role RDP detection rule directly covers RDP from clinical/end-user subnets to server subnets | Rule is RDP-specific; does not cover SMB, WinRM, or other remote-service protocols generally | Extend the cross-role detection logic to other remote-access protocols (SMB port 445, WinRM 5985/5986) |
| T1071.004 | Application Layer Protocol: DNS | OBSERVED | **DETECTED** | 4x01's DNS-tunneling TXT-query-pattern rule (>10 queries/120s to one domain, encoded labels) directly covers this | None significant — this is the best-covered technique in the whole mapping | Maintain and tune thresholds against the evolving baseline (Task 0, 4x01) |
| T1071.001 | Application Layer Protocol: Web Protocols | OBSERVED | PARTIALLY DETECTED | Wazuh 100081 (known domains) + 4x01's C2-beaconing frequency rule (regular-interval connections, domain-agnostic) | The beaconing rule catches ongoing C2 check-ins but not the one-time Stage 2 payload download itself | Add a rule for first-time outbound connection to a domain immediately followed by a large download, correlated with recent email attachment receipt |
| T1132.001 | Data Encoding: Standard Encoding | OBSERVED | PARTIALLY DETECTED | Implicitly covered by the DNS-tunneling rule's "encoded labels" trigger condition | No detection for base64/base32 encoding used over non-DNS channels (e.g., HTTP body) | Extend the DNS-tunneling detection concept to HTTP/HTTPS payload entropy analysis for other channels |
| T1048.003 | Exfiltration Over Alternative Protocol | OBSERVED | **DETECTED** | Same 4x01 DNS-tunneling rule | None significant | Maintain and validate against real traffic periodically |
| T1041 | Exfiltration Over C2 Channel | OBSERVED | **DETECTED** | Same 4x01 DNS-tunneling rule (the C2 and exfil channel are the same DNS tunnel in this campaign) | None significant | Maintain and validate |

## 2. Detection Status Summary

| Status | Count | Percentage |
|---|---|---|
| DETECTED | 4 | 18% |
| PARTIALLY DETECTED | 10 | 46% |
| NOT DETECTED | 8 | 36% |
| **Total** | **22** | **100%** |

## 3. Prioritized Gap List

### Priority 1 — OBSERVED and NOT DETECTED (7 techniques)

These are confirmed adversary behaviors in this campaign with **zero**
documented detection coverage at MedDefense:

1. **T1204.002 (User Execution: Malicious File)**
   - *Why it matters:* This is the exact step that turns a stolen credential
     into a running executable — the Stage 1→2 pivot point.
   - *Detection idea:* Disable Office macros by default (HC3 5.3); require
     attestation for macro-enabled documents from external senders.
   - *Required data source:* Group Policy / mail-gateway attachment
     handling configuration.
   - *Suggested owner:* IT/endpoint management team.

2. **T1059.005 (VBA macro execution)**
   - *Why it matters:* Direct precursor to the dropped executable; catching
     this stops Stage 2 before persistence is established.
   - *Detection idea:* EDR rule alerting on Office applications spawning
     child processes.
   - *Required data source:* EDR process-tree telemetry (not currently
     documented as collected).
   - *Suggested owner:* SOC/detection engineering.

3. **T1053.005 (Scheduled Task)**
   - *Why it matters:* HC3 already published the exact detection logic
     needed ("Sync"/"Update"/"Service" named tasks by non-admins); this is
     the lowest-effort, highest-confidence gap to close in this entire list.
   - *Detection idea:* Deploy HC3's recommended Wazuh rule directly.
   - *Required data source:* Windows Task Scheduler event log (Event ID
     4698).
   - *Suggested owner:* SOC (rule authoring is largely done — HC3 wrote it).

4. **T1547.001 (Registry Run Keys)**
   - *Why it matters:* Same "already documented, not yet deployed" pattern
     as T1053.005 — a quick win.
   - *Detection idea:* Deploy HC3's recommended Registry Run-key alert.
   - *Required data source:* Sysmon Event ID 13 (Registry value set) or
     equivalent EDR telemetry.
   - *Suggested owner:* SOC.

5. **T1589.002 (Gather Victim Identity: Email)** / 6. **T1585.002
   (Establish Accounts: Email)** / 7. **T1587.001 (Develop Capabilities:
   Malware)**
   - *Why they matter:* All three occur entirely on attacker-side
     infrastructure before any MedDefense-visible event.
   - *Detection idea:* Not directly detectable by MedDefense; the only
     lever is earlier sector-level intelligence sharing (HC3 reporting
     channel) to shorten the window between campaign start and MedDefense
     awareness.
   - *Required data source:* External threat intelligence (already the
     subject of this whole project).
   - *Suggested owner:* Threat intel function / HC3 liaison (James Chen).

### Priority 2 — INFERRED and NOT DETECTED (1 technique)

1. **T1036 (Masquerading)**
   - *Why it matters:* If confirmed, this would explain how
     `svchost_update.exe` evades casual process-list review; currently only
     a filename-pattern hypothesis.
   - *Detection idea:* EDR rule flagging unsigned binaries named after
     common system processes but not running from their expected system
     directory (e.g., `svchost*.exe` outside `C:\Windows\System32`).
   - *Required data source:* EDR file-path + code-signing telemetry.
   - *Suggested owner:* SOC/detection engineering — lower priority than
     Priority 1 precisely because the underlying technique is unconfirmed;
     building a rule for it is a reasonable hunting hypothesis, not an
     urgent gap closure.

### Priority 3 — Partially Detected (10 techniques)

Full detail in Section 1's table; the three most impactful upgrades:

1. **T1078 (Valid Accounts):** generalize Wazuh 100082 from a
   single-account (dmarsh) rule into an org-wide anomalous-geography
   authentication rule — directly actionable, HC3 5.4 already recommends
   this pattern generally.
2. **T1059.001 (PowerShell):** convert HC3's documented base64-payload
   hunting query into an automated alert rather than a manual procedure.
3. **T1071.001 / T1132.001:** extend the 4x01 DNS-tunneling detection
   concept (rate + encoding pattern) to other protocols, since the
   technique itself (encoded-payload smuggling) is not DNS-specific even
   though this campaign happened to use DNS.

## 4. Closing Note

The strongest existing coverage in this campaign is, notably, at the very
end of the kill chain (DNS exfiltration, 3 of 4 fully-DETECTED techniques)
rather than the beginning — a consequence of 4x01's network-forensics work
producing genuinely tested, evidence-grounded detection logic for that
stage. The weakest coverage is squarely in Stage 2 (macro execution,
scheduled task, registry persistence) — three of the seven Priority 1 gaps
are Stage 2 techniques for which HC3 has *already published* ready-to-deploy
detection logic that MedDefense has not yet operationalized. Closing those
three specific gaps is the highest-leverage, lowest-effort action available
from this entire analysis.
