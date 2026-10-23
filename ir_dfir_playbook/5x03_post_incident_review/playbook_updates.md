# Playbook Updates: IR-2026-0414-01

- **Case:** LH-2026-0414-01
- **Playbook changed:** `playbook_credential_exposure.yaml` (PB-001, "Credential Exposure via Phishing with Foreign Sign-In", `ir_dfir_playbook/5x00_incident_response/`)
- **Inputs:** `gap_analysis.md` (Gap IDs), `control_effectiveness.yaml`, `forensic_findings_summary.md`
- **Owner of the update:** IR Commander (James Chen); review by Technical Lead (Robert Kim) and Legal (Helena Reyes) for PB-UPD-004
- **Effective:** after approval at the PIR close-out; playbook version bumped to PB-001 v2

| Change | Section | Gap closed | Summary |
|---|---|---|---|
| PB-UPD-001 | applies_to.triggers | GAP-004, GAP-005, GAP-001 | VPN new-geography / impossible travel as an independent trigger |
| PB-UPD-002 | containment_actions (new scope_expansion block) | GAP-013, GAP-014 | Scope expansion checklist when lateral movement / Pass-the-Ticket is detected |
| PB-UPD-003 | containment_actions + eradication_actions | GAP-015, GAP-011 | Mandatory krbtgt double reset for confirmed Pass-the-Ticket |
| PB-UPD-004 | severity_mapping + new decision node hipaa_assessment | GAP-014 | HIPAA four-factor assessment when ePHI systems are in the blast radius |
| PB-UPD-005 | evidence_preservation + containment_actions | GAP-008, GAP-006 | Host-level persistence and LOLBin check before closing a credential case |

---

### Change PB-UPD-001

**Playbook:** playbook_credential_exposure.yaml
**Section:** applies_to.triggers
**Gap closed:** GAP-004, GAP-005, GAP-001
**Finding reference:** control_effectiveness.yaml phase 2 (VPN access using stolen credentials from a foreign IP); forensic_findings_summary.md open item 2 (Azure AD risk signal suppressed by the "compliant device" rule)

**Before:**
```yaml
triggers:
  - Azure AD Identity Protection alert for sign-in from an unfamiliar foreign IP
  - Azure AD impossible travel alert on a MedDefense user account
  - User reports entering credentials on a fake Microsoft login page
  - Email gateway click alert on a known credential-harvesting URL
```

**After:**
```yaml
triggers:
  - Azure AD Identity Protection alert for sign-in from an unfamiliar foreign IP
  - Azure AD impossible travel alert on a MedDefense user account
  - Azure AD risk detection on a MedDefense account even if a Conditional Access exclusion (e.g. compliant device) let the sign-in succeed
  - VPN authentication from a country not seen for this account in the prior 30 days (SIEM rule vpn_geo_baseline / CA-VPN-02)
  - VPN authentication blocked by CA-VPN-01 (non-approved country) for a valid username and password
  - Impossible travel across sources - two successful logins (VPN, Azure AD, OWA) for the same account from geographically inconsistent IPs within 2 hours
  - VPN logon from an IP that already appears in an Azure AD risky sign-in for the same account in the last 24 hours
  - User reports entering credentials on a fake Microsoft login page
  - Email gateway click alert on a known credential-harvesting URL
  - Proxy log shows a POST / form submission to a newly registered domain imitating Microsoft 365
```

**Reason:** The attacker used dmarsh's phished credentials from 45.63.9.88 (RU) at 18:14:41Z and again for VPN at 02:44:17Z. The Azure AD signal was suppressed and the VPN logon matched no existing trigger, because the playbook only listed Azure AD alerts and user reports. The intrusion ran for over eight hours with no playbook activation. VPN geography now triggers PB-001 on its own, even when no Azure AD alert exists.

---

### Change PB-UPD-002

**Playbook:** playbook_credential_exposure.yaml
**Section:** containment_actions (new block `scope_expansion`, inserted after the VPN/Epic containment steps) and escalation_triggers
**Gap closed:** GAP-013, GAP-014
**Finding reference:** ART-003-M01 (MSBuild on WST-WS-017 launched via Kerberos logon from WST-WS-031); AD-LOG-01 (14 PDF reads on LIS-WSIDE-01); 5x01 incident_timeline 03:34:12Z (lateral move happened between preservation end and isolation; single-host assumption invalidated)

**Before:**
```yaml
containment_actions:
  - step: Keep the attacker session open up to 15 minutes under monitoring, or reset immediately
  ...
  - step: Block the attacker IP and the phishing URL at the firewall, proxy, and email gateway
# no step for new hosts discovered during containment
escalation_triggers:
  - Same attacker IP or phishing URL found on additional MedDefense accounts
```

**After:**
```yaml
scope_expansion:
  trigger:
    - Kerberos TGS for cifs/host/HTTP SPN requested by the compromised account from a host where it has no interactive session (DC Event 4769 without 4624 type 2/10)
    - DC flag second_request_with_ticket_reuse, or the same ticket seen from two source IPs
    - Network logon (4624 type 3) by the compromised account on a new host, remote service creation (7045) or ADMIN$ access
    - New C2 destination or LOLBin (MSBuild, csc, InstallUtil) alert on any host other than the first one
  owner: Technical_Lead
  timebox_minutes: 15 per new host
  checklist:
    - "[ ] Query all DCs for every TGS_REQ / 4769 and 4624 of the compromised account since the first malicious activity; list every target host and SPN"
    - "[ ] For each new host: capture memory (winpmem) and process/network state BEFORE isolation, hash into the evidence store"
    - "[ ] Isolate each new host (quarantine VLAN 999 + EDR containment); do not wait for the full scope list to isolate the first new host"
    - "[ ] Block every new C2 IP/domain found on the new host at perimeter and proxy (e.g. 91.234.99.107)"
    - "[ ] Identify whether the new host stores or serves ePHI (LIS, Epic, file shares); if yes run decision node hipaa_assessment (PB-UPD-004) and escalate to SEV1"
    - "[ ] Treat credentials of every account logged on to a new host as exposed; add them to the reset list"
    - "[ ] Run the krbtgt decision (PB-UPD-003) if Pass-the-Ticket is confirmed"
    - "[ ] Repeat the checklist from the newest host until no new host appears in the auth logs for 60 minutes"
    - "[ ] Notify IR Commander and Executive Sponsor on each scope expansion (ir_team_structure on_scope_expansion)"
  trade_off: Pre-isolation memory capture costs about 10 minutes per host; skipping it loses the in-memory implant evidence (ART-003 was only possible because WST-WS-017 was captured before isolation)
escalation_triggers:
  - Same attacker IP or phishing URL found on additional MedDefense accounts
  - Compromised account used to log on to any host other than the user's own workstation (lateral movement) -> SEV1
```

**Reason:** Containment in this incident assumed a single host (decision at 03:06:10Z). The lateral move to WST-WS-017 at 03:22:47Z and then LIS-WSIDE-01 at 03:42:08Z was found only at 03:34:12Z and 03:44:20Z through an ad-hoc auth query. There was no structured step to hunt, preserve, isolate and escalate per new host. The checklist makes scope expansion repeatable and time-boxed.

---

### Change PB-UPD-003

**Playbook:** playbook_credential_exposure.yaml
**Section:** containment_actions ("Reset the Active Directory password and force change at next logon") and eradication_actions
**Gap closed:** GAP-015, GAP-011
**Finding reference:** ART-002-M04 (NTLM hash material for dmarsh in lsass); ART-003-M01 and AD-LOG-01 (dmarsh Kerberos ticket reused to reach LIS-WSIDE-01, T1550.003); 5x01 containment_execution 03:30:20Z ("existing Kerberos tickets remain valid until expiry")

**Before:**
```yaml
  - step: Reset the Active Directory password and force change at next logon
    owner: Technical_Lead
    decision_point: Not applicable
    trade_off: Cuts attacker access to on-premises resources; the user is locked out until helpdesk issues a new password
```

**After:**
```yaml
  - step: Reset the Active Directory password and force change at next logon
    owner: Technical_Lead
    decision_point: Not applicable
    trade_off: Cuts new password-based logons only; Kerberos tickets already issued stay valid until expiry (default TGT 10 h, renewable 7 days)
  - step: Invalidate Kerberos tickets of the compromised account
    owner: Technical_Lead
    actions:
      - Add the account to the "Protected Users" group (no NTLM, no DES/RC4, TGT lifetime 4 h, no delegation)
      - Run klist purge for the account on every host in the scope_expansion list
      - Disable and re-enable the account to force KDC re-validation on TGS renewal
    decision_point: Not applicable
  - step: krbtgt double reset - MANDATORY when Pass-the-Ticket, Golden/Silver Ticket, or lsass credential access on any host is confirmed
    owner: Technical_Lead
    approval: Executive_Sponsor (CISO) - SEV1 authority
    actions:
      - Confirm AD replication is healthy on all DCs (repadmin /replsummary shows 0 failures)
      - Reset krbtgt password #1 with Microsoft New-KrbtgtKeys.ps1 (mode: reset), force replication (repadmin /syncall /AdeP)
      - Wait at least the maximum TGT lifetime (10 hours, per Default Domain Policy "Maximum lifetime for user ticket") plus 15 minutes of clock skew
      - Reset krbtgt password #2 and force replication again
      - Record both reset times and the msDS-KeyVersionNumber of krbtgt before and after in the incident timeline
    decision_point: Do not perform the two resets back to back - it breaks every Kerberos session in the domain at once (clinical applications, Epic, LIS service accounts). Warn the clinical on-call before reset #2.
    trade_off: Forged and stolen tickets signed with the old krbtgt key stop working; some services may need restart and users may need to log on again
eradication_actions:
  - ...
  - Verify krbtgt msDS-KeyVersionNumber increased by 2 and both resets replicated to every DC
  - Hunt DC logs for TGS requests with RC4 encryption (0x17) or tickets with lifetime above policy after reset #2 (forged ticket indicator)
```

**Reason:** The playbook said "reset compromised account password", and the team did that at 03:30:20Z. The stolen dmarsh tickets still worked, and the attacker reached LIS-WSIDE-01 12 minutes later. A password reset does not invalidate tickets already issued. Only purging and expiring the tickets, plus a krbtgt double reset when ticket theft or forgery is possible, removes Kerberos material from the attacker. The 10-hour wait is required because a single reset leaves the previous key valid in the krbtgt password history.

---

### Change PB-UPD-004

**Playbook:** playbook_credential_exposure.yaml
**Section:** severity_mapping.escalate_if, communication_plan (Legal_Liaison) and new decision node `hipaa_assessment`
**Gap closed:** GAP-014
**Finding reference:** AD-LOG-01 (14 patient lab report PDFs read on LIS-WSIDE-01, share LIS_REPORTS$, 03:43:30Z); forensic_findings_summary.md scope ("data access is confirmed, data transfer is not") and open item 3 (DLP review pending)

**Before:**
```yaml
severity_mapping:
  escalate_if:
    - ePHI confirmed accessed or exported during the exposure window -> SEV1
communication_plan:
  - audience: Legal_Liaison (General Counsel)
    trigger: As soon as the account is confirmed to have Epic or file share access to ePHI (HIPAA assessment trigger - was ePHI accessible from the compromised account during the exposure window?)
# no branch for clinical systems (LIS, Epic servers) in the blast radius, no assessment method
```

**After:**
```yaml
severity_mapping:
  escalate_if:
    - ePHI confirmed accessed or exported during the exposure window -> SEV1
    - Any host in the blast radius stores or serves ePHI (LIS, Epic, PACS, clinical file shares such as LIS_REPORTS$) -> SEV1 and run hipaa_assessment
hipaa_assessment:
  type: decision_node
  trigger: An ePHI system is in the blast radius (scope_expansion checklist item) or ePHI access appears in any audit log
  owner: Legal_Liaison (Helena Reyes), with Technical_Lead providing evidence and Privacy Officer
  timebox: Start within 24 hours of trigger; decision documented before day 30; individual notification no later than 60 days after discovery (45 CFR 164.404)
  presumption: Any impermissible access to ePHI is a breach unless the four-factor assessment shows a low probability of compromise (45 CFR 164.402)
  factors:
    - factor_1: Nature and extent of the PHI involved - types of identifiers, sensitivity (e.g. lab results, microbiology), likelihood of re-identification; list each file and patient count (here 14 lab report PDFs)
    - factor_2: The unauthorized person who used or accessed the PHI - external threat actor with Cobalt Strike C2 infrastructure vs. internal workforce member
    - factor_3: Whether the PHI was actually acquired or viewed - file read audit (4663), SMB copy to staging, egress volume to C2, DLP logs; record "accessed, transfer not shown" vs "exfiltrated"
    - factor_4: Extent to which the risk has been mitigated - containment time, C2 blocked, no evidence of publication, assurances obtained
  outcomes:
    - low_probability_of_compromise: Document the four-factor analysis and evidence, retain 6 years, no notification
    - breach: Notify affected individuals (<= 60 days), HHS (within 60 days if >= 500 individuals, else annual log within 60 days of year end), media if > 500 residents of a state; involve Communications (Marcus Webb)
  evidence_required:
    - File access audit export from the ePHI system (Event 4663, share and path list) hashed into the evidence store
    - Proxy/firewall egress volumes from every host that touched the ePHI to every C2 IP for the exposure window
    - DLP review result (open item 3 in this case)
communication_plan:
  - audience: Legal_Liaison (General Counsel)
    trigger: Immediately (within 1 hour) when an ePHI system enters the blast radius - not only when the account has access - with the hipaa_assessment evidence pack
```

**Reason:** The attacker read 14 patient lab report PDFs on LIS-WSIDE-01. The old playbook only had a SEV1 escalation line and a vague "was ePHI accessible?" question. It had no branch for a clinical system being in the blast radius and no method for the breach decision. The four-factor assessment is the HIPAA standard for deciding whether notification is required. Making it a decision node with an owner, evidence and deadlines keeps the 60-day notification clock from running without a documented decision.

---

### Change PB-UPD-005

**Playbook:** playbook_credential_exposure.yaml
**Section:** evidence_preservation and containment_actions
**Gap closed:** GAP-008, GAP-006
**Finding reference:** ART-001-R01 (Run key WindowsUpdateSvc), ART-001-R02 (scheduled task {7B4F2D81-...}), ART-001-F01 / F02 (update.xml, update.exe in Temp), ART-002-M03 (in-memory implant)

**Before:**
```yaml
evidence_preservation:
  - artifact: Authentication logs (domain controllers, VPN, Epic login audit) for the user
  ...
# credential playbook covers cloud/account artifacts only; no endpoint check on the user's workstation
```

**After:**
```yaml
evidence_preservation:
  - artifact: Memory and persistence state of the user's workstation
    method: winpmem memory image, autoruns (Run keys, scheduled tasks, services) export, list of executables in %LOCALAPPDATA%\Temp and Downloads, all hashed into the evidence store
    before_step: Workstation isolation
containment_actions:
  - step: Check the user's workstation for payload and LOLBin activity (EDR query for MSBuild/csc/InstallUtil child of powershell, Sigma rules R1/R2 in the SIEM for the exposure window)
    owner: Technical_Lead
    decision_point: If any hit - treat as malware + credential incident, isolate the workstation and follow scope_expansion
```

**Reason:** This case started as a credential exposure but also dropped a payload with two persistence mechanisms and an MSBuild implant. The credential playbook only looked at cloud and account artifacts, so the workstation had to be investigated ad hoc. The new steps make sure the endpoint is checked every time PB-001 runs.
