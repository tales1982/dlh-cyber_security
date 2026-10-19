# Containment Decision: IR-2026-0414-01

Decision owner: Tales Lima, on-call SOC
Approving authority: James Chen, IR Commander (authority ceiling SEV2; incident is SEV2 at decision time)
Asset: WST-WS-031 (10.42.118.31), clinical workstation with LIS and Epic access, West Campus Laboratory
Known at decision time (03:06Z): MSBuild.exe PID 8104 runs an in-memory payload with live C2 to 185.220.101.47:443 (Tor exit); persistence via Run key WindowsUpdateSvc and scheduled task {7B4F2D81-…}; dmarsh M365 credentials used from 45.63.9.88 (RU) on 2026-04-13T18:14:41Z. Not known: any other host involved, any ePHI access.
Assumption (to confirm with the lab supervisor): the lab has a spare workstation so Daniel Marsh's shift can continue.

## Candidate strategies

### A. Network isolation (quarantine VLAN)

- action: move WST-WS-031 switchport to quarantine VLAN 999 (deny all except IR jumpbox soc-jump01 and EDR manager), perimeter deny for 185.220.101.47, EDR device containment flag
- attacker effect: C2 severed at the network layer; attacker loses hands-on access and lateral paths from this host; implant stays dormant, not killed
- evidence effect: volatile state preserved (memory, processes, injected region in PID 8104 stay intact for a second acquisition if needed); disk untouched
- patient care effect: one lab workstation unavailable; technician moves to a spare workstation; LIS/Epic services unaffected
- time to execute: ~5 min (NAC/switch change + firewall rule + EDR flag)
- reversibility: fully reversible (VLAN reassignment back in < 5 min)

### B. Host power-off

- action: hard power-off WST-WS-031
- attacker effect: C2 and in-memory implant stop immediately; persistence (Run key + scheduled task) relaunches update.exe at the next logon
- evidence effect: destroys all volatile evidence: injected MZ region, C2 config, LSASS ticket cache, live sockets; only disk survives; memory acquisition (Task 2 step 1) becomes impossible to repeat
- patient care effect: same single-workstation loss as A; risk of losing unsaved LIS work in progress
- time to execute: < 1 min
- reversibility: not reversible for evidence; host must stay off until rebuilt

### C. Selective process termination + firewall egress block

- action: kill PIDs 8104 (MSBuild) and 7812 (powershell), 7204 (update.exe) from EDR; perimeter deny for 185.220.101.47
- attacker effect: current implant and C2 stop, but host stays on the production network; any process or credential material not seen (fallback C2, stolen Kerberos tickets) keeps working; scheduled task re-launches at next logon
- evidence effect: kills the memory-resident payload (loss of process memory); netstat and process state change
- patient care effect: lowest; workstation stays usable (but a compromised host keeps processing lab data)
- time to execute: ~3 min
- reversibility: block reversible; process kill not reversible

### D. Account containment (companion, not standalone)

- action: reset dmarsh AD password (force change), revoke Azure AD sessions/refresh tokens (Revoke-MgUserSignInSession), per PB-CRED-001 ("reset immediately if the account has Epic access to ePHI")
- attacker effect: cuts reuse of the stolen password and cloud sessions; does NOT invalidate Kerberos TGT/TGS already issued (TGT from 2026-04-14T02:44:02Z valid 10 h)
- evidence effect: none on host; auth logs already preserved (Task 2 step 8, PB before_step satisfied)
- patient care effect: Daniel Marsh locked out until helpdesk reissues password and MFA re-enrolment
- time to execute: ~2 min
- reversibility: reversible by helpdesk

## Chosen: A + D

Rationale: Option A severs the C2 channel immediately while keeping the injected payload in PID 8104 and the rest of the volatile state intact for forensics, stays fully reversible, and limits clinical impact to a single workstation with a spare available. Option B ends the threat fastest but destroys exactly the evidence Task 2 was ordered to protect, and persistence would relaunch the implant at next logon anyway. Option C keeps a compromised host on the clinical network, depends on us having seen every malicious process, and leaves persistence and credential material in place. D is added because PB-CRED-001 mandates immediate reset for an account with ePHI access. Its known gap is that Kerberos tickets already issued survive a password reset, so DC logs for dmarsh TGS requests stay under watch after containment.

## Execution window

- Evidence preservation end: 2026-04-14T03:20:40Z (Task 2 verification passed)
- Lab supervisor notified, technician moved to spare workstation: 03:21:10Z
- Containment execution start: 2026-04-14T03:24:10Z
- Gap: 3 min 30 s. Accepted risk: C2 stays live from 02:47:02Z until isolation (~37 min) to preserve volatile evidence; no ePHI access was visible when this was accepted.

## Approval

- Action authorized by James Chen, IR Commander, at 2026-04-14T03:12:40Z (SEV2, within his authority ceiling)

## Rollback plan

- Trigger: lab operations blocked (no spare workstation, LIS result entry stopped) or isolation breaks a clinical dependency.
- Steps: (1) revert switchport of WST-WS-031 to the production VLAN within 5 min; (2) keep the perimeter deny for 185.220.101.47 and the phishing-domain block; (3) fall back to Option C (kill PIDs 8104/7812/7204, disable scheduled task {7B4F2D81-…} and Run value WindowsUpdateSvc); (4) log the rollback as DECISION + ACTION entries.
- Rollback of D: helpdesk issues temporary password after identity check by phone; MFA re-enrolment required.
- Approval for rollback: James Chen (IR Commander); if rollback is driven by patient-care impact, inform Patricia Morales (CISO, Executive Sponsor).
