# Containment Decision: IR-2026-0420-01

- Decision owner: Tales Lima, on-call IR. Approving authority: Patricia Morales, CISO (SEV1, above the IR Commander ceiling of SEV2). Decision presented 20:16Z, approved 20:18Z.
- Assets: CS-WS-101, CS-WS-104, CS-WS-107, CS-WS-112 (active Cobalt Strike beacon `svchost32.exe` to `staging.office365-cdn.net` / 45.152.66.114), SCHED-SVR-01 (attacker process since 18:02Z, disk saturated), FILE-SVR-01 (no beacon since 2026-04-19T02:41Z, holds the PHI access record).
- Known at decision time: service WinHealthSvc on every host; `encryption_staging.ps1` dropped in `C:\Windows\System32` on the four workstations at 14:23-14:26Z, not executed; C2 check-ins every ~60 s; one shared account (MEDDEFENSE\jdoe) behind the activity. Not known: whether SCHED-SVR-01 is encrypting, whether other hosts are involved.

## Candidate strategies

| | A. Coordinated isolation in one window | B. Rolling isolation, host by host | C. Power off all affected hosts |
|---|---|---|---|
| Action | Perimeter deny for 45.152.66.114 + proxy/DNS sinkhole of the squatted domain, then EDR network containment of all six hosts within 5 min (FILE-SVR-01: host firewall restricted, not fully cut), IOC execution block fleet-wide, then credential revocation | Isolate each host as soon as its own memory is hashed; perimeter block at the end | Hard power-off of the 4 workstations and SCHED-SVR-01; FILE-SVR-01 shut down cleanly |
| Effect on attacker | Every beacon loses C2 in the same minute: no host goes dark while others stay live, so the operator has no window to trigger the staged scripts from a surviving beacon | First isolated host warns the operator; the remaining beacons (up to 15 min) can launch `encryption_staging.ps1` | Stops processes at once, but persistence (WinHealthSvc, auto start) relaunches the beacon at next boot; staged scripts stay on disk |
| Effect on patient care | 4 clinical workstations + scheduling server offline; ED charge desk and scheduling desk on paper downtime; FILE-SVR-01 stays readable by clinicians on the clinical VLAN | Same end state, reached more slowly | Same workstation loss, plus clinical notes and lab PDFs unavailable while FILE-SVR-01 is down; unsaved work lost |
| Evidence preserved | All memory images taken first (ART-001 to ART-007); disks intact; EDR keeps the jumpbox path so CS-WS-101 imaging continues | Same | Disks only |
| Evidence destroyed | Live C2 sockets close (already captured in memory images and netstat outputs) | Same | Any memory not yet captured, ransomware keys in SCHED-SVR-01 RAM if encryption is running |
| Time to execute | ~5 min after the last memory hash (20:30Z) | ~30 min spread | ~3 min |
| Reversibility | Fully reversible (EDR release, rule removal) | Fully reversible | Not reversible for evidence |

## Chosen: A, with one exception

Strategy A is chosen. With a 72-hour hands-on attacker and ransomware already staged on four workstations, the main risk is not losing one host but the operator noticing the response and triggering encryption from the beacons that are still alive. A single cut-over removes that window, and it only costs about 40 minutes of C2 exposure, which buys memory images of every live beacon host for the investigation and for the HIPAA question. Option B loses the surprise. Option C destroys the RAM of SCHED-SVR-01, where any encryption key would be, and it does not remove the persistence. On the clinical side, A takes four workstations and the scheduling server offline but keeps FILE-SVR-01 available to clinicians. The ED charge nurse confirmed at 20:01Z that paper downtime covers the charge desk and scheduling desk; option C would also remove clinical notes and lab results from the floors.

Exception: SCHED-SVR-01 is isolated as soon as its memory hash is recorded (about 20:21Z), before the coordinated window. Its disk activity may be encryption in progress, so active damage outweighs the risk of alerting the operator.

## Authorization and rollback

- Authorized by: Patricia Morales, CISO (Executive Sponsor, SEV1 decision authority), 20:18Z, by phone on the bridge, confirmed in `#ir-2026-0420-01`. IR Commander James Chen runs the execution.
- Rollback trigger: (1) a clinical system that patients depend on (Epic, LIS, ED tracking board) stops working because of the isolation and downtime procedures cannot cover it for more than 15 minutes; or (2) FILE-SVR-01 restrictions block clinicians from lab results or notes for active patients.
- Rollback steps: release only the host that breaks the clinical dependency, onto the quarantine VLAN with the perimeter block still in place; keep the IOC execution block; log DECISION + ACTION entries. Releasing a host fully back to production needs the CISO's approval.
