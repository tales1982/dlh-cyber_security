# 3. The 72-Hour Emergency Response Plan MedDefense Health Systems

**Analyst:** Security Analyst
**Date:** Current
**Available resources:** Sarah Park (IT Director) plus 2 IT staff, tonight; the Board convenes at 9:00 AM.

## Tier 1 Tonight (0-12 hours)

```
Action: Physically isolate NAS-01 from the production network (disconnect the uplink or move it to a dead-end VLAN)
Phase Blocked: 5 (Backup Destruction)
Owner: Sarah Park + 1 IT staff
Prerequisites: Confirm no backup job is mid-write (avoid corrupting the last known-good backup)
Risk of Action: No new backup jobs can complete until reconnected on an isolated path — a short recoverability gap, but a controlled one
Risk of Inaction: NAS-01 is destroyed alongside production in an active incident, exactly as it happened in all 5 real Crimson Tide cases
```

```
Action: Verify the FortiGate 100F's exact firmware build (`get system status`)
Phase Blocked: 1 (Initial Access)
Owner: Sarah Park
Prerequisites: None
Risk of Action: None — read-only check
Risk of Inaction: Every other Tier 1/2 decision about SSL-VPN depends on knowing whether the box is actually in the vulnerable range
```

```
Action: Review FortiGate logs for the advisory's listed IOCs — oversized /remote/logincheck payloads, unusual CLI commands (show system interface), unexpected VPN sessions
Phase Blocked: 1, 2 (confirms whether MedDefense is already inside the 4-7 day dwell window)
Owner: Security Analyst (you), with remaining IT staff support
Prerequisites: FortiGate log retention sufficient to cover the last 7 days
Risk of Action: Time-consuming tonight; a false-negative read (nothing found does not guarantee nothing happened) could create misplaced confidence
Risk of Inaction: MedDefense could already be inside Crimson Tide's dwell window without anyone knowing
```

```
Action: If the firmware check confirms a vulnerable build and the support contract cannot be renewed before morning, disable the SSL-VPN portal as an interim stopgap
Phase Blocked: 1
Owner: Sarah Park
Prerequisites: Firmware check (above) confirms the vulnerable range
Risk of Action: Cuts off remote VPN access for all 3 sites overnight — real operational disruption for any remote/on-call staff
Risk of Inaction: The confirmed, currently-exploited entry point stays open through the night
```

```
Action: Preserve current FortiGate logs and begin a written incident timeline before any further changes are made to the device
Phase Blocked: Supports Phase 1/2 investigation and any later forensic need
Owner: Security Analyst (you)
Prerequisites: None
Risk of Action: None
Risk of Inaction: If MedDefense is later found to be compromised, early log changes could destroy the evidence needed to scope the incident
```

## Tier 2 Tomorrow (12-36 hours)

```
Action: Board approves emergency renewal of the FortiGate support contract ($2,400); IT downloads and applies the firmware patch (7.0.12+/7.2.5+ or later) the same night
Phase Blocked: 1
Owner: James Chen / Board (approval), Sarah Park (execution)
Prerequisites: 9:00 AM Board approval; firmware confirmed vulnerable (Tier 1)
Risk of Action: Brief VPN outage during patch install and reboot — meaningful because the FortiGate has no redundancy and terminates all 3 sites' tunnels
Risk of Inaction: MedDefense remains open to a CVE now confirmed weaponized against 3 regional peer hospitals
```

```
Action: Disable RC4 and DES Kerberos encryption types domain-wide (AES-only), following the 1x04 Implementation Playbook Action #1, compressed from its normal 48-hour notice window
Phase Blocked: 3 (Lateral Movement / Kerberoasting)
Owner: Sarah Park
Prerequisites: Abbreviated service-account encryption-type check (the full inventory the playbook normally requires is compressed given the emergency, raising rollback risk slightly)
Risk of Action: Could break authentication for any undiscovered legacy system still requiring RC4; maximum acceptable downtime before rollback is 30 minutes of authentication failures on any clinical system (unchanged from the playbook's own standard)
Risk of Inaction: RC4-enabled Kerberoasting remains open — the exact mechanism used in 3 of 5 real Crimson Tide incidents
```

```
Action: Complete MFA rollout to 100% enforcement on VPN and administrative accounts
Phase Blocked: 2 (limits what a captured/replayed credential can do elsewhere, even though it does not stop a fully-owned FortiGate)
Owner: Sarah Park + IT staff
Prerequisites: Existing O365 E3 licensing (already available, no procurement needed)
Risk of Action: User friction, helpdesk load spike during a already-stressful 24 hours
Risk of Inaction: Any credential captured anywhere else in the chain remains freely reusable
```

```
Action: Formalize NAS-01's isolation into a dedicated backup VLAN, and confirm the ehr-db-01-to-ehr-srv-01 restriction (Quick Win, 1x03 Task 13) still holds
Phase Blocked: 5, 4
Owner: Sarah Park
Prerequisites: Tier 1 physical isolation already in place
Risk of Action: Low — this is hardening an already-isolated state, not a new change
Risk of Inaction: A "temporary" physical disconnect from last night quietly gets reversed under operational pressure
```

```
Action: Draft a one-page emergency crisis-communication and ransom-response protocol (who authorizes contact with an attacker, who speaks for MedDefense, escalation to legal and law enforcement) ahead of the Board meeting
Phase Blocked: 7 (Extortion)
Owner: James Chen + Security Analyst (you) + Maria Santos (legal)
Prerequisites: None
Risk of Action: None
Risk of Inaction: A real extortion contact is handled entirely improvised, under a 96-hour clock, the way Hospital B's leadership was forced to (data ultimately published)
```

## Tier 3 This Week (36-72 hours)

```
Action: Begin network segmentation configuration — Server, Clinical Workstation, and Management zones first (1x03 Task 14 design), 2-3 days minimum for new switch configs
Phase Blocked: 3 primarily; indirectly 2, 4, 5
Owner: Sarah Park + external network engineer if procurement allows
Prerequisites: Segmentation design already exists (1x03 Task 14); Kerberos and MFA changes (Tier 2) stable first, so three major network/auth changes are not destabilizing production simultaneously
Risk of Action: Reachability testing required before cutover; a rushed cutover could break legitimate clinical connectivity, especially to medical devices
Risk of Inaction: The flat network remains the single factor the advisory calls the "critical enabling factor" in all 5 real incidents
```

```
Action: Deploy Wazuh SIEM Phase 1 (critical servers + firewall) on an accelerated timeline
Phase Blocked: 6 (enables detection of the advisory's own listed IOC — new GPO creation outside change windows)
Owner: Security Analyst (you) / contracted deployment support, not Sarah Park's own IT staff
Prerequisites: Labor allocation already funded ($28,000, 1x03 Task 8)
Risk of Action: A freshly-deployed SIEM produces noise before it produces signal; false negatives during initial tuning
Risk of Inaction: Zero detection capability continues (GAP-002) through the highest-risk week MedDefense has faced
```

```
Action: Enforce TLS-only PostgreSQL connections on ehr-db-01 and begin scoping full at-rest encryption (1x04 Implementation Playbook Actions #2, accelerating CRYPTO-001)
Phase Blocked: 4
Owner: Sarah Park + DBA support
Prerequisites: Certificate issuance (internal CA, 1x04 Task 17)
Risk of Action: Requires a brief maintenance window and application-side connection-string testing
Risk of Inaction: The unencrypted patient database remains trivially exfiltrable to anyone who reaches it
```

```
Action: Complete offsite immutable backup replication (Control 4, $14,400) to formally replace Tier 1's temporary physical isolation
Phase Blocked: 5
Owner: Sarah Park, AWS vendor
Prerequisites: NAS-01 isolated and stable (Tier 1/2)
Risk of Action: Initial full upload takes time/bandwidth
Risk of Inaction: The temporary physical isolation is the only thing standing between MedDefense and a repeat single point of failure
```

## Resource Conflict Assessment

Sarah Park and her 2 IT staff are three people being asked to cover: NAS-01 isolation, FortiGate firmware verification and log review, an emergency FortiGate patch/reboot, a domain-wide Kerberos encryption change, MFA completion, and the start of network segmentation all within 72 hours. Three conflicts stand out:

**1. Tonight is workable, tomorrow night is not.** NAS-01 isolation and the FortiGate firmware/log review (Tier 1) can run in parallel across 2 of the 3 staff, with Sarah coordinating and liaising with James feasible within 12 hours. But Tier 2's FortiGate patch/reboot and the Kerberos RC4/DES change **cannot both run the same overnight window** with only 3 people: both carry real rollback risk (VPN connectivity on one side, domain authentication on the other), and running them concurrently means nobody is free to execute either rollback if something goes wrong simultaneously. **Resolution:** sequence them across two consecutive nights FortiGate patch on Night 2 (once Board approval unlocks the contract renewal that morning, giving the day to stage the patch), Kerberos change on Night 3.

**2. Sarah Park is a single point of failure on the people side.** She is named as the approver or executor on nearly every Tier 1 and Tier 2 action. This mirrors the exact single-point-of-failure risk already flagged for the FortiGate itself. **Resolution:** the analyst (you) takes direct ownership of everything that does not require Sarah's own administrative credentials log review, the crisis-communication draft, coordination with James and Maria Santos freeing Sarah and her 2 staff to focus exclusively on hands-on-keyboard changes to the FortiGate, AD, and NAS-01.

**3. Segmentation and SIEM deployment compete for the same people as Tier 2's changes.** Segmentation realistically should not begin in earnest until Kerberos and MFA changes are stable three major network/authentication changes landing simultaneously is itself an availability risk. SIEM deployment, however, is a different skill set (Wazuh install and log-source onboarding) and does not require Sarah's own IT staff at all if outside deployment support is engaged. **Resolution:** start SIEM deployment in parallel with Tier 2 using the analyst/contracted support, while segmentation waits for Tier 3 once Kerberos and MFA have proven stable.
