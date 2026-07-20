# 19. The Remediation Map — MedDefense Vulnerability Scan

**Analyst:** Threat Intelligence Analyst
**Date:** Current

## Finding 031 — Ghostcat (CVE-2020-1938), `ehr-srv-01`

```
Response Type: Configuration Change

Change Description: Disable the Tomcat AJP connector in server.xml if the
  EHR application does not actually use it (the registry shows the app
  served primarily over 443; AJP is very likely a leftover default). If AJP
  is genuinely required by some internal integration, bind it to
  127.0.0.1 only and set the requiredSecret attribute rather than removing
  it outright.
Impact Assessment: If AJP is unused (the expected case), zero impact on
  EHR availability. Requires a brief confirmation with the application
  team before disabling, since taking down the wrong connector on this
  host would interrupt EHR access clinic-wide.

Timeline: Immediate (24-48h)
Owner: IT (with Security sign-off on the change)
Cost Estimate: $0-1K
```

## Finding 003 — PostgreSQL Unrestricted Network Access, `ehr-db-01`

```
Response Type: Configuration Change

Change Description: Restrict pg_hba.conf to accept connections only from
  ehr-srv-01 (10.10.2.10); change listen_addresses from '*' to the specific
  interface required, and add a host firewall rule dropping all other
  inbound connections to port 5432.
Impact Assessment: The Asset Registry documents no other legitimate
  consumer of this database besides ehr-srv-01 — expected impact is zero,
  but confirm with the DBA/application owner before cutover in case an
  undocumented reporting or integration job also connects directly.

Timeline: Immediate (24-48h)
Owner: IT/Security
Cost Estimate: $0-1K
```

## Finding 001/002 — Apache RCE-to-Root Chain, `billing-srv-01`

```
Response Type: Patch

Patch Source: Apache HTTP Server 2.4.52+ (fixes CVE-2021-44790) and 2.4.39+
  (fixes CVE-2019-0211). Ubuntu 18.04 without ESM does not receive these
  upstream — the fastest safe path is enrolling in Ubuntu Pro/ESM
  immediately (per Task 12's own recommendation) rather than waiting for a
  full OS migration.
Prerequisites: A full VM snapshot/Veeam backup taken immediately before any
  change (confirm the nightly backup is current first); test the Apache
  upgrade and mod_lua behavior in a staging clone of billing-srv-01 before
  touching production, given this server has already broken unexpectedly
  twice before under far less deliberate circumstances.
Rollback Plan: Restore from the pre-patch VM snapshot if the billing
  application fails to start or mod_lua scripts misbehave post-upgrade.
Operational Risk: Apache module/configuration incompatibilities between
  the ancient 2.4.29 build and a current patched version; billing
  application downtime during the restart; if a full OS migration is
  pursued instead of ESM in this window, dependency-breakage risk is
  significantly higher and should not be attempted under a 7-day timeline.

Timeline: 7 days (ESM enrollment + emergency Apache patch; full OS
  migration follows separately on the 90-day horizon per Task 12)
Owner: IT, with the billing application vendor consulted if the billing
  software itself has version dependencies on this Apache build
Cost Estimate: $1-10K (Ubuntu Pro/ESM subscription plus staging/testing
  labor)
```

## Finding 004 — Windows XP EOL Bundle, `WS-RAD-01`

```
Response Type: Compensating Control

Control Description: Implement Control 1 from the 1x00 Task 6 strategy —
  move WS-RAD-01 onto its own isolated network segment with a firewall
  rule permitting communication only with pacs-srv-01. This was already
  designed and approved conceptually in 1x00; it has simply never been
  executed, which is what allowed Finding 004 to still exist unchanged in
  this scan.
Residual Risk: The underlying OS remains permanently unpatched — this
  control reduces reachability, not the vulnerability itself. If
  pacs-srv-01 (the one permitted peer) is ever compromised, or if an
  attacker gains physical access to the workstation directly, this control
  provides no protection (matching the original 1x00 analysis's own
  documented limitation).

Timeline: 30 days
Owner: IT (network team)
Cost Estimate: $10-50K
```

## Finding 015 — NAS-01 Exposed Management Interface

```
Response Type: Configuration Change

Change Description: Restrict the DSM web interface (ports 5000/5001) via
  firewall ACL to a specific administrative management subnet or jump host
  only, and enable DSM's built-in backup-encryption feature for data at
  rest.
Impact Assessment: Nightly Veeam backup jobs use a separate protocol path,
  not the DSM web UI, so restricting DSM's own management interface should
  not interrupt backup operations. Administrators will need to access DSM
  only from the designated management network going forward — a workflow
  change, not a service interruption.

Timeline: 7 days
Owner: IT
Cost Estimate: $0-1K
```

## Finding 016 — Medical Device HTTP Interfaces, Philips Fleet

```
Response Type: Compensating Control

Control Description: Extend the dedicated VLAN and firewall-restriction
  approach already funded for the BD Alaris pump fleet (1x00 GAP-004) to
  the Philips IntelliVue monitor fleet — this is explicitly GAP-007's
  "Phase 2," which 1x00's own Risk Decisions deliberately deferred to next
  fiscal year. This scan's findings (13 monitors reachable network-wide,
  with a documented real-world unauthenticated read/write capability for
  this device family, per Task 15) are a strong argument for accelerating
  that timeline rather than waiting.
Residual Risk: Until this segmentation is implemented, the monitor fleet
  remains flat-network-exposed; even after segmentation, device firmware
  itself (some dated 2019) remains unpatched, and Philips' own update cycle
  is entirely outside MedDefense's control.

Timeline: 90 days
Owner: IT + Clinical Engineering (device fleet coordination required, since
  monitors cannot be simply unplugged/reconfigured without clinical
  awareness)
Cost Estimate: $10-50K
```

## Finding 007 — LDAP Signing / SMBv1, `ad-dc-01`

```
Response Type: Configuration Change

Change Description: Enforce LDAP signing requirements (LDAPServerIntegrity
  registry setting or equivalent GPO) on both ad-dc-01 and ad-dc-02, and
  disable the SMBv1 protocol via Windows Features/Group Policy.
Impact Assessment: Any legacy client or application still relying on
  unsigned LDAP binds or SMBv1 would lose connectivity to the domain
  controllers — given this environment's own EOL systems (WS-RAD-01,
  print-srv-01), a brief compatibility audit is required before a hard
  cutover, specifically checking whether either EOL host depends on legacy
  SMB dialects for any domain-facing function.

Timeline: 30 days (compatibility audit first, then enforcement)
Owner: IT (Active Directory/Identity team)
Cost Estimate: $0-1K
```

## Finding 029 — Grafana Path Traversal, Westside Shadow IT

```
Response Type: Compensating Control (as an immediate first step, pending an
  ownership decision this project cannot make on MedDefense's behalf)

Control Description: Immediately block network access to 10.10.10.200 at
  the Westside router/FortiGate pending an ownership investigation — no one
  has claimed this device, so the responsible first action is containment,
  not remediation of a system whose purpose and full exposure remain
  unknown. Once ownership is established, either decommission the device
  entirely or formally bring it under IT management, patch Grafana to a
  current version, and add it to the Asset Registry.
Residual Risk: Blocking access could disrupt an undocumented but
  functionally relied-upon monitoring tool someone at Westside actually
  uses day to day — this is a real trade-off, not a free action, and is
  exactly why the investigation step cannot be skipped even under time
  pressure.

Timeline: Immediate (network block), 30 days (investigation and permanent
  disposition)
Owner: Security (immediate containment) transitioning to IT (investigation,
  decommission or formal onboarding)
Cost Estimate: $0-1K
```

## Repo

- **GitHub repository:** `dlh-cyber_security`
- **Directory:** `blue_team/1x02_the_weak_links`
- **File:** `19-remediation_map.md`
