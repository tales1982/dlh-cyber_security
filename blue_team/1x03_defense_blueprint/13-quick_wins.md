# 13. The Quick Wins — MedDefense Health Systems

**Analyst:** Security Analyst
**Date:** Current

## Quick Win #1: Disable the Tomcat AJP Connector

```
Quick Win #1: Disable the Tomcat AJP Connector on ehr-srv-01
Risk Addressed: RISK-001
Action:
  1. Confirm with the EHR application team that port 8009/AJP is not
     actively used by any current integration (expected: it is not).
  2. Comment out or remove the AJP Connector entry in Tomcat's
     server.xml on ehr-srv-01.
  3. Restart the Tomcat service during a low-traffic window and confirm
     the EHR application still loads normally over its standard port.
Owner: IT Director (Sarah Park), executed by IT server administration
Timeline: 2 days (1 day to confirm no dependency, 1 day to schedule
  the restart window and execute)
Cost: $0 — a configuration change using existing administrative access
Risk Reduction: Closes the single most severe confirmed-active,
  CISA-KEV-listed vulnerability in the entire 1x02 assessment
  (CVE-2020-1938, CVSS 9.8). This is not on a named kill chain, but it
  sits directly on the application server for ehr-db-01, the asset
  every kill chain in 1x01 treats as the ultimate objective.
Verification: Attempt a raw connection to port 8009 from another host
  on the network (e.g., nc -zv ehr-srv-01 8009) and confirm the
  connection is refused; re-run the specific OpenVAS plugin for this
  finding and confirm it now reports the connector inactive.
```

## Quick Win #2: Restrict PostgreSQL to `ehr-srv-01` Only

```
Quick Win #2: Restrict ehr-db-01's network access to ehr-srv-01 only
Risk Addressed: RISK-002 (via GAP-001 / 1x02 Finding 003)
Action:
  1. Edit pg_hba.conf on ehr-db-01 to replace the 10.10.0.0/16 rule
     with a rule scoped to ehr-srv-01's specific IP (10.10.2.10) only.
  2. Change listen_addresses from '*' to the specific interface
     required.
  3. Reload the PostgreSQL configuration (no restart/downtime required
     for a pg_hba.conf change) and confirm the EHR application still
     connects successfully.
Owner: IT Director (Sarah Park), executed by IT server administration
Timeline: 1 day
Cost: $0 — a configuration change
Risk Reduction: Directly breaks Kill Chain #5 ("Vendor Compromise to
  Direct Patient Data Access"), Step 3, which explicitly names this
  exact exposure ("ehr-db-01 is reachable network-wide, not restricted
  to ehr-srv-01 alone") as the mechanism that lets a compromised
  vendor session reach the patient database. Also removes the primary
  mechanism behind RISK-002's worst-case exfiltration step.
Verification: From a host other than ehr-srv-01, attempt
  psql -h 10.10.2.11 -p 5432 and confirm the connection times out or
  is refused; confirm the EHR application itself still connects
  without error as a positive control.
```

## Quick Win #3: Reset Default Credentials on the BD Alaris Fleet

```
Quick Win #3: Change the default admin/admin credentials on all 7
  scanned BD Alaris infusion pumps
Risk Addressed: RISK-005
Action:
  1. Obtain the current web-interface default credentials list from
     Clinical Engineering (7 pumps confirmed unchanged, 1x02 Finding
     010).
  2. Schedule credential changes during routine device
     rounds/maintenance checks already performed by Clinical
     Engineering, to avoid any dedicated device downtime.
  3. Record the new credentials in the approved credential management
     tool (Section 6, Task 12 AUP), not in a spreadsheet.
Owner: Clinical Engineering, coordinated with IT Director (Sarah Park)
Timeline: 5 days (bounded by device rounds schedule, not technical
  complexity)
Cost: $0 — no new tooling, uses existing device management access
Risk Reduction: Removes the specific, confirmed default-credential
  vector documented in Kill Chain #4 ("Unpatched Web Server to Medical
  Device Exposure"); does not require the segmentation project (Task
  14) to already be complete to deliver value.
Verification: Attempt to log into each pump's web interface using the
  known default credentials and confirm access is denied; confirm the
  new credentials are recorded in the credential management tool, not
  left undocumented.
```

## Quick Win #4: Enable MFA on VPN and Administrative Accounts

```
Quick Win #4: Deploy MFA using existing O365 E3 licensing
Risk Addressed: RISK-002, RISK-010
Action:
  1. Enable Azure AD Conditional Access (already licensed under O365
     E3) requiring MFA for all remote/VPN authentication and all
     accounts with administrative roles.
  2. Enroll administrative and remote-access users in an MFA method
     (authenticator app preferred over SMS) over a 3-day rollout window
     to avoid locking out staff mid-shift.
  3. Communicate the change in advance via existing email distribution
     lists — no new communication tooling required.
Owner: Deputy CISO (James Chen), executed by IT Director (Sarah Park)
Timeline: 10 days (rollout paced to avoid clinical disruption, per the
  Task 12 AUP's own emphasis on practicality for hospital staff)
Cost: $0 net new spend — uses licensing MedDefense already pays for
Risk Reduction: Directly breaks Kill Chain #1 Step 4 (pass-the-hash to
  Domain Admin) and Kill Chain #2 in its entirety (VPN credential
  compromise requires only a password today); per Task 6's own
  calculation, this single change reduces the ransomware risk's ALE
  from $300,000 to approximately $96,000.
Verification: Attempt to authenticate to the VPN and to an
  administrative account using only a password (in a controlled test)
  and confirm MFA is enforced; review Azure AD sign-in logs for MFA
  challenge completion across 100% of in-scope accounts.
```

## Quick Win #5: Deploy a USB Mass Storage Restriction GPO

```
Quick Win #5: Restrict USB mass storage devices on clinical
  workstations via existing Active Directory Group Policy
Risk Addressed: RISK-004
Action:
  1. Create a Group Policy Object restricting USB mass storage device
     classes, using the GPO tooling already available in the existing
     AD environment.
  2. Apply the GPO to the clinical workstation OU (~280 machines, 1x02
     Finding 023) rather than IT/admin workstations that may have a
     legitimate documented need.
  3. Pilot on a single nursing unit for 48 hours before organization-
     wide rollout, to catch any legitimate workflow dependency early.
Owner: IT Director (Sarah Park)
Timeline: 7 days (2 days pilot, 5 days phased rollout)
Cost: $0 — uses existing AD Group Policy infrastructure
Risk Reduction: Directly disrupts Step 3 of Kill Chain #3 ("Insider
  Data Exfiltration via Legitimate Access") and the physical
  exfiltration step in Scenario 2 ("The Quiet Departure," 1x01 Task
  14), both of which rely explicitly on an unrestricted personal USB
  drive as the removal mechanism for exported patient records.
Verification: Attempt to connect a USB storage device to a pilot-group
  workstation and confirm it is blocked or read-only; confirm no
  legitimate workflow (e.g., a documented medical device data-transfer
  need) was broken during the 48-hour pilot before full rollout.
```

## Why Quick Wins Matter Beyond Their Immediate Risk Reduction

Quick wins matter because the first month of a security program is a credibility test, not just a risk-reduction exercise. A Board that just approved $120,000 based on a threat landscape and a vulnerability assessment wants to see the program produce visible, verifiable change before the big architecture work (segmentation, SIEM tuning) even finishes its first phase — and these five actions, none of which required a purchase order or a vendor contract, prove that MedDefense already had more capacity to reduce risk than "we have no budget" ever suggested. Internally, quick wins also build the habit this program most needs: the discipline of verifying that a fix actually worked (Section 1's own emphasis throughout this project) rather than assuming it did, which is exactly the muscle a two-person security team has to build before the SIEM, the segmented network, and the rest of the six-month roadmap arrive and multiply the number of things that need that same disciplined verification.

## Repo

- **GitHub repository:** `dlh-cyber_security`
- **Directory:** `blue_team/1x03_defense_blueprint`
- **File:** `13-quick_wins.md`
