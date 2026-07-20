# 23. The Validation Plan — MedDefense Health Systems

**Analyst:** Threat Intelligence Analyst
**Date:** Current

## 1. Post-Patch Verification

For the 3 findings featured in this cycle's Patch Briefing (Task 22), each drawn from Task 20's Immediate horizon:

**Finding 031 (Ghostcat, `ehr-srv-01`):**
- Inspect `server.xml` directly to confirm the AJP connector is either removed, commented out, or bound to `127.0.0.1` with a `requiredSecret` set.
- Attempt a raw connection to port 8009 from a second host on the internal network (e.g., `nc -zv 10.10.2.10 8009` or a Ghostcat-specific test script) and confirm the connection is refused rather than accepted.
- Re-run the specific OpenVAS plugin for this finding (targeted at `ehr-srv-01` only, not a full network re-scan) and confirm it now reports the connector as inactive.

**Finding 003 (PostgreSQL, `ehr-db-01`):**
- Inspect `pg_hba.conf` directly to confirm it now restricts connections to `ehr-srv-01`'s IP only, and that `listen_addresses` no longer equals `'*'`.
- From a host other than `ehr-srv-01` (e.g., a workstation or `billing-srv-01`), attempt `psql -h 10.10.2.11 -p 5432` and confirm the connection times out or is actively refused.
- As a positive control, confirm the EHR application itself (via `ehr-srv-01`) still connects successfully — a restriction that silently breaks the legitimate application is a failure, not a fix.

**Finding 001/002 (Apache chain, `billing-srv-01`):**
- Confirm the installed Apache version via `apache2 -v` (or the HTTP response header, if not suppressed) shows 2.4.52 or later.
- Re-run `searchsploit apache <new version>` and confirm CVE-2021-44790/CVE-2019-0211 no longer match the installed version string.
- In a staging clone (never production), attempt the known public PoC (EDB-51193) and confirm it now fails rather than triggering the buffer overflow.

## 2. Compensating Control Validation

**MRI segmentation (Control 1, `WS-RAD-01`):** From an ordinary workstation on `10.10.1.0/24`, attempt to reach `WS-RAD-01` on ports 445 and 3389 and confirm the connection is blocked — not just "not answered," but confirmed dropped at the firewall via the FortiGate's own logs, which should show a denied-traffic entry for the attempt. As a positive control, confirm `pacs-srv-01` — the one host still permitted to communicate with the MRI — retains full functional access; a segmentation rule that blocks everyone, including the systems that need to work, is not a validated success. Review the firewall rule hit-counters periodically to confirm the rule is actually being evaluated in production, not just present in the configuration file.

**Medical IoT segmentation (Philips fleet, once GAP-007 Phase 2 is implemented):** The same reachability logic applies at fleet scale — attempt to reach a sample of monitors' web interfaces (ports 80/443) and the HL7 port (2575) from a general workstation outside the new dedicated VLAN and confirm denial; confirm any clinical system that legitimately needs monitor data (e.g., a central nursing station display) retains access. Follow up with a targeted `nmap` sweep of the medical device subnet from outside the new VLAN boundary to independently confirm the devices no longer appear reachable, rather than relying solely on the firewall's own configuration as proof.

## 3. Rescan Schedule

**Recommendation: a full authenticated scan monthly, with two exceptions running tighter cadences.** A monthly full scan is a reasonable baseline for an organization of MedDefense's size, balancing the fact that this report is explicitly "a snapshot of one night" (Task 0) against the operational cost of scanning more frequently. The two exceptions: `billing-srv-01` and the FortiGate perimeter deserve a **weekly** targeted scan, because `billing-srv-01` is the only asset in this environment with a proven, repeated real-world compromise history and the FortiGate is the single perimeter chokepoint every kill chain in 1x01 either starts or passes through. Separately, **any host that receives a remediation action should be re-scanned (targeted, not full-network) within 7 days of the change** regardless of the regular monthly cycle — this is what closes the loop on the Post-Patch Verification items above and ensures a "silently failed" patch doesn't sit undetected for a full month.

## 4. Continuous Intelligence

MedDefense should formally subscribe to, at minimum: the **CISA KEV catalog** (RSS or email notification), **Fortinet PSIRT advisories** (given the FortiGate's role as the sole perimeter device), **Microsoft MSRC** and **Ubuntu Security Notices** (covering the Windows Server and Ubuntu estate respectively), and the medical device vendor advisory pages for **BD** and **Philips** specifically. All of these should route to a single, named owner — not "the IT team" generically, which is exactly the diffusion of responsibility that let alerts go unreviewed in the first place (1x00 GAP-002). The most efficient path is to fold this intake directly into the SIEM deployment already funded under GAP-002: once Wazuh (or equivalent) is live, KEV and advisory ingestion becomes one more feed reviewed on the same operational cadence as security logs, rather than a separate, easily-neglected task. Any advisory matching an asset in the current Asset Registry (1x00 Task 7) should trigger an out-of-cycle targeted scan of that specific asset within 48 hours, independent of the monthly schedule.

## 5. Lifecycle Diagram

```
SCAN
  Who: Security Analyst (contracts/coordinates with SecurePoint or runs
    internal tooling)
  What: Full authenticated scan monthly; targeted scans weekly for
    billing-srv-01/FortiGate and within 7 days of any remediation.
       |
       v
TRIAGE
  Who: Security Analyst
  What: Read the raw scan for structure first (Task 0's own discipline);
    identify false positives (Task 11); classify every finding into
    Actionable Critical / Actionable Standard / Informational / False
    Positive (Task 16) before any deeper research begins.
       |
       v
PRIORITIZE
  Who: Security Analyst, with IT Ops input on operational constraints
  What: Cross-reference against asset criticality (1x00), kill chain
    position and threat actor mapping (1x01), exploit availability (CISA
    KEV/Exploit-DB), and existing compensating controls (Tasks 17-18) to
    produce a threat-informed priority, not a CVSS-only one.
       |
       v
REMEDIATE
  Who: IT Ops (patches, configuration changes); Vendor (firmware updates
    for medical devices and network appliances, entirely outside
    MedDefense's own control); Clinical Engineering (coordinating any
    change that touches a device in active clinical use); Management
    (approving budget and timeline for Medium/Long-term items per the
    Priority Matrix, Task 20)
       |
       v
VALIDATE
  Who: Security Analyst
  What: Execute the specific Post-Patch Verification or Compensating
    Control Validation check for each remediated finding (Sections 1-2
    above) — not a general "looks fine" check, but the exact test
    documented for that finding type.
       |
       v
REPEAT
  Who: Security Analyst (schedules the next cycle); Management (reviews
    trend over time — is the Actionable Critical count shrinking scan over
    scan, or holding steady?)
  What: The next scheduled scan (Section 3) feeds newly discovered findings
    back into Triage, closing the loop. Continuous Intelligence (Section 4)
    can also trigger an out-of-cycle entry into Triage at any point in the
    month, independent of the regular schedule.
```

The critical discipline this lifecycle enforces is that **Validate is a distinct, mandatory step, not an assumption** — the same principle established at the very start of this project (Task 0's "junior vs. senior analyst" framing) applies at the end of the cycle as much as the beginning: a fix that hasn't been independently re-tested is a claim, not a fact.

## Repo

- **GitHub repository:** `dlh-cyber_security`
- **Directory:** `blue_team/1x02_the_weak_links`
- **File:** `23-validation_plan.md`
