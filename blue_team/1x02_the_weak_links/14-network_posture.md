# 14. The Network Posture — MedDefense Vulnerability Scan

**Analyst:** Threat Intelligence Analyst
**Date:** Current

## Analysis 1 — CVE-2021-44790 (`billing-srv-01`)

```
CVE: CVE-2021-44790
Host: 10.10.2.15 (billing-srv-01)
CVSS Base Score: 9.8

Scenario A: Current (flat network)
  Who can reach this vulnerability: Anyone on the internet (this Apache
    instance is internet-facing per 1x01 Task 6), plus any of the ~350+
    devices across every MedDefense subnet -- Central servers, ~320 Central
    workstations, the medical IoT fleet, Westside's ~36 workstations (via
    site-to-site VPN), and Corporate HQ's ~145 endpoints (via site-to-site
    VPN) -- since the 1x00 Task 7 network scan confirmed the entire
    10.10.0.0/16 range is reachable from a single HQ workstation with zero
    access restriction.
  What the attacker can reach AFTER exploitation: Everything on that same
    10.10.0.0/16 range. A shell on billing-srv-01 sits on the same flat
    network as ehr-db-01, ad-dc-01, NAS-01 and the entire medical IoT fleet --
    exactly the pattern that already turned this same vulnerability class into
    a domain-wide ransomware event and a cryptominer infection twice before
    (1x00 Tasks 1-2).
  Effective Risk: Critical and immediate -- an internet-reachable RCE that
    lands the attacker on the same network as every other critical asset in
    the environment, with no containment boundary anywhere.

Scenario B: Hypothetical (segmented network)
  Who can reach this vulnerability: Still anyone on the internet, since this
    is an internet-facing service -- segmentation does not change external
    reachability of a service intentionally exposed to the internet.
  What the attacker can reach AFTER exploitation: Only other hosts in the
    same VLAN as billing-srv-01 (e.g., a "Finance/Billing" segment), unless a
    firewall rule specifically permits further pivoting. ehr-db-01, ad-dc-01,
    NAS-01 and the medical IoT fleet would sit behind separate segment
    boundaries requiring an additional, independent compromise (a firewall
    misconfiguration or a second vulnerability) to reach.
  Effective Risk: Still High (the RCE itself is unchanged, and Confidential
    billing/financial data remains at risk), but now contained -- a
    single-segment incident rather than an organization-wide one.

Risk Amplification Factor: The vulnerability's exploitability (CVSS 9.8) does
  not change at all with segmentation -- what changes is blast radius, from
  "one department's data" to "every critical asset MedDefense has." This is
  the largest possible amplification category: segmentation converts this
  from a contained incident into the exact opening move of Kill Chain #4.
```

## Analysis 2 — CVE-2020-1938 "Ghostcat" (`ehr-srv-01`)

```
CVE: CVE-2020-1938
Host: 10.10.2.10 (ehr-srv-01)
CVSS Base Score: 9.8

Scenario A: Current (flat network)
  Who can reach this vulnerability: Any of the ~47+ scanned hosts plus every
    workstation and medical device on the flat 10.10.0.0/16 range -- port
    8009/AJP is not designed to be internet-facing, but the flat network
    means "internal-only" provides no real containment: any compromised
    workstation, medical device, or shadow-IT host reaches it identically to
    a legitimate internal application server.
  What the attacker can reach AFTER exploitation: Configuration files on
    ehr-srv-01, very likely including database credentials for ehr-db-01 --
    which, given Finding 003's own unrestricted PostgreSQL exposure, means
    the attacker reaches the full 50,000+ patient record database almost
    immediately afterward.
  Effective Risk: Critical -- this finding alone, combined with the flat
    network, is a near-direct path from any foothold anywhere to the
    organization's single highest-value asset.

Scenario B: Hypothetical (segmented network)
  Who can reach this vulnerability: Only hosts in the same "Clinical
    Application Servers" VLAN as ehr-srv-01 -- realistically just ehr-db-01
    and any application-tier systems that legitimately need to reach it, not
    general workstations, medical IoT, or Westside/HQ endpoints.
  What the attacker can reach AFTER exploitation: The same narrow segment --
    an attacker would need to already be inside that specific VLAN (a much
    smaller, more monitorable population of systems) before this finding
    becomes reachable at all.
  Effective Risk: Still Critical for the segment itself (ehr-db-01's
    exposure doesn't disappear), but the population of systems that could
    ever reach this finding drops from ~350+ devices to a small handful.

Risk Amplification Factor: Extreme. In the current flat network, literally
  any of the ~350 devices across four physical/logical sites is a valid
  starting point for reaching this vulnerability. A segmented network would
  reduce that reachable population by roughly two orders of magnitude,
  turning "any compromised device anywhere" into "an attacker who is already
  inside the clinical application tier specifically."
```

## Analysis 3 — CVE-2017-0144 "EternalBlue" (`WS-RAD-01`, MRI Workstation)

```
CVE: CVE-2017-0144
Host: 10.10.1.70 (WS-RAD-01)
CVSS Base Score: 8.1

Scenario A: Current (flat network)
  Who can reach this vulnerability: Every device on the 10.10.1.0/24 general
    workstation subnet -- roughly 320 Windows 10 workstations plus reception,
    admin, pharmacy and lab endpoints -- since the 1x00 Task 7 scan and this
    finding both confirm no VLAN isolates the MRI from ordinary staff
    machines.
  What the attacker can reach AFTER exploitation: A wormable SMB exploit
    means the attacker does not even need to "reach further" deliberately --
    EternalBlue is self-propagating by design (as it was in WannaCry), so any
    single compromised workstation on this subnet can automatically spread
    to the MRI, and from the MRI to anything else reachable on the same flat
    address space.
  Effective Risk: Critical -- a patient-safety device reachable by a
    self-spreading exploit from a population of ~320 general-purpose
    endpoints with no isolation whatsoever.

Scenario B: Hypothetical (segmented network)
  Who can reach this vulnerability: Only the PACS server, per the Control 1
    compensating-control design already proposed in 1x00 Task 6 (MRI
    isolated to a microsegment permitted to talk only to PACS).
  What the attacker can reach AFTER exploitation: Nothing further --
    reaching the MRI would require first compromising PACS itself (a
    separate, independent target with its own credentials and controls), not
    simply landing on any of ~320 ordinary workstations.
  Effective Risk: Substantially reduced -- the vulnerability itself is still
    unpatchable (EOL, Task 12), but the population that can ever reach it
    drops from ~320 general endpoints to exactly one purpose-specific server.

Risk Amplification Factor: Extreme, and uniquely urgent because this
  specific vulnerability is self-propagating. Unlike the other two CVEs
  analyzed here, EternalBlue does not require an attacker to manually decide
  to pivot toward the MRI -- on a flat network, a single phished workstation
  anywhere in the ~320-endpoint population can reach and infect it
  automatically. This is the clearest possible case where segmentation
  (a control already designed and approved in 1x00, per Task 12's own
  analysis, but never implemented) would have fully neutralized the finding
  regardless of the OS ever being patched.
```

## Network Posture Summary

Across all three analyses, the exploitability of each individual CVE (9.8, 9.8, 8.1) never changes between the flat and segmented scenarios — what changes, by one to two orders of magnitude each time, is how many of MedDefense's roughly 350+ devices across four sites can reach the vulnerability and how much of the environment becomes reachable afterward. This is the aggregate effect across the entire 31-finding report: the flat network does not create any single vulnerability, but it is a **force multiplier applied uniformly to every one of them**, converting isolated departmental risks (a billing server bug, a print server bug, an MRI workstation bug) into organization-wide ones by default. This is why network segmentation is arguably more impactful than patching any single CVE in this report: patching CVE-2021-44790 closes exactly one vulnerability, while segmenting the network would simultaneously shrink the blast radius of **all 31 findings at once** — including the ones not yet discovered, the misconfigurations that will never receive a CVE, and the next zero-day that appears on any host, at no marginal additional engineering cost per finding. A patch fixes what you already found; segmentation reduces the consequence of everything you haven't found yet.

## Repo

- **GitHub repository:** `dlh-cyber_security`
- **Directory:** `blue_team/1x02_the_weak_links`
- **File:** `14-network_posture.md`
