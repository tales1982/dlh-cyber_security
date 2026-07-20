# 6. The Misconfiguration Findings — MedDefense Vulnerability Scan

**Analyst:** Threat Intelligence Analyst
**Date:** Current

## Finding 003 — PostgreSQL Unrestricted Network Access (`ehr-db-01`)

- **Finding ID:** 003
- **Host:** 10.10.2.11 (`ehr-db-01`)
- **Misconfiguration:** `pg_hba.conf` accepts connections from the entire `10.10.0.0/16` range instead of only from `ehr-srv-01`; `listen_addresses = '*'` binds PostgreSQL to every network interface.
- **Why No CVE:** PostgreSQL's code is behaving exactly as designed — it is *supposed* to accept connections from whatever hosts an administrator lists in `pg_hba.conf`. There is no software defect to assign an identifier to; the defect is a human decision (or a default left unchanged) about *which* hosts to list. A CVE describes a flaw in the product; this is a flaw in how the product was set up.
- **Severity Assessment:** **Critical.** This is the database behind MedDefense's #1 Top-5 Critical Asset (1x00 Task 8), holding PHI for 50,000+ patients, with zero barrier beyond a password between it and every device on a flat network.
- **Cross-Reference 1x00:** Directly confirmed in the 1x00 Task 7 Network Scan Summary, Anomaly #4 ("Exposed Services"): *"PostgreSQL on `ehr-db-01` (10.10.2.11:5432) is accessible from the entire internal network. Should be restricted to `ehr-srv-01`."* This is also the exact exposure named in GAP-001 (1x00 Task 12): "EHR database reachable from the entire internal network, with no detection of anomalous access."
- **Comparable CVE Risk:** Comparable to **CVE-2020-1938 (Ghostcat, Finding 031, CVSS 9.8)** — both hand an attacker a path to `ehr-srv-01`/`ehr-db-01` data without needing a sophisticated exploit chain. Ghostcat needs a crafted AJP request; this needs nothing but network reachability and a guessed or reused password. Arguably worse: Ghostcat at least requires the attacker to know the vulnerability exists — this misconfiguration requires nothing but curiosity.

## Finding 006 — MySQL Unrestricted Network Binding (`billing-srv-01`)

- **Finding ID:** 006
- **Host:** 10.10.2.15 (`billing-srv-01`)
- **Misconfiguration:** `bind-address = 0.0.0.0` in `mysqld.cnf`, exposing the billing database to every host on the internal network instead of only the application server that needs it.
- **Why No CVE:** Identical reasoning to Finding 003 — `bind-address` is a documented, intentional configuration directive. MySQL is not malfunctioning; it is faithfully doing what an administrator (or an unchanged installer default) told it to do.
- **Severity Assessment:** **High**, matching the report's own label. Financial/billing data is rated Confidential rather than Restricted (1x00 Task 8 Criticality Matrix), and this is the same host already compromised twice before (ransomware, then a cryptominer, per the 1x00 Asset Registry) — this misconfiguration adds a third distinct exposure vector on top of an already-proven target.
- **Cross-Reference 1x00:** Also directly confirmed in the 1x00 Network Scan Summary, Anomaly #4, in the very same bullet list as the PostgreSQL exposure — this is not a new discovery, it is a known, previously-flagged issue that persisted from 1x00 all the way into this new scan.
- **Comparable CVE Risk:** Comparable to **CVE-2021-44790 (Finding 001, CVSS 9.8, same host)** — both put `billing-srv-01`'s data at risk with no sophistication required from the attacker's side once they have any foothold on the internal network, whether via the Apache RCE or simply by connecting to port 3306 directly.

## Finding 007 — LDAP Signing Not Required + SMBv1 Enabled (`ad-dc-01`)

- **Finding ID:** 007
- **Host:** 10.10.2.20 (`ad-dc-01`)
- **Misconfiguration:** The domain controller does not enforce LDAP signing (enabling LDAP relay attacks) and still has the legacy SMBv1 protocol enabled.
- **Why No CVE:** LDAP signing enforcement and SMBv1 support are both configuration *toggles* Microsoft ships and documents, defaulted historically to permissive settings for backward compatibility. The vulnerability here is the operational decision never to harden those toggles, not a flaw in Active Directory's code — Microsoft's own security advisory on this topic is a hardening recommendation, not a patch.
- **Severity Assessment:** **Critical** — I am rating this above the report's own "High" label. `ad-dc-01` is the #2 Top-5 Critical Asset (1x00 Task 8): "the trust anchor for nearly every login in the organization." An LDAP relay attack against the primary domain controller is a path to domain-wide compromise, not a single-host issue — the same class of impact as the Critical-rated findings elsewhere in this report.
- **Cross-Reference 1x00:** The 1x00 Network Scan Summary shows ports 389 and 445 open on `ad-dc-01`/`ad-dc-02`, confirming the exposed surface existed at the time of the original scan — but neither the signing requirement nor the SMBv1 status was checked back then (Sarah's scan was a port/OS fingerprint pass, not a configuration audit). This gap in configuration-level visibility is exactly what GAP-002 describes (1x00 Task 12): logs and surface exist, but nothing reviews configuration or behavior for a problem like this until an authenticated deep scan finally looks for it.
- **Comparable CVE Risk:** Comparable to **CVE-2017-0144 (EternalBlue, Finding 004, CVSS 8.1)** — both are SMB-layer trust weaknesses that convert a single foothold into organization-wide reach: EternalBlue via a wormable exploit chain, this misconfiguration via LDAP relay against the credential store everything else depends on.

## Finding 015 — Synology NAS Management Interface Exposed, Backups Unencrypted (`NAS-01`)

- **Finding ID:** 015
- **Host:** 10.10.2.41 (`NAS-01`)
- **Misconfiguration:** The DSM web management interface (ports 5000/5001) is reachable from the entire internal network instead of being restricted to administrative IPs, and backup data is stored unencrypted.
- **Why No CVE:** Both facts describe administrative choices about network placement and encryption-at-rest settings that DSM exposes as configuration options — not a defect in Synology's DSM software itself. No vendor patch fixes "we didn't restrict the management VLAN" or "we didn't turn on backup encryption."
- **Severity Assessment:** **Critical** — I am rating this above the report's own "Medium" label. `NAS-01` is the #3 Top-5 Critical Asset (1x00 Task 8): MedDefense's only backup copy, untested for full disaster recovery, with no offsite replica. A network-reachable management interface on the organization's *last line of defense* against a ransomware event, combined with backups an attacker can simply read once inside, is a materially worse risk than "Medium" implies.
- **Cross-Reference 1x00:** Confirmed in the 1x00 Network Scan Summary, Anomaly #4 ("The NAS management interface... is accessible from the entire network") and directly matches GAP-003 (1x00 Task 12, rated **Critical** there): "Sole backup repository has no protection or redundancy of its own... A single ransomware event with lateral movement destroys production and the last-resort recovery copy simultaneously." The severity disagreement between this scan's "Medium" label and 1x00's own "Critical" gap rating on the *same asset* is itself worth flagging to James.
- **Comparable CVE Risk:** Comparable to **CVE-2008-4250 (MS08-067, Finding 004, CVSS 10.0)** — both require essentially zero attacker sophistication once inside the network (MS08-067 is fully wormable; this is just browsing to an open management port), and both threaten a resource MedDefense cannot easily replace if it fails — an EOL medical workstation, or the only backup in existence.

## Finding 016 — Medical Device HTTP Interfaces Accessible, No Authentication (Philips IntelliVue Fleet)

- **Finding ID:** 016
- **Host:** Multiple (10.10.3.10–32, 13 Philips IntelliVue monitors)
- **Misconfiguration:** Web management interfaces and the HL7 (port 2575) patient-data channel are reachable from the entire flat network, with no authentication layer beyond whatever the network itself provides — which, on a flat network, is none.
- **Why No CVE:** This is how these monitors ship and are deployed by design — network-based management and HL7 integration are intended features, not bugs. The absence of authentication and the absence of network segmentation are both deployment decisions, not defects in the Philips firmware itself.
- **Severity Assessment:** **High** — I am rating this above the report's own "Medium" label. The 1x00 Criticality Matrix (Task 8) rates the entire Medical IoT category **Critical** specifically because "integrity/availability failures here are not data problems — they are patient-safety problems." A finding touching 13 patient-vitals monitors, reachable network-wide, deserves that same weight rather than the generic "Medium" a vulnerability scanner assigns to a missing-authentication pattern it cannot contextualize clinically.
- **Cross-Reference 1x00:** Directly confirmed in the 1x00 Network Scan Summary, Anomaly #5 ("Medical Device Exposure"): *"All Philips monitors, BD Alaris pumps and other medical devices have HTTP/HTTPS management interfaces accessible from the entire network."* This also matches GAP-007 (1x00 Task 12, rated Critical): "Medical IoT devices share a flat network with no isolation."
- **Comparable CVE Risk:** Comparable to **CVE-2020-25165 (BD Alaris, Finding 010, CVSS 7.5)** — both are medical-IoT findings on the same flat network with the same root cause (GAP-007), one with a CVE because it is a specific firmware DoS condition, one without because it is "no authentication was ever configured." The absence of a CVE here does not make it less dangerous — arguably more so, since no firmware update from BD can ever fix a network design decision.

## Finding 025 — DNS Zone Transfer Enabled (`ad-dc-01`)

- **Finding ID:** 025
- **Host:** 10.10.2.20 (`ad-dc-01`)
- **Misconfiguration:** The DNS server permits zone transfers (AXFR) to any requester, rather than restricting them to designated secondary name servers.
- **Why No CVE:** Zone transfer is a legitimate, documented DNS protocol feature (used for legitimate primary-to-secondary replication); the vulnerability is entirely in *who is allowed to request it*, an access-control setting, not a flaw in the DNS server software.
- **Severity Assessment:** **Low**, matching the report's label — this finding does not by itself grant access to anything; it grants *knowledge* (hostnames, IP structure) that makes every other attack in this report easier to aim.
- **Cross-Reference 1x00:** The 1x00 Network Scan Summary shows port 53 open on `ad-dc-01`, confirming DNS was already an exposed service at the time of the original walk-through, though the zone-transfer-specific misconfiguration was never checked until this authenticated deep scan.
- **Comparable CVE Risk:** Comparable to **CVE-2021-43798 (Grafana path traversal, Finding 029, CVSS 7.5)** — both are reconnaissance-enabling findings that look individually minor but multiply the effectiveness of everything else in this report: a full DNS zone dump hands an attacker the exact hostname map (`ehr-db-01`, `backup-srv-01`, `NAS-01`...) needed to go straight for Findings 001, 003, 006 and 015 instead of scanning blind.

## Why "Our CVE Scan Shows Nothing Critical, We Are Secure" Is Dangerous

That statement conflates "no CVE-based finding above a threshold" with "no risk," and this analysis shows exactly how large that gap can be. Four of the six findings above carry **no CVE, no CVSS score, and no NVD or Exploit-DB entry at all** — meaning any prioritization process built purely around CVE/CVSS numbers would rank the direct, unauthenticated, network-wide exposure of the patient database (Finding 003) and the organization's only backup copy (Finding 015) as *invisible*, while a CVE-scored but ultimately less consequential finding might get all the remediation attention purely because it produces a number to sort by. The MongoDB Ransomware Wave (28,000 databases, zero CVEs) and the Capital One breach (100 million records, one misconfigured WAF rule) are not edge cases — they are the normal shape of how real breaches happen, because misconfigurations require no exploit development, no patch-Tuesday delay and no attacker sophistication at all: they are simply a door someone forgot to lock. A vulnerability management program that reports "clean" based on CVE counts alone is measuring one instrument on the dashboard and calling the whole aircraft safe.

## Repo

- **GitHub repository:** `dlh-cyber_security`
- **Directory:** `blue_team/1x02_the_weak_links`
- **File:** `6-misconfiguration_analysis.md`
