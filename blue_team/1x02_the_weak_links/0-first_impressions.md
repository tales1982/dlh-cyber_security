
# 0. First Impressions Summary MedDefense Vulnerability Scan

**Analyst:** Threat Intelligence Analyst
**Date:** Current

## 1. Scan Metadata

- **Scanner:** OpenVAS 22.x (Greenbone Community Edition)
- **Scope:** 10.10.0.0/16 all internal subnets (Central and Westside)
- **Scan Policy:** Full and Deep, authenticated where credentials were available
- **Requested by:** James Chen, Deputy CISO
- **Executed by:** SecurePoint Consulting (third party)
- **Window:** 02:00–06:00, off-peak hours, to avoid clinical disruption
- **Hosts scanned:** 47 responsive hosts

**Authentication coverage was not uniform.** Linux servers (SSH) and Windows systems (domain credentials) were scanned authenticated; medical devices were scanned **unauthenticated**, since no credentials were available for them. That single fact should lower confidence in the medical-device findings (010, 016, 024) relative to the server findings an unauthenticated scan of a device fleet that already carries default credentials (Finding 010) can only see what is exposed on the network, not what is misconfigured underneath.

**What was explicitly NOT scanned** (per SecurePoint's own methodology notes):

- Cloud services (Microsoft O365)
- Mobile devices (iPads)
- Any asset that was offline during the scan window

## 2. Finding Distribution

| Severity        | Header Count | Actual Count (by reading each finding) |
| --------------- | ------------ | -------------------------------------- |
| Critical        | 4            | 4                                      |
| High            | 7            | **8**                            |
| Medium          | 11           | **10**                           |
| Low             | 5            | 5                                      |
| Informational   | 4            | 4                                      |
| **Total** | **31** | **31**                           |

The header's severity breakdown does not reconcile with the individual findings, even though both add up to 31. Counting the findings by hand: 001–004 are Critical (4), 005–011 are High (7), 012–021 are Medium (10, not 11), 022–026 are Low (5), 027–030 are Informational (4) that is 30 findings, matching a report that originally had **30** automated findings, not 31. **Finding 031** was appended afterward as "Added by SecurePoint Manual Finding," rated **High**, and the header summary was never updated to reflect it. The header's "11 Medium" appears to be the artifact of a report that was drafted for 30 findings and then had one High-severity manual finding bolted on without a header revision the true distribution is 4 Critical / **8 High** / 10 Medium / 5 Low / 4 Informational.

This matters beyond arithmetic pedantry: Finding 031 carries a CVSS of 9.8, sits on `ehr-srv-01`  the application server for the single highest-value asset in the environment and confirms an *active* AJP connector with a public PoC. If a reader trusted the header's "7 High, no changes" and moved straight to the four Critical items, they would miss the one finding that most needed their attention. **Medium** has the most header-stated findings (11), but **High** has the most actual findings once 031 is counted correctly (8), and it is the single most severe of them.

## 3. Asset Heat Map

Ranking hosts by number of *distinct finding entries* that name them individually (excluding entries that group many devices under one line, which are called out separately below):

| Rank | Host                            | Findings                     | Count               | Asset Registry Role (1x00 T7)                                                                                                                                                                 |
| ---- | ------------------------------- | ---------------------------- | ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | `billing-srv-01` (10.10.2.15) | 001, 002, 006, 009, 011, 026 | **6**         | A-004 Billing/claims server. Already compromised**twice** before this scan (ransomware in 1x00 Task 1, cryptominer in Task 2), both times through this same unpatched Apache instance. |
| 2    | `web-srv-01` (10.10.2.50)     | 005, 012, 013, 021           | 4                   | A-011 Hosts the Patient Portal (A-018), which already suffered a broken-access-control/IDOR incident (1x00 Task 1, Incident B).                                                              |
| 2    | `ehr-srv-01` (10.10.2.10)     | 017, 022, 030, 031           | 4                   | A-001 EHR application server. Part of the#1 Top-5 Critical Asset pairing (with `ehr-db-01`, 1x00 Task 8).                                                                                  |
| 4    | `ad-dc-01` (10.10.2.20)       | 007, 018, 025                | 3                   | A-005 Primary domain controller.#2 Top-5 Critical Asset the trust anchor for every domain login (1x00 Task 8).                                                                              |
| 5    | `WS-RAD-01` (10.10.1.70)      | 004                          | 1 (bundling 3 CVEs) | A-014 MRI scanner control, Windows XP SP3, explicitly cannot be patched, upgraded, replaced or disconnected (1x00 Task 6).                                                                   |

`WS-RAD-01` earns the 5th spot on severity density rather than raw count: its single finding bundles **three** independently weaponized, CVSS-8+ CVEs (EternalBlue, BlueKeep, MS08-067) on one host with zero possibility of remediation through patching a different (and arguably worse) kind of concentration than a host with many low-value findings.

Two multi-host findings deserve a mention outside the ranking because of scale rather than per-host count: **Finding 023** (USB mass storage unrestricted) affects roughly **280 workstations**, and **Finding 016** (medical device HTTP interfaces) affects **13** Philips monitors both single line items in the report, both far larger in blast radius than any single top-5 host.

## 4. First Observations

- **The two `billing-srv-01` Criticals are not independent they are a chain.** Finding 001 (CVE-2021-44790, unauthenticated RCE as `www-data`) and Finding 002 (CVE-2019-0211, local privesc to root) sit on the same host, on the same Apache instance, and the report says so explicitly. Read together, they describe a path from "anonymous internet request" to "root on the billing server" using only two findings.
- **This is the third time this exact door has been used.** The Asset Registry (1x00 T7) already notes `billing-srv-01` was compromised twice the January ransomware and a cryptominer both via the same unpatched Apache 2.4.29. Findings 001/002/006/009/011/026 are not new risk; they are the same unresolved root cause (GAP-008, "billing server weak coverage despite two prior compromises") showing up for a third round in a formal scan.
- **The scan's own severity labels are inconsistent with actual exploitability.** Finding 003 (PostgreSQL open to the whole /16, on the database holding 50,000+ patient records) is rated Critical with no CVSS score at all, because it is a misconfiguration rather than a CVE. Finding 031 (Ghostcat, CVSS 9.8, confirmed active, on the EHR application server, public PoC) is rated only High. A severity list sorted by label alone would deprioritize a confirmed, actively-exploitable 9.8 in favor of unscored "Critical" misconfigurations label and actual risk do not move together here.
- **Finding 031 exists only because a human went back and checked.** Finding 017 flagged that the scanner *could not confirm* whether Tomcat's AJP connector was active and recommended manual verification. SecurePoint did that manually and found it live meaning the fully-automated pass alone would have missed the single most dangerous confirmed vulnerability in the entire report, on the crown-jewel asset.
- **Shadow IT reappears, and this time with a concrete exploit path.** `10.10.2.99` (Finding 028) and the Westside device at `10.10.10.200` (Finding 029) are both already known as undocumented shadow IT from the 1x00 Asset Registry (A-012, A-025). What is new here is specificity: the Westside device is running **Grafana 8.2.0**, which has a known, trivially-exploitable, unauthenticated path traversal (CVE-2021-43798). Shadow IT stopped being an abstract governance gap the moment the scan attached a real CVE to it.
- **The medical-device findings are symptoms of one already-known cause, not four separate problems.** Finding 004 (MRI on Windows XP), Finding 010 (Alaris pumps with default credentials), Finding 016 (Philips monitors with open web interfaces) and Finding 024 (PACS DICOM in cleartext) span Critical to Low in the report's own labeling, but all four exist because of the same flat, unsegmented clinical network already flagged as GAP-007 in the 1x00 Gap Analysis. Fixing any one device does nothing; the shared network is the actual finding.
- **SecurePoint flagged one of its own findings as a probable false positive** Finding 020 (CVE-2023-38408 on `backup-srv-01`) requires ssh-agent forwarding to an attacker-controlled host to be exploitable, which the vendor itself says is unlikely in this environment. This is a useful reminder from the project's own framing: not everything in red is real, and the vendor already did some of that filtering for us.
- **What surprised me most** was not any single finding but the header/body mismatch described in Section 2 a scan report is itself a document that can contain an error, and the discipline of counting instead of trusting the summary caught something the summary missed.

## 5. Scan Limitations

- **No cloud coverage.** Microsoft O365, which hosts MedDefense email (a documented external surface in 1x01 Task 7), is entirely outside this scan's scope. Business Email Compromise and phishing the vector behind Kill Chain #1 (1x01 Task 10) cannot be assessed from this data.
- **No mobile device coverage.** iPads used clinically are unassessed.
- **Offline assets are invisible.** Anything powered off during the 02:00–06:00 window (including, potentially, the still-unconfirmed "second Westside server" noted in the 1x00 Asset Registry) would not appear here at all its absence from this report is not evidence it doesn't exist.
- **No active exploitation was attempted.** Every finding is version detection, configuration analysis, or authenticated checks none of the 31 findings have been confirmed exploitable in this specific environment through an actual proof-of-concept run. Confidence still varies finding to finding (compare Finding 031, manually verified, against Finding 020, flagged as a likely false positive).
- **Unauthenticated scanning of medical devices** means the Alaris, Philips and PACS findings reflect only what is visible from the network layer; firmware-level or configuration-level issues on those devices that would require credentials to see are not represented here.
- **This is a snapshot, not a monitoring feed.** As James put it directly: it tells us what the scanner found on one night last week. CVEs disclosed after the scan date, or a misconfiguration introduced the next morning, are both invisible to this document by definition vulnerability management from here on has to be continuous, not a one-time report.
- **Human and physical vectors are out of scope by design.** Social engineering, tailgating, and process gaps (already covered in 1x01's Human Vector and Attack Surface tasks) are not something a network vulnerability scanner measures at all this report is one input among several, not the whole picture.
