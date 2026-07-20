# 20. The Priority Matrix — MedDefense Vulnerability Scan

**Analyst:** Threat Intelligence Analyst
**Date:** Current

*Covers all 24 Actionable findings from Task 16 (10 Actionable Critical + 14 Actionable Standard). False Positives (020, 022, 030) and Informational findings (012, 017, 021, 025) are excluded — already documented and dismissed/monitored per Tasks 11 and 16.*

## Immediate — 24-48 Hours

| Finding | Description | Remediation Action | Owner | Cost |
|---|---|---|---|---|
| 031 | Ghostcat (CVE-2020-1938), confirmed active on `ehr-srv-01` | Disable/restrict the Tomcat AJP connector | IT/Security | $0-1K |
| 003 | PostgreSQL open to the entire `/16` on `ehr-db-01` | Restrict `pg_hba.conf` to `ehr-srv-01` only | IT/Security | $0-1K |
| 001 | Apache mod_lua RCE on internet-facing `billing-srv-01` | Enroll Ubuntu Pro/ESM, apply emergency Apache patch | IT | $1-10K |
| 002 | Apache privilege escalation, same host/chain as 001 | Resolved by the same patch as Finding 001 | IT | $0 (covered above) |
| 029 | Grafana path traversal on unmonitored Westside device | Block network access pending ownership investigation | Security | $0-1K |

## Short-term — 7 Days

| Finding | Description | Remediation Action | Owner | Cost |
|---|---|---|---|---|
| 007 | LDAP signing not required + SMBv1 on `ad-dc-01` | Enforce LDAP signing, disable SMBv1 | IT | $0-1K |
| 015 | NAS-01 management interface exposed, backups unencrypted | Restrict DSM interface to admin subnet, enable backup encryption | IT | $0-1K |
| 018 | Weak Kerberos encryption (DES/RC4) on domain controllers | Disable weak encryption types via GPO | IT | $0-1K |
| 026 | 47 unpatched kernel CVEs on `billing-srv-01` | Resolved by the same ESM enrollment as Finding 001 | IT | $0 (covered above) |
| 006 | MySQL bound to 0.0.0.0 on `billing-srv-01` | Bind to localhost/restrict to app server IPs | IT | $0-1K |
| 009 | SSH password authentication enabled on `billing-srv-01` | Enforce key-only authentication | IT | $0-1K |
| 013 | SSL certificate expiring in 23 days on `web-srv-01` | Renew certificate, configure auto-renewal | IT | $0-1K |

## Medium-term — 30 Days

| Finding | Description | Remediation Action | Owner | Cost |
|---|---|---|---|---|
| 004 | Windows XP EOL bundle (3 weaponized CVEs) on MRI workstation | Implement network segmentation (1x00 Control 1) | IT | $10-50K |
| 010 | BD Alaris default credentials, no network isolation | Reset default credentials; validate firmware version against BD advisory | Clinical Engineering/IT | $0-1K |
| 019 | RDP enabled unjustified on 5 hosts | Restrict/disable RDP, confirm NLA enforcement | IT | $0-1K |
| 024 | DICOM traffic unencrypted, `pacs-srv-01` | Enable DICOM TLS or isolate PACS traffic | IT/Vendor | $1-10K |
| 028 | Undocumented Linux host on server subnet | Identify owner, decommission or formally onboard | Security | $0-1K |
| 027 | Sophos agent inactive on 15 workstations | Reinstall/re-enable endpoint agents | IT | $0-1K |
| 023 | USB mass storage unrestricted, ~280 workstations | Deploy USB-restriction GPO | IT | $0-1K |
| 005 | TLS 1.0 enabled on `web-srv-01` (Patient Portal) | Disable TLS 1.0/1.1, enforce TLS 1.3 | IT | $0-1K |

## Long-term — 90 Days

| Finding | Description | Remediation Action | Owner | Cost |
|---|---|---|---|---|
| 011 | Ubuntu 18.04 EOL, `billing-srv-01` | Full OS migration (ESM is the interim step, already funded above) | IT | $0 (ESM already covers the interim; migration cost tracked separately if pursued) |
| 016 | Philips monitor fleet reachable network-wide | Extend medical IoT VLAN segmentation (GAP-007 Phase 2) | IT + Clinical Engineering | $10-50K |
| 014 | Consumer-grade router at Westside Clinic | Replace with enterprise-grade firewall/router | IT | $1-10K |
| 008 | Windows Server 2012 R2 EOL, `print-srv-01` | Replace/upgrade print server OS | IT | $1-10K |

## Budget Summary

Using the midpoint of each cost bracket ($500 for $0-1K, $5,500 for $1-10K, $30,000 for $10-50K) for a working estimate:

| Horizon | Estimated Cost |
|---|---|
| Immediate | ~$7,000 |
| Short-term | ~$3,000 |
| Medium-term | ~$38,500 |
| Long-term | ~$41,000 |
| **Total (working estimate)** | **~$89,500** |
| **Range (bracket floor to ceiling)** | **~$24,000 to ~$155,000** |

**Comparison to the $120,000 annual security budget:** This total cannot be evaluated against the full $120,000 in isolation — the 1x00 Task 14 Risk Treatment Decisions already committed **~$80,400** of this fiscal year's budget to that project's own prioritized gaps (SIEM deployment, cloud backup replication, the BD Alaris pump VLAN, the network closet fix, PACS badge authentication, and the `ehr-db-01` firewall rule), leaving only **~$39,600** genuinely uncommitted — and that remainder was already earmarked in 1x00 for GAP-005 (server antivirus coverage).

**What fits, and what doesn't:** The **Immediate and Short-term horizons together cost only ~$10,000** — comfortably inside the ~$39,600 that remains, with room to spare. This is the single most important number in this budget summary: closing every genuinely urgent, actively-exploitable finding from this entire vulnerability assessment does **not** require new money and does **not** require touching GAP-005's already-planned antivirus spend. The **Medium-term horizon (~$38,500)**, however, essentially consumes what would be left after that — driven almost entirely by one item, the MRI network segmentation (Finding 004, ~$30,000). The **Long-term horizon (~$41,000)** — Philips fleet segmentation and the two remaining EOL replacements — has **no funding source left in this fiscal year at all**.

**What must be deferred, and why:** Given the ~$39,600 remaining budget, the recommended sequence is: (1) fund Immediate + Short-term now (~$10,000, leaving ~$29,600), (2) reallocate the remaining ~$29,600 toward Finding 004's MRI segmentation rather than GAP-005's antivirus rollout — this scan's findings make a stronger case for urgency than server AV coverage does, since Finding 004 involves three KEV-listed, wormable RCEs on an unpatchable patient-safety device, compared to GAP-005's defense-in-depth value on already-backed-up servers. This still leaves an ~$8,900 shortfall on Finding 004 alone, and the entire Long-term horizon (~$41,000: Philips segmentation, Westside router, print server replacement) has zero funding this cycle. **Recommendation to James Chen:** request supplemental budget for the Long-term horizon items now, framed explicitly around this assessment's findings (a documented real-world memory read/write capability on patient monitors, and two systems that will remain permanently unpatchable until replaced) rather than waiting for the next annual budget cycle to raise it — the cost of asking is a conversation; the cost of not asking is another year of exactly the exposure this report documents.

## Repo

- **GitHub repository:** `dlh-cyber_security`
- **Directory:** `blue_team/1x02_the_weak_links`
- **File:** `20-priority_matrix.md`
