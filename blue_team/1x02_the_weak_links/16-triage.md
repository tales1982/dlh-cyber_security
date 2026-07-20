# 16. The Noise Filter — MedDefense Vulnerability Scan

**Analyst:** Threat Intelligence Analyst
**Date:** Current

## Full Triage (All 31 Findings)

```
Finding 001 | CVSS 9.8 | billing-srv-01 | Category: AC | Reason: Unauthenticated RCE on an internet-facing host with confirmed real-world exploitation history (twice).
Finding 002 | CVSS 7.8 | billing-srv-01 | Category: AC | Reason: Completes the root-compromise chain with Finding 001 on the same internet-facing host.
Finding 003 | Critical (scanner) | ehr-db-01 | Category: AC | Reason: Direct, exploit-free network path to the full patient database, named explicitly in Kill Chain #5.
Finding 004 | Critical (scanner) | WS-RAD-01 | Category: AC | Reason: Three independently weaponized, KEV-listed RCEs on an unpatchable patient-safety device.
Finding 005 | CVSS 7.5 | web-srv-01 | Category: AS | Reason: Real downgrade-capable TLS weakness on the public portal, but requires a MITM position to matter.
Finding 006 | High (scanner) | billing-srv-01 | Category: AS | Reason: Same misconfiguration pattern as Finding 003 (CWE-1327), but on a High- rather than Critical-rated asset.
Finding 007 | High (scanner) | ad-dc-01 | Category: AC | Reason: LDAP relay + SMBv1 on the organization's #2 Top-5 Critical Asset threatens domain-wide compromise.
Finding 008 | High (scanner) | print-srv-01 | Category: AS | Reason: Weaponized PoC (PrintNightmare) exists, but the asset itself is independently rated Low risk (GAP-013).
Finding 009 | High (scanner) | billing-srv-01 | Category: AS | Reason: Enables brute-force credential attacks; real but requires an additional attack step to matter.
Finding 010 | CVSS 7.5 | BD Alaris fleet | Category: AS | Reason: Firmware version suggests the specific CVE may already be patched (needs vendor validation, Task 15), but default credentials and lack of network isolation are independently confirmed and unaddressed.
Finding 011 | High (scanner) | billing-srv-01 | Category: AC | Reason: Root enabler of Findings 001/002/026; Task 12 identifies this as the organization's top EOL-migration priority.
Finding 012 | Medium (scanner) | web-srv-01 | Category: I | Reason: Defense-in-depth headers missing, but no direct exploit path exists on their own.
Finding 013 | Medium (scanner) | web-srv-01 | Category: AS | Reason: Real, time-bound availability/trust issue with a hard 23-day deadline.
Finding 014 | Medium (scanner) | Westside router | Category: AS | Reason: Architecturally weak perimeter device terminating a site-to-site VPN; needs planned replacement, not emergency action.
Finding 015 | Medium (scanner) | NAS-01 | Category: AC | Reason: Named as the decisive step of Kill Chain #1; the organization's only backup copy is exposed and unencrypted.
Finding 016 | Medium (scanner) | Philips monitor fleet | Category: AC | Reason: Documented real-world capability (unauthenticated memory read/write) already exists for this exact device family; patient-safety asset.
Finding 017 | Medium (scanner) | ehr-srv-01 | Category: I | Reason: Information disclosure only; already served its purpose by leading directly to Finding 031's discovery.
Finding 018 | Medium (scanner) | ad-dc-01/02 | Category: AS | Reason: Weak Kerberos encryption enables offline credential cracking on the domain controllers.
Finding 019 | Medium (scanner) | Multiple (5 hosts) | Category: AS | Reason: Unjustified RDP exposure on reception/admin workstations and Westside server; brute-force target.
Finding 020 | CVSS 9.8 (scanner) | backup-srv-01 | Category: FP | Reason: Requires ssh-agent forwarding to an attacker-controlled host, an implausible usage pattern for this server; SecurePoint's own note and Task 11 validation confirm.
Finding 021 | Medium (scanner) | web-srv-01 | Category: I | Reason: Low-risk in isolation per the report's own text; only relevant if paired with a future XSS finding.
Finding 022 | Low (scanner) | ehr-srv-01 | Category: FP | Reason: 47-second clock skew is far inside Kerberos/TLS tolerance thresholds; confirmed non-issue in Task 11.
Finding 023 | Low (scanner) | ~280 workstations | Category: AS | Reason: Real, broad exfiltration/malware-entry vector across clinical endpoints; needs a GPO fix, not urgent individually.
Finding 024 | Low (scanner) | pacs-srv-01 | Category: AS | Reason: Cleartext DICOM traffic exposes patient identifiers and imaging in transit.
Finding 025 | Low (scanner) | ad-dc-01 | Category: I | Reason: Reconnaissance-enabler only; no direct access granted by the finding itself.
Finding 026 | Low (scanner) | billing-srv-01 | Category: AS | Reason: 47 unpatched kernel CVEs, resolved by the same ESM enrollment that fixes Finding 011.
Finding 027 | Informational (scanner) | 15 workstations | Category: AS | Reason: Endpoint protection silently inactive on 15 hosts with no one having noticed; a concrete, low-cost fix (restore agent reporting) exists.
Finding 028 | Informational (scanner) | 10.10.2.99 (unknown) | Category: AS | Reason: Undocumented Linux host with open SSH/Jupyter/Cockpit on the server subnet needs identification and disposition, not just a note.
Finding 029 | Informational (scanner) | 10.10.10.200 (Westside, unknown) | Category: AC | Reason: A real, trivial, unauthenticated CVE (CVE-2021-43798, CVSS 7.5) sits on a completely unmonitored shadow-IT device — nobody would notice exploitation.
Finding 030 | Informational (scanner) | ehr-srv-01 | Category: FP | Reason: Report itself states this is operational, not a security vulnerability; confirmed in Task 11.
Finding 031 | High (scanner) | ehr-srv-01 | Category: AC | Reason: Confirmed-active, CISA-KEV-listed CVSS 9.8 on the application server for the organization's single highest-value asset — the single most urgent finding in the report despite its "High" label.
```

## Triage Summary

| Category | Count |
|---|---|
| Actionable Critical (AC) | 10 |
| Actionable Standard (AS) | 14 |
| Informational (I) | 4 |
| False Positive (FP) | 3 |
| **Total** | **31** |

## Actionable Findings List (Sorted by Priority)

### Actionable Critical — Immediate Remediation (24-48h)

1. **Finding 031** — Ghostcat (CVE-2020-1938), `ehr-srv-01` — confirmed active, KEV-listed, crown-jewel asset.
2. **Finding 003** — PostgreSQL unrestricted access, `ehr-db-01` — no exploit needed, named in an existing kill chain.
3. **Finding 001** — Apache mod_lua RCE (CVE-2021-44790), `billing-srv-01` — internet-facing, proven exploitation history.
4. **Finding 002** — Apache privilege escalation (CVE-2019-0211), `billing-srv-01` — completes the root chain with Finding 001.
5. **Finding 004** — Windows XP EOL bundle, `WS-RAD-01` — three wormable RCEs on an unpatchable patient-safety device.
6. **Finding 015** — NAS-01 exposure — the sole backup copy, decisive step of Kill Chain #1.
7. **Finding 016** — Medical device HTTP interfaces, Philips fleet — documented real-world memory read/write capability.
8. **Finding 007** — LDAP signing/SMBv1, `ad-dc-01` — domain-wide compromise path on the #2 Top-5 Critical Asset.
9. **Finding 029** — Grafana path traversal (CVE-2021-43798), Westside shadow IT — trivial exploit, zero monitoring.
10. **Finding 011** — Ubuntu 18.04 EOL, `billing-srv-01` — root enabler of Findings 001/002/026; top migration priority (Task 12).

### Actionable Standard — Scheduled Remediation (7-30 days)

1. **Finding 026** — Outdated kernel, `billing-srv-01` (resolved alongside Finding 011).
2. **Finding 006** — MySQL unrestricted binding, `billing-srv-01`.
3. **Finding 009** — SSH password authentication, `billing-srv-01`.
4. **Finding 018** — Weak Kerberos encryption, `ad-dc-01`/`ad-dc-02`.
5. **Finding 008** — Windows Server 2012 R2 EOL / PrintNightmare, `print-srv-01`.
6. **Finding 010** — BD Alaris default credentials / missing isolation (CVE status pending vendor validation).
7. **Finding 019** — RDP enabled, 5 hosts.
8. **Finding 024** — Cleartext DICOM, `pacs-srv-01`.
9. **Finding 028** — Unidentified device, `10.10.2.99`.
10. **Finding 013** — SSL certificate expiring in 23 days, `web-srv-01`.
11. **Finding 014** — Consumer-grade router, Westside.
12. **Finding 027** — Inactive Sophos agents, 15 workstations.
13. **Finding 023** — Unrestricted USB storage, ~280 workstations.
14. **Finding 005** — TLS 1.0 enabled, `web-srv-01`.

## Repo

- **GitHub repository:** `dlh-cyber_security`
- **Directory:** `blue_team/1x02_the_weak_links`
- **File:** `16-triage.md`
