# 13. The Web Exposure — MedDefense Vulnerability Scan

**Analyst:** Threat Intelligence Analyst
**Date:** Current

## Host 1: `ehr-srv-01` (10.10.2.10)

- **Host:** `ehr-srv-01`, 10.10.2.10
- **Exposure:** Internal, but flat-network accessible — reachable from all 47 hosts scanned, not internet-facing directly (not listed on the 1x01 Task 7 Attack Surface Map's External Surface table).
- **Findings:** 017 (Tomcat default error page information disclosure, version 9.0.31 exposed), 030 (TLS certificate CN mismatch — already established as a false positive, Task 11), 031 (Ghostcat AJP file read/inclusion, CVE-2020-1938, CVSS 9.8, confirmed active).
- **Combined Risk:** One real Critical (031) directly preceded by the exact breadcrumb that revealed it (017). Finding 030 contributes nothing (a non-issue). Together, these three findings on one host tell a single story: a moderately-hardened web application server whose only genuinely dangerous flaw was invisible to automated scanning alone and only surfaced through manual follow-up on a "Medium" finding.
- **Attack Scenario:** Once any attacker gains a foothold anywhere on the flat network — via billing-srv-01's internet-facing RCE chain (Findings 001/002), via a phished VPN credential (Kill Chain #2), or via any other host — Ghostcat gives direct file-read access to `ehr-srv-01`'s configuration files, very likely exposing the database credentials for `ehr-db-01`. That directly compounds with Finding 003's already-open PostgreSQL access: an attacker would not even need the stolen credentials to matter, since the database already accepts connections from the whole `/16` — but stolen credentials would confirm and legitimize direct queries rather than relying on any default/weak authentication.
- **Priority:** **1st.** This is the only confirmed-active, CISA-KEV-listed, Exploitability-5 finding in the entire web-exposure set, sitting on the application server for MedDefense's single highest-criticality asset.

## Host 2: `billing-srv-01` (10.10.2.15)

- **Host:** `billing-srv-01`, 10.10.2.15
- **Exposure:** **Internet-facing** — 1x01 Task 6's own Threat Actor Matrix states directly that this Apache instance is exploited via "internet-facing unpatched service," consistent with two real prior external compromises (1x00 Tasks 1-2).
- **Findings:** 001 (CVE-2021-44790, unauthenticated buffer-overflow RCE, CVSS 9.8), 002 (CVE-2019-0211, local privilege escalation to root, CVSS 7.8).
- **Combined Risk:** A complete, two-finding chain from an anonymous internet request to root on the host — the only pair in this report that converts a web application flaw into full host takeover with no intermediate steps required.
- **Attack Scenario:** Matches **Kill Chain #4, Step 1** exactly (1x01 Task 10): "A mass internet scanner finds `billing-srv-01`'s exposed, unpatched Apache instance and exploits it automatically — the same vulnerability already used twice against MedDefense." From there, Kill Chain #4 continues into the flat network toward the medical IoT fleet.
- **Priority:** **2nd.** Internet-facing and empirically proven (twice), but the ultimate asset criticality (Billing & Financial, rated High, not Critical) and the fact that this is a known, already-analyzed recurring pattern place it just below the EHR server's unprecedented, KEV-listed exposure.

## Host 3: `NAS-01` (10.10.2.41)

- **Host:** `NAS-01`, 10.10.2.41
- **Exposure:** Internal, flat-network accessible — reachable from all 47 hosts, same category as `ehr-srv-01`.
- **Findings:** 015 (Synology DSM web management interface exposed on ports 5000/5001, backups stored unencrypted).
- **Combined Risk:** A single finding, but on the organization's sole backup repository — the DSM web interface is a *management* surface, meaning access here is not "read some data," it is "control the last line of defense against ransomware."
- **Attack Scenario:** Matches **Kill Chain #1, Step 4** exactly (1x01 Task 10): "NAS-01's management interface is used to delete backup jobs and stored backups before a GPO pushes the ransomware payload domain-wide." This is not an entry point — it is the *decisive* step of the environment's single highest-impact documented kill chain.
- **Priority:** **3rd.** Severe in ultimate consequence, but this finding functions as a late-stage objective for an attacker already executing a broader campaign, rather than an initial-access or standalone compromise path the way Findings 001/002/031 are.

## Host 4: `web-srv-01` (10.10.2.50, Patient Portal)

- **Host:** `web-srv-01`, 10.10.2.50
- **Exposure:** **Internet-facing** — hosts the public Patient Portal (A-018), the organization's only intentionally public-facing clinical application (1x00 Asset Registry; 1x01 Task 7 Attack Surface Map External Surface).
- **Findings:** 005 (TLS 1.0 enabled alongside TLS 1.2, CVSS 7.5), 012 (missing security headers — CSP, X-Frame-Options, HSTS, X-Content-Type-Options), 013 (SSL certificate expiring in 23 days), 021 (HTTP TRACE method enabled).
- **Combined Risk:** No single finding here grants direct compromise — this is a **hardening deficit**, not a code-execution path. But combined, they describe a public-facing patient application with: a downgrade-able transport layer (BEAST/POODLE-capable TLS 1.0), no defense-in-depth headers to blunt an XSS attempt if one is ever found, a TRACE method that would amplify credential theft from any future XSS, and a certificate that will start breaking access entirely in 23 days if unaddressed. This is also the same application that already suffered a real IDOR incident (1x00 Task 1, Incident B) — a hardening-weak portal with a documented history of a real, different vulnerability class.
- **Attack Scenario:** A MITM-positioned attacker (e.g., on public WiFi a patient is using) downgrades the connection to TLS 1.0 and intercepts session data; the missing security headers mean no HSTS enforcement blocks the downgrade and no CSP limits what an injected script could do if the portal's known IDOR-adjacent weaknesses are ever paired with an XSS finding. This matches the **Hacktivist** actor profile from 1x01 Task 6, for whom `web-srv-01`/Patient Portal is explicitly named as "the only symbolically public MedDefense asset."
- **Priority:** **4th (lowest of the four),** despite being internet-facing — none of these findings alone or combined provide a direct code-execution or data-access path the way the other three hosts' findings do. The one time-bound item (the certificate expiring in 23 days) deserves independent scheduling regardless of this ranking, since it is a hard deadline rather than a risk judgment call.

## Why Investigating "Medium" Version-Disclosure Findings Matters

Finding 017 was rated Medium and, taken alone, looks like exactly the kind of low-priority item a busy team might file away: a default error page revealing a Tomcat version number, "not directly exploitable" per the report's own text. But that single piece of version information (`Apache Tomcat/9.0.31`) is what told SecurePoint to specifically check whether the AJP connector was active — and manual verification confirmed it was, producing Finding 031, a confirmed-active CVSS 9.8. This demonstrates that **information-disclosure findings should be read as leads, not conclusions.** A version number by itself does nothing to an attacker or a defender — its value is entirely in what it lets either party check *next*. Dismissing Medium findings that reveal version or configuration detail, purely because the finding itself isn't "directly exploitable," would have meant this scan's single most dangerous confirmed vulnerability was never manually verified at all. The practical lesson for triage: any finding that narrows down exactly what software, version, or component is running behind an interface deserves a follow-up question — "given this specific version, what else might be true?" — even when its own severity label says otherwise.

## Repo

- **GitHub repository:** `dlh-cyber_security`
- **Directory:** `blue_team/1x02_the_weak_links`
- **File:** `13-web_exposure.md`
