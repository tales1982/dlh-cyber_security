# 9. The OSINT Hunt — MedDefense Vulnerability Scan

**Analyst:** Threat Intelligence Analyst
**Date:** Current

## 1. FortiGate FortiOS — CVE-2026-24858

- **Source:** NVD (https://nvd.nist.gov/vuln/detail/CVE-2026-24858), corroborated by CISA's January 28, 2026 alert ("Fortinet Releases Guidance to Address Ongoing Exploitation of Authentication Bypass Vulnerability CVE-2026-24858") and independent reporting (SecurityAffairs, SOC Prime, Rapid7).
- **CVE:** CVE-2026-24858
- **Affected Product:** MedDefense's FortiGate 100F (A-020) — the single perimeter/routing chokepoint and VPN termination point for the entire Central site (1x00 Top-5 Critical Asset #4).
- **Why the Scan Missed It:** The 31-finding scan report contains **zero findings for the FortiGate itself** — every finding is about hosts *behind* the firewall. OpenVAS was scanning `10.10.0.0/16`, the internal address space; a perimeter appliance's own management-plane firmware version is a different kind of target that requires either credentials to the device itself or a dedicated Fortinet-aware plugin set actively pointed at the appliance. Nothing in the scan's methodology notes suggests the FortiGate's own FortiOS build was ever fingerprinted — this is a scope gap, not a "scanner missed a signature" gap.
- **CVSS / Severity:** 9.8 (Critical), vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. Published January 27, 2026. **Listed in CISA KEV** with confirmed active exploitation and an aggressive due date (January 30, 2026 — a 3-day window, one of the shortest CISA issues, reserved for the most urgent active-exploitation cases).
- **MedDefense Impact:** This is an authentication-bypass flaw affecting the FortiCloud SSO path across FortiOS, FortiManager, FortiAnalyzer and related products — meaning an attacker with any registered FortiCloud device/account could authenticate to other organizations' devices under the same conditions. If MedDefense's FortiGate 100F has FortiCloud SSO enabled, this is a path to the single device every other kill chain in 1x01 (Task 10) either passes through or depends on — Kill Chains #1 and #2 both name the FortiGate/VPN as the initial access point. A compromise here does not require phishing Sarah Park or buying a credential from a broker at all; it bypasses authentication outright.
- **Recommendation:** Immediately confirm the installed FortiOS build against the affected-version list (7.0.0–7.0.18, 7.2.0–7.2.12, 7.4.0–7.4.10, 7.6.0–7.6.5 for FortiOS specifically) and patch per Fortinet's advisory regardless of scan-report silence on this device. In parallel, disable FortiCloud SSO on the device if it is not strictly required, since that is the specific mechanism this flaw abuses.

## 2. Microsoft 365 / Entra ID — CVE-2025-55241 (Actor Token Cross-Tenant Impersonation)

- **Source:** NVD (https://nvd.nist.gov/vuln/detail/CVE-2025-55241), Microsoft's own advisory, and independent research writeups (Dirk-jan Mollema/Practical365, The Hacker News, September 2025 disclosure).
- **CVE:** CVE-2025-55241
- **Affected Product:** MedDefense's O365 E3 tenant, organization-wide (every user, since the flaw affects Microsoft's own backend identity infrastructure, not a customer-side configuration).
- **Why the Scan Missed It:** Explicitly and unambiguously out of scope — SecurePoint's own methodology notes state the scan "does NOT cover: cloud services (O365)." No on-premises vulnerability scanner can reach Microsoft's backend Access Control Service or Azure AD Graph API in the first place; this class of vulnerability lives entirely in Microsoft's cloud infrastructure and is invisible to any tool pointed at `10.10.0.0/16`.
- **CVSS / Severity:** 10.0 (Critical, the maximum possible score) — vulnerability was already fixed server-side by Microsoft before public disclosure in September 2025, since Microsoft controls the vulnerable backend directly and no customer-side patch was ever required.
- **MedDefense Impact:** This flaw allowed an attacker holding a legacy "Actor token" (a service-to-service authentication artifact) to impersonate **any user in any tenant, including Global Administrators**, while bypassing MFA, Conditional Access policies, and — critically — leaving no log trail of the impersonation. Had this been exploited against MedDefense's tenant before Microsoft's fix, an attacker could have obtained Global Admin-equivalent access to the entire O365 environment (email, SharePoint, Teams, and anything federated to Entra ID) with zero indicators for MedDefense's own security team to ever find, given the current absence of any centralized log review (GAP-002, 1x00 Task 12).
- **Recommendation:** Since Microsoft already patched this server-side, there is no remediation action required against the vulnerability itself. The real actionable lesson for MedDefense is structural: this flaw is a reminder that cloud-hosted identity infrastructure is a vendor-controlled attack surface entirely outside MedDefense's own scanning and patching program — the organization should request Microsoft's own security bulletins/Message Center notices be routed to James Chen's team specifically, since no internal tool will ever surface this category of risk on its own.

## 3. Synology DSM 7 — CVE-2024-10441

- **Source:** NVD (https://nvd.nist.gov/vuln/detail/CVE-2024-10441), Synology's own Product Security Advisory.
- **CVE:** CVE-2024-10441
- **Affected Product:** `NAS-01` (A-010) — MedDefense's Synology DSM 7 backup NAS, the #3 Top-5 Critical Asset (1x00 Task 8).
- **Why the Scan Missed It:** Finding 015 in the scan report already flags `NAS-01`'s DSM web interface as network-exposed — but **it never records a DSM version number anywhere**, unlike, for example, Finding 017, which explicitly lists "Apache Tomcat/9.0.31." The scanner correctly detected the *exposure* (an unauthenticated network-reachability issue) but appears to have never version-fingerprinted the *software running behind that exposed interface* — meaning even if this CVE has been patched, no one currently has evidence of that, and if it hasn't, the scan gives no warning at all.
- **CVSS / Severity:** 9.8 (Critical), vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. CWE-116 (Improper Encoding or Escaping of Output) in the "system plugin daemon," enabling remote code execution. Published March 18, 2025. Fixed in DSM 7.2-64570-4, 7.2.1-69057-6, and 7.2.2-72806-1 and later.
- **MedDefense Impact:** Finding 015 already establishes that this interface is reachable from the entire internal network and that backup data is stored unencrypted. If `NAS-01` is running a DSM build older than the fixed versions above, this CVE converts "reachable management interface" into "remote code execution on the organization's only backup copy" — the exact GAP-003 scenario (1x00 Task 12, rated Critical): "a single ransomware event with lateral movement destroys production and the last-resort recovery copy simultaneously," except this path doesn't even require ransomware elsewhere first — RCE on the NAS itself is sufficient.
- **Recommendation:** Confirm the exact DSM build number on `NAS-01` immediately (this alone closes the gap the scan left open) and patch to at least 7.2.2-72806-1 if it predates that build, independent of and in addition to the network-restriction and backup-encryption fixes already recommended for Finding 015.

## Repo

- **GitHub repository:** `dlh-cyber_security`
- **Directory:** `blue_team/1x02_the_weak_links`
- **File:** `9-osint_hunt.md`
