# Hardening Updates: IR-2026-0414-01

- **Case:** LH-2026-0414-01
- **Inputs:** `gap_analysis.md` (Gap IDs), `control_effectiveness.yaml`, `forensic_findings_summary.md`
- **Scope:** MedDefense clinical and administrative Windows workstations (OU `MEDDEFENSE/Workstations/Clinical` and `/Admin`), VPN gateway, Azure AD tenant
- **Rollout rule:** every change goes to a pilot group (IT + 10 clinical workstations) in audit mode for 7 days, then enforce. Each change has an owner, a deadline and a validation test.

| ID | Control | Closes | Owner | Deadline |
|---|---|---|---|---|
| HRD-001 | PowerShell Constrained Language Mode | GAP-007, GAP-006 | Endpoint Engineering | 2026-11-20 |
| HRD-002 | AppLocker rule restricting MSBuild.exe | GAP-006 | Endpoint Engineering | 2026-11-20 |
| HRD-003 | Conditional access for VPN from new geographies | GAP-004, GAP-001, GAP-003 | Identity Team | 2026-11-06 |
| HRD-004 | Windows Defender Credential Guard | GAP-011, GAP-015 | Endpoint Engineering | 2026-12-04 |
| HRD-005 | LSA Protection + ASR lsass rule | GAP-011 | Endpoint Engineering | 2026-11-13 |
| HRD-006 | Block inbound SMB between workstations | GAP-013 | Network Team | 2026-11-13 |

---

## HRD-001: PowerShell Constrained Language Mode

**Closes:** GAP-007, GAP-006
**Evidence:** ART-002-M01 (`powershell.exe -ep bypass -w hidden -enc` PID 7812 wrote `update.xml` and launched `MSBuild.exe` PID 8104); same chain on WST-WS-017 (ART-003-M01)

**Configuration:**

- GPO: `MEDDEFENSE-WKS-PowerShell-CLM`, linked to `OU=Clinical,OU=Workstations` and `OU=Admin,OU=Workstations`
- GPO path: Computer Configuration > Preferences > Windows Settings > Registry
- Key: `HKLM\System\CurrentControlSet\Control\Session Manager\Environment`
- Value name: `__PSLockdownPolicy`
- Value type: `REG_SZ`
- Value data: `4`
- Item-level targeting: apply only when the user is **not** a member of `BUILTIN\Administrators` (so admin sessions keep Full Language)
- Companion settings (same GPO), Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell:
  - Turn on PowerShell Script Block Logging: **Enabled** (Event 4104)
  - Turn on Module Logging: **Enabled**, module names `*`
- Remove PowerShell 2.0 engine (it bypasses CLM and AMSI): `Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root`

**Effect:** Restricts PowerShell to Constrained Language Mode for standard users; blocks `[System.Management.Automation.ScriptBlock]::Create`, `Add-Type`, .NET type instantiation, COM object creation and `Invoke-Expression` of reflective loaders used in LOLBin proxy techniques like the one in this incident.

**Note:** `__PSLockdownPolicy` alone can be removed by an admin-level attacker. CLM becomes tamper-resistant when PowerShell detects an enforced AppLocker/WDAC script policy, so HRD-002 is deployed together with this change and enforces CLM automatically for scripts not allowed by policy.

**Applies to:** Non-administrative accounts on all clinical and administrative workstations (dmarsh class accounts).

**Validation:** As a standard user run `$ExecutionContext.SessionState.LanguageMode`; expected output: `ConstrainedLanguage`. Then `[System.Management.Automation.ScriptBlock]::Create('1')` must fail with "Cannot invoke method. Method invocation is supported only on core types in this language mode".

---

## HRD-002: AppLocker rule restricting MSBuild.exe

**Closes:** GAP-006
**Evidence:** ART-001-E01 (first-ever MSBuild run on WST-WS-031), ART-002-M01, ART-002-M03 (in-memory MZ implant in MSBuild PID 8104), ART-003-M01 (MSBuild on WST-WS-017)

**Configuration:**

- GPO: `MEDDEFENSE-WKS-AppLocker`, linked to `OU=Clinical,OU=Workstations` and `OU=Admin,OU=Workstations` (developer OU `OU=Engineering` keeps its own policy for WST-WS-042 / WST-WS-051)
- GPO path: Computer Configuration > Windows Settings > Security Settings > Application Control Policies > AppLocker > Executable Rules
- Service: Computer Configuration > Windows Settings > Security Settings > System Services > **Application Identity (AppIDSvc): Automatic**
- Enforcement: Executable rules **Audit only** for 7 days (review Event 8003 in `Microsoft-Windows-AppLocker/EXE and DLL`), then **Enforce rules**
- Logic: AppLocker deny rules override allow rules for every user, so MSBuild cannot be denied for Everyone and then allowed for admins. Instead:
  1. The default `%WINDIR%\*` allow rule for Everyone gets **exceptions** for `MSBuild.exe` (all paths and publisher), so standard users have no rule allowing it (implicit deny).
  2. A separate **allow** rule permits `MSBuild.exe` only to `BUILTIN\Administrators` (S-1-5-32-544) and the CI/CD group `MEDDEFENSE\GG-CICD-ServiceAccounts` (members: `svc-build01`, `svc-azdo-agent`).
  3. Also deny execution from user-writable paths used in this incident: no allow rule covers `%LOCALAPPDATA%\Temp\*` or `%USERPROFILE%\Downloads\*`, so `update.exe` is blocked.

**Rule XML structure:**

```xml
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">

    <!-- Default Windows rule for Everyone, with MSBuild carved out -->
    <FilePathRule Id="a61c8b2c-a319-4cd0-9690-d2177cad7b51"
                  Name="(Default) All files in Windows folder, except MSBuild"
                  Description="Allow Windows binaries, MSBuild excluded (IR-2026-0414-01)"
                  UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*" />
      </Conditions>
      <Exceptions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"
                                ProductName="*" BinaryName="MSBUILD.EXE">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
        <FilePathCondition Path="%WINDIR%\Microsoft.NET\Framework\*\MSBuild.exe" />
        <FilePathCondition Path="%WINDIR%\Microsoft.NET\Framework64\*\MSBuild.exe" />
      </Exceptions>
    </FilePathRule>

    <!-- Default Program Files rule for Everyone, MSBuild (Visual Studio copies) carved out -->
    <FilePathRule Id="921cc481-6e17-4653-8f75-050b80acca20"
                  Name="(Default) All files in Program Files, except MSBuild"
                  UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*" />
      </Conditions>
      <Exceptions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"
                                ProductName="*" BinaryName="MSBUILD.EXE">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Exceptions>
    </FilePathRule>

    <!-- MSBuild allowed only for local Administrators -->
    <FilePublisherRule Id="5e3d1a0f-6c2b-4f7e-9a41-0b8d2c7e6f10"
                       Name="MSBuild.exe - BUILTIN\Administrators only"
                       UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"
                                ProductName="*" BinaryName="MSBUILD.EXE">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>

    <!-- MSBuild allowed for named CI/CD service accounts (group SID resolved at import) -->
    <FilePublisherRule Id="8b7f2c44-1d9e-4a63-b2f0-6e5c3a9d1e27"
                       Name="MSBuild.exe - GG-CICD-ServiceAccounts"
                       UserOrGroupSid="S-1-5-21-MEDDEFENSE-DOMAIN-SID-RID-GG-CICD" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"
                                ProductName="*" BinaryName="MSBUILD.EXE">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>

    <!-- Admins keep full access (default rule) -->
    <FilePathRule Id="fd686d83-a829-4351-8ff4-27c7de5755d2"
                  Name="(Default) All files for Administrators"
                  UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions>
        <FilePathCondition Path="*" />
      </Conditions>
    </FilePathRule>

  </RuleCollection>
</AppLockerPolicy>
```

Replace `S-1-5-21-MEDDEFENSE-DOMAIN-SID-RID-GG-CICD` with the SID from `(Get-ADGroup GG-CICD-ServiceAccounts).SID.Value` before import. Apply the same exception/allow pattern for `csc.exe`, `InstallUtil.exe`, `RegAsm.exe` and `RegSvcs.exe` (LOLBAS list used in the Task 3 Sigma rule).

**Applies to:** All clinical and administrative workstations. Developer and build hosts are excluded by OU and covered by the R1/R2 detections.

**Validation:**
`Get-AppLockerPolicy -Effective | Test-AppLockerPolicy -Path C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe -User MEDDEFENSE\dmarsh`
expected `PolicyDecision: Denied`; the same test with `-User MEDDEFENSE\svc-build01` returns `Allowed`. On a pilot host, running `msbuild.exe` as a standard user logs Event 8004 (blocked).

---

## HRD-003: Conditional access policy for VPN authentication from new geographies

**Closes:** GAP-004, GAP-001, GAP-003
**Evidence:** Azure AD sign-in as dmarsh from 45.63.9.88 (RU) at 2026-04-13T18:14:41Z with the risk signal suppressed by the "compliant device" rule (forensic summary open item 2); VPN logon from the same RU IP at 2026-04-14T02:44:17Z with MFA approved (control_effectiveness.yaml phase 2)

**Configuration:**

- VPN gateway authentication moved to Azure AD (SAML enterprise app `MedDefense-VPN`), so Conditional Access evaluates every VPN logon. Legacy RADIUS path disabled; if RADIUS is kept, use the NPS extension for Azure AD MFA.
- Named location `ML-Approved-Countries`: United States (country of operation) + any country explicitly approved for named travellers.
- Per-user 30-day country history: SIEM job `vpn_geo_baseline` (runs every 15 min) builds `user -> set(countries seen in successful VPN/Azure AD sign-ins over the last 30 days)` and writes accounts with a new country into the Azure AD group `CA-NewGeo-StepUp` (membership expires after 24 h or after a successful step-up).
- Excluded from all policies: two break-glass accounts only (`bg-admin01`, `bg-admin02`), monitored by a separate alert. The "compliant device" exclusion that suppressed the risk signal is **removed**.

**Policy logic:**

```text
POLICY CA-VPN-01  "VPN - block non-approved countries"
  Users:        All users (exclude break-glass)
  Cloud app:    MedDefense-VPN
  Conditions:   Location NOT IN ML-Approved-Countries
  Grant:        BLOCK

POLICY CA-VPN-02  "VPN - step-up on new geography"
  Users:        Group CA-NewGeo-StepUp
                (country of this sign-in NOT IN countries seen for this account in prior 30 days)
  Cloud app:    MedDefense-VPN
  Conditions:   Any location
  Grant:        Require authentication strength "Phishing-resistant MFA" (FIDO2 / Windows Hello)
                AND require device marked compliant (Intune)
  Session:      Sign-in frequency = every time

POLICY CA-RISK-01 "All apps - sign-in risk"
  Users:        All users (exclude break-glass)
  Cloud app:    All cloud apps (includes MedDefense-VPN and Office 365)
  Conditions:   Sign-in risk = Medium or High (atypical travel, impossible travel, unfamiliar sign-in properties)
  Grant:        High -> BLOCK ; Medium -> require phishing-resistant MFA + password change
  State:        On (not report-only)

Decision order for a VPN logon:
  1. country not approved          -> BLOCK (CA-VPN-01)
  2. sign-in risk high             -> BLOCK (CA-RISK-01)
  3. country new for this account  -> step-up: FIDO2 + compliant device (CA-VPN-02)
  4. otherwise                     -> normal MFA (number matching)
  Every BLOCK or step-up result     -> SIEM alert "VPN new geography" (high) to the SOC queue
```

**Applies to:** All MedDefense user accounts using VPN or Azure AD.

**Validation:** In Entra admin center run **What If** for user `dmarsh`, app `MedDefense-VPN`, country Russia, IP 45.63.9.88; expected result: `CA-VPN-01` applies with grant control `Block`. Live check: a test account signing in through a non-US VPN egress gets "AADSTS53003: Access has been blocked by Conditional Access policies".

---

## HRD-004: Windows Defender Credential Guard

**Closes:** GAP-011, GAP-015
**Evidence:** ART-002-M04 (NTLM hash material for dmarsh in lsass at capture), Kerberos ticket of dmarsh reused from WST-WS-017 to reach LIS-WSIDE-01 (ART-003-M01, AD-LOG-01, T1003.001 / T1558.003 / T1550.003)

**Configuration:**

- GPO: `MEDDEFENSE-WKS-CredentialGuard`
- GPO path: Computer Configuration > Administrative Templates > System > Device Guard > **Turn On Virtualization Based Security**: Enabled
  - Select Platform Security Level: **Secure Boot and DMA Protection**
  - Credential Guard Configuration: **Enabled with UEFI lock**
  - Virtualization Based Protection of Code Integrity: Enabled without lock (pilot), then with UEFI lock
- Equivalent registry (for Intune/scripted deployment):
  - `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard` `EnableVirtualizationBasedSecurity` = `1` (DWORD)
  - `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard` `RequirePlatformSecurityFeatures` = `3` (DWORD, Secure Boot + DMA)
  - `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` `LsaCfgFlags` = `1` (DWORD, enabled with UEFI lock; `2` = without lock)
- Intune alternative: Endpoint security > Account protection > Credential Guard = "Enable with UEFI lock"
- Reboot required.

**Effect:** NTLM hashes and Kerberos TGTs are kept in the isolated LSA process (`LsaIso.exe`) inside a hypervisor-protected (VTL1) memory region. Code running in normal lsass or any user process, like the implant in MSBuild PID 8104, can no longer read them, so pass-the-hash and TGT export (as in this incident) fail.

**Limits:** Credential Guard does not protect service tickets already issued, local SAM accounts, or credentials typed into a compromised host (keylogging). It is paired with HRD-005 and with the krbtgt double reset in the IR playbook (PB-UPD-003).

**Supported Windows versions:**

- Windows 10 Enterprise and Education, version 1607 or later; Windows 11 Enterprise and Education (enabled by default from 22H2 on qualifying domain-joined devices)
- Windows Server 2016, 2019, 2022 and 2025
- **Not supported:** Windows 10/11 Home and Pro editions (Pro workstations must be upgraded to Enterprise via the MedDefense M365 E3/E5 licence before rollout)
- Hardware: 64-bit CPU with VT-x/AMD-V and SLAT, UEFI 2.3.1+ with Secure Boot, TPM 2.0 recommended; not supported on domain controllers

**Applies to:** All clinical and administrative workstations, starting with WST-WS-031, WST-WS-017 after reimage, and LIS client workstations.

**Validation:** `(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning` contains `1` (Credential Guard running); `Get-Process LsaIso` returns a process; `msinfo32` shows "Virtualization-based security Services Running: Credential Guard".

---

## HRD-005: LSA Protection (RunAsPPL) and ASR rule for lsass

**Closes:** GAP-011
**Evidence:** ART-002-M04; MSBuild PID 8104 reached LSA from user context

**Configuration:**

- `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` `RunAsPPL` = `1` (DWORD); on Windows 11 22H2+ use GPO Computer Configuration > Administrative Templates > System > Local Security Authority > **Configure LSASS to run as a protected process**: Enabled with UEFI Lock
- Microsoft Defender ASR (Intune > Endpoint security > Attack surface reduction): rule **Block credential stealing from the Windows local security authority subsystem**, GUID `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` = Block
- Same profile: **Block execution of potentially obfuscated scripts** `5beb7efe-fd9a-4556-801d-275e5ffc04cc` = Block (encoded PowerShell, GAP-007)

**Validation:** `Get-WinEvent -LogName System | Where-Object {$_.Id -eq 12 -and $_.ProviderName -eq 'Microsoft-Windows-Wininit'}` shows "LSASS.exe was started as a protected process with level: 4"; `Get-MpPreference | Select -Expand AttackSurfaceReductionRules_Ids` lists `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` with action `1`.

---

## HRD-006: Block inbound SMB between workstations

**Closes:** GAP-013
**Evidence:** ART-003-M01 (Kerberos network logon and remote service from WST-WS-031 to WST-WS-017), AD-LOG-01 (14 PDF reads on `LIS_REPORTS$` from WST-WS-017)

**Configuration:**

- GPO `MEDDEFENSE-WKS-Firewall`: Computer Configuration > Windows Settings > Security Settings > Windows Defender Firewall with Advanced Security > Inbound Rules
  - Domain profile: Inbound connections = **Block (default)**
  - Disable the built-in rules `File and Printer Sharing (SMB-In)` and `Remote Service Management (RPC)` / `(NP-In)`
  - Rule `IR-0414-Allow-SMB-Mgmt`: Allow, TCP 445 and 135, Remote IP = `soc-jump01` and the SCCM servers only (no rule allows workstation VLANs, so WST-WS-031 -> WST-WS-017 SMB is blocked; Windows Firewall block rules override allow rules, so the design uses default-block + narrow allow instead of an explicit block)
- LIS-WSIDE-01: share `LIS_REPORTS$` permissions and NTFS ACL limited to `GG-LIS-Servers` and `GG-Lab-Reporting`; host firewall 445 allowed only from the LIS server subnet

**Validation:** From one workstation, `Test-NetConnection WST-WS-017 -Port 445` returns `TcpTestSucceeded : False`; from `soc-jump01` it returns `True`.
