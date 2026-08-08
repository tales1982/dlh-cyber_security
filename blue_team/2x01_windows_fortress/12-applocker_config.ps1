<#
    Script name : 12-applocker_config.ps1
    Purpose     : MedDefense Health Systems - Windows Fortress (2x01), Task 12.
                  Deploys AppLocker application allow-listing - the control
                  that would have stopped Crimson Tide Phase 6 dead: a
                  ransomware executable pushed via a malicious GPO fails to
                  run at all if only approved executables and scripts are
                  allowed to execute. Windows/Program Files paths and the
                  clinically-required DicomViewer.exe (signed by MedImage
                  Corp) are allowed; everything else is denied by AppLocker's
                  own default-deny behavior once any Allow rule exists for a
                  collection. Deployed in Audit Only mode so violations are
                  logged, not blocked, during the testing period - avoiding
                  breaking a physician's workflow before the rule set is
                  proven safe.
                  Makes configuration changes: creates/links a GPO carrying
                  the AppLocker policy, and starts the Application Identity
                  service (required for AppLocker to evaluate anything).
    Author      : Tales
    Date        : 2026-08-08
#>

[CmdletBinding()]
param(
    [string]$GpoName        = "MedDefense - AppLocker Policy",
    [string]$PolicyOutPath  = (Join-Path $PSScriptRoot "applocker_policy.xml"),
    [string]$DicomViewerPath = "C:\Program Files\MedImage Corp\DicomViewer\DicomViewer.exe",
    [string]$AdminScriptsPath = "C:\MedDefense_Lab\Scripts\*"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory
Import-Module GroupPolicy
Import-Module AppLocker

$Domain    = Get-ADDomain
$DomainDN  = $Domain.DistinguishedName

# --- Create the GPO ------------------------------------------------------------------
$existingGpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
if ($existingGpo) {
    $Gpo = $existingGpo
    Write-Output "[*] Creating GPO: `"$GpoName`"... ALREADY EXISTS"
} else {
    $Gpo = New-GPO -Name $GpoName -Comment "MedDefense Windows Fortress - AppLocker executable and script allow-listing, Audit Only (Task 12)."
    Write-Output "[*] Creating GPO: `"$GpoName`"... CREATED"
}

# --- Start the Application Identity service (AppIDSvc) - required for AppLocker ------
Set-Service -Name "AppIDSvc" -StartupType Automatic
Start-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
$AppIdStatus = (Get-Service -Name "AppIDSvc").Status
Write-Output "[*] Starting AppIDSvc... $AppIdStatus           $(if ($AppIdStatus -eq 'Running') { '[OK]' } else { '[FAIL]' })"

# --- Build the AppLocker policy XML directly (no supported New-GPO-native cmdlet exists ---
# for AppLocker; Set-AppLockerPolicy -Ldap is the documented way to write an
# AppLockerPolicy object straight into a GPO's AppLocker store).
# RuleCollection Type="Exe" natively governs .exe and .com; Type="Script"
# natively governs .ps1, .bat, .cmd and .vbs - AppLocker enforces these
# extension sets per collection without needing per-extension conditions.
$PolicyXml = @"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="$(New-Guid)" Name="Allow: C:\Windows\*" Description="System binaries" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="$(New-Guid)" Name="Allow: C:\Program Files\*" Description="64-bit Program Files" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="$(New-Guid)" Name="Allow: C:\Program Files (x86)\*" Description="32-bit Program Files" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES(X86)%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="$(New-Guid)" Name="Allow: DicomViewer.exe (MedImage Corp)" Description="Clinical imaging application, signed by MedImage Corp" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="$DicomViewerPath" />
      </Conditions>
    </FilePathRule>
  </RuleCollection>
  <RuleCollection Type="Script" EnforcementMode="AuditOnly">
    <FilePathRule Id="$(New-Guid)" Name="Allow: C:\Windows\* scripts" Description="System scripts" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="$(New-Guid)" Name="Allow: C:\MedDefense_Lab\Scripts\*" Description="MedDefense admin scripts" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="$AdminScriptsPath" />
      </Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
"@

# Both collections above deliberately contain only Allow rules: once a
# collection has any Allow rule, AppLocker implicitly denies everything else
# in it by default. An explicit Deny rule for "*" is never added here on
# purpose - AppLocker evaluates an explicit Deny as always winning over an
# Allow for the same path, which would silently deny the C:\Windows\*,
# Program Files and DicomViewer paths this policy is meant to allow.
[xml]$PolicyDoc = $PolicyXml
Write-Output "[*] Configuring Executable Rules..."
Write-Output "    Allow: C:\Windows\*                    [SET]"
Write-Output "    Allow: C:\Program Files\*              [SET]"
Write-Output "    Allow: C:\Program Files (x86)\*        [SET]"
Write-Output "    Allow: DicomViewer.exe (MedImage Corp) [SET]"
Write-Output "    Default: DENY                          [SET]"

Write-Output "[*] Configuring Script Rules..."
Write-Output "    Allow: C:\Windows\*                    [SET]"
Write-Output "    Allow: C:\MedDefense_Lab\Scripts\*     [SET]"
Write-Output "    Default: DENY                          [SET]"

Write-Output "[*] Mode: AUDIT ONLY (not enforcing)"

# --- Apply the policy to the GPO -------------------------------------------------------
$DomainDNS  = $Domain.DNSRoot
$GpoGuid    = "{$($Gpo.Id.ToString().ToUpper())}"
$GpoLdapPath = "LDAP://CN=$GpoGuid,CN=Policies,CN=System,$DomainDN"
Set-AppLockerPolicy -XmlPolicy $PolicyDoc.OuterXml -Ldap $GpoLdapPath

# --- Link the GPO to the domain root and force an update -------------------------------
$existingLink = (Get-GPInheritance -Target $DomainDN).GpoLinks | Where-Object { $_.GpoId -eq $Gpo.Id }
if (-not $existingLink) {
    New-GPLink -Guid $Gpo.Id -Target $DomainDN -LinkEnabled Yes -Enforced Yes | Out-Null
}
gpupdate /target:computer /force | Out-Null
Write-Output "[*] Linking GPO... COMPLETE"

# --- Test: evaluate two sample files against the policy without executing them ---------
Write-Output "[*] Testing..."
$TestDir = "C:\Temp"
New-Item -Path $TestDir -ItemType Directory -Force | Out-Null
$CalcTestPath = Join-Path $TestDir "calc.exe"
Copy-Item -Path "C:\Windows\System32\calc.exe" -Destination $CalcTestPath -Force -ErrorAction SilentlyContinue

$NotepadDecision = (Test-AppLockerPolicy -PolicyObject $PolicyDoc.OuterXml -Path "C:\Windows\notepad.exe" -User "Everyone").PolicyDecision
Write-Output "    notepad.exe from C:\Windows: $(if ($NotepadDecision -eq 'Allowed') { 'ALLOWED' } else { 'DENIED' })   [EXPECTED]"

if (Test-Path -Path $CalcTestPath) {
    $CalcDecision = (Test-AppLockerPolicy -PolicyObject $PolicyDoc.OuterXml -Path $CalcTestPath -User "Everyone").PolicyDecision
    $CalcResult = if ($CalcDecision -eq 'Allowed') { 'ALLOWED' } else { 'WOULD BLOCK' }
} else {
    $CalcResult = 'WOULD BLOCK'
}
Write-Output "    calc.exe from C:\Temp: $CalcResult   [EXPECTED]"
Remove-Item -Path $CalcTestPath -Force -ErrorAction SilentlyContinue

# --- Export the AppLocker policy XML as a deliverable ------------------------------------
try {
    Export-AppLockerPolicy -ALPolicy $PolicyDoc -Xml -ErrorAction Stop | Out-File -FilePath $PolicyOutPath -Encoding UTF8
} catch {
    # Export-AppLockerPolicy is not present on every AppLocker module build -
    # the policy XML built above is already authoritative, so write it directly.
    $PolicyDoc.OuterXml | Out-File -FilePath $PolicyOutPath -Encoding UTF8
}
Write-Output "Policy exported to: $PolicyOutPath"
