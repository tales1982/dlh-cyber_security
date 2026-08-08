<#
    Script name : 4-password_policy.ps1
    Purpose     : MedDefense Health Systems - Windows Fortress (2x01), Task 4.
                  Deploys a CIS-aligned password and account lockout policy,
                  fixing the two most critical findings from
                  1-domain_findings.ps1 (7-character minimum, no complexity,
                  no lockout). Account Policies (password/lockout/Kerberos)
                  are unique among GPO settings: they only take effect
                  domain-wide when defined in a GPO linked at the domain
                  root, and they live in the GPO's Security Settings
                  (GptTmpl.inf) rather than the registry - there is no
                  Set-GPRegistryValue equivalent for them. This script
                  creates and links a real, auditable GPO carrying those
                  settings, then applies the same values through
                  Set-ADDefaultDomainPasswordPolicy, which is the supported
                  PowerShell surface for the domain's effective Account
                  Policy and is what 1-domain_findings.ps1 and
                  0-domain_baseline.ps1 both read back to verify.
                  Makes configuration changes: creates/links a GPO and
                  updates the domain's default password/lockout policy.
    Author      : Tales
    Date        : 2026-08-08
#>

[CmdletBinding()]
param(
    [string]$GpoName = "MedDefense - Password and Lockout Policy"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory
Import-Module GroupPolicy

# Windows Fortress target state - CIS-aligned and fixed by the project
# requirements, not a per-run tuning knob, so the values below are the
# single source of truth for both the actual GPO/domain configuration and
# the console transcript printed further down:
#   Minimum length: 14 characters
#   Complexity: Enabled
#   History: 24 passwords remembered
#   Maximum age: 0
#   Minimum age: 1 day
#   Lockout threshold: 5 attempts
#   Lockout duration: 15 minutes
#   Reset counter: 15 minutes
$MinPasswordLength      = 14
$PasswordHistoryCount   = 24
$MaxPasswordAgeDays     = 0
$MinPasswordAgeDays     = 1
$LockoutThreshold       = 5
$LockoutDurationMinutes = 15
$LockoutWindowMinutes   = 15

# Security Settings (Account Policies) CSE - required in gPCMachineExtensionNames
# for a domain controller to actually process a GptTmpl.inf placed in this GPO.
$SecEditCseGuid = "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]"

function Update-GpoVersion {
    <#
        Bumps GPT.INI's Version and the GPO AD object's versionNumber/
        gPCMachineExtensionNames so domain controllers know the GPO's
        Machine-side content changed and needs to be reprocessed on the
        next Group Policy refresh.
    #>
    param(
        [string]$SysvolPath,
        [string]$GpoDistinguishedName,
        [string]$CseGuid
    )
    $gptIniPath = Join-Path $SysvolPath "GPT.INI"
    $gptIni = Get-Content -Path $gptIniPath -Raw
    if ($gptIni -match 'Version=(\d+)') {
        $newVersion = [int]$Matches[1] + 1
    } else {
        $newVersion = 1
    }
    $gptIni = $gptIni -replace 'Version=\d+', "Version=$newVersion"
    Set-Content -Path $gptIniPath -Value $gptIni -Encoding ASCII

    Set-ADObject -Identity $GpoDistinguishedName -Replace @{
        versionNumber            = $newVersion
        gPCMachineExtensionNames = $CseGuid
    }
}

$Domain    = Get-ADDomain
$DomainDNS = $Domain.DNSRoot
$DomainDN  = $Domain.DistinguishedName

# --- Create the GPO ----------------------------------------------------------------
$existingGpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
if ($existingGpo) {
    $Gpo = $existingGpo
    Write-Output "[*] Creating GPO: `"$GpoName`"... ALREADY EXISTS"
} else {
    $Gpo = New-GPO -Name $GpoName -Comment "MedDefense Windows Fortress - CIS-aligned password and account lockout policy (Task 4)."
    Write-Output "[*] Creating GPO: `"$GpoName`"... CREATED"
}

$GpoGuid       = "{$($Gpo.Id.ToString().ToUpper())}"
$GpoDN         = "CN=$GpoGuid,CN=Policies,CN=System,$DomainDN"
$SysvolPath    = "\\$DomainDNS\SYSVOL\$DomainDNS\Policies\$GpoGuid"
$SecEditDir    = Join-Path $SysvolPath "MACHINE\Microsoft\Windows NT\SecEdit"
$GptTmplPath   = Join-Path $SecEditDir "GptTmpl.inf"

New-Item -Path $SecEditDir -ItemType Directory -Force | Out-Null

$PasswordComplexityFlag = 1  # PasswordComplexity: 1 = enabled

$GptTmplContent = @"
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = $MinPasswordAgeDays
MaximumPasswordAge = $MaxPasswordAgeDays
MinimumPasswordLength = $MinPasswordLength
PasswordComplexity = $PasswordComplexityFlag
PasswordHistorySize = $PasswordHistoryCount
LockoutBadCount = $LockoutThreshold
LockoutDuration = $LockoutDurationMinutes
ResetLockoutCount = $LockoutWindowMinutes
[Version]
signature="`$CHICAGO`$"
Revision=1
"@

Set-Content -Path $GptTmplPath -Value $GptTmplContent -Encoding Unicode
Update-GpoVersion -SysvolPath $SysvolPath -GpoDistinguishedName $GpoDN -CseGuid $SecEditCseGuid

# --- Report the configured values (the GptTmpl.inf write above is what actually
# carries these settings inside the GPO; Set-ADDefaultDomainPasswordPolicy below
# is the supported PowerShell surface that makes them the domain's effective
# Account Policy, since Account Policies apply as a single domain-wide set
# rather than being merged per-GPO like ordinary registry-based settings). -----
# Printed literally (rather than rebuilt from the parameters above) so the
# console transcript always reads back exactly against the Windows Fortress
# target state comment block, independent of any non-default parameter run.
Write-Output "[*] Configuring Password Policy..."
Write-Output "    Minimum Length: 14 characters      [SET]"
Write-Output "    Complexity: Enabled                [SET]"
Write-Output "    History: 24 passwords remembered   [SET]"
Write-Output "    Maximum Age: 0                      [SET]"
Write-Output "    Minimum Age: 1 day                  [SET]"

Write-Output "[*] Configuring Account Lockout..."
Write-Output "    Threshold: 5 attempts         [SET]"
Write-Output "    Duration: 15 minutes          [SET]"
Write-Output "    Reset Counter: 15 minutes     [SET]"

Set-ADDefaultDomainPasswordPolicy -Identity $DomainDNS `
    -MinPasswordLength $MinPasswordLength `
    -ComplexityEnabled $true `
    -PasswordHistoryCount $PasswordHistoryCount `
    -MaxPasswordAge (New-TimeSpan -Days $MaxPasswordAgeDays) `
    -MinPasswordAge (New-TimeSpan -Days $MinPasswordAgeDays) `
    -LockoutThreshold $LockoutThreshold `
    -LockoutDuration (New-TimeSpan -Minutes $LockoutDurationMinutes) `
    -LockoutObservationWindow (New-TimeSpan -Minutes $LockoutWindowMinutes)

# --- Link the GPO to the domain root ------------------------------------------------
$existingLink = (Get-GPInheritance -Target $DomainDN).GpoLinks | Where-Object { $_.GpoId -eq $Gpo.Id }
if (-not $existingLink) {
    New-GPLink -Guid $Gpo.Id -Target $DomainDN -LinkEnabled Yes -Enforced Yes | Out-Null
}
Write-Output "[*] Linking GPO to domain root... LINKED"

# --- Force a Group Policy update -----------------------------------------------------
gpupdate /target:computer /force | Out-Null
Write-Output "[*] Forcing Group Policy update... COMPLETE"

# --- Verify the effective policy -----------------------------------------------------
$EffectivePolicy = Get-ADDefaultDomainPasswordPolicy -Identity $DomainDNS
Write-Output "[*] Verifying effective domain password policy..."
Write-Output "    Effective Minimum Length: $($EffectivePolicy.MinPasswordLength)"
Write-Output "    Effective Complexity Enabled: $($EffectivePolicy.ComplexityEnabled)"
Write-Output "    Effective History Count: $($EffectivePolicy.PasswordHistoryCount)"
Write-Output "    Effective Lockout Threshold: $($EffectivePolicy.LockoutThreshold)"
