<#
    Script name : 15-master_validation.ps1
    Purpose     : MedDefense Health Systems - Windows Fortress (2x01), Task 15.
                  The weekly compliance check James Chen runs every Friday -
                  the Windows equivalent of 2x00's 15-validation.sh. Reads
                  every setting deployed by 4-password_policy.ps1 through
                  14-service_accounts.ps1, compares each against its
                  expected value, and prints a PASS/WARN/FAIL compliance
                  dashboard. Exits 0 only if every critical check passes;
                  exits 1 if any critical check fails, so this script can be
                  wired into a scheduled task or CI gate.
                  Read-only: this script makes no configuration changes.
    Author      : Tales
    Date        : 2026-08-08
#>

[CmdletBinding()]
param(
    [string]$SysmonConfigPath   = (Join-Path $PSScriptRoot "sysmonconfig.xml"),
    [int]$PasswordAgeWarningDays = 90,
    [string]$AuthorizedRdpGroup = "G_IT_Admins",
    [string]$ReportPath        = (Join-Path $PSScriptRoot "master_validation_report.json")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Capstone (2x05) fix: the five reads below crash under Set-StrictMode when
# the target registry value does not exist yet (e.g. this script is run as
# a pre-hardening baseline, before 4-14 have applied their GPOs). The
# original one-liners dot straight into Get-ItemProperty's result, which is
# $null pre-hardening. This helper returns $null instead of throwing.
function Get-SafeRegistryValue {
    param([string]$Path, [string]$Name)
    $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($item -and ($item.PSObject.Properties.Name -contains $Name)) {
        return $item.$Name
    }
    return $null
}

Import-Module ActiveDirectory

$script:CriticalFailures = 0
$script:AllChecks = [System.Collections.Generic.List[object]]::new()

function Write-Check {
    param(
        [string]$Description,
        [bool]$Passed,
        [bool]$Critical = $true
    )
    if ($Passed) {
        $status = "PASS"
        Write-Output "[PASS] $Description"
    } elseif (-not $Critical) {
        $status = "WARN"
        Write-Output "[WARN] $Description"
    } else {
        $status = "FAIL"
        Write-Output "[FAIL] $Description"
        $script:CriticalFailures++
    }
    $script:AllChecks.Add([PSCustomObject]@{
        description = $Description
        status      = $status
        critical    = $Critical
    })
}

function ConvertFrom-KerberosEncryptionMask {
    param([Nullable[int]]$Value)
    if ($null -eq $Value -or $Value -eq 0) { return @("DES", "RC4", "AES128", "AES256") }
    $types = @()
    if ($Value -band 0x1)  { $types += "DES" }
    if ($Value -band 0x2)  { $types += "DES" }
    if ($Value -band 0x4)  { $types += "RC4" }
    if ($Value -band 0x8)  { $types += "AES128" }
    if ($Value -band 0x10) { $types += "AES256" }
    return ($types | Select-Object -Unique)
}

# --- Password & Lockout -----------------------------------------------------------------
Write-Output "--- Password & Lockout ---"
$PwdPolicy = Get-ADDefaultDomainPasswordPolicy
Write-Check -Description "Minimum length: $($PwdPolicy.MinPasswordLength)" -Passed ($PwdPolicy.MinPasswordLength -ge 14)
Write-Check -Description "Lockout threshold: $($PwdPolicy.LockoutThreshold)" -Passed ($PwdPolicy.LockoutThreshold -gt 0 -and $PwdPolicy.LockoutThreshold -le 5)
Write-Output ""

# --- Audit Policy --------------------------------------------------------------------------
Write-Output "--- Audit Policy ---"
$AuditCsv = auditpol /get /category:* /r | ConvertFrom-Csv
$ProcessCreationSetting = ($AuditCsv | Where-Object { $_.Subcategory -eq "Process Creation" }).'Inclusion Setting'
Write-Check -Description "Process Creation: Success" -Passed ($ProcessCreationSetting -like "*Success*")

$CmdLineLogging = Get-SafeRegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled"
Write-Check -Description "Command-line logging: Enabled" -Passed ($CmdLineLogging -eq 1)

$SecurityLogMaxSize = Get-SafeRegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security" -Name "MaxSize"
Write-Check -Description "Security log: 1 GB" -Passed ($SecurityLogMaxSize -ge 1048576)
Write-Output ""

# --- PowerShell ------------------------------------------------------------------------------
Write-Output "--- PowerShell ---"
$ScriptBlockLogging = Get-SafeRegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging"
Write-Check -Description "Script Block Logging: Enabled" -Passed ($ScriptBlockLogging -eq 1)

$Transcription = Get-SafeRegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting"
Write-Check -Description "Transcription: Enabled" -Passed ($Transcription -eq 1)
Write-Output ""

# --- Sysmon ------------------------------------------------------------------------------------
Write-Output "--- Sysmon ---"
$SysmonService = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
Write-Check -Description "Service: Running" -Passed ($SysmonService -and $SysmonService.Status -eq "Running")

$CustomRuleCount = 0
if (Test-Path -Path $SysmonConfigPath) {
    [xml]$SysmonXml = Get-Content -Path $SysmonConfigPath -Raw
    $CustomGroup = $SysmonXml.Sysmon.EventFiltering.RuleGroup | Where-Object { $_.name -eq "MedDefense Custom Detections" }
    if ($CustomGroup) {
        $RuleNames = $CustomGroup.SelectNodes(".//Rule") | ForEach-Object { $_.name }
        $CustomRuleCount = @($RuleNames | ForEach-Object { ($_ -split '-')[0] } | Select-Object -Unique).Count
    }
}
Write-Check -Description "Custom rules: 5 present" -Passed ($CustomRuleCount -eq 5)
Write-Output ""

# --- Kerberos ------------------------------------------------------------------------------
Write-Output "--- Kerberos ---"
$Krbtgt = Get-ADUser -Identity "krbtgt" -Properties msDS-SupportedEncryptionTypes
$KerberosTypes = ConvertFrom-KerberosEncryptionMask -Value $Krbtgt.'msDS-SupportedEncryptionTypes'
Write-Check -Description "DES: Disabled" -Passed ($KerberosTypes -notcontains "DES")
Write-Check -Description "RC4: Disabled" -Passed ($KerberosTypes -notcontains "RC4")
Write-Output ""

# --- SMB ------------------------------------------------------------------------------------
Write-Output "--- SMB ---"
$SmbServerConfig = Get-SmbServerConfiguration
Write-Check -Description "SMBv1: Disabled" -Passed (-not $SmbServerConfig.EnableSMB1Protocol)
Write-Check -Description "Signing: Required" -Passed ([bool]$SmbServerConfig.RequireSecuritySignature)
Write-Output ""

# --- Firewall ------------------------------------------------------------------------------
Write-Output "--- Firewall ---"
$FirewallProfiles = Get-NetFirewallProfile -All
$AllProfilesHardened = -not ($FirewallProfiles | Where-Object { -not $_.Enabled -or $_.DefaultInboundAction -ne "Block" })
Write-Check -Description "All profiles: ON, DefaultInbound: Block" -Passed $AllProfilesHardened
Write-Output ""

# --- RDP ------------------------------------------------------------------------------------
Write-Output "--- RDP ---"
$NlaSetting = Get-SafeRegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "UserAuthentication"
Write-Check -Description "NLA: Required" -Passed ($NlaSetting -eq 1)

$RdpUsersGroup  = Get-ADGroup -Identity "Remote Desktop Users"
$RdpMembers     = @(Get-ADGroupMember -Identity $RdpUsersGroup)
$RdpAccessOk    = ($RdpMembers.Count -eq 1) -and ($RdpMembers[0].Name -eq $AuthorizedRdpGroup)
Write-Check -Description "$AuthorizedRdpGroup only" -Passed $RdpAccessOk
Write-Output ""

# --- Service Accounts ------------------------------------------------------------------------
# Re-checks the delegation and password-age posture 14-service_accounts.ps1
# remediates, across every one of MedDefense's service accounts (svc_*
# accounts plus anything in the Service Accounts OU).
Write-Output "--- Service Accounts ---"
$ServiceAccounts = @(Get-ADUser -Filter * -Properties Enabled, PasswordLastSet, DistinguishedName, userAccountControl |
    Where-Object { ($_.SamAccountName -like "*svc*") -or ($_.DistinguishedName -like "*OU=Service Accounts*") })
# ADS_UF_NOT_DELEGATED (0x100000) is the UserAccountControl bit set by
# Set-ADAccountControl -AccountNotDelegated $true in 14-service_accounts.ps1.
$NotDelegatedCount = @($ServiceAccounts | Where-Object { $_.userAccountControl -band 0x100000 }).Count
$TotalServiceAccounts = $ServiceAccounts.Count
Write-Check -Description "Delegation restricted: $NotDelegatedCount/$TotalServiceAccounts" -Passed ($NotDelegatedCount -eq $TotalServiceAccounts)

foreach ($acct in $ServiceAccounts) {
    if ($acct.PasswordLastSet) {
        $ageDays = [int]((Get-Date) - $acct.PasswordLastSet).TotalDays
        if ($ageDays -gt $PasswordAgeWarningDays) {
            Write-Check -Description "$($acct.SamAccountName) password age: $ageDays days" -Passed $false -Critical $false
        }
    }
}

Write-Output ""
Write-Output "Critical failures: $CriticalFailures"

# Saved so 16-hardened_state_export.ps1 can fold this run's results into its
# validation_summary section instead of reporting "not_found".
$Report = [PSCustomObject]@{
    Timestamp        = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    TotalChecks      = $script:AllChecks.Count
    PassCount        = ($script:AllChecks | Where-Object { $_.status -eq "PASS" }).Count
    WarnCount        = ($script:AllChecks | Where-Object { $_.status -eq "WARN" }).Count
    FailCount        = ($script:AllChecks | Where-Object { $_.status -eq "FAIL" }).Count
    CriticalFailures = $CriticalFailures
    Checks           = $script:AllChecks
}
$Report | ConvertTo-Json -Depth 4 | Set-Content -Path $ReportPath -Encoding UTF8

if ($CriticalFailures -gt 0) {
    exit 1
} else {
    exit 0
}
