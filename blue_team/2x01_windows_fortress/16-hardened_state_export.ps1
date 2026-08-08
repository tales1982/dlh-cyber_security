<#
    Script name : 16-hardened_state_export.ps1
    Purpose     : MedDefense Health Systems - Windows Fortress (2x01), Task 16.
                  Exports the final hardened Windows domain state - every
                  control built across Tasks 4-14 (GPOs, audit policy,
                  PowerShell logging, Sysmon, firewall, AppLocker, RDP,
                  authentication protocols, SMB, service account posture) -
                  into a single structured evidence package. Hardening is
                  only useful if it can be proven, reviewed and handed off;
                  this is the machine-readable artifact Module 3 analysts
                  use for validation, detection planning and weekly drift
                  checks against the telemetry they should expect from a
                  domain in this state.
                  Read-only: this script makes no configuration changes.
    Author      : Tales
    Date        : 2026-08-08
#>

[CmdletBinding()]
param(
    [string]$OutputPath              = (Join-Path $PSScriptRoot "windows_hardened_state.json"),
    [string]$SysmonConfigPath        = (Join-Path $PSScriptRoot "sysmonconfig.xml"),
    [string]$AppLockerPolicyPath     = (Join-Path $PSScriptRoot "applocker_policy.xml"),
    [string]$ValidationReportPath    = (Join-Path $PSScriptRoot "master_validation_report.json")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory
Import-Module GroupPolicy

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

$Domain    = Get-ADDomain
$DomainDNS = $Domain.DNSRoot

# --- domain_metadata --------------------------------------------------------------------
$DomainMetadata = [PSCustomObject]@{
    domain_name        = $DomainDNS
    domain_controller   = (Get-ADDomainController -Discover).HostName[0]
    timestamp           = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    script_runner       = "$env:USERDOMAIN\$env:USERNAME"
}
Write-Output "[*] Exporting domain metadata... OK"

# --- gpo_inventory -----------------------------------------------------------------------
$MedDefenseGpos = Get-GPO -All | Where-Object { $_.DisplayName -like "MedDefense*" }
$GpoInventory = foreach ($gpo in $MedDefenseGpos) {
    $linkedScopes = @()
    try {
        $linkedScopes = (Get-ADObject -LDAPFilter "(gPLink=*{$($gpo.Id)}*)" -SearchBase $Domain.DistinguishedName -Properties DistinguishedName) |
            Select-Object -ExpandProperty DistinguishedName
    } catch { $linkedScopes = @() }

    $keySettings = @{}
    try {
        $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml
        $keySettings["hasComputerSettings"] = [bool]([xml]$report).GPO.Computer.ExtensionData
    } catch { $keySettings["hasComputerSettings"] = $false }

    [PSCustomObject]@{
        name          = $gpo.DisplayName
        id            = $gpo.Id
        enabled_state = $gpo.GpoStatus
        linked_scopes = $linkedScopes
        key_settings  = $keySettings
    }
}
Write-Output "[*] Exporting GPO settings... $($GpoInventory.Count) GPOs"

# --- audit_policy --------------------------------------------------------------------------
$RawAuditPolOutput = auditpol /get /category:* /r
$AuditCsv = $RawAuditPolOutput | ConvertFrom-Csv
$RequiredSubcategories = @("Credential Validation", "Kerberos Authentication", "Logon", "Logoff",
    "Special Logon", "User Account Management", "Sensitive Privilege Use", "File System",
    "Registry", "Process Creation", "System Integrity")
$RequiredSubcategoryStatus = foreach ($sub in $RequiredSubcategories) {
    $setting = ($AuditCsv | Where-Object { $_.Subcategory -eq $sub }).'Inclusion Setting'
    [PSCustomObject]@{
        subcategory = $sub
        setting     = $setting
        enabled     = [bool]($setting -and $setting -ne "No Auditing")
    }
}
$AuditPolicy = [PSCustomObject]@{
    raw_auditpol_output          = $RawAuditPolOutput
    required_subcategory_status  = $RequiredSubcategoryStatus
}
Write-Output "[*] Exporting audit policy... $($RequiredSubcategoryStatus.Count) subcategories"

# --- powershell_logging ---------------------------------------------------------------------
$ScriptBlockLogging = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging
$ModuleLogging      = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -ErrorAction SilentlyContinue).EnableModuleLogging
$Transcription      = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -ErrorAction SilentlyContinue).EnableTranscripting
$PowerShellLogging = [PSCustomObject]@{
    script_block_logging = [bool]($ScriptBlockLogging -eq 1)
    module_logging        = [bool]($ModuleLogging -eq 1)
    transcription          = [bool]($Transcription -eq 1)
    event_ids              = @(4103, 4104)
}
Write-Output "[*] Exporting PowerShell logging... OK"

# --- sysmon_posture ---------------------------------------------------------------------------
$SysmonService = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
$SysmonDriver  = Get-CimInstance -ClassName Win32_SystemDriver -Filter "Name = 'SysmonDrv'" -ErrorAction SilentlyContinue
$SysmonCustomRuleCount = 0
if (Test-Path -Path $SysmonConfigPath) {
    [xml]$SysmonXml = Get-Content -Path $SysmonConfigPath -Raw
    $CustomGroup = $SysmonXml.Sysmon.EventFiltering.RuleGroup | Where-Object { $_.name -eq "MedDefense Custom Detections" }
    if ($CustomGroup) {
        $RuleNames = $CustomGroup.SelectNodes(".//Rule") | ForEach-Object { $_.name }
        $SysmonCustomRuleCount = ($RuleNames | ForEach-Object { ($_ -split '-')[0] } | Select-Object -Unique).Count
    }
}
$ActiveSysmonEventIds = @()
try {
    $ActiveSysmonEventIds = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 200 -ErrorAction Stop |
        Select-Object -ExpandProperty Id -Unique
} catch { $ActiveSysmonEventIds = @() }

$SysmonPosture = [PSCustomObject]@{
    service_status     = if ($SysmonService) { $SysmonService.Status.ToString() } else { "NotInstalled" }
    driver_status       = if ($SysmonDriver) { $SysmonDriver.State } else { "NotLoaded" }
    config_path         = $SysmonConfigPath
    custom_rule_count   = $SysmonCustomRuleCount
    active_event_ids    = $ActiveSysmonEventIds
}
Write-Output "[*] Exporting Sysmon config... $SysmonCustomRuleCount custom rules"

# --- firewall_posture ------------------------------------------------------------------------
$FirewallProfiles = Get-NetFirewallProfile -All
$MedDefFirewallRules = Get-NetFirewallRule -DisplayName "MedDef-*" -ErrorAction SilentlyContinue
$FirewallPosture = [PSCustomObject]@{
    profile_states          = $FirewallProfiles | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
    inbound_policy           = ($FirewallProfiles | Select-Object -First 1).DefaultInboundAction.ToString()
    meddefense_rules         = $MedDefFirewallRules | Select-Object DisplayName, Direction, Action, Enabled
    dropped_packet_logging   = [bool](($FirewallProfiles | Select-Object -First 1).LogBlocked -eq "True")
}
Write-Output "[*] Exporting firewall rules... $($MedDefFirewallRules.Count) rules"

# --- applocker_posture -----------------------------------------------------------------------
$ExecutableRuleCount = 0
$ScriptRuleCount = 0
$EnforcementModes = @{}
if (Test-Path -Path $AppLockerPolicyPath) {
    [xml]$AppLockerXml = Get-Content -Path $AppLockerPolicyPath -Raw
    $ExeCollection    = $AppLockerXml.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -eq "Exe" }
    $ScriptCollection = $AppLockerXml.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -eq "Script" }
    if ($ExeCollection)    { $ExecutableRuleCount = @($ExeCollection.FilePathRule).Count; $EnforcementModes["Exe"] = $ExeCollection.EnforcementMode }
    if ($ScriptCollection) { $ScriptRuleCount = @($ScriptCollection.FilePathRule).Count; $EnforcementModes["Script"] = $ScriptCollection.EnforcementMode }
}
$AppLockerPosture = [PSCustomObject]@{
    enforcement_mode      = $EnforcementModes
    executable_rules       = $ExecutableRuleCount
    script_rules            = $ScriptRuleCount
    exported_policy_path   = $AppLockerPolicyPath
}
$TotalAppLockerRules = $ExecutableRuleCount + $ScriptRuleCount
Write-Output "[*] Exporting AppLocker policy... $TotalAppLockerRules rules"

# --- rdp_posture ------------------------------------------------------------------------------
$NlaSetting     = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication
$ClipboardOff   = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableClip" -ErrorAction SilentlyContinue).fDisableClip
$DriveRedirOff  = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCdm" -ErrorAction SilentlyContinue).fDisableCdm
$MaxIdleMs      = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxIdleTime" -ErrorAction SilentlyContinue).MaxIdleTime
$RdpUsersGroup  = Get-ADGroup -Identity "Remote Desktop Users"
$RdpMembers     = Get-ADGroupMember -Identity $RdpUsersGroup | Select-Object -ExpandProperty Name

$RdpPosture = [PSCustomObject]@{
    nla_state           = if ($NlaSetting -eq 1) { "Required" } else { "Not Required" }
    allowed_group        = $RdpMembers
    redirection_state    = [PSCustomObject]@{
        clipboard = if ($ClipboardOff -eq 1) { "Disabled" } else { "Enabled" }
        drive     = if ($DriveRedirOff -eq 1) { "Disabled" } else { "Enabled" }
    }
    session_timeout_minutes = if ($MaxIdleMs) { [int]($MaxIdleMs / 60000) } else { $null }
}
Write-Output "[*] Exporting remote access posture... OK"

# --- authentication_protocols ------------------------------------------------------------------
$Krbtgt = Get-ADUser -Identity "krbtgt" -Properties msDS-SupportedEncryptionTypes
$KerberosTypes = ConvertFrom-KerberosEncryptionMask -Value $Krbtgt.'msDS-SupportedEncryptionTypes'
$LmCompatibilityLevel = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue).LmCompatibilityLevel
$SmbConfig = Get-SmbServerConfiguration

$AuthenticationProtocols = [PSCustomObject]@{
    des          = if ($KerberosTypes -contains "DES") { "Enabled" } else { "Disabled" }
    rc4          = if ($KerberosTypes -contains "RC4") { "Enabled" } else { "Disabled" }
    aes          = if ($KerberosTypes -contains "AES128" -or $KerberosTypes -contains "AES256") { "Enabled" } else { "Disabled" }
    ntlmv1       = if ($LmCompatibilityLevel -eq 5) { "Refused" } else { "Permitted" }
    smbv1        = if ($SmbConfig.EnableSMB1Protocol) { "Enabled" } else { "Disabled" }
    smb_signing  = if ($SmbConfig.RequireSecuritySignature) { "Required" } else { "Not Required" }
}
Write-Output "[*] Exporting authentication protocol posture... OK"

# --- service_account_posture ---------------------------------------------------------------------
$PrivilegedGroups = @("Domain Admins", "Enterprise Admins", "G_IT_Admins")
$ServiceAccounts = Get-ADUser -Filter * -Properties PasswordLastSet, MemberOf, TrustedForDelegation, `
    LogonWorkstations, userAccountControl, DistinguishedName |
    Where-Object { ($_.SamAccountName -like "*svc*") -or ($_.DistinguishedName -like "*OU=Service Accounts*") }

$ServiceAccountPosture = foreach ($acct in $ServiceAccounts) {
    $passwordAgeDays = if ($acct.PasswordLastSet) { [int]((Get-Date) - $acct.PasswordLastSet).TotalDays } else { $null }
    $privilegedMembership = [bool]($acct.MemberOf | Where-Object {
        $groupName = ($_ -split ',')[0] -replace '^CN=', ''
        $PrivilegedGroups -contains $groupName
    })
    [PSCustomObject]@{
        sam_account_name         = $acct.SamAccountName
        delegation                = if ($acct.TrustedForDelegation) { "Unconstrained" } else { "None" }
        password_age_days         = $passwordAgeDays
        privileged_membership     = $privilegedMembership
        interactive_logon_risk    = [string]::IsNullOrEmpty($acct.LogonWorkstations)
        not_delegated_flag_set    = [bool]($acct.userAccountControl -band 0x100000)
    }
}
Write-Output "[*] Exporting service account posture... $($ServiceAccountPosture.Count) accounts"

# --- validation_summary -------------------------------------------------------------------------
if (Test-Path -Path $ValidationReportPath) {
    $ValidationSummary = Get-Content -Path $ValidationReportPath -Raw | ConvertFrom-Json
    Write-Output "[*] Loading validation summary... OK"
} else {
    $ValidationSummary = [PSCustomObject]@{ status = "not_found" }
    Write-Output "[*] Loading validation summary... not_found"
}

# --- Assemble and save -----------------------------------------------------------------------
$HardenedState = [PSCustomObject]@{
    domain_metadata           = $DomainMetadata
    gpo_inventory              = $GpoInventory
    audit_policy                = $AuditPolicy
    powershell_logging          = $PowerShellLogging
    sysmon_posture               = $SysmonPosture
    firewall_posture             = $FirewallPosture
    applocker_posture            = $AppLockerPosture
    rdp_posture                   = $RdpPosture
    authentication_protocols      = $AuthenticationProtocols
    service_account_posture       = $ServiceAccountPosture
    validation_summary             = $ValidationSummary
}
$HardenedState | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8

Write-Output ""
Write-Output "Hardened state exported to: $OutputPath"
