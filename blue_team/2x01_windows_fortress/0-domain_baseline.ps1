<#
    Script name : 0-domain_baseline.ps1
    Purpose     : MedDefense Health Systems - Windows Fortress (2x01), Task 0.
                  Captures the complete, unhardened security baseline of the
                  meddefense.local Active Directory domain before any GPO
                  hardening work begins (Windows equivalent of the Lynis
                  baseline captured in 2x00 Task 0). Every number recorded
                  here is what every later hardening task is measured
                  against - domain info, accounts, groups, service accounts,
                  GPOs, password/lockout policy, Kerberos encryption types
                  and privileged group membership.
                  Read-only: this script makes no configuration changes.
    Author      : Tales
    Date        : 2026-08-08
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\domain_baseline_report.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory
Import-Module GroupPolicy

$Timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$Findings  = [System.Collections.Generic.List[object]]::new()

function Add-Finding {
    param(
        [ValidateSet("Critical", "High", "Medium", "Low")][string]$Severity,
        [string]$Description
    )
    $Findings.Add([PSCustomObject]@{
        Severity    = $Severity
        Description = $Description
    })
}

# --- Domain / forest identification -----------------------------------------
$Domain = Get-ADDomain
$Forest = Get-ADForest
$DomainControllers = Get-ADDomainController -Filter * |
    Select-Object -ExpandProperty HostName

# --- User accounts -----------------------------------------------------------
$AllUsers = Get-ADUser -Filter * -Properties Enabled, LastLogonDate, `
    PasswordLastSet, PasswordNeverExpires, DistinguishedName, TrustedForDelegation

$UserList = $AllUsers | ForEach-Object {
    [PSCustomObject]@{
        SamAccountName       = $_.SamAccountName
        Enabled              = $_.Enabled
        LastLogonDate        = $_.LastLogonDate
        PasswordLastSet      = $_.PasswordLastSet
        PasswordNeverExpires = $_.PasswordNeverExpires
    }
}
$PasswordNeverExpiresCount = ($UserList | Where-Object { $_.PasswordNeverExpires }).Count

# --- Groups and members -------------------------------------------------------
$AllGroups = Get-ADGroup -Filter *
$GroupList = $AllGroups | ForEach-Object {
    $members = @()
    try {
        $members = Get-ADGroupMember -Identity $_.DistinguishedName -ErrorAction Stop |
            Select-Object -ExpandProperty SamAccountName
    } catch {
        $members = @("<unresolvable: $($_.Exception.Message)>")
    }
    [PSCustomObject]@{
        Name    = $_.Name
        Members = $members
    }
}

# --- Service accounts ---------------------------------------------------------
$ServiceAccounts = $AllUsers | Where-Object {
    $_.SamAccountName -like "*svc*" -or $_.DistinguishedName -like "*OU=Service Accounts*"
}
$UnconstrainedDelegationAccounts = $ServiceAccounts | Where-Object { $_.TrustedForDelegation }
$ServiceAccountList = $ServiceAccounts | ForEach-Object {
    [PSCustomObject]@{
        SamAccountName          = $_.SamAccountName
        Enabled                 = $_.Enabled
        UnconstrainedDelegation = [bool]$_.TrustedForDelegation
    }
}

# --- GPOs linked to the domain and OUs ----------------------------------------
$AllGPOs = Get-GPO -All
$OUs = Get-ADOrganizationalUnit -Filter * -Properties LinkedGroupPolicyObjects

$GPOLinks = [System.Collections.Generic.List[object]]::new()
if ($Domain.LinkedGroupPolicyObjects.Count -gt 0) {
    $GPOLinks.Add([PSCustomObject]@{ Target = $Domain.DistinguishedName; LinkedGPOs = $Domain.LinkedGroupPolicyObjects })
}
foreach ($ou in $OUs) {
    if ($ou.LinkedGroupPolicyObjects.Count -gt 0) {
        $GPOLinks.Add([PSCustomObject]@{ Target = $ou.DistinguishedName; LinkedGPOs = $ou.LinkedGroupPolicyObjects })
    }
}

$DefaultGPONames = @("Default Domain Policy", "Default Domain Controllers Policy")
$NonDefaultGPOs = $AllGPOs | Where-Object { $DefaultGPONames -notcontains $_.DisplayName }
$GPOsAreDefaultOnly = ($NonDefaultGPOs.Count -eq 0)

# --- Password policy -----------------------------------------------------------
$PwdPolicy = Get-ADDefaultDomainPasswordPolicy

$LockoutConfigured = -not (
    $PwdPolicy.LockoutThreshold -eq 0 -and
    $PwdPolicy.LockoutDuration.TotalSeconds -eq 0 -and
    $PwdPolicy.LockoutObservationWindow.TotalSeconds -eq 0
)

$FineGrainedPolicies = @(Get-ADFineGrainedPasswordPolicy -Filter *)

# --- Kerberos supported encryption types ---------------------------------------
# "Network security: Configure encryption types allowed for Kerberos" is a
# machine-level GPO setting written to this registry value on every DC.
# When it is Not Configured, Windows does not restrict any type - i.e. legacy
# DES and RC4 remain usable alongside AES, which is the finding itself.
$KerberosRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters"
$SupportedEncryptionTypes = @()
$KerbRegValue = $null
try {
    $KerbRegValue = (Get-ItemProperty -Path $KerberosRegPath -Name "SupportedEncryptionTypes" -ErrorAction Stop).SupportedEncryptionTypes
} catch {
    $KerbRegValue = $null
}

if ($null -eq $KerbRegValue) {
    # Not configured via GPO/registry -> nothing is restricted.
    $SupportedEncryptionTypes = @("DES", "RC4", "AES128", "AES256")
} else {
    if ($KerbRegValue -band 0x1)  { $SupportedEncryptionTypes += "DES" }
    if ($KerbRegValue -band 0x2)  { $SupportedEncryptionTypes += "DES" }
    if ($KerbRegValue -band 0x4)  { $SupportedEncryptionTypes += "RC4" }
    if ($KerbRegValue -band 0x8)  { $SupportedEncryptionTypes += "AES128" }
    if ($KerbRegValue -band 0x10) { $SupportedEncryptionTypes += "AES256" }
    $SupportedEncryptionTypes = $SupportedEncryptionTypes | Select-Object -Unique
}

# --- SMBv1 on the domain controller --------------------------------------------
$SMBv1Enabled = $false
try {
    $SMBv1Enabled = [bool](Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol
} catch {
    $SMBv1Enabled = $false
}

# --- Privileged group membership ------------------------------------------------
$DomainAdmins = Get-ADGroupMember -Identity "Domain Admins" -Recursive |
    Select-Object -ExpandProperty SamAccountName
$EnterpriseAdmins = @()
try {
    $EnterpriseAdmins = Get-ADGroupMember -Identity "Enterprise Admins" -Recursive -ErrorAction Stop |
        Select-Object -ExpandProperty SamAccountName
} catch {
    $EnterpriseAdmins = @()
}

# --- Findings (Critical / High / Medium) -----------------------------------------
if ($PwdPolicy.MinPasswordLength -lt 14) {
    Add-Finding -Severity "Critical" -Description "Password minimum length ($($PwdPolicy.MinPasswordLength)) is below the CIS-recommended 14 characters."
}
if (-not $PwdPolicy.ComplexityEnabled) {
    Add-Finding -Severity "Critical" -Description "Password complexity requirements are disabled."
}
if ($PwdPolicy.LockoutThreshold -eq 0) {
    Add-Finding -Severity "Critical" -Description "Account lockout threshold is not configured (0) - unlimited password guesses are permitted."
}
if ($SupportedEncryptionTypes -contains "DES" -or $SupportedEncryptionTypes -contains "RC4") {
    Add-Finding -Severity "High" -Description "Weak Kerberos encryption types (DES/RC4) are permitted: $($SupportedEncryptionTypes -join ', ')."
}
if ($UnconstrainedDelegationAccounts.Count -gt 0) {
    Add-Finding -Severity "High" -Description "$($UnconstrainedDelegationAccounts.Count) service account(s) are configured for unconstrained Kerberos delegation."
}
if ($SMBv1Enabled) {
    Add-Finding -Severity "High" -Description "SMBv1 protocol is enabled on the domain controller."
}
if ($GPOsAreDefaultOnly) {
    Add-Finding -Severity "High" -Description "Only the built-in Default GPOs exist ($($AllGPOs.Count) total); no custom security hardening GPOs are linked."
}
if ($PasswordNeverExpiresCount -gt 0) {
    Add-Finding -Severity "Medium" -Description "$PasswordNeverExpiresCount user account(s) have PasswordNeverExpires set."
}
if ($DomainAdmins.Count -gt 2) {
    Add-Finding -Severity "Medium" -Description "$($DomainAdmins.Count) accounts hold Domain Admin privileges; membership should be minimized."
}

$CriticalCount = ($Findings | Where-Object { $_.Severity -eq "Critical" }).Count
$HighCount     = ($Findings | Where-Object { $_.Severity -eq "High" }).Count
$MediumCount   = ($Findings | Where-Object { $_.Severity -eq "Medium" }).Count

# --- Assemble report -------------------------------------------------------------
$Report = [PSCustomObject]@{
    Timestamp = $Timestamp
    Domain    = [PSCustomObject]@{
        Name               = $Domain.DNSRoot
        NetBIOSName        = $Domain.NetBIOSName
        DomainMode         = $Domain.DomainMode.ToString()
        ForestMode         = $Forest.ForestMode.ToString()
        DomainControllers  = $DomainControllers
    }
    Users = [PSCustomObject]@{
        Count                      = $UserList.Count
        PasswordNeverExpiresCount  = $PasswordNeverExpiresCount
        List                       = $UserList
    }
    Groups = [PSCustomObject]@{
        Count = $GroupList.Count
        List  = $GroupList
    }
    ServiceAccounts = [PSCustomObject]@{
        Count                         = $ServiceAccountList.Count
        UnconstrainedDelegationCount  = $UnconstrainedDelegationAccounts.Count
        List                          = $ServiceAccountList
    }
    GPOs = [PSCustomObject]@{
        Count              = $AllGPOs.Count
        DefaultOnly        = $GPOsAreDefaultOnly
        List               = $AllGPOs | Select-Object DisplayName, Id, GpoStatus, CreationTime, ModificationTime
        Links              = $GPOLinks
    }
    PasswordPolicy = [PSCustomObject]@{
        MinPasswordLength    = $PwdPolicy.MinPasswordLength
        ComplexityEnabled    = $PwdPolicy.ComplexityEnabled
        PasswordHistoryCount = $PwdPolicy.PasswordHistoryCount
        MaxPasswordAge       = $PwdPolicy.MaxPasswordAge.ToString()
        FineGrainedPolicies  = if ($FineGrainedPolicies.Count -eq 0) { "NOT CONFIGURED" } else { $FineGrainedPolicies.Name }
    }
    LockoutPolicy = if ($LockoutConfigured) {
        [PSCustomObject]@{
            LockoutThreshold          = $PwdPolicy.LockoutThreshold
            LockoutDuration           = $PwdPolicy.LockoutDuration.ToString()
            LockoutObservationWindow  = $PwdPolicy.LockoutObservationWindow.ToString()
        }
    } else {
        "NOT CONFIGURED"
    }
    KerberosEncryptionTypes = $SupportedEncryptionTypes
    SMBv1Enabled            = $SMBv1Enabled
    PrivilegedUsers = [PSCustomObject]@{
        DomainAdmins     = $DomainAdmins
        EnterpriseAdmins = $EnterpriseAdmins
    }
    Findings = [PSCustomObject]@{
        Total    = $Findings.Count
        Critical = $CriticalCount
        High     = $HighCount
        Medium   = $MediumCount
        Details  = $Findings
    }
}

$Report | ConvertTo-Json -Depth 6 | Set-Content -Path $OutputPath -Encoding UTF8

# --- Human-readable summary -------------------------------------------------------
Write-Output "Domain: $($Domain.DNSRoot)"
Write-Output "DC: $($DomainControllers -join ', ')"
Write-Output "User Accounts: $($UserList.Count)"
Write-Output "  Password Never Expires: $PasswordNeverExpiresCount"
Write-Output "Service Accounts: $($ServiceAccountList.Count)"
Write-Output "  Unconstrained delegation: $($UnconstrainedDelegationAccounts.Count)"
Write-Output "GPOs: $($AllGPOs.Count) $(if ($GPOsAreDefaultOnly) { '(Default only)' })"
Write-Output "Password Minimum Length: $($PwdPolicy.MinPasswordLength)"
Write-Output "Complexity: $(if ($PwdPolicy.ComplexityEnabled) { 'Enabled' } else { 'Disabled' })"
Write-Output "Lockout Threshold: $($PwdPolicy.LockoutThreshold)"
Write-Output "Kerberos: $($SupportedEncryptionTypes -join ', ')"
Write-Output "Domain Admins: $($DomainAdmins -join ', ')"
Write-Output "Findings: $($Findings.Count) (Critical: $CriticalCount, High: $HighCount, Medium: $MediumCount)"
Write-Output "Report saved to: $OutputPath"
