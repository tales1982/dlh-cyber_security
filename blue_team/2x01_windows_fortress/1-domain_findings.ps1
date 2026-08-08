<#
    Script name : 1-domain_findings.ps1
    Purpose     : MedDefense Health Systems - Windows Fortress (2x01), Task 1.
                  Turns the raw baseline from 0-domain_baseline.ps1 into an
                  actionable risk inventory: every weak password/lockout
                  setting, PasswordNeverExpires account, disabled-but-still-
                  privileged account, stale computer object, missing audit
                  category, risky service account and weak GPO posture is
                  captured as a discrete finding with id, severity, category,
                  asset, evidence, risk, recommended_remediation and the task
                  that remediates it. This is the punch list the rest of the
                  Windows Fortress project (4-password_policy.ps1 onward)
                  works down.
                  Read-only: this script makes no configuration changes.
    Author      : Tales
    Date        : 2026-08-08
#>

[CmdletBinding()]
param(
    [string]$OutputPath           = ".\domain_security_findings.json",
    [int]$TargetMinPasswordLength = 14,
    [int]$TargetPasswordHistory   = 24,
    [int]$TargetLockoutThreshold  = 5,
    [int]$StaleDays               = 90
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory
Import-Module GroupPolicy

$Findings  = [System.Collections.Generic.List[object]]::new()
$NextId    = 1

function Add-Finding {
    param(
        [ValidateSet("Critical", "High", "Medium", "Low")][string]$Severity,
        [string]$Category,
        [string]$Asset,
        [string]$Evidence,
        [string]$Risk,
        [string]$RecommendedRemediation,
        [string]$MappedTask,
        [string]$Message
    )
    $script:Findings.Add([PSCustomObject]@{
        id                      = "F-{0:D3}" -f $script:NextId
        severity                = $Severity
        category                = $Category
        asset                   = $Asset
        evidence                = $Evidence
        risk                    = $Risk
        recommended_remediation = $RecommendedRemediation
        mapped_task             = $MappedTask
        message                 = $Message
    })
    $script:NextId++
}

# --- Gather source data --------------------------------------------------------
$AllUsers = Get-ADUser -Filter * -Properties Enabled, PasswordLastSet, PasswordNeverExpires, `
    MemberOf, DistinguishedName, TrustedForDelegation, ServicePrincipalName, LastLogonDate, `
    'msDS-SupportedEncryptionTypes'

$PwdPolicy = Get-ADDefaultDomainPasswordPolicy
$AllGPOs   = Get-GPO -All
$DefaultGPONames = @("Default Domain Policy", "Default Domain Controllers Policy")

# --- 1. Accounts with PasswordNeverExpires --------------------------------------
$NeverExpireUsers = $AllUsers | Where-Object { $_.PasswordNeverExpires }
if ($NeverExpireUsers.Count -gt 0) {
    $Evidence = ($NeverExpireUsers | ForEach-Object {
        $isSvc = ($_.SamAccountName -like "*svc*") -or ($_.DistinguishedName -like "*OU=Service Accounts*")
        $groups = ($_.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace '^CN=', '' }) -join '; '
        "{0} (Enabled={1}, PasswordLastSet={2}, ServiceAccount={3}, Groups=[{4}])" -f `
            $_.SamAccountName, $_.Enabled, $_.PasswordLastSet, $isSvc, $groups
    }) -join ' | '
    Add-Finding -Severity "High" -Category "Password Hygiene" -Asset "Domain Users" `
        -Evidence $Evidence `
        -Risk "Non-expiring passwords remove the only forcing function for credential rotation, so a leaked password (breach dump, phishing, shoulder surfing) stays valid indefinitely." `
        -RecommendedRemediation "Clear PasswordNeverExpires on every non-service account and enforce MaxPasswordAge via 4-password_policy.ps1; managed service accounts should migrate to gMSA instead of a never-expiring password." `
        -MappedTask "4-password_policy.ps1" `
        -Message "$($NeverExpireUsers.Count) accounts with PasswordNeverExpires"
}

# --- 2. Disabled accounts still in privileged groups ----------------------------
$PrivilegedGroups = @("Domain Admins", "Enterprise Admins", "G_IT_Admins")
$DisabledPrivileged = [System.Collections.Generic.List[object]]::new()
foreach ($groupName in $PrivilegedGroups) {
    try {
        $members = Get-ADGroupMember -Identity $groupName -Recursive -ErrorAction Stop
    } catch {
        continue
    }
    foreach ($member in $members) {
        if ($member.objectClass -ne 'user') { continue }
        $user = $AllUsers | Where-Object { $_.DistinguishedName -eq $member.DistinguishedName }
        if ($user -and -not $user.Enabled) {
            $DisabledPrivileged.Add("$($user.SamAccountName) (in $groupName)")
        }
    }
}
if ($DisabledPrivileged.Count -gt 0) {
    Add-Finding -Severity "Medium" -Category "Privileged Access" -Asset "Domain Admins / Enterprise Admins / G_IT_Admins" `
        -Evidence (($DisabledPrivileged | Select-Object -Unique) -join ' | ') `
        -Risk "A disabled account left in a privileged group can be re-enabled by anyone with account-management rights (or a compromised helpdesk account), instantly granting Domain Admin without touching group membership at all." `
        -RecommendedRemediation "Remove disabled accounts from all privileged groups; only remove group membership, never leave 'disabled + privileged' as a resting state." `
        -MappedTask "GPO Hardening / Privileged Access Cleanup" `
        -Message "$($DisabledPrivileged.Count) disabled accounts remain in privileged groups"
}

# --- 3. Stale computer objects (90+ days) ---------------------------------------
$StaleThreshold = (Get-Date).AddDays(-$StaleDays)
$AllComputers = Get-ADComputer -Filter * -Properties LastLogonTimestamp, PasswordLastSet
$StaleComputers = $AllComputers | Where-Object {
    $lastLogon = if ($_.LastLogonTimestamp) { [DateTime]::FromFileTime($_.LastLogonTimestamp) } else { $null }
    (-not $lastLogon) -or ($lastLogon -lt $StaleThreshold)
}
if ($StaleComputers.Count -gt 0) {
    $Evidence = ($StaleComputers | ForEach-Object {
        $lastLogon = if ($_.LastLogonTimestamp) { [DateTime]::FromFileTime($_.LastLogonTimestamp) } else { "never" }
        "$($_.Name) (LastLogon=$lastLogon)"
    }) -join ' | '
    Add-Finding -Severity "Medium" -Category "Stale Objects" -Asset "Computer Accounts" `
        -Evidence $Evidence `
        -Risk "Stale computer objects are unmonitored, often unpatched, and their machine account credentials remain valid - a common lateral-movement and persistence foothold that never shows up in day-to-day operations." `
        -RecommendedRemediation "Disable and, after a verification window, remove computer objects with no authentication activity in $StaleDays+ days." `
        -MappedTask "Stale Object Cleanup" `
        -Message "Stale computer objects: $($StaleComputers.Count)"
}

# --- 4. Password and lockout policy gaps vs. Windows Fortress target state -----
if ($PwdPolicy.MinPasswordLength -lt $TargetMinPasswordLength) {
    Add-Finding -Severity "Critical" -Category "Password Policy" -Asset "meddefense.local Default Domain Password Policy" `
        -Evidence "MinPasswordLength=$($PwdPolicy.MinPasswordLength) (target=$TargetMinPasswordLength)" `
        -Risk "Short minimum length makes offline and online brute-force/spray attacks trivial; Crimson Tide used exactly this gap for credential harvesting in all 5 hospital breaches." `
        -RecommendedRemediation "Raise MinPasswordLength to $TargetMinPasswordLength via 4-password_policy.ps1." `
        -MappedTask "4-password_policy.ps1" `
        -Message "Password policy minimum length: $($PwdPolicy.MinPasswordLength)"
}
if (-not $PwdPolicy.ComplexityEnabled) {
    Add-Finding -Severity "Critical" -Category "Password Policy" -Asset "meddefense.local Default Domain Password Policy" `
        -Evidence "ComplexityEnabled=False" `
        -Risk "Without complexity requirements, dictionary and pattern-based passwords (Summer2026, Password1) dominate, collapsing the effective keyspace for brute-force attacks." `
        -RecommendedRemediation "Enable password complexity via 4-password_policy.ps1." `
        -MappedTask "4-password_policy.ps1" `
        -Message "Password complexity: disabled"
}
if ($PwdPolicy.PasswordHistoryCount -lt $TargetPasswordHistory) {
    Add-Finding -Severity "Medium" -Category "Password Policy" -Asset "meddefense.local Default Domain Password Policy" `
        -Evidence "PasswordHistoryCount=$($PwdPolicy.PasswordHistoryCount) (target=$TargetPasswordHistory)" `
        -Risk "A shallow password history lets users cycle back to a previously leaked or known password almost immediately after a forced reset." `
        -RecommendedRemediation "Raise PasswordHistoryCount to $TargetPasswordHistory via 4-password_policy.ps1." `
        -MappedTask "4-password_policy.ps1" `
        -Message "Password history: $($PwdPolicy.PasswordHistoryCount) (target $TargetPasswordHistory)"
}
if ($PwdPolicy.LockoutThreshold -eq 0) {
    Add-Finding -Severity "Critical" -Category "Account Lockout" -Asset "meddefense.local Default Domain Password Policy" `
        -Evidence "LockoutThreshold=0" `
        -Risk "With no lockout, an attacker can attempt unlimited password guesses per account with no throttling or alerting - the exact condition Crimson Tide exploited for brute-force initial access." `
        -RecommendedRemediation "Set LockoutThreshold to $TargetLockoutThreshold via 4-password_policy.ps1." `
        -MappedTask "4-password_policy.ps1" `
        -Message "Account lockout: not configured"
}

# --- 5. Kerberos weak encryption types ------------------------------------------
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
$Krbtgt = Get-ADUser -Identity "krbtgt" -Properties msDS-SupportedEncryptionTypes
$KerberosTypes = ConvertFrom-KerberosEncryptionMask -Value $Krbtgt.'msDS-SupportedEncryptionTypes'
if ($KerberosTypes -contains "DES" -or $KerberosTypes -contains "RC4") {
    Add-Finding -Severity "Critical" -Category "Kerberos Hardening" -Asset "krbtgt / Domain Controllers" `
        -Evidence "Supported encryption types: $($KerberosTypes -join ', ')" `
        -Risk "RC4 tickets are vulnerable to Kerberoasting/offline cracking and DES is cryptographically broken; both let an attacker with any authenticated foothold request and crack service-account tickets offline." `
        -RecommendedRemediation "Restrict Kerberos to AES128/AES256 via the 'Network security: Configure encryption types allowed for Kerberos' GPO setting." `
        -MappedTask "Kerberos Hardening" `
        -Message "Kerberos DES/RC4 enabled"
}

# --- 6. Missing audit visibility -------------------------------------------------
$AuditCsv = auditpol /get /category:* /r 2>$null | ConvertFrom-Csv
$AuditMap = @{}
foreach ($row in $AuditCsv) { $AuditMap[$row.Subcategory] = $row.'Inclusion Setting' }

function Test-SubcategoryEnabled {
    param([string]$Name)
    return ($AuditMap.ContainsKey($Name)) -and ($AuditMap[$Name] -ne "No Auditing") -and ($AuditMap[$Name] -ne "")
}

$RequiredSubcategories = @("Process Creation", "Special Logon", "User Account Management")
$ObjectAccessSubcategories = @("File System", "Registry")
$MissingAudit = $RequiredSubcategories + $ObjectAccessSubcategories | Where-Object { -not (Test-SubcategoryEnabled -Name $_) }

$ScriptBlockLoggingEnabled = $false
try {
    $sblPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    $ScriptBlockLoggingEnabled = ((Get-ItemProperty -Path $sblPath -Name EnableScriptBlockLogging -ErrorAction Stop).EnableScriptBlockLogging -eq 1)
} catch { $ScriptBlockLoggingEnabled = $false }

$SysmonRunning = [bool](Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" })

if ($MissingAudit.Count -gt 0 -or -not $ScriptBlockLoggingEnabled -or -not $SysmonRunning) {
    Add-Finding -Severity "High" -Category "Audit Visibility" -Asset "Advanced Audit Policy / PowerShell Logging / Sysmon" `
        -Evidence "Missing subcategories: [$($MissingAudit -join ', ')]; ScriptBlockLogging=$ScriptBlockLoggingEnabled; SysmonRunning=$SysmonRunning" `
        -Risk "Without process creation, special logon, account management and object access auditing - plus PowerShell and Sysmon telemetry - an attacker's actions generate no evidence at all; this was the exact blind spot Crimson Tide operated in during all 5 hospital breaches." `
        -RecommendedRemediation "Deploy the Advanced Audit Policy GPO, enable PowerShell Script Block Logging, and install Sysmon with a detection-tuned config." `
        -MappedTask "5-audit_policy.ps1" `
        -Message "Advanced Audit Policy: not configured"
}

# --- 7. Service account risks -----------------------------------------------------
$ServiceAccounts = $AllUsers | Where-Object {
    ($_.SamAccountName -like "*svc*") -or ($_.DistinguishedName -like "*OU=Service Accounts*")
}
$UnconstrainedDelegation = $ServiceAccounts | Where-Object { $_.TrustedForDelegation }
if ($UnconstrainedDelegation.Count -gt 0) {
    Add-Finding -Severity "High" -Category "Service Account Risk" -Asset "Service Accounts" `
        -Evidence (($UnconstrainedDelegation | Select-Object -ExpandProperty SamAccountName) -join ', ') `
        -Risk "Unconstrained delegation lets any compromised host that a delegated service authenticates to extract that account's TGT from memory and impersonate it anywhere in the domain - a direct path to Domain Admin." `
        -RecommendedRemediation "Move affected accounts to constrained or resource-based constrained delegation; disable unconstrained delegation entirely where not required." `
        -MappedTask "Service Account Hardening" `
        -Message "$($UnconstrainedDelegation.Count) service accounts with unconstrained delegation"
}

$RiskyServiceAccounts = $ServiceAccounts | Where-Object {
    $svc = $_
    $desOnly     = (ConvertFrom-KerberosEncryptionMask -Value $svc.'msDS-SupportedEncryptionTypes') -contains "DES"
    $isPrivileged = [bool]($svc.MemberOf | Where-Object { $_ -match '^CN=(Domain Admins|Enterprise Admins|G_IT_Admins),' })
    $stalePassword = $svc.PasswordLastSet -and ($svc.PasswordLastSet -lt (Get-Date).AddDays(-365))
    $neverLoggedOn = $svc.Enabled -and (-not $svc.LastLogonDate)
    $desOnly -or $isPrivileged -or $stalePassword -or $neverLoggedOn
}
if ($RiskyServiceAccounts.Count -gt 0) {
    $sev = if ($RiskyServiceAccounts | Where-Object { $_.MemberOf -match '^CN=(Domain Admins|Enterprise Admins)' }) { "Critical" } else { "High" }
    Add-Finding -Severity $sev -Category "Service Account Risk" -Asset "Service Accounts" `
        -Evidence (($RiskyServiceAccounts | Select-Object -ExpandProperty SamAccountName) -join ', ') `
        -Risk "DES-only encryption, privileged group membership, passwords older than a year, or accounts that have never logged on are all signs of unmanaged, over-privileged, or forgotten service accounts - prime targets for Kerberoasting and privilege escalation." `
        -RecommendedRemediation "Audit each flagged account individually: remove privileged membership where not required, rotate stale passwords, migrate to gMSA, and disable unused accounts." `
        -MappedTask "Service Account Hardening" `
        -Message "$($RiskyServiceAccounts.Count) service accounts show elevated risk (DES-only, privileged membership, stale password, or never logged on)"
}

# --- 8. Weak GPO security posture -------------------------------------------------
$NonDefaultGPOs = $AllGPOs | Where-Object { $DefaultGPONames -notcontains $_.DisplayName }
$MedDefenseGPOs = $AllGPOs | Where-Object { $_.DisplayName -like "MedDefense*" }
if ($MedDefenseGPOs.Count -eq 0) {
    Add-Finding -Severity "Medium" -Category "GPO Posture" -Asset "Group Policy Objects" `
        -Evidence "Total GPOs=$($AllGPOs.Count); non-default GPOs=$($NonDefaultGPOs.Count); MedDefense-prefixed hardening GPOs=0" `
        -Risk "With no dedicated hardening GPOs, every workstation and DC runs on out-of-the-box Windows defaults - weak password policy, no advanced auditing, no AppLocker, no firewall enforcement - domain-wide." `
        -RecommendedRemediation "Deploy the MedDefense hardening GPO set (password/lockout, audit policy, AppLocker, firewall) and link them at the appropriate OU/domain scope." `
        -MappedTask "GPO Hardening" `
        -Message "No MedDefense hardening GPOs present"
}

# --- Summary ------------------------------------------------------------------
$CriticalCount = ($Findings | Where-Object { $_.severity -eq "Critical" }).Count
$HighCount     = ($Findings | Where-Object { $_.severity -eq "High" }).Count
$MediumCount   = ($Findings | Where-Object { $_.severity -eq "Medium" }).Count
$LowCount      = ($Findings | Where-Object { $_.severity -eq "Low" }).Count

$Report = [PSCustomObject]@{
    Timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    Domain    = (Get-ADDomain).DNSRoot
    Findings  = $Findings
    Summary   = [PSCustomObject]@{
        Total    = $Findings.Count
        Critical = $CriticalCount
        High     = $HighCount
        Medium   = $MediumCount
        Low      = $LowCount
    }
}
$Report | ConvertTo-Json -Depth 6 | Set-Content -Path $OutputPath -Encoding UTF8

# --- Console output -------------------------------------------------------------
foreach ($sevOrder in @("Critical", "High", "Medium", "Low")) {
    foreach ($f in ($Findings | Where-Object { $_.severity -eq $sevOrder })) {
        Write-Output "[$($f.severity.ToUpper())] $($f.message)"
    }
}
Write-Output ""
Write-Output "Findings: $($Findings.Count)"
Write-Output "Critical: $CriticalCount"
Write-Output "High: $HighCount"
Write-Output "Medium: $MediumCount"
Write-Output "Report saved to: $OutputPath"
