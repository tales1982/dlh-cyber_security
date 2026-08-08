<#
    Script name : 14-service_accounts.ps1
    Purpose     : MedDefense Health Systems - Windows Fortress (2x01), Task 14.
                  Audits every MedDefense service account (svc_backup,
                  svc_ehr, svc_sql and any other "svc" / Service Accounts OU
                  member) for the exact weaknesses 1-domain_findings.ps1
                  flagged - excessive privileges, ancient passwords,
                  unconstrained delegation - then remediates them. svc_ehr's
                  suspicious off-hours logon is the reason this task exists:
                  service accounts should never be able to log on
                  interactively, should never be delegable (an attacker who
                  compromises a delegable service account can impersonate
                  any user it authenticates on behalf of), and should hold
                  no group membership beyond what the service itself
                  requires.
                  Makes configuration changes: sets "Account is sensitive
                  and cannot be delegated" on every service account, denies
                  interactive logon rights via GPO, and removes service
                  accounts from privileged groups.
    Author      : Tales
    Date        : 2026-08-08
#>

[CmdletBinding()]
param(
    [string]$GpoName            = "MedDefense - Service Account Hardening",
    [int]$PasswordAgeWarningDays = 90
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory
Import-Module GroupPolicy

$PrivilegedGroups = @("Domain Admins", "Enterprise Admins", "G_IT_Admins")

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

# --- Discover service accounts ---------------------------------------------------------
$ServiceAccounts = Get-ADUser -Filter * -Properties Enabled, PasswordLastSet, MemberOf, `
    TrustedForDelegation, 'msDS-AllowedToDelegateTo', ServicePrincipalName, LastLogonDate, `
    UseDESKeyOnly, DistinguishedName |
    Where-Object { ($_.SamAccountName -like "*svc*") -or ($_.DistinguishedName -like "*OU=Service Accounts*") }

# --- Audit: security posture per account -------------------------------------------------
$AuditResults = [System.Collections.Generic.List[object]]::new()
foreach ($acct in $ServiceAccounts) {
    $passwordAgeDays = if ($acct.PasswordLastSet) { [int]((Get-Date) - $acct.PasswordLastSet).TotalDays } else { $null }

    $delegation = if ($acct.TrustedForDelegation) {
        "Unconstrained"
    } elseif ($acct.'msDS-AllowedToDelegateTo' -and $acct.'msDS-AllowedToDelegateTo'.Count -gt 0) {
        "Constrained"
    } else {
        "None"
    }

    $privilegedMembership = $acct.MemberOf | Where-Object {
        $groupName = ($_ -split ',')[0] -replace '^CN=', ''
        $PrivilegedGroups -contains $groupName
    }

    $lastLogonHour = if ($acct.LastLogonDate) { $acct.LastLogonDate.Hour } else { $null }
    $offHoursLogon = ($null -ne $lastLogonHour) -and ($lastLogonHour -lt 6 -or $lastLogonHour -ge 22)

    Write-Output "$($acct.SamAccountName):"
    if ($null -ne $passwordAgeDays) {
        $flag = if ($passwordAgeDays -gt $PasswordAgeWarningDays) { "[!]" } else { "[OK]" }
        Write-Output "  Password age: $passwordAgeDays days                  $flag"
    }
    if ($delegation -ne "None") {
        Write-Output "  Delegation: $delegation               [!]"
    }
    if ($acct.UseDESKeyOnly) {
        Write-Output "  UseDESKeyOnly: True                     [!]"
    }
    if ($privilegedMembership) {
        Write-Output "  Privileged membership: $(($privilegedMembership | ForEach-Object { ($_ -split ',')[0] -replace '^CN=','' }) -join ', ')    [!]"
    }
    if ($acct.LastLogonDate) {
        $timeLabel = $acct.LastLogonDate.ToString("hh:mm tt")
        Write-Output "  Last logon: $timeLabel                    $(if ($offHoursLogon) { '[!!!]' } else { '[OK]' })"
    }
    if ($acct.ServicePrincipalName -and $acct.ServicePrincipalName.Count -gt 0) {
        Write-Output "  SPN: $($acct.ServicePrincipalName -join ', ')    [!] Kerberoastable"
    }

    $AuditResults.Add([PSCustomObject]@{
        SamAccountName        = $acct.SamAccountName
        DistinguishedName     = $acct.DistinguishedName
        PasswordAgeDays       = $passwordAgeDays
        Delegation            = $delegation
        UseDESKeyOnly         = [bool]$acct.UseDESKeyOnly
        PrivilegedMembership  = [bool]$privilegedMembership
        OffHoursLogon         = $offHoursLogon
        SPN                   = @($acct.ServicePrincipalName)
    })
}

# --- Remediate: create the GPO for the Deny interactive logon user right ---------------
$existingGpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
if ($existingGpo) {
    $Gpo = $existingGpo
} else {
    $Gpo = New-GPO -Name $GpoName -Comment "MedDefense Windows Fortress - service account interactive logon denial (Task 14)."
}

Write-Output "[*] Remediating service accounts..."

# "Account is sensitive and cannot be delegated" (UserAccountControl:
# ADS_UF_NOT_DELEGATED) - stops any other service from delegating as this account.
foreach ($acct in $ServiceAccounts) {
    Set-ADAccountControl -Identity $acct.DistinguishedName -AccountNotDelegated $true
    Write-Output "    $($acct.SamAccountName): Account is sensitive and cannot be delegated   [SET]"
}

# Deny interactive logon rights (SeDenyInteractiveLogonRight) via GptTmpl.inf, applied
# to every service account SID - the same technique 5-audit_policy.ps1 uses for
# SeSecurityPrivilege, since no supported cmdlet sets user rights directly.
$Domain     = Get-ADDomain
$DomainDNS  = $Domain.DNSRoot
$DomainDN   = $Domain.DistinguishedName
$GpoGuid    = "{$($Gpo.Id.ToString().ToUpper())}"
$GpoDN      = "CN=$GpoGuid,CN=Policies,CN=System,$DomainDN"
$SysvolPath = "\\$DomainDNS\SYSVOL\$DomainDNS\Policies\$GpoGuid"
$SecEditDir = Join-Path $SysvolPath "MACHINE\Microsoft\Windows NT\SecEdit"
New-Item -Path $SecEditDir -ItemType Directory -Force | Out-Null

$ServiceAccountSids = ($ServiceAccounts | ForEach-Object { "*$($_.SID.Value)" }) -join ','
$GptTmplContent = @"
[Unicode]
Unicode=yes
[Privilege Rights]
SeDenyInteractiveLogonRight = $ServiceAccountSids
[Version]
signature="`$CHICAGO`$"
Revision=1
"@
Set-Content -Path (Join-Path $SecEditDir "GptTmpl.inf") -Value $GptTmplContent -Encoding Unicode

$SecEditCse = "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]"
$gptIniPath = Join-Path $SysvolPath "GPT.INI"
$gptIni = Get-Content -Path $gptIniPath -Raw
$newVersion = if ($gptIni -match 'Version=(\d+)') { [int]$Matches[1] + 1 } else { 1 }
Set-Content -Path $gptIniPath -Value ($gptIni -replace 'Version=\d+', "Version=$newVersion") -Encoding ASCII
Set-ADObject -Identity $GpoDN -Replace @{ versionNumber = $newVersion; gPCMachineExtensionNames = $SecEditCse }
Write-Output "    Deny interactive logon rights applied to all service accounts   [SET]"

# Remove service accounts from privileged groups they should not belong to.
foreach ($acct in $AuditResults | Where-Object { $_.PrivilegedMembership }) {
    $fullAcct = $ServiceAccounts | Where-Object { $_.SamAccountName -eq $acct.SamAccountName }
    foreach ($groupName in $PrivilegedGroups) {
        $group = Get-ADGroup -Identity $groupName -ErrorAction SilentlyContinue
        if ($group -and (Get-ADGroupMember -Identity $group | Where-Object { $_.SID -eq $fullAcct.SID })) {
            Remove-ADGroupMember -Identity $group -Members $fullAcct -Confirm:$false
            Write-Output "    $($acct.SamAccountName): Removed from $groupName   [DONE]"
        }
    }
}

# --- Link the GPO to the domain root and force an update -------------------------------
$existingLink = (Get-GPInheritance -Target $DomainDN).GpoLinks | Where-Object { $_.GpoId -eq $Gpo.Id }
if (-not $existingLink) {
    New-GPLink -Guid $Gpo.Id -Target $DomainDN -LinkEnabled Yes -Enforced Yes | Out-Null
}
gpupdate /target:computer /force | Out-Null
