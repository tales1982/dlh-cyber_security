<#
    Script name : 7-auth_hardening.ps1
    Purpose     : MedDefense Health Systems - Windows Fortress (2x01), Task 7.
                  Blocks Kerberoasting and legacy-protocol credential theft:
                  clears the UseDESKeyOnly flag on any service account still
                  carrying it, restricts the domain to AES128/AES256
                  Kerberos tickets only (RC4 tickets are crackable offline
                  in minutes with hashcat - AES-256 takes years), refuses
                  NTLMv1, and reports Credential Guard readiness. 1x02 found
                  DES and RC4 Kerberos enabled; the Crimson Tide advisory
                  confirmed Kerberoasting (cracked RC4 service tickets) was
                  used in 3 of 5 hospital breaches. Every account carrying
                  an SPN (svc_backup, svc_ehr, svc_sql in this domain) is a
                  Kerberoastable target until RC4 is gone domain-wide.
                  Makes configuration changes: creates/links a GPO, clears
                  UseDESKeyOnly on flagged accounts, sets the domain's
                  supported Kerberos encryption types, and disables NTLMv1.
    Author      : Tales
    Date        : 2026-08-08
#>

[CmdletBinding()]
param(
    [string]$GpoName = "MedDefense - Kerberos and NTLM Hardening"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory
Import-Module GroupPolicy

# AES128 (0x8) + AES256 (0x10) = 24 - RC4 and both DES types excluded entirely.
$AesOnlyMask = 24

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
$DomainDN  = $Domain.DistinguishedName

# --- Current Kerberos encryption types --------------------------------------------------
$Krbtgt = Get-ADUser -Identity "krbtgt" -Properties msDS-SupportedEncryptionTypes
$CurrentTypes = ConvertFrom-KerberosEncryptionMask -Value $Krbtgt.'msDS-SupportedEncryptionTypes'
Write-Output "[*] Current Kerberos types: $($CurrentTypes -join ', ')"
if ($CurrentTypes -contains "DES") { Write-Output "    [!] DES enabled - trivially breakable" }
if ($CurrentTypes -contains "RC4") { Write-Output "    [!] RC4 enabled - Kerberoastable" }

# --- Accounts with the "Use DES encryption types" (UseDESKeyOnly) flag ------------------
Write-Output "[*] Accounts with DES flag..."
$DesFlaggedAccounts = Get-ADUser -Filter { UseDESKeyOnly -eq $true } -Properties UseDESKeyOnly, ServicePrincipalName
if ($DesFlaggedAccounts.Count -eq 0) {
    Write-Output "    (none found)"
} else {
    foreach ($acct in $DesFlaggedAccounts) {
        Write-Output "    $($acct.SamAccountName): UseDESKeyOnly = True          [!]"
    }
}

# --- Service Principal Names - every SPN-bearing account is Kerberoastable --------------
Write-Output "[*] Service Principal Names..."
$SpnAccounts = Get-ADUser -Filter { ServicePrincipalName -like "*" } -Properties ServicePrincipalName |
    Where-Object { $_.ServicePrincipalName.Count -gt 0 }
$SpnCount = 0
foreach ($acct in $SpnAccounts) {
    foreach ($spn in $acct.ServicePrincipalName) {
        Write-Output "    $($acct.SamAccountName): $spn"
        $SpnCount++
    }
}
if ($SpnCount -gt 0) {
    Write-Output "    [!] All $SpnCount SPNs are Kerberoastable targets"
}

# --- Create the GPO ------------------------------------------------------------------
$existingGpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
if ($existingGpo) {
    $Gpo = $existingGpo
} else {
    $Gpo = New-GPO -Name $GpoName -Comment "MedDefense Windows Fortress - AES-only Kerberos, NTLMv1 refused (Task 7)."
}

# --- Remediate --------------------------------------------------------------------------
Write-Output "[*] Remediating..."
foreach ($acct in $DesFlaggedAccounts) {
    Set-ADAccountControl -Identity $acct.DistinguishedName -UseDESKeyOnly $false
    Write-Output "    $($acct.SamAccountName): Clearing DES flag              [DONE]"
}

# Restrict the domain (krbtgt + every DC computer object) to AES128/AES256 only.
Set-ADUser -Identity "krbtgt" -Replace @{ 'msDS-SupportedEncryptionTypes' = $AesOnlyMask }
$DomainControllers = Get-ADDomainController -Filter *
foreach ($dc in $DomainControllers) {
    Set-ADComputer -Identity $dc.ComputerObjectDN -Replace @{ 'msDS-SupportedEncryptionTypes' = $AesOnlyMask }
}
Set-GPRegistryValue -Name $GpoName -Key "HKLM\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters" `
    -ValueName "SupportedEncryptionTypes" -Type DWord -Value $AesOnlyMask | Out-Null
Write-Output "    Supported encryption: AES128 + AES256   [SET]"

# --- Disable NTLMv1 (LmCompatibilityLevel 5 = send NTLMv2 only, refuse LM and NTLM) ------
Set-GPRegistryValue -Name $GpoName -Key "HKLM\System\CurrentControlSet\Control\Lsa" `
    -ValueName "LmCompatibilityLevel" -Type DWord -Value 5 | Out-Null
Write-Output "    NTLMv1: Refused (LmCompatibilityLevel=5) [SET]"

# --- Credential Guard awareness ----------------------------------------------------------
# Credential Guard needs UEFI Secure Boot and (ideally) Hyper-V-backed VBS, which a lab
# domain controller VM may not have - this "configures awareness" rather than assuming
# it will silently activate: it sets the enabling GPO policy and reports whether the
# host currently meets the hardware/hypervisor prerequisites.
Set-GPRegistryValue -Name $GpoName -Key "HKLM\System\CurrentControlSet\Control\LSA" `
    -ValueName "LsaCfgFlags" -Type DWord -Value 1 | Out-Null
Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard" `
    -ValueName "EnableVirtualizationBasedSecurity" -Type DWord -Value 1 | Out-Null
try {
    $DeviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
    $CredentialGuardRunning = [bool]($DeviceGuard.SecurityServicesRunning -contains 1)
} catch {
    $CredentialGuardRunning = $false
}
Write-Output "[*] Credential Guard awareness: policy enabled, currently running = $CredentialGuardRunning"

# --- Link the GPO to the domain root and force an update ---------------------------------
$existingLink = (Get-GPInheritance -Target $DomainDN).GpoLinks | Where-Object { $_.GpoId -eq $Gpo.Id }
if (-not $existingLink) {
    New-GPLink -Guid $Gpo.Id -Target $DomainDN -LinkEnabled Yes -Enforced Yes | Out-Null
}
gpupdate /target:computer /force | Out-Null

# --- Verify -------------------------------------------------------------------------------
Write-Output "[*] Verifying..."
$VerifyKrbtgt      = Get-ADUser -Identity "krbtgt" -Properties msDS-SupportedEncryptionTypes
$VerifyTypes       = ConvertFrom-KerberosEncryptionMask -Value $VerifyKrbtgt.'msDS-SupportedEncryptionTypes'
$ExpectedTypes     = @("AES128", "AES256")
$KerberosVerified  = (@($VerifyTypes | Sort-Object) -join ',') -eq (@($ExpectedTypes | Sort-Object) -join ',')
Write-Output "    Kerberos: $($VerifyTypes -join ', ') only           $(if ($KerberosVerified) { '[VERIFIED]' } else { '[MISMATCH]' })"

$VerifyLmCompat  = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue).LmCompatibilityLevel
$NtlmVerified    = ($VerifyLmCompat -eq 5)
Write-Output "    NTLM: v2 only                           $(if ($NtlmVerified) { '[VERIFIED]' } else { '[MISMATCH]' })"
