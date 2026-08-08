<#
    Script name : 8-smb_hardening.ps1
    Purpose     : MedDefense Health Systems - Windows Fortress (2x01), Task 8.
                  Eliminates SMBv1 (the protocol behind EternalBlue /
                  WannaCry / NotPetya), enforces required SMB signing
                  (blocks relay attacks), enables SMB encryption (blocks
                  passive sniffing of file transfers), and disables the
                  legacy name-resolution protocols - NetBIOS over TCP/IP
                  and LLMNR - that tools like Responder abuse for
                  credential capture. SMBv1 was found enabled on the
                  domain controller; disabling it costs nothing and
                  removes an entire attack class.
                  Makes configuration changes: reconfigures the local SMB
                  server/client, disables NetBIOS on every IP-enabled
                  adapter, and creates/links a GPO enforcing signing and
                  disabling LLMNR domain-wide.
    Author      : Tales
    Date        : 2026-08-08
#>

[CmdletBinding()]
param(
    [string]$GpoName = "MedDefense - SMB and Protocol Hardening"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory
Import-Module GroupPolicy

function Get-SmbStateSummary {
    $serverCfg = Get-SmbServerConfiguration
    $clientCfg = Get-SmbClientConfiguration
    [PSCustomObject]@{
        Smb1Enabled            = [bool]$serverCfg.EnableSMB1Protocol
        Smb1ClientEnabled      = [bool]$clientCfg.EnableSMB1Protocol
        SigningRequired        = [bool]$serverCfg.RequireSecuritySignature
        ClientSigningRequired  = [bool]$clientCfg.RequireSecuritySignature
        EncryptionEnabled      = [bool]$serverCfg.EncryptData
    }
}

$Domain    = Get-ADDomain
$DomainDN  = $Domain.DistinguishedName

# --- Current SMB server and client configuration -----------------------------------------
$Before = Get-SmbStateSummary
Write-Output "[*] Current SMB Configuration..."
Write-Output "    SMBv1 (server): $(if ($Before.Smb1Enabled) { 'Enabled' } else { 'Disabled' })                 $(if ($Before.Smb1Enabled) { '[!]' } else { '[OK]' })"
Write-Output "    SMBv1 (client): $(if ($Before.Smb1ClientEnabled) { 'Enabled' } else { 'Disabled' })                 $(if ($Before.Smb1ClientEnabled) { '[!]' } else { '[OK]' })"
Write-Output "    Signing Required: $($Before.SigningRequired)                $(if (-not $Before.SigningRequired) { '[!]' } else { '[OK]' })"
Write-Output "    Encryption: $($Before.EncryptionEnabled)                      $(if (-not $Before.EncryptionEnabled) { '[!]' } else { '[OK]' })"

# --- Disable SMBv1 (server + client) -------------------------------------------------------
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
try {
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction Stop | Out-Null
} catch {
    # Feature already removed, or this Windows edition manages it differently -
    # the registry-level disable below still takes effect either way.
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name "Start" -Type DWord -Value 4 -ErrorAction SilentlyContinue
Write-Output "[*] Disabling SMBv1 (server + client)...   [DONE]"

# --- Enforce SMB signing (required, not just enabled) --------------------------------------
Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force
Set-SmbClientConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force
Write-Output "[*] Enforcing SMB Signing...               [SET]"

# --- Enable SMB encryption where supported --------------------------------------------------
Set-SmbServerConfiguration -EncryptData $true -Force
Write-Output "[*] Enabling SMB Encryption...             [SET]"

# --- Create the GPO for domain-wide, persistent enforcement ---------------------------------
$existingGpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
if ($existingGpo) {
    $Gpo = $existingGpo
} else {
    $Gpo = New-GPO -Name $GpoName -Comment "MedDefense Windows Fortress - SMB signing, NetBIOS and LLMNR hardening (Task 8)."
}

# "Microsoft network server/client: Digitally sign communications (always)"
Set-GPRegistryValue -Name $GpoName -Key "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" `
    -ValueName "RequireSecuritySignature" -Type DWord -Value 1 | Out-Null
Set-GPRegistryValue -Name $GpoName -Key "HKLM\System\CurrentControlSet\Services\LanManWorkstation\Parameters" `
    -ValueName "RequireSecuritySignature" -Type DWord -Value 1 | Out-Null

# --- Disable NetBIOS over TCP/IP on every IP-enabled adapter --------------------------------
# No dedicated cmdlet exists for this - WMI's SetTcpipNetbios(2) ("Disable NetBIOS over
# TCP/IP") is the supported mechanism.
$Adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True"
foreach ($adapter in $Adapters) {
    Invoke-CimMethod -InputObject $adapter -MethodName "SetTcpipNetbios" -Arguments @{ TcpipNetbiosOptions = 2 } | Out-Null
}
Write-Output "[*] Disabling NetBIOS over TCP/IP...       [SET]"

# --- Disable LLMNR via GPO ("Turn OFF Multicast Name Resolution") --------------------------
Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" `
    -ValueName "EnableMulticast" -Type DWord -Value 0 | Out-Null
Write-Output "[*] Disabling LLMNR via GPO...             [SET]"

# --- Link the GPO to the domain root and force an update ------------------------------------
$existingLink = (Get-GPInheritance -Target $DomainDN).GpoLinks | Where-Object { $_.GpoId -eq $Gpo.Id }
if (-not $existingLink) {
    New-GPLink -Guid $Gpo.Id -Target $DomainDN -LinkEnabled Yes -Enforced Yes | Out-Null
}
gpupdate /target:computer /force | Out-Null

# --- Verification: before/after comparison ---------------------------------------------------
$After = Get-SmbStateSummary
$LlmnrValue = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue).EnableMulticast

Write-Output "[*] Verification..."
Write-Output "    SMBv1 (server): $(if ($After.Smb1Enabled) { 'Enabled' } else { 'Disabled' })                $(if (-not $After.Smb1Enabled) { '[VERIFIED]' } else { '[MISMATCH]' })"
Write-Output "    SMBv1 (client): $(if ($After.Smb1ClientEnabled) { 'Enabled' } else { 'Disabled' })                $(if (-not $After.Smb1ClientEnabled) { '[VERIFIED]' } else { '[MISMATCH]' })"
Write-Output "    Signing: $(if ($After.SigningRequired) { 'Required' } else { 'Not Required' })                        $(if ($After.SigningRequired) { '[VERIFIED]' } else { '[MISMATCH]' })"
Write-Output "    Encryption: $(if ($After.EncryptionEnabled) { 'Enabled' } else { 'Disabled' })                      $(if ($After.EncryptionEnabled) { '[VERIFIED]' } else { '[MISMATCH]' })"
Write-Output "    LLMNR: $(if ($LlmnrValue -eq 0) { 'Disabled' } else { 'Enabled' })                        $(if ($LlmnrValue -eq 0) { '[VERIFIED]' } else { '[MISMATCH]' })"
