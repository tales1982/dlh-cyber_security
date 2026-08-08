<#
    Script name : 13-rdp_hardening.ps1
    Purpose     : MedDefense Health Systems - Windows Fortress (2x01), Task 13.
                  Closes RDP as a lateral-movement entry point - the exact
                  mechanism Crimson Tide used in Phase 3. Requires Network
                  Level Authentication (pre-auth before a session even
                  starts), restricts session access to G_IT_Admins only,
                  bounds idle/max session time, forces the highest
                  encryption level, and disables clipboard/drive redirection
                  and Remote Assistance - all three are direct exfiltration
                  or remote-control channels riding inside an otherwise
                  "legitimate" RDP session.
                  Makes configuration changes: creates/links a GPO with the
                  RDP registry policy, and updates membership of the
                  Remote Desktop Users domain group.
    Author      : Tales
    Date        : 2026-08-08
#>

[CmdletBinding()]
param(
    [string]$GpoName          = "MedDefense - RDP Hardening",
    [string]$AuthorizedGroup  = "G_IT_Admins",
    [int]$IdleTimeoutMinutes  = 15,
    [int]$MaxSessionHours     = 8
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory
Import-Module GroupPolicy

$Domain    = Get-ADDomain
$DomainDN  = $Domain.DistinguishedName
$TsKey     = "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services"

# --- Create the GPO ------------------------------------------------------------------
$existingGpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
if ($existingGpo) {
    $Gpo = $existingGpo
} else {
    $Gpo = New-GPO -Name $GpoName -Comment "MedDefense Windows Fortress - RDP NLA, session limits, redirection lockdown (Task 13)."
}

# --- Enable Network Level Authentication --------------------------------------------
Set-GPRegistryValue -Name $GpoName -Key $TsKey -ValueName "UserAuthentication" -Type DWord -Value 1 | Out-Null
Write-Output "[*] Enabling NLA... UserAuthentication = 1       [SET]"

# --- Restrict RDP access to G_IT_Admins only -----------------------------------------
# 0-domain_baseline.ps1 found "Domain Users" in Remote Desktop Users, meaning
# every domain account - not just admins - could open an RDP session. The
# loop below removes whatever is currently there (Domain Users included),
# not just that one hardcoded name, so it stays correct if membership drifts.
Write-Output "[*] Restricting to $AuthorizedGroup..."
$RdpUsersGroup = Get-ADGroup -Identity "Remote Desktop Users"
$CurrentMembers = Get-ADGroupMember -Identity $RdpUsersGroup
foreach ($member in $CurrentMembers) {
    if ($member.Name -ne $AuthorizedGroup) {
        Remove-ADGroupMember -Identity $RdpUsersGroup -Members $member -Confirm:$false
        Write-Output "    Removed: $($member.Name) from Remote Desktop Users"
    }
}
$AuthorizedGroupObj = Get-ADGroup -Identity $AuthorizedGroup
$alreadyMember = Get-ADGroupMember -Identity $RdpUsersGroup | Where-Object { $_.SID -eq $AuthorizedGroupObj.SID }
if (-not $alreadyMember) {
    Add-ADGroupMember -Identity $RdpUsersGroup -Members $AuthorizedGroupObj
}
Write-Output "    Added: $AuthorizedGroup                           [SET]"

# --- Session limits: idle timeout and maximum session length ------------------------
$IdleTimeoutMs = $IdleTimeoutMinutes * 60 * 1000
$MaxSessionMs  = $MaxSessionHours * 60 * 60 * 1000
Set-GPRegistryValue -Name $GpoName -Key $TsKey -ValueName "MaxIdleTime" -Type DWord -Value $IdleTimeoutMs | Out-Null
Set-GPRegistryValue -Name $GpoName -Key $TsKey -ValueName "MaxConnectionTime" -Type DWord -Value $MaxSessionMs | Out-Null
Write-Output "[*] Session limits..."
Write-Output "    Idle timeout: $IdleTimeoutMinutes min                         [SET]"
Write-Output "    Max session: $MaxSessionHours hours                         [SET]"

# --- Enforce highest encryption level (High) over SSL/TLS ----------------------------
Set-GPRegistryValue -Name $GpoName -Key $TsKey -ValueName "MinEncryptionLevel" -Type DWord -Value 3 | Out-Null
Set-GPRegistryValue -Name $GpoName -Key $TsKey -ValueName "SecurityLayer" -Type DWord -Value 2 | Out-Null
Write-Output "[*] Encryption: High/SSL                         [SET]"

# --- Disable clipboard and drive redirection (exfiltration risk) ---------------------
Set-GPRegistryValue -Name $GpoName -Key $TsKey -ValueName "fDisableClip" -Type DWord -Value 1 | Out-Null
Write-Output "[*] Clipboard: Disabled                          [SET]"

Set-GPRegistryValue -Name $GpoName -Key $TsKey -ValueName "fDisableCdm" -Type DWord -Value 1 | Out-Null
Write-Output "[*] Drive redirection: Disabled                  [SET]"

# --- Disable Remote Assistance ---------------------------------------------------------
Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" `
    -ValueName "fAllowToGetHelp" -Type DWord -Value 0 | Out-Null
Write-Output "[*] Remote Assistance: Disabled                  [SET]"

# --- Link the GPO to the domain root and force an update -----------------------------
$existingLink = (Get-GPInheritance -Target $DomainDN).GpoLinks | Where-Object { $_.GpoId -eq $Gpo.Id }
if (-not $existingLink) {
    New-GPLink -Guid $Gpo.Id -Target $DomainDN -LinkEnabled Yes -Enforced Yes | Out-Null
}
gpupdate /target:computer /force | Out-Null

# --- Verification -----------------------------------------------------------------------
Write-Output "[*] Verification..."
$NlaVerify = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication
Write-Output "    NLA: Required                                $(if ($NlaVerify -eq 1) { '[VERIFIED]' } else { '[MISMATCH]' })"

$FinalMembers = Get-ADGroupMember -Identity $RdpUsersGroup
$AccessVerified = ($FinalMembers.Count -eq 1) -and ($FinalMembers[0].Name -eq $AuthorizedGroup)
Write-Output "    Access: $AuthorizedGroup only                     $(if ($AccessVerified) { '[VERIFIED]' } else { '[MISMATCH]' })"
