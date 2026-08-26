<#
    Script name : 11-firewall_hardening.ps1
    Purpose     : MedDefense Health Systems - Windows Fortress (2x01), Task 11.
                  Implements endpoint-level network segmentation: default-
                  deny inbound on all three firewall profiles (0-domain_baseline.ps1
                  found Domain ON but permissive, Private and Public OFF -
                  meaning any application could listen on any port with no
                  restriction), then opens narrow allow rules for exactly
                  the services a domain controller must expose - RDP and
                  WinRM only from the management subnet, SMB only from the
                  server subnet, DNS/LDAP/Kerberos for AD operation - and
                  logs everything the firewall drops.
                  Makes configuration changes: enables all firewall
                  profiles with default-deny inbound, creates 6 MedDef-*
                  allow rules, enables dropped-packet logging, and disables
                  legacy inbound allow rules that conflict with the new
                  default-deny posture.
    Author      : Tales
    Date        : 2026-08-08
#>

[CmdletBinding()]
param(
    # Capstone (2x05) fix: the original 10.10.3.0/24 / 10.10.1.0/24 defaults
    # are the fictional corporate network from the 2x01 module. Hawthorne's
    # actual lab topology is the VirtualBox host-only network the analyst
    # workstation and DC01 both live on - the wrong default here locks out
    # WinRM/RDP management access the moment this GPO applies.
    [string]$ManagementSubnet = "192.168.56.0/24",
    [string]$ServerSubnet     = "192.168.56.0/24"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# --- Current firewall state ------------------------------------------------------------
Write-Output "[*] Current Firewall State..."
$ProfilesBefore = Get-NetFirewallProfile -All
foreach ($p in $ProfilesBefore) {
    $status = if ($p.Enabled) { "ON" } else { "OFF" }
    $flag   = if (-not $p.Enabled -or $p.DefaultInboundAction -eq "Allow") { "[!]" } else { "[OK]" }
    if ($p.Enabled) {
        Write-Output "    $($p.Name): $status, DefaultInbound: $($p.DefaultInboundAction)       $flag"
    } else {
        Write-Output "    $($p.Name): $status                            $flag"
    }
}

# --- Enable all three profiles with default-deny inbound --------------------------------
Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
Write-Output "[*] Setting default-deny on all profiles... [SET]"

# --- Allow rules for required services only ----------------------------------------------
Write-Output "[*] Creating allow rules..."

$Rules = @(
    @{ Name = "MedDef-RDP-Mgmt"; DisplayName = "MedDef-RDP-Mgmt"; Protocol = "TCP"; Port = "3389";      Remote = $ManagementSubnet; Label = "TCP 3389 from $ManagementSubnet" }
    @{ Name = "MedDef-DNS-TCP";  DisplayName = "MedDef-DNS";       Protocol = "TCP"; Port = "53";        Remote = "Any";             Label = "TCP/UDP 53" }
    @{ Name = "MedDef-DNS-UDP";  DisplayName = "MedDef-DNS";       Protocol = "UDP"; Port = "53";        Remote = "Any";             Label = $null }
    @{ Name = "MedDef-LDAP";     DisplayName = "MedDef-LDAP";      Protocol = "TCP"; Port = "389";       Remote = "Any";             Label = "TCP 389" }
    @{ Name = "MedDef-Kerberos-TCP"; DisplayName = "MedDef-Kerberos"; Protocol = "TCP"; Port = "88";     Remote = "Any";             Label = "TCP/UDP 88" }
    @{ Name = "MedDef-Kerberos-UDP"; DisplayName = "MedDef-Kerberos"; Protocol = "UDP"; Port = "88";     Remote = "Any";             Label = $null }
    @{ Name = "MedDef-SMB";      DisplayName = "MedDef-SMB";       Protocol = "TCP"; Port = "445";       Remote = $ServerSubnet;     Label = "TCP 445 from $ServerSubnet" }
    @{ Name = "MedDef-WinRM";    DisplayName = "MedDef-WinRM";     Protocol = "TCP"; Port = "5985-5986"; Remote = $ManagementSubnet; Label = "TCP 5985-5986 from $ManagementSubnet" }
)

foreach ($rule in $Rules) {
    $existing = Get-NetFirewallRule -Name $rule.Name -ErrorAction SilentlyContinue
    if (-not $existing) {
        $params = @{
            Name        = $rule.Name
            DisplayName = $rule.DisplayName
            Direction   = "Inbound"
            Action      = "Allow"
            Protocol    = $rule.Protocol
            LocalPort   = $rule.Port
            Profile     = "Domain"
            Enabled     = "True"
        }
        if ($rule.Remote -ne "Any") { $params["RemoteAddress"] = $rule.Remote }
        New-NetFirewallRule @params | Out-Null
    }
    if ($rule.Label) {
        Write-Output "    $($rule.DisplayName):  $($rule.Label)     [CREATED]"
    }
}

# --- Enable logging for dropped packets ----------------------------------------------------
$LogPath = "%systemroot%\system32\LogFiles\Firewall\pfirewall.log"
Set-NetFirewallProfile -All -LogBlocked True -LogAllowed False -LogFileName $LogPath -LogMaxSizeKilobytes 16384
Write-Output "[*] Enabling dropped packet logging...     [SET]"

# --- Disable legacy allow rules that conflict with the new default-deny policy -----------
$LegacyRules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True |
    Where-Object { $_.DisplayName -notlike "MedDef-*" -and $_.Group -notlike "*Core Networking*" }
foreach ($legacy in $LegacyRules) {
    Disable-NetFirewallRule -Name $legacy.Name
}
Write-Output "[*] Disabling $($LegacyRules.Count) legacy allow rules...     [DONE]"

# --- Verification ---------------------------------------------------------------------------
Write-Output "[*] Verification..."
$ProfilesAfter = Get-NetFirewallProfile -All
$AllOnDefaultBlock = -not ($ProfilesAfter | Where-Object { -not $_.Enabled -or $_.DefaultInboundAction -ne "Block" })
Write-Output "    All 3 profiles: ON, DefaultInbound: Block  $(if ($AllOnDefaultBlock) { '[VERIFIED]' } else { '[MISMATCH]' })"

$CustomRuleCount = @(Get-NetFirewallRule -DisplayName "MedDef-*" -Enabled True).Count
Write-Output "    Custom rules: $CustomRuleCount active                     $(if ($CustomRuleCount -ge 6) { '[VERIFIED]' } else { '[MISMATCH]' })"
