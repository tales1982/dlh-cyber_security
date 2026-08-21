#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Aligns Windows Firewall to the MedDefense segmentation_rules.json contract.
.DESCRIPTION
    MedDefense Health Systems - Perimeter and Network Defense (2x04)

    The nftables ruleset (T4) and this Windows Firewall ruleset consume the
    SAME segmentation_rules.json - the two platforms have to agree on what
    is allowed. This script is idempotent: it removes every previous
    MedDefense-* rule before re-creating the set, so re-running it never
    duplicates rules or leaves a stale one behind after a flow is removed
    from the source file.
.PARAMETER RulesPath
    Path to segmentation_rules.json. Defaults to the file next to this script.
.EXAMPLE
    .\6-windows_firewall.ps1
#>
[CmdletBinding()]
param(
    [string]$RulesPath = (Join-Path $PSScriptRoot "segmentation_rules.json")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Test-Path -Path $RulesPath)) {
    $fallback = Join-Path (Split-Path $PSScriptRoot -Parent) "segmentation_rules.json"
    if (Test-Path -Path $fallback) {
        $RulesPath = $fallback
    } else {
        Write-Error "segmentation_rules.json not found at '$RulesPath' (run 2-segmentation_rules.sh first)"
        exit 1
    }
}

Write-Host "[*] Reading segmentation_rules.json..."
$rules = Get-Content -Path $RulesPath -Raw | ConvertFrom-Json

$zoneByName = @{}
foreach ($zone in $rules.zones) {
    $zoneByName[$zone.name] = $zone
}

# --- Profile defaults --------------------------------------------------------
Write-Host "[*] Setting profile defaults..."
$logDir = "%systemroot%\system32\LogFiles\Firewall"
$logFile = "$logDir\meddefense.log"

foreach ($profileName in @("Domain", "Private", "Public")) {
    Set-NetFirewallProfile -Profile $profileName `
        -DefaultInboundAction Block `
        -DefaultOutboundAction Allow `
        -LogBlocked True `
        -LogFileName $logFile `
        -LogMaxSizeKilobytes 16384 | Out-Null
    Write-Host ("  {0,-8} DefaultInboundAction=Block  LogBlocked=True   [SET]" -f "${profileName}:")
}

# --- Idempotency: remove every previously created MedDefense-* rule --------
Write-Host "[*] Clearing previous MedDefense-* rules..."
$existing = Get-NetFirewallRule -DisplayName "MedDefense-*" -ErrorAction SilentlyContinue
$removedCount = 0
if ($existing) {
    $removedCount = ($existing | Measure-Object).Count
    $existing | Remove-NetFirewallRule
}
Write-Host "                                                           [$removedCount removed]"

# --- Create rules from the flow matrix --------------------------------------
# Only inbound flows that TERMINATE on a Windows host are relevant here - a
# flow is "inbound to this host" when its dst_zone is the zone this host's
# own IPv4 address falls into. Detected the same way the nftables task
# detects its own zone: match the host's real addresses against each zone
# CIDR, never assume.
function Test-IpInCidr {
    param([string]$IpAddress, [string]$Cidr)
    $parts = $Cidr -split '/'
    $network = [System.Net.IPAddress]::Parse($parts[0])
    $prefixLength = [int]$parts[1]
    $ipBytes = ([System.Net.IPAddress]::Parse($IpAddress)).GetAddressBytes()
    $netBytes = $network.GetAddressBytes()
    if ($ipBytes.Length -ne 4 -or $netBytes.Length -ne 4) { return $false }
    [Array]::Reverse($ipBytes); [Array]::Reverse($netBytes)
    $ipInt = [BitConverter]::ToUInt32($ipBytes, 0)
    $netInt = [BitConverter]::ToUInt32($netBytes, 0)
    $mask = if ($prefixLength -eq 0) { 0 } else { [uint32]::MaxValue -shl (32 - $prefixLength) }
    return ($ipInt -band $mask) -eq ($netInt -band $mask)
}

$hostAddresses = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } |
    Select-Object -ExpandProperty IPAddress

$hostZone = $null
foreach ($zone in $rules.zones) {
    foreach ($addr in $hostAddresses) {
        if (Test-IpInCidr -IpAddress $addr -Cidr $zone.cidr) {
            $hostZone = $zone.name
            break
        }
    }
    if ($hostZone) { break }
}

if (-not $hostZone) {
    Write-Warning "This host's address does not match any zone in segmentation_rules.json - no inbound rules created."
} else {
    Write-Host "[*] This host belongs to zone: $hostZone"
}

Write-Host "[*] Creating rules from flow matrix..."
$createdCount = 0
foreach ($flow in $rules.flows) {
    if ($flow.dst_zone -ne $hostZone) { continue }

    $srcZone = $zoneByName[$flow.src_zone]
    if (-not $srcZone) {
        Write-Warning "Flow references unknown src_zone '$($flow.src_zone)' - skipping"
        continue
    }

    $protoUpper = $flow.proto.ToUpperInvariant()
    $displayName = "MedDefense-$($flow.src_zone)-$protoUpper-$($flow.dport)"

    # src_hosts, when present, is a real restriction ("only these named DMZ
    # app hosts") - it must narrow RemoteAddress to those literal addresses,
    # not the whole source zone, or the nftables ruleset (T4) and this one
    # silently diverge on what each platform actually allows.
    $remoteAddress = $srcZone.cidr
    if ($flow.PSObject.Properties['src_hosts'] -and $flow.src_hosts -and $flow.src_hosts.Count -gt 0) {
        $remoteAddress = $flow.src_hosts
    }

    New-NetFirewallRule `
        -DisplayName $displayName `
        -Direction Inbound `
        -Action Allow `
        -Protocol $protoUpper `
        -LocalPort $flow.dport `
        -RemoteAddress $remoteAddress `
        -Profile Any `
        -Description $flow.justification | Out-Null

    $createdCount++
    Write-Host ("  {0,-28} Inbound Allow {1,-4} {2,-7} [CREATED]" -f $displayName, $flow.proto, $flow.dport)
}

Write-Host "[*] Rules created: $createdCount"
