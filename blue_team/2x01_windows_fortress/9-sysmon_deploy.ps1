<#
    Script name : 9-sysmon_deploy.ps1
    Purpose     : MedDefense Health Systems - Windows Fortress (2x01), Task 9.
                  Deploys Sysmon - the single most important endpoint
                  detection tool on Windows - with a detection-optimized
                  configuration. Windows Event Logs cover authentication and
                  process creation; Sysmon covers everything else: network
                  connections, DNS queries, file creation, registry
                  persistence, driver/image loads, WMI events and named
                  pipes. Without it, detecting Crimson Tide's lateral
                  movement (PsExec, WMI), exfiltration (Rclone) and
                  ransomware deployment is nearly impossible.
                  Makes configuration changes: downloads and installs the
                  Sysmon service/driver with sysmonconfig.xml, and writes a
                  test file under C:\Windows\Temp\ to prove FileCreate
                  telemetry is flowing.
    Author      : Tales
    Date        : 2026-08-08
#>

[CmdletBinding()]
param(
    [string]$WorkingDirectory = "C:\MedDefense\Sysmon",
    [string]$LocalConfigPath  = (Join-Path $PSScriptRoot "sysmonconfig.xml")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Official Microsoft Sysinternals and SwiftOnSecurity community reference URLs -
# well-known, static download locations for these specific tools.
$SysmonZipUrl        = "https://download.sysinternals.com/files/Sysmon.zip"
$SwiftOnSecurityUrl  = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"

New-Item -Path $WorkingDirectory -ItemType Directory -Force | Out-Null

# --- Download Sysmon ----------------------------------------------------------------------
$SysmonZipPath = Join-Path $WorkingDirectory "Sysmon.zip"
try {
    Invoke-WebRequest -Uri $SysmonZipUrl -OutFile $SysmonZipPath -UseBasicParsing -ErrorAction Stop
    Expand-Archive -Path $SysmonZipPath -DestinationPath $WorkingDirectory -Force
    Write-Output "[*] Downloading Sysmon... OK"
} catch {
    Write-Output "[*] Downloading Sysmon... FAILED ($($_.Exception.Message))"
    throw
}

$Sysmon64Path = Join-Path $WorkingDirectory "Sysmon64.exe"
if (-not (Test-Path -Path $Sysmon64Path)) {
    throw "Sysmon64.exe not found after extraction - Sysinternals package layout may have changed."
}

# --- Download the SwiftOnSecurity config as a baseline, falling back to the local ---------
# repo copy (sysmonconfig.xml, also this task's own deliverable) if offline.
$ActiveConfigPath = Join-Path $WorkingDirectory "sysmonconfig.xml"
try {
    Invoke-WebRequest -Uri $SwiftOnSecurityUrl -OutFile $ActiveConfigPath -UseBasicParsing -ErrorAction Stop
    Write-Output "[*] Downloading SwiftOnSecurity config... OK"
} catch {
    Write-Output "[*] Downloading SwiftOnSecurity config... FAILED, using local MedDefense baseline instead"
    Copy-Item -Path $LocalConfigPath -Destination $ActiveConfigPath -Force
}

# --- Install Sysmon with the configuration -------------------------------------------------
Write-Output "[*] Installing Sysmon with config..."
Write-Output "    Sysmon64.exe -accepteula -i sysmonconfig.xml"
Push-Location $WorkingDirectory
try {
    & $Sysmon64Path -accepteula -i $ActiveConfigPath | Out-Null
} finally {
    Pop-Location
}

Start-Sleep -Seconds 3

$SysmonService = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
$ServiceStatus = if ($SysmonService -and $SysmonService.Status -eq "Running") { "Running" } else { "Not Running" }
Write-Output "    Service: Sysmon64 - $ServiceStatus            $(if ($ServiceStatus -eq 'Running') { '[OK]' } else { '[FAIL]' })"

$SysmonDriver = Get-CimInstance -ClassName Win32_SystemDriver -Filter "Name = 'SysmonDrv'" -ErrorAction SilentlyContinue
$DriverStatus = if ($SysmonDriver -and $SysmonDriver.State -eq "Running") { "Loaded" } else { "Not Loaded" }
Write-Output "    Driver: SysmonDrv - $DriverStatus            $(if ($DriverStatus -eq 'Loaded') { '[OK]' } else { '[FAIL]' })"

# --- Verify event generation -----------------------------------------------------------------
Write-Output "[*] Verifying event generation..."
Start-Sleep -Seconds 60
$Since = (Get-Date).AddSeconds(-60)
$RecentCount = @(Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue |
    Where-Object { $_.TimeCreated -ge $Since }).Count
Write-Output "    Events in last 60 seconds: $RecentCount          $(if ($RecentCount -gt 0) { '[OK]' } else { '[FAIL]' })"

# --- Test FileCreate detection (Event ID 11) ---------------------------------------------------
Write-Output "[*] Testing FileCreate detection..."
$TestFilePath = "C:\Windows\Temp\sysmon_test.txt"
"MedDefense Sysmon FileCreate test - $(Get-Date -Format o)" | Out-File -FilePath $TestFilePath -Encoding UTF8 -Force
Write-Output "    Created: $TestFilePath"
Start-Sleep -Seconds 2

$FileCreateEvent = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 100 -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -eq 11 -and $_.Message -like "*$TestFilePath*" } |
    Select-Object -First 1

if ($FileCreateEvent) {
    Write-Output "    Event ID 11 captured                   [VERIFIED]"
} else {
    Write-Output "    Event ID 11 NOT captured                   [FAIL]"
}

Remove-Item -Path $TestFilePath -Force -ErrorAction SilentlyContinue
