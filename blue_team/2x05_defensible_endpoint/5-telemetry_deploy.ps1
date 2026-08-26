# Artifacts (relative to this script's directory):
#   capstone/telemetry/windows_events.json
#   capstone/telemetry/windows_coverage.json

$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$CapstoneDir = Join-Path $ScriptDir "capstone"
$TelemetryDir = Join-Path $CapstoneDir "telemetry"
$EventsFile = Join-Path $TelemetryDir "windows_events.json"
$CoverageFile = Join-Path $TelemetryDir "windows_coverage.json"

New-Item -ItemType Directory -Path $TelemetryDir -Force | Out-Null

$SysmonService = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue | Select-Object -First 1
$SysmonRunning = [bool]($SysmonService -and $SysmonService.Status -eq 'Running')

$SblKey = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue
$SblEnabled = [bool]($SblKey -and $SblKey.EnableScriptBlockLogging -eq 1)

if (-not $SysmonRunning) {
    Write-Error "Sysmon is not installed/running. Run Task 4 (4-windows_harden.ps1) first."
    exit 2
}

if (-not $SblEnabled) {
    Write-Error "Script Block Logging is not enabled. Run Task 4 (4-windows_harden.ps1) first."
    exit 2
}

function Test-EventPresent {
    param(
        [string]$LogName,
        [int]$EventId,
        [int]$WithinMinutes = 10
    )
    try {
        $since = (Get-Date).AddMinutes(-$WithinMinutes)
        $events = Get-WinEvent -FilterHashtable @{ LogName = $LogName; Id = $EventId; StartTime = $since } -ErrorAction SilentlyContinue
        return [bool]($events -and $events.Count -gt 0)
    }
    catch {
        return $false
    }
}

$Coverage = New-Object System.Collections.Generic.List[object]
$AllFound = $true

function Add-Result {
    param([string]$Action, [string]$LogName, [int]$EventId, [bool]$Found)
    $script:Coverage.Add([PSCustomObject]@{ action = $Action; log = $LogName; event_id = $EventId; found = $Found })
    if (-not $Found) { $script:AllFound = $false }
}

$TestId = "meddefense_test_$PID"

# --- Test 1: create a local user ---------------------------------------------
try {
    $SecurePw = ConvertTo-SecureString ([System.Guid]::NewGuid().ToString() + "!Aa1") -AsPlainText -Force
    New-LocalUser -Name $TestId -Password $SecurePw -Description "Capstone telemetry test user" -ErrorAction Stop | Out-Null
}
catch {
    Write-Output "WARNING: could not create test user: $($_.Exception.Message)"
}
Start-Sleep -Seconds 2
Add-Result -Action "create_local_user" -LogName "Security" -EventId 4720 -Found (Test-EventPresent -LogName "Security" -EventId 4720)

# --- Test 2: create and run a scheduled task ----------------------------------
$TaskName = "MedDefenseCapstoneTest"
try {
    $Action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c exit"
    $Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date)
    Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Force -ErrorAction Stop | Out-Null
    Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
}
catch {
    Write-Output "WARNING: could not create/run scheduled task: $($_.Exception.Message)"
}
Start-Sleep -Seconds 2
Add-Result -Action "scheduled_task" -LogName "Security" -EventId 4698 -Found (Test-EventPresent -LogName "Security" -EventId 4698)

try {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
}
catch {}

# --- Test 3: start and stop a service -----------------------------------------
try {
    Restart-Service -Name "Spooler" -Force -ErrorAction Stop
}
catch {
    Write-Output "WARNING: could not restart service: $($_.Exception.Message)"
}
Start-Sleep -Seconds 2
Add-Result -Action "service_start_stop" -LogName "System" -EventId 7036 -Found (Test-EventPresent -LogName "System" -EventId 7036)

# --- Test 4: run a short authorized PowerShell command ------------------------
try {
    & { Get-Date | Out-Null }
}
catch {}
Start-Sleep -Seconds 2
Add-Result -Action "authorized_powershell_command" -LogName "Microsoft-Windows-PowerShell/Operational" -EventId 4104 -Found (Test-EventPresent -LogName "Microsoft-Windows-PowerShell/Operational" -EventId 4104)

try {
    if (-not (Get-LocalUser -Name $TestId -ErrorAction SilentlyContinue)) { throw "not found, skip removal" }
    Remove-LocalUser -Name $TestId -ErrorAction SilentlyContinue
}
catch {}

# --- Export last 30 minutes of Sysmon and PowerShell events -------------------
$Since30 = (Get-Date).AddMinutes(-30)

$SysmonEvents = @()
try {
    $SysmonEvents = Get-WinEvent -FilterHashtable @{ LogName = "Microsoft-Windows-Sysmon/Operational"; StartTime = $Since30 } -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, LevelDisplayName, Message
}
catch {}

$PowerShellEvents = @()
try {
    $PowerShellEvents = Get-WinEvent -FilterHashtable @{ LogName = "Microsoft-Windows-PowerShell/Operational"; StartTime = $Since30 } -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, LevelDisplayName, Message
}
catch {}

$HostnameVal = $env:COMPUTERNAME
$Timestamp = (Get-Date).ToUniversalTime().ToString("o")

$EventsResult = [PSCustomObject]@{
    timestamp         = $Timestamp
    hostname          = $HostnameVal
    sysmon_events     = $SysmonEvents
    powershell_events = $PowerShellEvents
}

$CoverageResult = [PSCustomObject]@{
    timestamp = $Timestamp
    hostname  = $HostnameVal
    coverage  = $Coverage
}

try {
    $EventsResult | ConvertTo-Json -Depth 6 | Set-Content -Path $EventsFile -Encoding UTF8
    $CoverageResult | ConvertTo-Json -Depth 6 | Set-Content -Path $CoverageFile -Encoding UTF8
}
catch {
    Write-Error "Failed to write telemetry output: $($_.Exception.Message)"
    exit 2
}

Write-Output "Telemetry events written to $EventsFile"
Write-Output "Telemetry coverage written to $CoverageFile"

if ($AllFound) {
    exit 0
}
else {
    exit 1
}
