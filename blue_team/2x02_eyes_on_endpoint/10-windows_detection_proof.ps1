<#
    Script name : 10-windows_detection_proof.ps1
    purpose     : MedDefense Health Systems - Eyes on the Endpoint (2x02), Task 10.
                  Two datasets now exist: the ground truth of exactly what
                  the attacker simulation did (windows_attack_log.json,
                  Task 9) and the telemetry the instrumentation actually
                  captured (Sysmon, Security, PowerShell logs). This
                  script maps one to the other - for every simulated
                  action, was it captured, by which source, with what
                  Event ID, at what detail level (full/partial/missed)?
                  This detection matrix is the proof, not a claim, that
                  the instrumentation built across this whole project
                  works under realistic multi-step attack conditions.
                  Read-only: searches event logs, writes only the report.
    author      : Tales
    Date        : 2026-08-12
#>

[CmdletBinding()]
param(
    [string]$GroundTruthPath = (Join-Path $PSScriptRoot "windows_attack_log.json"),
    [string]$ReportPath      = (Join-Path $PSScriptRoot "windows_detection_matrix.json"),
    [int]$WindowSeconds      = 30  # the 30-second search window around each action's timestamp
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Test-Path -Path $GroundTruthPath)) {
    throw "$GroundTruthPath not found - run 9-windows_attack_sim.ps1 first."
}

# source label (as recorded in the ground truth) -> the real Windows log name to search.
$SourceToLogName = @{
    "Security"       = "Security"
    "Sysmon"         = "Microsoft-Windows-Sysmon/Operational"
    "PS ScriptBlock" = "Microsoft-Windows-PowerShell/Operational"
}

# Event ID -> the key fields that must be populated for "full" detail; if the
# event fires but these are empty, that is only "partial" detail.
$KeyFieldsByEventId = @{
    4720 = @("TargetUserName")
    4732 = @("MemberName")
    4104 = @("ScriptBlockText")
    1    = @("Image", "CommandLine")
    3    = @("DestinationIp", "DestinationPort")
    11   = @("TargetFilename")
}

function Get-EventDataValue {
    param([System.Diagnostics.Eventing.Reader.EventLogRecord]$EventRecord, [string]$Name)
    if (-not $EventRecord) { return $null }
    [xml]$eventXml = $EventRecord.ToXml()
    $node = $eventXml.Event.EventData.Data | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
    if ($node) { return $node.'#text' }
    return $null
}

$GroundTruth = Get-Content -Path $GroundTruthPath -Raw | ConvertFrom-Json
$Actions = @($GroundTruth.actions)
Write-Output "[*] Loading ground truth ($($Actions.Count) actions)..."
Write-Output "[*] Searching telemetry for each action..."

$MatrixRows = [System.Collections.Generic.List[object]]::new()
$ActionsCaptured = 0
$MultiSourceCount = 0

foreach ($action in $Actions) {
    $centerTime = [datetime]::Parse($action.timestamp, [System.Globalization.CultureInfo]::InvariantCulture).ToUniversalTime()
    $windowStart = $centerTime.AddSeconds(-$WindowSeconds)
    $windowEnd   = $centerTime.AddSeconds($WindowSeconds)

    $anySourceCaptured = $false
    $sourcesCaptured = 0

    foreach ($expected in @($action.expected_detection_sources)) {
        $logName = $SourceToLogName[$expected.source]
        $eventId = [int]$expected.event_id

        $found = Get-WinEvent -LogName $logName -ErrorAction SilentlyContinue |
            Where-Object { $_.Id -eq $eventId -and $_.TimeCreated -ge $windowStart -and $_.TimeCreated -le $windowEnd } |
            Select-Object -First 1

        $keyFields = $KeyFieldsByEventId[$eventId]

        if ($found) {
            $populatedCount = 0
            foreach ($f in $keyFields) {
                if (Get-EventDataValue -EventRecord $found -Name $f) { $populatedCount++ }
            }
            $detail = if ($populatedCount -eq $keyFields.Count) { "Full" } else { "Partial" }
            $status = "[CAPTURED]"
            $anySourceCaptured = $true
            $sourcesCaptured++
        } else {
            $detail = "Missed"
            $status = "[MISSED]"
        }

        $MatrixRows.Add([PSCustomObject]@{
            action_number = $action.action_number
            action        = $action.description
            source        = $expected.source
            event_id      = $eventId
            key_fields    = $keyFields
            detail_level  = $detail
            status        = $status
        })
    }

    if ($anySourceCaptured) { $ActionsCaptured++ }
    if ($sourcesCaptured -gt 1) { $MultiSourceCount++ }
}

# --- Console table ---------------------------------------------------------------------------------
Write-Output ("{0,-26} {1,-14} {2,-10} {3,-9} {4}" -f "Action", "Source", "Event ID", "Detail", "Status")
Write-Output ("{0,-26} {1,-14} {2,-10} {3,-9} {4}" -f "------", "------", "--------", "------", "------")

$lastActionNumber = -1
foreach ($row in $MatrixRows) {
    $actionLabel = if ($row.action_number -eq $lastActionNumber) { "" } else { $row.action }
    Write-Output ("{0,-26} {1,-14} {2,-10} {3,-9} {4}" -f $actionLabel, $row.source, $row.event_id, $row.detail_level, $row.status)
    $lastActionNumber = $row.action_number
}

$CapturedPct = if ($Actions.Count -gt 0) { [math]::Round(($ActionsCaptured / $Actions.Count) * 100, 0) } else { 0 }
Write-Output "Actions: $($Actions.Count) | Captured: $ActionsCaptured/$($Actions.Count) ($CapturedPct%) | Multi-source: $MultiSourceCount"

$Report = [PSCustomObject]@{
    generated          = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    source_ground_truth = $GroundTruthPath
    window_seconds       = $WindowSeconds
    actions_total        = $Actions.Count
    actions_captured     = $ActionsCaptured
    captured_percentage  = $CapturedPct
    multi_source_actions = $MultiSourceCount
    detection_matrix     = $MatrixRows
}
$Report | ConvertTo-Json -Depth 6 | Set-Content -Path $ReportPath -Encoding UTF8

Write-Output "Report saved to: $ReportPath"
