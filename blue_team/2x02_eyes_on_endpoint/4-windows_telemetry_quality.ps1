<#
    Script name : 4-windows_telemetry_quality.ps1
    purpose     : MedDefense Health Systems - Eyes on the Endpoint (2x02), Task 4.
                  A telemetry export can exist and still be useless: empty
                  command-line fields, missing source IPs on every logon
                  event, or a 3-hour silent gap where nothing was
                  captured. This is the quality gate windows_events_export.json
                  (Task 3) must clear before it enters the final handoff
                  package - event distribution, channel balance, hour-by-
                  hour time coverage, gap detection (>30 minutes silent),
                  field completeness on the event types analysts actually
                  triage, and a single weighted 0-100 score with a
                  good/acceptable/poor verdict.
                  Read-only: reads the export, writes only the report.
    author      : Tales
    Date        : 2026-08-12
#>

[CmdletBinding()]
param(
    [string]$InputPath  = (Join-Path $PSScriptRoot "windows_events_export.json"),
    [string]$ReportPath = (Join-Path $PSScriptRoot "windows_telemetry_quality.json"),
    [int]$GapThresholdMinutes = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Test-Path -Path $InputPath)) {
    throw "$InputPath not found - run 3-windows_telemetry_export.ps1 first."
}

Write-Output "[*] Analyzing $InputPath..."
$Export = Get-Content -Path $InputPath -Raw | ConvertFrom-Json
$Events = @($Export.events)
$TotalEvents = $Events.Count

# --- Event Distribution: count and percentage per Event ID ------------------------------------
$EventDistribution = @($Events | Group-Object -Property event_id | Sort-Object -Property Count -Descending | ForEach-Object {
    [PSCustomObject]@{
        event_id   = $_.Name
        count      = $_.Count
        percentage = if ($TotalEvents -gt 0) { [math]::Round(($_.Count / $TotalEvents) * 100, 1) } else { 0 }
    }
})

# --- Channel Distribution: Security, Sysmon, PowerShell (as populated by Task 3) -----------------
$ChannelDistribution = @($Events | Group-Object -Property channel | ForEach-Object {
    [PSCustomObject]@{
        channel    = $_.Name
        count      = $_.Count
        percentage = if ($TotalEvents -gt 0) { [math]::Round(($_.Count / $TotalEvents) * 100, 1) } else { 0 }
    }
})

# --- Time Coverage: events per hour, hours with/without events -----------------------------------
$Timestamps = @($Events | ForEach-Object { [datetime]$_.timestamp } | Sort-Object)
$WindowStart = if ($Export.window_start) { [datetime]$Export.window_start } elseif ($Timestamps.Count -gt 0) { $Timestamps[0] } else { Get-Date }
$WindowEnd   = if ($Export.window_end) { [datetime]$Export.window_end } elseif ($Timestamps.Count -gt 0) { $Timestamps[-1] } else { Get-Date }
$TotalHours  = [math]::Max(1, [math]::Ceiling(($WindowEnd - $WindowStart).TotalHours))

$EventsPerHour = [ordered]@{}
for ($h = 0; $h -lt $TotalHours; $h++) {
    $bucketStart = $WindowStart.AddHours($h)
    $bucketEnd   = $WindowStart.AddHours($h + 1)
    $count = @($Timestamps | Where-Object { $_ -ge $bucketStart -and $_ -lt $bucketEnd }).Count
    $EventsPerHour[$bucketStart.ToString("yyyy-MM-ddTHH:00:00Z")] = $count
}
$HoursWithEvents    = @($EventsPerHour.Values | Where-Object { $_ -gt 0 }).Count
$HoursWithoutEvents = $TotalHours - $HoursWithEvents

# --- Gap Detection: periods longer than the threshold with no events -----------------------------
$Gaps = [System.Collections.Generic.List[object]]::new()
$LargestGapMinutes = 0
for ($i = 1; $i -lt $Timestamps.Count; $i++) {
    $delta = ($Timestamps[$i] - $Timestamps[$i - 1]).TotalMinutes
    if ($delta -gt $GapThresholdMinutes) {
        $Gaps.Add([PSCustomObject]@{
            gap_start        = $Timestamps[$i - 1].ToString("yyyy-MM-ddTHH:mm:ssZ")
            gap_end          = $Timestamps[$i].ToString("yyyy-MM-ddTHH:mm:ssZ")
            duration_minutes = [math]::Round($delta, 1)
        })
    }
    if ($delta -gt $LargestGapMinutes) { $LargestGapMinutes = $delta }
}
$LargestGapMinutes = [math]::Round($LargestGapMinutes, 1)

# --- Field Completeness -------------------------------------------------------------------------
function Get-CompletenessPercent {
    param([object[]]$Candidates, [string]$FieldPath)
    if ($Candidates.Count -eq 0) { return 100.0 }
    $populated = 0
    foreach ($e in $Candidates) {
        $value = $e
        foreach ($segment in ($FieldPath -split '\.')) {
            if ($null -eq $value) { break }
            if ($value.PSObject.Properties.Name -contains $segment) {
                $value = $value.$segment
            } else {
                $value = $null
            }
        }
        if ($value -and "$value".Trim().Length -gt 0) { $populated++ }
    }
    return [math]::Round(($populated / $Candidates.Count) * 100, 1)
}

$ProcessEvents = @($Events | Where-Object { $_.event_id -eq 4688 -or $_.event_id -eq "Sysmon-1" })
$LogonEvents   = @($Events | Where-Object { $_.event_id -eq 4624 -or $_.event_id -eq 4625 })
$PsEvents      = @($Events | Where-Object { $_.event_id -eq 4104 })

$CommandLineCompleteness = Get-CompletenessPercent -Candidates $ProcessEvents -FieldPath "enriched.command_line"
$SourceIPCompleteness    = Get-CompletenessPercent -Candidates $LogonEvents   -FieldPath "enriched.source_ip"
# ScriptBlockText is the field 3-windows_telemetry_export.ps1 enriches EID 4104 events with.
$ScriptBlockCompleteness = Get-CompletenessPercent -Candidates $PsEvents      -FieldPath "enriched.script_block_text"

$FieldCompletenessByType = @($Events | Group-Object -Property event_id | ForEach-Object {
    $groupEvents = @($_.Group)
    $withEnriched = @($groupEvents | Where-Object { $_.PSObject.Properties.Name -contains 'enriched' })
    [PSCustomObject]@{
        event_id           = $_.Name
        total_events       = $groupEvents.Count
        events_with_enriched_fields = $withEnriched.Count
        completeness_pct   = if ($groupEvents.Count -gt 0) { [math]::Round(($withEnriched.Count / $groupEvents.Count) * 100, 1) } else { 0 }
    }
})

# --- Quality Score: weighted 0-100 ----------------------------------------------------------------
$TimeCoverageScore = if ($TotalHours -gt 0) { ($HoursWithEvents / $TotalHours) * 100 } else { 0 }
$GapScore = [math]::Max(0, 100 - ($Gaps.Count * 10))
$WeightedScore = ($TimeCoverageScore * 0.25) + ($GapScore * 0.15) +
                 ($CommandLineCompleteness * 0.20) + ($SourceIPCompleteness * 0.20) +
                 ($ScriptBlockCompleteness * 0.20)
$QualityScore = [math]::Round($WeightedScore, 1)
$Assessment = if ($QualityScore -ge 90) { "good" } elseif ($QualityScore -ge 70) { "acceptable" } else { "poor" }

Write-Output "Total events: $TotalEvents"
Write-Output "Hours with events: $HoursWithEvents/$TotalHours"
Write-Output "Largest gap: $LargestGapMinutes minutes"
Write-Output "Command-line completeness: $CommandLineCompleteness%"
Write-Output "Source IP completeness: $SourceIPCompleteness%"
Write-Output "Script block completeness: $ScriptBlockCompleteness%"
Write-Output "Quality score: $QualityScore% ($Assessment)"

$Report = [PSCustomObject]@{
    generated                 = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    source_export              = $InputPath
    total_events                = $TotalEvents
    event_distribution          = $EventDistribution
    channel_distribution        = $ChannelDistribution
    time_coverage                = [PSCustomObject]@{
        total_hours          = $TotalHours
        hours_with_events    = $HoursWithEvents
        hours_without_events = $HoursWithoutEvents
        events_per_hour       = $EventsPerHour
    }
    gap_detection                = [PSCustomObject]@{
        threshold_minutes = $GapThresholdMinutes
        gap_count          = $Gaps.Count
        largest_gap_minutes = $LargestGapMinutes
        gaps               = @($Gaps)
    }
    field_completeness           = [PSCustomObject]@{
        command_line_pct   = $CommandLineCompleteness
        source_ip_pct       = $SourceIPCompleteness
        script_block_pct    = $ScriptBlockCompleteness
        by_event_type        = $FieldCompletenessByType
    }
    quality_score                = $QualityScore
    assessment                    = $Assessment
}
$Report | ConvertTo-Json -Depth 6 | Set-Content -Path $ReportPath -Encoding UTF8

Write-Output "Report saved to: $ReportPath"
