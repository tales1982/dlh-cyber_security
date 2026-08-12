<#
    Script name : 3-windows_telemetry_export.ps1
    purpose     : MedDefense Health Systems - Eyes on the Endpoint (2x02), Task 3.
                  Raw EVTX data is not analyst-ready: three logs (Security,
                  Sysmon Operational, PowerShell Operational) use three
                  different schemas and timestamp conventions. This script
                  exports a configurable time window (default: last 24
                  hours) from all three into one normalized JSON file -
                  every record carries the same common fields, and the
                  event types that matter most for detection (4624, 4625,
                  4672, 4688, 4104, Sysmon 1/3/11/13/22) get their key
                  fields extracted from the event's structured XML data,
                  not regex-scraped from the free-text message. This
                  becomes the Windows half of the telemetry handoff
                  package Module 3 consumes.
                  Read-only: queries event logs, writes only the export.
    author      : Tales
    Date        : 2026-08-12
#>

[CmdletBinding()]
param(
    [datetime]$StartTime = (Get-Date).ToUniversalTime().AddHours(-24),
    [datetime]$EndTime   = (Get-Date).ToUniversalTime(),
    [string]$OutputPath  = (Join-Path $PSScriptRoot "windows_events_export.json")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Hostname = $env:COMPUTERNAME

# LogName -> (friendly source_type, channel label)
$LogSources = @(
    [PSCustomObject]@{ LogName = "Security";                              SourceType = "Security";   Channel = "Security" }
    [PSCustomObject]@{ LogName = "Microsoft-Windows-Sysmon/Operational";  SourceType = "Sysmon";      Channel = "Sysmon" }
    [PSCustomObject]@{ LogName = "Microsoft-Windows-PowerShell/Operational"; SourceType = "PowerShell"; Channel = "PowerShell" }
)

function Get-EventDataValue {
    param([xml]$EventXml, [string]$Name)
    $node = $EventXml.Event.EventData.Data | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
    if ($node) { return $node.'#text' }
    return $null
}

function Get-EnrichedFields {
    param([System.Diagnostics.Eventing.Reader.EventLogRecord]$EventRecord, [xml]$EventXml)

    switch ($EventRecord.Id) {
        4624 {
            return [PSCustomObject]@{
                target_user      = Get-EventDataValue -EventXml $EventXml -Name "TargetUserName"
                logon_type       = Get-EventDataValue -EventXml $EventXml -Name "LogonType"
                source_ip        = Get-EventDataValue -EventXml $EventXml -Name "IpAddress"
                workstation      = Get-EventDataValue -EventXml $EventXml -Name "WorkstationName"
            }
        }
        4625 {
            return [PSCustomObject]@{
                target_user      = Get-EventDataValue -EventXml $EventXml -Name "TargetUserName"
                failure_reason   = Get-EventDataValue -EventXml $EventXml -Name "FailureReason"
                source_ip        = Get-EventDataValue -EventXml $EventXml -Name "IpAddress"
            }
        }
        4672 {
            return [PSCustomObject]@{
                privileged_account = Get-EventDataValue -EventXml $EventXml -Name "SubjectUserName"
            }
        }
        4688 {
            return [PSCustomObject]@{
                process_name    = Get-EventDataValue -EventXml $EventXml -Name "NewProcessName"
                command_line    = Get-EventDataValue -EventXml $EventXml -Name "CommandLine"
                parent_process  = Get-EventDataValue -EventXml $EventXml -Name "ParentProcessName"
            }
        }
        4104 {
            return [PSCustomObject]@{
                script_block_text = Get-EventDataValue -EventXml $EventXml -Name "ScriptBlockText"
            }
        }
        1 {
            if ($EventRecord.LogName -ne "Microsoft-Windows-Sysmon/Operational") { return $null }
            return [PSCustomObject]@{
                image         = Get-EventDataValue -EventXml $EventXml -Name "Image"
                command_line  = Get-EventDataValue -EventXml $EventXml -Name "CommandLine"
                parent_image  = Get-EventDataValue -EventXml $EventXml -Name "ParentImage"
                hashes        = Get-EventDataValue -EventXml $EventXml -Name "Hashes"
            }
        }
        3 {
            if ($EventRecord.LogName -ne "Microsoft-Windows-Sysmon/Operational") { return $null }
            return [PSCustomObject]@{
                destination_ip   = Get-EventDataValue -EventXml $EventXml -Name "DestinationIp"
                destination_port = Get-EventDataValue -EventXml $EventXml -Name "DestinationPort"
                process          = Get-EventDataValue -EventXml $EventXml -Name "Image"
            }
        }
        11 {
            if ($EventRecord.LogName -ne "Microsoft-Windows-Sysmon/Operational") { return $null }
            return [PSCustomObject]@{
                target_filename  = Get-EventDataValue -EventXml $EventXml -Name "TargetFilename"
                creating_process = Get-EventDataValue -EventXml $EventXml -Name "Image"
            }
        }
        13 {
            if ($EventRecord.LogName -ne "Microsoft-Windows-Sysmon/Operational") { return $null }
            $targetObject = Get-EventDataValue -EventXml $EventXml -Name "TargetObject"
            $registryKey  = $targetObject
            $valueName    = $null
            if ($targetObject -and $targetObject.Contains("\")) {
                $registryKey = $targetObject.Substring(0, $targetObject.LastIndexOf("\"))
                $valueName   = $targetObject.Substring($targetObject.LastIndexOf("\") + 1)
            }
            return [PSCustomObject]@{
                registry_key = $registryKey
                value_name   = $valueName
            }
        }
        22 {
            if ($EventRecord.LogName -ne "Microsoft-Windows-Sysmon/Operational") { return $null }
            return [PSCustomObject]@{
                query_name    = Get-EventDataValue -EventXml $EventXml -Name "QueryName"
                query_results = Get-EventDataValue -EventXml $EventXml -Name "QueryResults"
            }
        }
        default { return $null }
    }
}

Write-Output "[*] Exporting Windows telemetry from last 24 hours..."

$AllEvents = [System.Collections.Generic.List[object]]::new()
$PerChannelCount = @{}

foreach ($source in $LogSources) {
    $records = @(Get-WinEvent -FilterHashtable @{
        LogName   = $source.LogName
        StartTime = $StartTime
        EndTime   = $EndTime
    } -ErrorAction SilentlyContinue)

    $PerChannelCount[$source.Channel] = $records.Count

    foreach ($rec in $records) {
        [xml]$eventXml = $rec.ToXml()
        $enriched = Get-EnrichedFields -EventRecord $rec -EventXml $eventXml

        $normalized = [PSCustomObject]@{
            timestamp        = $rec.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            hostname          = $Hostname
            platform          = "windows"
            source_type       = $source.SourceType
            channel           = $source.Channel
            event_id          = if ($source.SourceType -eq "Sysmon") { "Sysmon-$($rec.Id)" } else { $rec.Id }
            event_category    = $rec.TaskDisplayName
            provider          = $rec.ProviderName
            raw_message       = $rec.Message
        }
        if ($enriched) {
            $normalized | Add-Member -MemberType NoteProperty -Name "enriched" -Value $enriched
        }
        $AllEvents.Add($normalized)
    }
}

$SecurityCount   = if ($PerChannelCount.ContainsKey("Security")) { $PerChannelCount["Security"] } else { 0 }
$SysmonCount     = if ($PerChannelCount.ContainsKey("Sysmon")) { $PerChannelCount["Sysmon"] } else { 0 }
$PowerShellCount = if ($PerChannelCount.ContainsKey("PowerShell")) { $PerChannelCount["PowerShell"] } else { 0 }
$TotalCount      = $AllEvents.Count

$TopEventIds = ($AllEvents | Group-Object -Property event_id | Sort-Object -Property Count -Descending | Select-Object -First 4).Name

Write-Output "Security events: $SecurityCount"
Write-Output "Sysmon events: $SysmonCount"
Write-Output "PowerShell events: $PowerShellCount"
Write-Output "Total events: $TotalCount"
Write-Output "Top Event IDs: $($TopEventIds -join ', ')"

$Report = [PSCustomObject]@{
    generated       = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    window_start    = $StartTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    window_end      = $EndTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    hostname        = $Hostname
    counts          = [PSCustomObject]@{
        security    = $SecurityCount
        sysmon      = $SysmonCount
        powershell  = $PowerShellCount
        total       = $TotalCount
    }
    top_event_ids   = $TopEventIds
    events          = $AllEvents
}
$Report | ConvertTo-Json -Depth 6 | Set-Content -Path $OutputPath -Encoding UTF8

Write-Output "Output: $OutputPath"
