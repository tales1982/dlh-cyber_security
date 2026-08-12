<#
    Script name : 1-sysmon_coverage_matrix.ps1
    purpose     : MedDefense Health Systems - Eyes on the Endpoint (2x02), Task 1.
                  A Sysmon Event ID being "enabled" in sysmonconfig.xml does
                  not mean an attacker action using it will actually be
                  logged - an onmatch="include" rule scoped to 3 process
                  names or 3 ports silently drops everything else. This
                  script parses the live sysmonconfig.xml deployed in 2x01
                  (Task 9, tuned in Task 10), maps 7 MITRE ATT&CK techniques
                  to the Sysmon Event IDs required to see them, and reasons
                  about whether each technique's actual include/exclude
                  filtering will realistically catch it (covered), catch
                  only a narrow slice of it (partial), or miss it entirely
                  because the required Event ID has no rule group at all
                  (blind). Read-only: parses XML, writes only the report.
    author      : Tales
    Date        : 2026-08-12
#>

[CmdletBinding()]
param(
    [string]$SysmonConfigPath = $(
        $local = Join-Path $PSScriptRoot "sysmonconfig.xml"
        $shared = Join-Path $PSScriptRoot "..\2x01_windows_fortress\sysmonconfig.xml"
        if (Test-Path -Path $local) { $local } else { $shared }
    ),
    [string]$ReportPath = (Join-Path $PSScriptRoot "sysmon_coverage_matrix.json")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Test-Path -Path $SysmonConfigPath)) {
    throw "Sysmon config not found at '$SysmonConfigPath'. Pass -SysmonConfigPath explicitly."
}

Write-Output "[*] Parsing Sysmon config: $SysmonConfigPath"
[xml]$SysmonXml = Get-Content -Path $SysmonConfigPath -Raw
$RuleGroups = @($SysmonXml.Sysmon.EventFiltering.RuleGroup)

# Sysmon schema: XML element tag name (what appears inside a RuleGroup) -> the
# Event ID(s) that element type controls/generates. RegistryEvent covers
# CreateKey/DeleteKey (12), SetValue (13) and RenameKey (14) together - Sysmon
# does not split these into separate config elements.
$TagToEventIds = [ordered]@{
    ProcessCreate        = @(1)
    FileCreateTime       = @(2)
    NetworkConnect       = @(3)
    ProcessTerminate     = @(5)
    DriverLoad           = @(6)
    ImageLoad            = @(7)
    CreateRemoteThread   = @(8)
    RawAccessRead        = @(9)
    ProcessAccess        = @(10)
    FileCreate           = @(11)
    RegistryEvent        = @(12, 13, 14)
    FileCreateStreamHash = @(15)
    PipeEvent            = @(17, 18)
    WmiEvent             = @(19, 20, 21)
    DnsQuery             = @(22)
    FileDelete           = @(23)
}
$EventIdToTag = @{}
foreach ($tag in $TagToEventIds.Keys) {
    foreach ($id in $TagToEventIds[$tag]) { $EventIdToTag[$id] = $tag }
}

function Get-TagElements {
    param([string]$TagName)
    @($RuleGroups | ForEach-Object { $_.$TagName } | Where-Object { $_ })
}

function Get-ConditionElements {
    # A RuleGroup's event-type element can either hold condition elements
    # directly (<Image condition="...">) or wrap them in one or more named
    # <Rule> groups (used by the MedDefense Custom Detections block) - flatten
    # both shapes to the actual condition elements.
    param([System.Xml.XmlElement]$Parent)
    foreach ($child in @($Parent.ChildNodes | Where-Object { $_.NodeType -eq 'Element' })) {
        if ($child.Name -eq 'Rule') {
            Get-ConditionElements -Parent $child
        } else {
            $child
        }
    }
}

function Get-TagFilterInfo {
    param([string]$TagName)
    $elements = Get-TagElements -TagName $TagName
    if (-not $elements) { return $null }
    $conditions = foreach ($el in $elements) {
        foreach ($child in @(Get-ConditionElements -Parent $el)) {
            "$($el.onmatch): $($child.Name) $($child.condition) '$($child.InnerText)'"
        }
    }
    [PSCustomObject]@{
        OnMatchValues = @($elements | ForEach-Object { $_.onmatch } | Select-Object -Unique)
        Conditions    = @($conditions)
    }
}

# Union of every Event ID whose tag has at least one RuleGroup entry anywhere
# in the config - this is "enabled" in the sense Sysmon will emit that event
# type at all, independent of how narrowly it may be filtered.
$EnabledEventIds = [System.Collections.Generic.List[int]]::new()
foreach ($tag in $TagToEventIds.Keys) {
    if (Get-TagElements -TagName $tag) {
        foreach ($id in $TagToEventIds[$tag]) { $EnabledEventIds.Add($id) }
    }
}
$EnabledEventIds = @($EnabledEventIds | Sort-Object -Unique)

# Minimum ATT&CK mappings this task requires. Verdict/Reason/Recommendation
# reflect actual analysis of THIS config's real filter scope for THIS
# specific technique - an include filter can be narrow and still adequate
# (T1547's Run/RunOnce/Services scope IS the autostart surface) or narrow
# and genuinely leaky (T1055's lsass/winlogon-only scope misses injection
# into any other process). That judgment cannot be derived from XML
# structure alone, so it is made explicitly here, grounded in the actual
# onmatch/condition values read from sysmonconfig.xml above. The mechanical
# check below can still force a technique down to "blind" if a future edit
# to sysmonconfig.xml removes a required Event ID's RuleGroup entirely.
$Techniques = @(
    [PSCustomObject]@{ Id = 'T1059';     Name = 'Command and Scripting Interpreter'; Required = @(1);     Fields = @('Image','CommandLine','ParentImage','ParentCommandLine','User'); Verdict = 'covered'; Reason = 'ProcessCreate has an exclude-only RuleGroup (svchost.exe, MsMpEng.exe, SearchIndexer.exe) in addition to the MedDefense include rules, so command-line execution is logged broadly by default.'; Recommendation = 'None - coverage is adequate.' }
    [PSCustomObject]@{ Id = 'T1053';     Name = 'Scheduled Task/Job';                Required = @(1);     Fields = @('Image','CommandLine','ParentImage','User'); Verdict = 'covered'; Reason = 'Covered by the same broad ProcessCreate visibility as T1059, plus the dedicated Rule5-ScheduledTaskPersistence include rule for schtasks.exe /create.'; Recommendation = 'None - coverage is adequate.' }
    [PSCustomObject]@{ Id = 'T1547';     Name = 'Boot or Logon Autostart Execution'; Required = @(13);    Fields = @('TargetObject','Details','EventType','Image'); Verdict = 'covered'; Reason = 'RegistryEvent is include-only, but its scope (\CurrentVersion\Run, \CurrentVersion\RunOnce, \Services\) IS the primary autostart-persistence surface this technique targets - the narrow filter is well-aligned, not a gap.'; Recommendation = 'None - coverage is adequate.' }
    [PSCustomObject]@{ Id = 'T1055';     Name = 'Process Injection';                 Required = @(8, 10); Fields = @('SourceImage','TargetImage','GrantedAccess','CallTrace'); Verdict = 'partial'; Reason = 'CreateRemoteThread and ProcessAccess are both include-only and scoped to lsass.exe/winlogon.exe as targets - real process injection is not limited to credential-theft targets, so injection into explorer.exe, browsers or Office processes currently generates no event.'; Recommendation = 'Broaden the CreateRemoteThread/ProcessAccess include filters beyond lsass.exe and winlogon.exe - add explorer.exe and commonly abused browser/Office processes as additional TargetImage entries.' }
    [PSCustomObject]@{ Id = 'T1071';     Name = 'Application Layer Protocol';        Required = @(3, 22); Fields = @('DestinationIp','DestinationPort','Image','QueryName','QueryResults'); Verdict = 'partial'; Reason = 'NetworkConnect is include-only and scoped to 3 specific process images or ports 445/3389/4444 - a C2 channel over standard web ports (80/443/8080) from a non-whitelisted process currently generates no event, even though DnsQuery itself is broadly (exclude-only) covered.'; Recommendation = 'Broaden the NetworkConnect include filter to also match common C2 ports (80, 443, 8080, 8443), or switch it to an exclude-based rule so traffic is captured by default.' }
    [PSCustomObject]@{ Id = 'T1574.002'; Name = 'DLL Side-Loading';                  Required = @(7);     Fields = @('Image','ImageLoaded','Signed','Signature','Hashes'); Verdict = 'covered'; Reason = 'ImageLoad is include-only (unsigned OR amsi.dll), but side-loaded payload DLLs are overwhelmingly unsigned in practice, so this scope catches the realistic majority of side-loading attempts.'; Recommendation = 'None - coverage is adequate.' }
    [PSCustomObject]@{ Id = 'T1027';     Name = 'Obfuscated or Compressed Files';    Required = @(11, 15); Fields = @('TargetFilename','Image','Hash','Contents'); Verdict = 'covered'; Reason = 'FileCreate is include-only but scoped to .exe/.ps1/.dll and the Startup folder - the extensions attackers overwhelmingly drop - and FileCreateStreamHash tags Mark-of-the-Web on anything landing in Downloads.'; Recommendation = 'None - coverage is adequate.' }
)

$Matrix = foreach ($tech in $Techniques) {
    $enabledForTech = @($tech.Required | Where-Object { $_ -in $EnabledEventIds })
    $missingForTech = @($tech.Required | Where-Object { $_ -notin $EnabledEventIds })

    $allConflicts = [System.Collections.Generic.List[string]]::new()
    foreach ($id in $tech.Required) {
        $tag = $EventIdToTag[$id]
        $info = Get-TagFilterInfo -TagName $tag
        if ($info -and ($info.OnMatchValues -contains 'include')) {
            foreach ($c in $info.Conditions) { $allConflicts.Add("EID $id ($tag) $c") }
        }
    }

    if ($missingForTech.Count -eq $tech.Required.Count) {
        $status = 'blind'
        $reason = "None of the required Event IDs ($($tech.Required -join ', ')) have a RuleGroup in this config - Sysmon generates no telemetry for this technique at all."
    } elseif ($missingForTech.Count -gt 0) {
        $status = 'partial'
        $reason = "Event ID(s) $($missingForTech -join ', ') required for this technique have no RuleGroup in the current config - only $($enabledForTech -join ', ') are enabled."
    } else {
        $status = $tech.Verdict
        $reason = $tech.Reason
    }

    [PSCustomObject]@{
        technique_id            = $tech.Id
        technique_name          = $tech.Name
        required_event_ids      = $tech.Required
        enabled_event_ids       = $enabledForTech
        filter_conflicts        = @($allConflicts)
        coverage_status         = $status
        evidence_fields_expected = $tech.Fields
        recommendation          = $tech.Recommendation
        status_reason           = $reason
    }
}

$CoveredCount = @($Matrix | Where-Object { $_.coverage_status -eq 'covered' }).Count
$PartialCount = @($Matrix | Where-Object { $_.coverage_status -eq 'partial' }).Count
$BlindCount   = @($Matrix | Where-Object { $_.coverage_status -eq 'blind' }).Count

Write-Output "Enabled Event IDs: $($EnabledEventIds -join ', ')"
Write-Output "Techniques assessed: $($Matrix.Count)"
Write-Output "Covered: $CoveredCount"
Write-Output "Partial: $PartialCount"
Write-Output "Blind: $BlindCount"

$Report = [PSCustomObject]@{
    generated          = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    source_config       = $SysmonConfigPath
    enabled_event_ids   = $EnabledEventIds
    techniques_assessed = $Matrix.Count
    covered_count       = $CoveredCount
    partial_count       = $PartialCount
    blind_count         = $BlindCount
    matrix              = $Matrix
}
$Report | ConvertTo-Json -Depth 6 | Set-Content -Path $ReportPath -Encoding UTF8

Write-Output "Report saved to: $ReportPath"
