<#
    Script name : 2-eventlog_assessment.ps1
    Purpose     : MedDefense Health Systems - Windows Fortress (2x01), Task 2.
                  Quantifies the gap between what the domain can currently
                  see and what it needs to see. For each critical Event ID
                  (4624, 4625, 4648, 4688, 4720, 4726, 4732, 4672, 1102) this
                  script checks whether the audit subcategory that generates
                  it is actually enabled (auditpol /get /category:*) and
                  cross-checks the Security log for real occurrences in the
                  last 24 hours. If 4688 is not generating, every process an
                  attacker runs is invisible; if 4672 is not generating,
                  privilege use is invisible.
                  Read-only: this script makes no configuration changes.
    Author      : Tales
    Date        : 2026-08-08
#>

[CmdletBinding()]
param(
    [int]$LookbackHours = 24
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# --- Critical Event ID reference table -------------------------------------------
# DisplaySubcategory matches the legacy Basic Audit Policy category name shown to
# analysts; AuditPolSubcategory is the granular Advanced Audit Policy subcategory
# actually queried against `auditpol /get /category:*` output.
$EventMap = @(
    [PSCustomObject]@{ EventId = 4624; Description = "Successful Logon";      DisplaySubcategory = "Logon";               AuditPolSubcategory = "Logon" }
    [PSCustomObject]@{ EventId = 4625; Description = "Failed Logon";          DisplaySubcategory = "Logon";               AuditPolSubcategory = "Logon" }
    [PSCustomObject]@{ EventId = 4648; Description = "Explicit Credentials";  DisplaySubcategory = "Logon";               AuditPolSubcategory = "Logon" }
    [PSCustomObject]@{ EventId = 4688; Description = "Process Creation";      DisplaySubcategory = "Process Tracking";    AuditPolSubcategory = "Process Creation" }
    [PSCustomObject]@{ EventId = 4720; Description = "Account Created";       DisplaySubcategory = "Account Management";  AuditPolSubcategory = "User Account Management" }
    [PSCustomObject]@{ EventId = 4726; Description = "Account Deleted";       DisplaySubcategory = "Account Management";  AuditPolSubcategory = "User Account Management" }
    [PSCustomObject]@{ EventId = 4732; Description = "Member Added to Group"; DisplaySubcategory = "Account Management";  AuditPolSubcategory = "Security Group Management" }
    [PSCustomObject]@{ EventId = 4672; Description = "Special Logon";         DisplaySubcategory = "Special Logon";       AuditPolSubcategory = "Special Logon" }
    [PSCustomObject]@{ EventId = 1102; Description = "Audit Log Cleared";     DisplaySubcategory = "System Integrity";    AuditPolSubcategory = "System Integrity" }
)

# --- Current audit policy configuration -------------------------------------------
# auditpol /get /category:* enumerates every subcategory across all nine audit
# categories; /r returns it as parseable CSV instead of fixed-width columns.
$AuditCsvRaw = auditpol /get /category:* /r
$AuditRows   = $AuditCsvRaw | ConvertFrom-Csv
$AuditMap    = @{}
foreach ($row in $AuditRows) {
    $AuditMap[$row.Subcategory] = $row.'Inclusion Setting'
}

function Test-SubcategoryEnabled {
    param([string]$Name)
    if (-not $AuditMap.ContainsKey($Name)) { return $false }
    $setting = $AuditMap[$Name]
    return ($setting -ne "No Auditing") -and ($setting -ne "")
}

# --- Actual Security log generation in the lookback window ------------------------
$Since = (Get-Date).AddHours(-$LookbackHours)
$EventIdList = $EventMap.EventId
$GeneratedRecently = @{}
try {
    $RecentEvents = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; StartTime = $Since; Id = $EventIdList } -ErrorAction Stop
    foreach ($id in $EventIdList) {
        $GeneratedRecently[$id] = [bool]($RecentEvents | Where-Object { $_.Id -eq $id })
    }
} catch {
    # No matching events in the window (or log unreadable) - treat as none seen.
    foreach ($id in $EventIdList) { $GeneratedRecently[$id] = $false }
}

# --- Build assessment rows ---------------------------------------------------------
$Results = foreach ($evt in $EventMap) {
    $subcategoryEnabled = Test-SubcategoryEnabled -Name $evt.AuditPolSubcategory
    $seenRecently       = $GeneratedRecently[$evt.EventId]
    # 1102 is written by the OS unconditionally whenever the Security log is
    # cleared - it does not depend on any audit subcategory being enabled, so
    # only the actual-occurrence check applies to it.
    $isGenerating = if ($evt.EventId -eq 1102) { $seenRecently } else { $subcategoryEnabled -or $seenRecently }

    [PSCustomObject]@{
        EventId             = $evt.EventId
        Description         = $evt.Description
        DisplaySubcategory  = $evt.DisplaySubcategory
        AuditPolSubcategory = $evt.AuditPolSubcategory
        SubcategoryEnabled  = $subcategoryEnabled
        SeenLast24h         = $seenRecently
        Status              = if ($isGenerating) { "[GENERATING]" } else { "[NOT CONFIGURED]" }
    }
}

# --- Console table -------------------------------------------------------------------
"{0,-9} {1,-25} {2,-21} {3}" -f "Event ID", "Description", "Audit Subcategory", "Status"
"{0,-9} {1,-25} {2,-21} {3}" -f "--------", "-----------", "-----------------", "------"
foreach ($r in $Results) {
    "{0,-9} {1,-25} {2,-21} {3}" -f $r.EventId, $r.Description, $r.DisplaySubcategory, $r.Status
}
