# Runs the provided win_audit.ps1 audit helper (CIS Level 1 control checks
# reported per-line as PASS, FAIL or NOT_APPLICABLE) and computes the
# resulting pass rate.
#
# Artifacts (relative to this script's directory):
#   capstone/baseline/windows_baseline.log
#   capstone/baseline/baseline_windows.json

$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$CapstoneDir = Join-Path $ScriptDir "capstone"
$BaselineDir = Join-Path $CapstoneDir "baseline"
$LogFile = Join-Path $BaselineDir "windows_baseline.log"
$OutputJsonFile = Join-Path $BaselineDir "baseline_windows.json"

$WinAuditHelper = "C:\MedDefense_Lab\capstone\win_audit.ps1"
$MasterValidation = Join-Path $ScriptDir "overrides\15-master_validation.ps1"
if (-not (Test-Path $MasterValidation)) {
    $MasterValidation = Join-Path $ScriptDir "..\2x01_windows_fortress\15-master_validation.ps1"
}
$SysmonConfigPath = Join-Path $ScriptDir "..\2x01_windows_fortress\sysmonconfig.xml"

if (-not (Test-Path $WinAuditHelper)) {
    Write-Error "Required audit helper not found: $WinAuditHelper"
    exit 2
}

if (-not (Test-Path $MasterValidation)) {
    Write-Error "Required validation script not found: $MasterValidation"
    exit 2
}

New-Item -ItemType Directory -Path $BaselineDir -Force | Out-Null

$LogLines = New-Object System.Collections.Generic.List[string]
$LogLines.Add("===== win_audit.ps1 (feature inventory) =====")
$LogLines.Add((Get-Date).ToUniversalTime().ToString("o"))

try {
    $WinAuditOutput = & $WinAuditHelper 2>&1 | Out-String
    $LogLines.Add($WinAuditOutput)
}
catch {
    $LogLines.Add("ERROR: $($_.Exception.Message)")
}

$LogLines.Add("===== 15-master_validation.ps1 (CIS Level 1 scoring) =====")
$LogLines.Add((Get-Date).ToUniversalTime().ToString("o"))

$ValidationReportPath = Join-Path $BaselineDir "master_validation_report.json"

try {
    $ValidationOutput = & $MasterValidation -ReportPath $ValidationReportPath -SysmonConfigPath $SysmonConfigPath 2>&1 | Out-String
    $LogLines.Add($ValidationOutput)
}
catch {
    $LogLines.Add("ERROR: $($_.Exception.Message)")
    $LogLines -join "`r`n`r`n" | Set-Content -Path $LogFile -Encoding UTF8
    Write-Error "15-master_validation.ps1 failed to run: $($_.Exception.Message)"
    exit 2
}

$LogLines -join "`r`n`r`n" | Set-Content -Path $LogFile -Encoding UTF8

if (-not (Test-Path $ValidationReportPath)) {
    Write-Error "master_validation_report.json was not produced."
    exit 2
}

$Report = Get-Content $ValidationReportPath -Raw | ConvertFrom-Json

$ControlsTotal = [int]$Report.TotalChecks
$PassCount = [int]$Report.PassCount
$FailCount = [int]$Report.FailCount
$NaCount = [int]$Report.WarnCount

$PassRatePercent = 0
if ($ControlsTotal -gt 0) {
    $PassRatePercent = [math]::Round(($PassCount / $ControlsTotal) * 100, 2)
}

$HostnameVal = $env:COMPUTERNAME
$Timestamp = (Get-Date).ToUniversalTime().ToString("o")

$Result = [PSCustomObject]@{
    timestamp         = $Timestamp
    hostname          = $HostnameVal
    controls_total    = $ControlsTotal
    pass_count        = $PassCount
    fail_count        = $FailCount
    na_count          = $NaCount
    pass_rate_percent = $PassRatePercent
    log_path          = $LogFile
}

try {
    $Result | ConvertTo-Json -Depth 5 | Set-Content -Path $OutputJsonFile -Encoding UTF8
}
catch {
    Write-Error "Failed to write ${OutputJsonFile}: $($_.Exception.Message)"
    exit 2
}

Write-Output "Baseline written to $OutputJsonFile (pass_rate_percent=$PassRatePercent)"

if ($ControlsTotal -eq 0) {
    exit 1
}

exit 0
