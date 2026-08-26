$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$CapstoneDir = Join-Path $ScriptDir "capstone"
$ExecDir = Join-Path $CapstoneDir "exec"
$BaselineFile = Join-Path $CapstoneDir "baseline\baseline_windows.json"
$TargetStateFile = Join-Path $CapstoneDir "target_state.json"
$LogFile = Join-Path $ExecDir "windows_harden.log"
$OutputJsonFile = Join-Path $ExecDir "windows_harden.json"

$FortressDir = Join-Path $ScriptDir "..\2x01_windows_fortress"
$OverridesDir = Join-Path $ScriptDir "overrides"
$WinAuditHelper = "C:\MedDefense_Lab\capstone\win_audit.ps1"
$MasterValidation = Join-Path $OverridesDir "15-master_validation.ps1"
if (-not (Test-Path $MasterValidation)) {
    $MasterValidation = Join-Path $FortressDir "15-master_validation.ps1"
}
$SysmonConfigPath = Join-Path $FortressDir "sysmonconfig.xml"

if (-not (Test-Path $TargetStateFile)) {
    Write-Error "'$TargetStateFile' is missing. Run 2-target_state.sh first."
    exit 2
}

try {
    $TargetState = Get-Content $TargetStateFile -Raw | ConvertFrom-Json
}
catch {
    Write-Error "'$TargetStateFile' is corrupted: $($_.Exception.Message)"
    exit 2
}

if (-not (Test-Path $BaselineFile)) {
    Write-Error "'$BaselineFile' is missing. Run 1-baseline_snapshot.ps1 first."
    exit 2
}

$Baseline = Get-Content $BaselineFile -Raw | ConvertFrom-Json
$PassRateBefore = [double]$Baseline.pass_rate_percent

$CisControl = $TargetState.controls | Where-Object { $_.id -eq "WIN-CIS-01" } | Select-Object -First 1
$TargetPassRate = 85
if ($CisControl) {
    $TargetPassRate = [double]$CisControl.expected_value
}

New-Item -ItemType Directory -Path $ExecDir -Force | Out-Null

$Steps = @(
    @{ name = "account_policy";       script = "4-password_policy.ps1";  controls = @() }
    @{ name = "audit_policy";         script = "5-audit_policy.ps1";     controls = @("WIN-AUDIT-01") }
    @{ name = "firewall_baseline";    script = "11-firewall_hardening.ps1"; controls = @("WIN-FW-01") }
    @{ name = "sysmon_deployment";    script = "9-sysmon_deploy.ps1";    controls = @("WIN-SYSMON-01") }
    @{ name = "script_block_logging"; script = "6-powershell_security.ps1"; controls = @("WIN-PSLOG-01") }
    @{ name = "applocker_baseline";   script = "12-applocker_config.ps1"; controls = @() }
    @{ name = "service_minimization"; script = "14-service_accounts.ps1"; controls = @() }
)

$LogLines = New-Object System.Collections.Generic.List[string]
$StepResults = @()
$AllOk = $true
$ControlsTouched = New-Object System.Collections.Generic.List[string]

foreach ($Step in $Steps) {
    $ScriptPath = Join-Path $OverridesDir $Step.script
    if (-not (Test-Path $ScriptPath)) {
        $ScriptPath = Join-Path $FortressDir $Step.script
    }
    $LogLines.Add("===== STEP: $($Step.name) ($($Step.script)) =====")
    $LogLines.Add((Get-Date).ToUniversalTime().ToString("o"))

    $StartTime = Get-Date
    $ExitCode = 0

    if (-not (Test-Path $ScriptPath)) {
        $LogLines.Add("ERROR: script not found: $ScriptPath")
        $ExitCode = 1
    }
    else {
        try {
            $StepOutput = & $ScriptPath 2>&1 | Out-String
            $LogLines.Add($StepOutput)
        }
        catch {
            $LogLines.Add("ERROR: $($_.Exception.Message)")
            $ExitCode = 1
        }
    }

    $DurationSeconds = [math]::Round(((Get-Date) - $StartTime).TotalSeconds, 2)
    $LogLines.Add("exit_code=$ExitCode duration=${DurationSeconds}s")

    if ($ExitCode -ne 0) {
        $AllOk = $false
    }
    else {
        foreach ($ControlId in $Step.controls) {
            $ControlsTouched.Add($ControlId)
        }
    }

    $StepResults += [PSCustomObject]@{
        name             = $Step.name
        script_path      = $ScriptPath
        exit_code        = $ExitCode
        duration_seconds = $DurationSeconds
        changed          = ($ExitCode -eq 0)
    }
}

$LogLines.Add("===== POST-HARDENING CIS LEVEL 1 AUDIT =====")
$LogLines.Add((Get-Date).ToUniversalTime().ToString("o"))

if (Test-Path $WinAuditHelper) {
    try {
        $WinAuditOutput = & $WinAuditHelper 2>&1 | Out-String
        $LogLines.Add($WinAuditOutput)
    }
    catch {
        $LogLines.Add("ERROR (win_audit.ps1): $($_.Exception.Message)")
    }
}
else {
    $LogLines.Add("WARNING: win_audit.ps1 not found at $WinAuditHelper")
}

$PassRateAfter = 0
$ValidationReportPath = Join-Path $ExecDir "master_validation_report_post.json"

if (Test-Path $MasterValidation) {
    try {
        $ValidationOutput = & $MasterValidation -ReportPath $ValidationReportPath -SysmonConfigPath $SysmonConfigPath 2>&1 | Out-String
        $LogLines.Add($ValidationOutput)

        if (Test-Path $ValidationReportPath) {
            $Report = Get-Content $ValidationReportPath -Raw | ConvertFrom-Json
            if ([int]$Report.TotalChecks -gt 0) {
                $PassRateAfter = [math]::Round(([int]$Report.PassCount / [int]$Report.TotalChecks) * 100, 2)
            }
        }
    }
    catch {
        $LogLines.Add("ERROR (15-master_validation.ps1): $($_.Exception.Message)")
        $AllOk = $false
    }
}
else {
    $LogLines.Add("ERROR: 15-master_validation.ps1 not found at $MasterValidation")
    $AllOk = $false
}

if ($PassRateAfter -ge $TargetPassRate) {
    $ControlsTouched.Add("WIN-CIS-01")
}

$LogLines -join "`r`n`r`n" | Set-Content -Path $LogFile -Encoding UTF8

$IndexDelta = [math]::Round($PassRateAfter - $PassRateBefore, 2)
$HostnameVal = $env:COMPUTERNAME
$Timestamp = (Get-Date).ToUniversalTime().ToString("o")

$Result = [PSCustomObject]@{
    timestamp        = $Timestamp
    hostname         = $HostnameVal
    steps            = $StepResults
    lynis_before     = $PassRateBefore
    lynis_after      = $PassRateAfter
    index_delta      = $IndexDelta
    controls_touched = @($ControlsTouched | Select-Object -Unique)
}

try {
    $Result | ConvertTo-Json -Depth 6 | Set-Content -Path $OutputJsonFile -Encoding UTF8
}
catch {
    Write-Error "Failed to write ${OutputJsonFile}: $($_.Exception.Message)"
    exit 2
}

Write-Output "Windows hardening evidence written to $OutputJsonFile"
Write-Output "CIS L1 pass rate: $PassRateBefore -> $PassRateAfter (delta $IndexDelta, target $TargetPassRate)"

if ($AllOk -and ($PassRateAfter -ge $TargetPassRate)) {
    exit 0
}
else {
    exit 1
}
