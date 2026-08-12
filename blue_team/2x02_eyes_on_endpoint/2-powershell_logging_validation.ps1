<#
    Script name : 2-powershell_logging_validation.ps1
    purpose     : MedDefense Health Systems - Eyes on the Endpoint (2x02), Task 2.
                  6-powershell_security.ps1 (2x01) enabled Script Block
                  Logging, Module Logging and Transcription via GPO -
                  "enabled" is not "complete". This script proves each
                  layer works against the kinds of PowerShell the Crimson
                  Tide attacker actually used: a plain cmdlet, an encoded
                  (Base64) command, a module import, and a multi-line
                  script block, plus confirms a transcript file was
                  written for the session. Read-only against the system;
                  the only side effects are the throwaway commands run to
                  generate the telemetry being checked.
    author      : Tales
    Date        : 2026-08-12
#>

[CmdletBinding()]
param(
    [string]$PowerShellLogName = "Microsoft-Windows-PowerShell/Operational",
    [string]$TranscriptDir     = "C:\PSTranscripts",
    [int]$WaitSeconds          = 2
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:TestsRun  = 0
$script:Captured  = 0
$script:Missed    = 0

function Get-EventDataValue {
    # Event ID 4104 (Script Block Logging) carries the actual decoded
    # content in the ScriptBlockText field - checking that field is
    # populated is what proves full content was captured, not just that
    # some 4104 event with a matching substring in its free-text Message
    # happened to fire.
    param(
        [System.Diagnostics.Eventing.Reader.EventLogRecord]$EventRecord,
        [string]$Name
    )
    if (-not $EventRecord) { return $null }
    [xml]$eventXml = $EventRecord.ToXml()
    $node = $eventXml.Event.EventData.Data | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
    if ($node) { return $node.'#text' }
    return $null
}

function Write-TestResult {
    # Reports both the [PASS]/[FAIL] line this task's Expected Output shows,
    # and - per the task instructions ("report CAPTURED / MISSED and the
    # detail level: full content vs partial") - an explicit status/detail
    # line underneath it.
    param(
        [int]$Index,
        [string]$Label,
        [string]$SuccessDetail,
        [string]$FailureDetail,
        [bool]$Found,
        [string]$DetailLevel = "full content",
        [string]$ExtraLine = ""
    )
    $script:TestsRun++
    Write-Output "    [$Index/5] $Label..."
    if ($ExtraLine) { Write-Output "          $ExtraLine" }
    if ($Found) {
        $script:Captured++
        Write-Output "          $SuccessDetail   [PASS]"
        Write-Output "          Status: CAPTURED | Detail level: $DetailLevel"
    } else {
        $script:Missed++
        Write-Output "          $FailureDetail   [FAIL]"
        Write-Output "          Status: MISSED | Detail level: none"
    }
}

Write-Output "[*] Testing PowerShell logging coverage..."

# --- 1/5: Simple command (Get-Process), Event ID 4104 ----------------------------------------
Get-Process | Out-Null
Start-Sleep -Seconds $WaitSeconds
$Event1 = Get-WinEvent -LogName $PowerShellLogName -MaxEvents 100 -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -eq 4104 -and $_.Message -like "*Get-Process*" } |
    Select-Object -First 1
$ScriptBlockText1 = Get-EventDataValue -EventRecord $Event1 -Name "ScriptBlockText"
$Found1 = [bool]($Event1 -and $ScriptBlockText1 -and $ScriptBlockText1 -like "*Get-Process*")
Write-TestResult -Index 1 -Label "Simple command (Get-Process)" -Found $Found1 `
    -SuccessDetail "EID 4104 ScriptBlockText: `"Get-Process`" captured" -FailureDetail "EID 4104 ScriptBlockText: `"Get-Process`" NOT captured"

# --- 2/5: Encoded command, decoded content in Event ID 4104 -----------------------------------
$TestCommand         = 'Write-Host "Test"'
$EncodedTestCommand  = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($TestCommand))
powershell.exe -NoProfile -EncodedCommand $EncodedTestCommand | Out-Null
Start-Sleep -Seconds $WaitSeconds
$Event2 = Get-WinEvent -LogName $PowerShellLogName -MaxEvents 100 -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -eq 4104 -and $_.Message -like "*$TestCommand*" } |
    Select-Object -First 1
$ScriptBlockText2 = Get-EventDataValue -EventRecord $Event2 -Name "ScriptBlockText"
$Found2 = [bool]($Event2 -and $ScriptBlockText2 -and $ScriptBlockText2 -like "*$TestCommand*")
Write-TestResult -Index 2 -Label "Encoded command" -ExtraLine "Input: -enc $EncodedTestCommand" -Found $Found2 `
    -SuccessDetail "EID 4104 ScriptBlockText: `"$TestCommand`" (decoded) captured" -FailureDetail "EID 4104 ScriptBlockText: `"$TestCommand`" (decoded) NOT captured"

# --- 3/5: Module import, Event ID 4103 ---------------------------------------------------------
$ModuleName = "ActiveDirectory"
Import-Module $ModuleName -ErrorAction SilentlyContinue
Start-Sleep -Seconds $WaitSeconds
$Event3 = Get-WinEvent -LogName $PowerShellLogName -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -eq 4103 -and $_.Message -like "*Import-Module*$ModuleName*" } |
    Select-Object -First 1
Write-TestResult -Index 3 -Label "Module import" -Found ([bool]$Event3) `
    -SuccessDetail "EID 4103: `"Import-Module $ModuleName`" captured" -FailureDetail "EID 4103: `"Import-Module $ModuleName`" NOT captured"

# --- 4/5: Multi-line script block, full block captured ------------------------------------------
$MultiLineBlock = @'
$a = 1
$b = 2
$c = $a + $b
Write-Output "Sum: $c"
foreach ($i in 1..3) {
    Write-Output "Line $i"
}
if ($c -eq 3) {
    Write-Output "Check passed"
} else {
    Write-Output "Check failed"
}
Write-Output "End of block"
Write-Output "Done"
'@
$ExpectedLineCount = ($MultiLineBlock -split "`n").Count
Invoke-Expression $MultiLineBlock | Out-Null
Start-Sleep -Seconds $WaitSeconds
$Candidates4 = @(Get-WinEvent -LogName $PowerShellLogName -MaxEvents 100 -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -eq 4104 -and $_.Message -like "*Check passed*" })
$Event4Full = $Candidates4 | Where-Object {
    $sbt = Get-EventDataValue -EventRecord $_ -Name "ScriptBlockText"
    $sbt -and $sbt -like "*End of block*"
} | Select-Object -First 1
$Event4Partial = $Candidates4 | Select-Object -First 1
if ($Event4Full) {
    Write-TestResult -Index 4 -Label "Multi-line script block" -Found $true -DetailLevel "full content" `
        -SuccessDetail "EID 4104 ScriptBlockText: Full block captured ($ExpectedLineCount lines)" -FailureDetail ""
} elseif ($Event4Partial) {
    Write-TestResult -Index 4 -Label "Multi-line script block" -Found $true -DetailLevel "partial" `
        -SuccessDetail "EID 4104 ScriptBlockText: Block captured but truncated before the final lines" -FailureDetail ""
} else {
    Write-TestResult -Index 4 -Label "Multi-line script block" -Found $false `
        -SuccessDetail "" -FailureDetail "EID 4104 ScriptBlockText: Full block NOT captured"
}

# --- 5/5: Transcription file created in C:\PSTranscripts\ ---------------------------------------
$TranscriptFiles = @(Get-ChildItem -Path $TranscriptDir -Filter "*.txt" -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -ge (Get-Date).AddMinutes(-10) })
Write-TestResult -Index 5 -Label "Transcription file" -Found ($TranscriptFiles.Count -gt 0) `
    -SuccessDetail "$TranscriptDir\*.txt exists, session recorded" -FailureDetail "$TranscriptDir\*.txt NOT found for this session"

Write-Output "Tests: $script:TestsRun | Captured: $script:Captured | Missed: $script:Missed"

if ($script:Missed -gt 0) {
    exit 1
} else {
    exit 0
}
