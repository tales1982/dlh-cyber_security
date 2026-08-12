<#
    Script name : 9-windows_attack_sim.ps1
    purpose     : MedDefense Health Systems - Eyes on the Endpoint (2x02), Task 9.
                  Block 1 validated individual event types in isolation.
                  This script runs them together as one realistic sequence -
                  the Crimson Tide advisory's own playbook against this
                  project's own hardened endpoint: create a user, escalate
                  privileges, run encoded PowerShell, establish persistence,
                  beacon outbound, drop a startup payload. Every action is
                  timestamped precisely as it runs, so 10-windows_detection_proof.ps1
                  can later prove instrumentation caught each one. This
                  script's only output that matters afterward is
                  windows_attack_log.json - the ground truth.
                  Makes real, but fully cleaned-up, changes: a local user
                  account, an Administrators membership, a scheduled task
                  and a startup-folder file. Every one of these artifacts
                  is removed again before the script exits.
    author      : Tales
    Date        : 2026-08-12
#>

[CmdletBinding()]
param(
    [string]$UserName        = "support_update",
    [string]$ScheduledTaskName = "MedDefenseSimUpdateCheck",
    [string]$NetworkTarget   = "8.8.8.8",
    [int]$NetworkPort        = 443,
    [string]$StartupDir      = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
    [string]$StartupFileName = "update_check.vbs",
    [string]$GroundTruthPath = (Join-Path $PSScriptRoot "windows_attack_log.json")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:Actions = [System.Collections.Generic.List[object]]::new()
$StartupFilePath = Join-Path $StartupDir $StartupFileName

function Add-ActionLog {
    param(
        [int]$Number,
        [string]$Description,
        [string]$Timestamp,
        [array]$ExpectedDetectionSources,
        [string]$MitreTechnique
    )
    $script:Actions.Add([PSCustomObject]@{
        action_number             = $Number
        description                = $Description
        timestamp                  = $Timestamp
        expected_detection_sources = $ExpectedDetectionSources
        mitre_attack_technique     = $MitreTechnique
    })
}

Write-Output "[*] Running Windows attacker simulation..."

# --- 1/6: Create a new local user account - expected in Security Event ID 4720 (A user account was created) --
Write-Output "    [1/6] Creating local user '$UserName'..."
$Password = ConvertTo-SecureString -String ([System.Guid]::NewGuid().ToString() + "!Aa1") -AsPlainText -Force
New-LocalUser -Name $UserName -Password $Password -FullName "Support Update Service" `
    -Description "MedDefense attacker-simulation account (Task 9) - removed at end of run" | Out-Null
$Ts1 = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Write-Output "          $Ts1"
Add-ActionLog -Number 1 -Description "Creating local user '$UserName'" -Timestamp $Ts1 `
    -ExpectedDetectionSources @([PSCustomObject]@{ source = "Security"; event_id = 4720 }) `
    -MitreTechnique "T1136.001"

# --- 2/6: Add the user to the local Administrators group - expected in Security Event ID 4732 (A member was added to a security-enabled local group) --
Write-Output "    [2/6] Adding to Administrators group..."
Add-LocalGroupMember -Group "Administrators" -Member $UserName
$Ts2 = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Write-Output "          $Ts2"
Add-ActionLog -Number 2 -Description "Adding '$UserName' to Administrators group" -Timestamp $Ts2 `
    -ExpectedDetectionSources @([PSCustomObject]@{ source = "Security"; event_id = 4732 }) `
    -MitreTechnique "T1098"

# --- 3/6: Run an encoded PowerShell command (harmless payload) - expected in PS ScriptBlock Event ID 4104 (Script block logging) and Sysmon Event ID 1 (Process creation) --
Write-Output "    [3/6] Running encoded PowerShell..."
$PayloadCommand = 'Write-Host "C2 beacon"'
$EncodedPayload = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($PayloadCommand))
powershell.exe -NoProfile -EncodedCommand $EncodedPayload | Out-Null
$Ts3 = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Write-Output "          $Ts3"
Add-ActionLog -Number 3 -Description "Encoded PowerShell: -enc $EncodedPayload (decodes to: $PayloadCommand)" -Timestamp $Ts3 `
    -ExpectedDetectionSources @(
        [PSCustomObject]@{ source = "PS ScriptBlock"; event_id = 4104 },
        [PSCustomObject]@{ source = "Sysmon"; event_id = 1 }
    ) -MitreTechnique "T1059.001"

# --- 4/6: Create a scheduled task for persistence - expected in Sysmon Event ID 1 (Process creation) --
Write-Output "    [4/6] Creating scheduled task..."
schtasks /create /tn $ScheduledTaskName /tr "cmd.exe /c exit" /sc daily /st 03:00 /f | Out-Null
$Ts4 = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Write-Output "          $Ts4"
Add-ActionLog -Number 4 -Description "Creating scheduled task '$ScheduledTaskName'" -Timestamp $Ts4 `
    -ExpectedDetectionSources @([PSCustomObject]@{ source = "Sysmon"; event_id = 1 }) `
    -MitreTechnique "T1053.005"

# --- 5/6: Initiate an outbound network connection - expected in Sysmon Event ID 3 (Network connection) --
Write-Output "    [5/6] Outbound network connection..."
Test-NetConnection -ComputerName $NetworkTarget -Port $NetworkPort -WarningAction SilentlyContinue | Out-Null
$Ts5 = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Write-Output "          $Ts5"
Add-ActionLog -Number 5 -Description "Outbound TCP connection to $NetworkTarget`:$NetworkPort" -Timestamp $Ts5 `
    -ExpectedDetectionSources @([PSCustomObject]@{ source = "Sysmon"; event_id = 3 }) `
    -MitreTechnique "T1071"

# --- 6/6: Drop a file in a startup directory - expected in Sysmon Event ID 11 (FileCreate) ------------
Write-Output "    [6/6] Dropping file in Startup..."
New-Item -Path $StartupDir -ItemType Directory -Force | Out-Null
"' MedDefense attacker-simulation artifact (Task 9) - harmless, removed at end of run" |
    Out-File -FilePath $StartupFilePath -Encoding ASCII -Force
$Ts6 = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Write-Output "          $Ts6"
Add-ActionLog -Number 6 -Description "Dropping file in Startup: $StartupFilePath" -Timestamp $Ts6 `
    -ExpectedDetectionSources @([PSCustomObject]@{ source = "Sysmon"; event_id = 11 }) `
    -MitreTechnique "T1547.001"

# --- Save ground truth before cleanup, so a cleanup failure never loses the log ---------------------
# Each ground truth record carries: action number, description, exact
# timestamp, expected detection source (a Sysmon Event ID, a Security Event ID, or both) and MITRE ATT&CK technique -
# exactly what 10-windows_detection_proof.ps1 correlates against captured telemetry.
$GroundTruth = [PSCustomObject]@{
    generated      = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    actions_total  = $script:Actions.Count
    actions        = $script:Actions
}
$GroundTruth | ConvertTo-Json -Depth 6 | Set-Content -Path $GroundTruthPath -Encoding UTF8

# --- Cleanup: remove every artifact this script created ----------------------------------------------
Write-Output "[*] Cleaning up artifacts..."
$CleanupOk = $true

try { Remove-Item -Path $StartupFilePath -Force -ErrorAction Stop } catch { $CleanupOk = $false }
try { Unregister-ScheduledTask -TaskName $ScheduledTaskName -Confirm:$false -ErrorAction Stop } catch { $CleanupOk = $false }
try { Remove-LocalUser -Name $UserName -ErrorAction Stop } catch { $CleanupOk = $false }

if ($CleanupOk) {
    Write-Output "    User removed, task deleted, file removed           [CLEAN]"
} else {
    Write-Output "    Cleanup incomplete - review artifacts manually     [WARN]"
}

Write-Output "Actions executed: $($script:Actions.Count)"
Write-Output "Ground truth saved to: $GroundTruthPath"
