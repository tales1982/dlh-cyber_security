<#
    Script name : 0-sysmon_validation.ps1
    purpose     : MedDefense Health Systems - Eyes on the Endpoint (2x02), Task 0.
                  Deployment does not equal coverage. This script proves that
                  Sysmon (deployed in 2x01 Task 9, tuned in Task 10) actually
                  fires on the five event types every later task in this
                  project depends on: process creation (EID 1), network
                  connection (EID 3), file creation (EID 11), registry
                  modification (EID 13) and DNS query (EID 22). Each action
                  is a real, safe, reversible trigger - not a simulation -
                  checked against the live Sysmon Operational log.
                  Read-only against the system: the only writes are the
                  throwaway test file and registry value, both removed by
                  the cleanup step at the end of every run.
    author      : Tales
    Date        : 2026-08-12
#>

[CmdletBinding()]
param(
    [string]$SysmonLogName   = "Microsoft-Windows-Sysmon/Operational",
    [string]$TestFilePath    = "C:\Windows\Temp\test.txt",
    [string]$RegistryKeyPath = "HKCU:\Software\MedDefenseSysmonTest",
    [string]$RegistryValueName = "SysmonTest",
    [string]$DnsQueryName    = "example.com",
    [string]$NetworkTarget   = "8.8.8.8",
    [int]$NetworkPort        = 443,
    [int]$WaitSeconds        = 3
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:ActionsTested = 0
$script:Captured      = 0
$script:Missed        = 0

function Get-RecentSysmonEvent {
    param(
        [int]$EventId,
        [datetime]$Since,
        [string]$MessagePattern
    )
    Get-WinEvent -LogName $SysmonLogName -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -eq $EventId -and $_.TimeCreated -ge $Since -and $_.Message -like $MessagePattern } |
        Select-Object -First 1
}

function Get-EventDataValue {
    # Pulls a named field (CommandLine, DestinationIp, TargetFilename,
    # TargetObject, QueryName, ...) out of the event's structured XML data -
    # confirming the event fired is not enough, the field required for
    # triage has to actually be populated.
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

function Write-ValidationResult {
    param(
        [int]$Index,
        [string]$Label,
        [string]$Trigger,
        [int]$EventId,
        [object]$Event,
        [string]$DetailNote
    )
    $script:ActionsTested++
    Write-Output "    [$Index/5] $Label..."
    if ($Event) {
        $script:Captured++
        Write-Output "          $Trigger -> Sysmon EID $EventId captured, $DetailNote   [PASS]"
    } else {
        $script:Missed++
        Write-Output "          $Trigger -> Sysmon EID $EventId NOT captured   [FAIL]"
    }
}

Write-Output "[*] Running Sysmon telemetry validation..."

# Each action below records its own timestamp via Get-Date immediately
# before the trigger runs, then uses that timestamp to scope the Get-WinEvent
# search window - so a match is only counted if Sysmon logged it after this
# specific action, not a stale event from an earlier run.

# --- 1/5: Process creation (Event ID 1) -----------------------------------------------------
$Since1 = Get-Date
cmd.exe /c whoami | Out-Null
Start-Sleep -Seconds $WaitSeconds
$Event1 = Get-RecentSysmonEvent -EventId 1 -Since $Since1 -MessagePattern "*whoami*"
$CommandLine1 = Get-EventDataValue -EventRecord $Event1 -Name "CommandLine"
$Found1 = [bool]($Event1 -and $CommandLine1 -and $CommandLine1 -like "*whoami*")
Write-ValidationResult -Index 1 -Label "Process creation (Event ID 1)" -Trigger "cmd.exe /c whoami" -EventId 1 -Event $Found1 -DetailNote "CommandLine field present: `"$CommandLine1`""

# --- 2/5: Network connection (Event ID 3) ---------------------------------------------------
$Since2 = Get-Date
Test-NetConnection -ComputerName $NetworkTarget -Port $NetworkPort -WarningAction SilentlyContinue | Out-Null
Start-Sleep -Seconds $WaitSeconds
$Event2 = Get-RecentSysmonEvent -EventId 3 -Since $Since2 -MessagePattern "*$NetworkTarget*"
$DestinationIp2   = Get-EventDataValue -EventRecord $Event2 -Name "DestinationIp"
$DestinationPort2 = Get-EventDataValue -EventRecord $Event2 -Name "DestinationPort"
$Found2 = [bool]($Event2 -and $DestinationIp2 -and $DestinationPort2)
Write-ValidationResult -Index 2 -Label "Network connection (Event ID 3)" -Trigger "Outbound TCP" -EventId 3 -Event $Found2 -DetailNote "DestinationIp=$DestinationIp2, DestinationPort=$DestinationPort2 present"

# --- 3/5: File creation (Event ID 11) -------------------------------------------------------
$Since3 = Get-Date
"MedDefense Sysmon validation test - $(Get-Date -Format o)" | Out-File -FilePath $TestFilePath -Encoding UTF8 -Force
Start-Sleep -Seconds $WaitSeconds
$Event3 = Get-RecentSysmonEvent -EventId 11 -Since $Since3 -MessagePattern "*$TestFilePath*"
$TargetFilename3 = Get-EventDataValue -EventRecord $Event3 -Name "TargetFilename"
$CreatingImage3  = Get-EventDataValue -EventRecord $Event3 -Name "Image"
$Found3 = [bool]($Event3 -and $TargetFilename3)
Write-ValidationResult -Index 3 -Label "File creation (Event ID 11)" -Trigger $TestFilePath -EventId 11 -Event $Found3 -DetailNote "TargetFilename=$TargetFilename3, creating process (Image)=$CreatingImage3 present"

# --- 4/5: Registry modification (Event ID 13) -----------------------------------------------
$Since4 = Get-Date
New-Item -Path $RegistryKeyPath -Force | Out-Null
New-ItemProperty -Path $RegistryKeyPath -Name $RegistryValueName -Value "test" -PropertyType String -Force | Out-Null
Start-Sleep -Seconds $WaitSeconds
$Event4 = Get-RecentSysmonEvent -EventId 13 -Since $Since4 -MessagePattern "*$RegistryValueName*"
$TargetObject4 = Get-EventDataValue -EventRecord $Event4 -Name "TargetObject"
$Details4      = Get-EventDataValue -EventRecord $Event4 -Name "Details"
$EventType4    = Get-EventDataValue -EventRecord $Event4 -Name "EventType"
$Found4 = [bool]($Event4 -and $TargetObject4)
Write-ValidationResult -Index 4 -Label "Registry modification (Event ID 13)" -Trigger "HKCU\...\$RegistryValueName" -EventId 13 -Event $Found4 -DetailNote "TargetObject=$TargetObject4, EventType=$EventType4, Details=$Details4 present"

# --- 5/5: DNS query (Event ID 22) -----------------------------------------------------------
# Both triggers are fired: nslookup (matches this task's documented example
# command) and Resolve-DnsName (the native PowerShell resolver) - either can
# generate the underlying DNS query Sysmon EID 22 observes.
$Since5 = Get-Date
nslookup $DnsQueryName 2>&1 | Out-Null
Resolve-DnsName -Name $DnsQueryName -ErrorAction SilentlyContinue | Out-Null
Start-Sleep -Seconds $WaitSeconds
$Event5 = Get-RecentSysmonEvent -EventId 22 -Since $Since5 -MessagePattern "*$DnsQueryName*"
$QueryName5    = Get-EventDataValue -EventRecord $Event5 -Name "QueryName"
$QueryResults5 = Get-EventDataValue -EventRecord $Event5 -Name "QueryResults"
$Found5 = [bool]($Event5 -and $QueryName5)
Write-ValidationResult -Index 5 -Label "DNS query (Event ID 22)" -Trigger "nslookup $DnsQueryName" -EventId 22 -Event $Found5 -DetailNote "QueryName=$QueryName5, QueryResults=$QueryResults5 present"

# --- Cleanup ----------------------------------------------------------------------------------
Write-Output "[*] Cleanup: removing test artifacts..."
Remove-Item -Path $TestFilePath -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -Path $RegistryKeyPath -Name $RegistryValueName -Force -ErrorAction SilentlyContinue
Remove-Item -Path $RegistryKeyPath -Recurse -Force -ErrorAction SilentlyContinue

Write-Output "Actions tested: $script:ActionsTested | Captured: $script:Captured | Missed: $script:Missed"

if ($script:Missed -gt 0) {
    exit 1
} else {
    exit 0
}
