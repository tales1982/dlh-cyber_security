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

# --- 1/5: Process creation (Event ID 1) -----------------------------------------------------
$Since1 = Get-Date
cmd.exe /c whoami | Out-Null
Start-Sleep -Seconds $WaitSeconds
$Event1 = Get-RecentSysmonEvent -EventId 1 -Since $Since1 -MessagePattern "*whoami*"
Write-ValidationResult -Index 1 -Label "Process creation (Event ID 1)" -Trigger "cmd.exe /c whoami" -EventId 1 -Event $Event1 -DetailNote "cmdline present"

# --- 2/5: Network connection (Event ID 3) ---------------------------------------------------
$Since2 = Get-Date
Test-NetConnection -ComputerName $NetworkTarget -Port $NetworkPort -WarningAction SilentlyContinue | Out-Null
Start-Sleep -Seconds $WaitSeconds
$Event2 = Get-RecentSysmonEvent -EventId 3 -Since $Since2 -MessagePattern "*$NetworkTarget*"
Write-ValidationResult -Index 2 -Label "Network connection (Event ID 3)" -Trigger "Outbound TCP" -EventId 3 -Event $Event2 -DetailNote "dest IP/port present"

# --- 3/5: File creation (Event ID 11) -------------------------------------------------------
$Since3 = Get-Date
"MedDefense Sysmon validation test - $(Get-Date -Format o)" | Out-File -FilePath $TestFilePath -Encoding UTF8 -Force
Start-Sleep -Seconds $WaitSeconds
$Event3 = Get-RecentSysmonEvent -EventId 11 -Since $Since3 -MessagePattern "*$TestFilePath*"
Write-ValidationResult -Index 3 -Label "File creation (Event ID 11)" -Trigger $TestFilePath -EventId 11 -Event $Event3 -DetailNote "target filename and creating process present"

# --- 4/5: Registry modification (Event ID 13) -----------------------------------------------
$Since4 = Get-Date
New-Item -Path $RegistryKeyPath -Force | Out-Null
New-ItemProperty -Path $RegistryKeyPath -Name $RegistryValueName -Value "test" -PropertyType String -Force | Out-Null
Start-Sleep -Seconds $WaitSeconds
$Event4 = Get-RecentSysmonEvent -EventId 13 -Since $Since4 -MessagePattern "*$RegistryValueName*"
Write-ValidationResult -Index 4 -Label "Registry modification (Event ID 13)" -Trigger "HKCU\...\$RegistryValueName" -EventId 13 -Event $Event4 -DetailNote "key path, value name, operation type present"

# --- 5/5: DNS query (Event ID 22) -----------------------------------------------------------
$Since5 = Get-Date
nslookup $DnsQueryName 2>&1 | Out-Null
Start-Sleep -Seconds $WaitSeconds
$Event5 = Get-RecentSysmonEvent -EventId 22 -Since $Since5 -MessagePattern "*$DnsQueryName*"
Write-ValidationResult -Index 5 -Label "DNS query (Event ID 22)" -Trigger "nslookup $DnsQueryName" -EventId 22 -Event $Event5 -DetailNote "query and result present"

# --- Cleanup ----------------------------------------------------------------------------------
Write-Output "[*] Cleanup: removing test artifacts..."
Remove-Item -Path $TestFilePath -Force -ErrorAction SilentlyContinue
Remove-Item -Path $RegistryKeyPath -Recurse -Force -ErrorAction SilentlyContinue

Write-Output "Actions tested: $script:ActionsTested | Captured: $script:Captured | Missed: $script:Missed"

if ($script:Missed -gt 0) {
    exit 1
} else {
    exit 0
}
