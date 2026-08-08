<#
    Script name : 3-telemetry_reference.ps1
    Purpose     : MedDefense Health Systems - Windows Fortress (2x01), Task 3.
                  Builds a machine-readable reference connecting every event
                  this project cares about - Security log, PowerShell log,
                  Sysmon log - to its log source, its audit/sensor
                  dependency, what it actually means for detection, which
                  Crimson Tide attack phase it maps to, and how to validate
                  it is flowing. This is the bridge between audit policy
                  configuration (Task 5), Sysmon deployment, PowerShell
                  logging, and the Module 3 detection work that consumes
                  this telemetry.
                  Static reference data: this script makes no configuration
                  changes and does not query the live domain.
    Author      : Tales
    Date        : 2026-08-08
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\windows_event_reference.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Events = [System.Collections.Generic.List[object]]::new()

function Add-EventReference {
    param(
        [int]$EventId, [string]$EventName, [string]$LogSource, [string]$AuditOrSensorDependency,
        [string]$SecurityMeaning, [string]$NormalFrequency, [string]$TriagePriority,
        [string]$CrimsonTidePhase, [string]$ExampleSuspiciousPattern, [string]$ValidationMethod
    )
    $script:Events.Add([PSCustomObject]@{
        event_id                    = $EventId
        event_name                  = $EventName
        log_source                  = $LogSource
        audit_or_sensor_dependency  = $AuditOrSensorDependency
        security_meaning            = $SecurityMeaning
        normal_frequency            = $NormalFrequency
        triage_priority             = $TriagePriority
        crimson_tide_phase          = $CrimsonTidePhase
        example_suspicious_pattern  = $ExampleSuspiciousPattern
        validation_method           = $ValidationMethod
    })
}

# --- Security log ------------------------------------------------------------------
Add-EventReference -EventId 4624 -EventName "An account was successfully logged on" `
    -LogSource "Security" -AuditOrSensorDependency "Logon/Logoff > Logon (Success)" `
    -SecurityMeaning "Confirms successful authentication; the Logon Type field distinguishes interactive, network, service, RDP and unlock logons." `
    -NormalFrequency "Very high - every successful logon domain-wide" -TriagePriority "Low (baseline; elevated when Logon Type or source is unusual)" `
    -CrimsonTidePhase "Phase 2 - Initial Access / Phase 4 - Lateral Movement" `
    -ExampleSuspiciousPattern "Logon Type 3 from a workstation to a DC using a service account, or Logon Type 10 (RDP) outside business hours" `
    -ValidationMethod "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624}"

Add-EventReference -EventId 4625 -EventName "An account failed to log on" `
    -LogSource "Security" -AuditOrSensorDependency "Logon/Logoff > Logon (Failure)" `
    -SecurityMeaning "Direct indicator of brute-force or password-spray activity; Status/Sub Status codes reveal bad password vs. locked vs. disabled." `
    -NormalFrequency "Low under normal conditions; spikes indicate an attack" -TriagePriority "High when volume exceeds baseline" `
    -CrimsonTidePhase "Phase 2 - Initial Access (credential brute-force)" `
    -ExampleSuspiciousPattern "A burst of more than 5 failed logon attempts in 1 minute against one account, or 1 failed logon each across many accounts from one source (spray)" `
    -ValidationMethod "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625}"

Add-EventReference -EventId 4648 -EventName "A logon was attempted using explicit credentials" `
    -LogSource "Security" -AuditOrSensorDependency "Logon/Logoff > Logon" `
    -SecurityMeaning "Logged whenever a process authenticates using credentials different from the caller's own token - runas, scheduled tasks, or pass-the-hash/lateral movement tooling." `
    -NormalFrequency "Low; legitimate uses are admin runas and scheduled tasks" -TriagePriority "High" `
    -CrimsonTidePhase "Phase 4 - Lateral Movement" `
    -ExampleSuspiciousPattern "A workstation account explicitly authenticating as a Domain Admin to another host it has no administrative relationship with" `
    -ValidationMethod "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4648}"

Add-EventReference -EventId 4672 -EventName "Special privileges assigned to new logon" `
    -LogSource "Security" -AuditOrSensorDependency "Logon/Logoff > Special Logon" `
    -SecurityMeaning "Fires when an admin-equivalent token (SeDebugPrivilege, SeTcbPrivilege, etc.) is issued at logon - the clearest 'someone used admin rights' signal available." `
    -NormalFrequency "Low; expected only for administrative accounts" -TriagePriority "High" `
    -CrimsonTidePhase "Phase 4/5 - Lateral Movement / Privilege Escalation" `
    -ExampleSuspiciousPattern "A special logon on a workstation that should never see administrative activity" `
    -ValidationMethod "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4672}"

Add-EventReference -EventId 4688 -EventName "A new process has been created" `
    -LogSource "Security" -AuditOrSensorDependency "Detailed Tracking > Process Creation (+ 'Include command line' registry setting for full CLI capture)" `
    -SecurityMeaning "Core execution telemetry: which binary ran, its parent process, and - once command-line auditing is enabled - the full argument list." `
    -NormalFrequency "Extremely high - every process, every host" -TriagePriority "Critical - foundational EDR-equivalent telemetry" `
    -CrimsonTidePhase "Phase 3 - Execution" `
    -ExampleSuspiciousPattern "powershell.exe -enc <base64>, certutil.exe -urlcache, or rundll32.exe with unusual arguments" `
    -ValidationMethod "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688}"

Add-EventReference -EventId 4720 -EventName "A user account was created" `
    -LogSource "Security" -AuditOrSensorDependency "Account Management > User Account Management" `
    -SecurityMeaning "Marks creation of a new account - legitimate onboarding or attacker-established persistence." `
    -NormalFrequency "Rare - tied to HR onboarding events" -TriagePriority "High" `
    -CrimsonTidePhase "Phase 7 - Persistence" `
    -ExampleSuspiciousPattern "An account created outside the change window, especially one immediately added to a privileged group (see 4732)" `
    -ValidationMethod "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720}"

Add-EventReference -EventId 4726 -EventName "A user account was deleted" `
    -LogSource "Security" -AuditOrSensorDependency "Account Management > User Account Management" `
    -SecurityMeaning "Marks account deletion - legitimate offboarding or anti-forensic cleanup of an attacker-created account." `
    -NormalFrequency "Rare" -TriagePriority "Medium" `
    -CrimsonTidePhase "Phase 8 - Anti-Forensics / Cleanup" `
    -ExampleSuspiciousPattern "An account deleted shortly after being used for lateral movement or data access" `
    -ValidationMethod "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4726}"

Add-EventReference -EventId 4732 -EventName "A member was added to a security-enabled group" `
    -LogSource "Security" -AuditOrSensorDependency "Account Management > Security Group Management" `
    -SecurityMeaning "Direct privilege-escalation signal when the target group is privileged (Domain Admins, Enterprise Admins, local Administrators)." `
    -NormalFrequency "Rare outside planned access reviews" -TriagePriority "Critical when the target group is privileged" `
    -CrimsonTidePhase "Phase 5 - Privilege Escalation" `
    -ExampleSuspiciousPattern "A standard user added to Domain Admins or Enterprise Admins outside change control" `
    -ValidationMethod "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4732}"

Add-EventReference -EventId 1102 -EventName "The audit log was cleared" `
    -LogSource "Security" -AuditOrSensorDependency "None - written unconditionally by the OS whenever the Security log is cleared" `
    -SecurityMeaning "Near-certain sign of an attacker (or rogue admin) covering their tracks; legitimate log clearing is exceptionally rare in a managed environment." `
    -NormalFrequency "Should be zero" -TriagePriority "Critical - any occurrence warrants investigation" `
    -CrimsonTidePhase "Phase 8 - Anti-Forensics / Cleanup" `
    -ExampleSuspiciousPattern "Any occurrence at all, especially immediately following suspicious 4720/4732/4688 activity" `
    -ValidationMethod "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102}"

# --- PowerShell log (Microsoft-Windows-PowerShell/Operational) --------------------
Add-EventReference -EventId 4103 -EventName "Module Logging" `
    -LogSource "Microsoft-Windows-PowerShell/Operational" -AuditOrSensorDependency "GPO: Turn on Module Logging, Module Names = *" `
    -SecurityMeaning "Records the cmdlets and parameters invoked in a pipeline - narrower than 4104 but useful when script block content is unavailable." `
    -NormalFrequency "High on any host where PowerShell is used" -TriagePriority "Medium-High" `
    -CrimsonTidePhase "Phase 3 - Execution" `
    -ExampleSuspiciousPattern "Invoke-WebRequest to an external IP, or New-ADUser/Add-ADGroupMember invoked from a non-admin workstation" `
    -ValidationMethod "Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -FilterXPath '*[System[(EventID=4103)]]'"

Add-EventReference -EventId 4104 -EventName "Script Block Logging" `
    -LogSource "Microsoft-Windows-PowerShell/Operational" -AuditOrSensorDependency "GPO: Turn on PowerShell Script Block Logging" `
    -SecurityMeaning "Captures the full, de-obfuscated script block text as it is executed - including payloads reconstructed after Base64/compression decoding - making it the single highest-value PowerShell telemetry source." `
    -NormalFrequency "High on any host where PowerShell is used" -TriagePriority "Critical" `
    -CrimsonTidePhase "Phase 3 - Execution" `
    -ExampleSuspiciousPattern "A script block containing -EncodedCommand, IEX (New-Object Net.WebClient).DownloadString(...), or AMSI-bypass strings" `
    -ValidationMethod "Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -FilterXPath '*[System[(EventID=4104)]]'"

# --- Sysmon log (Microsoft-Windows-Sysmon/Operational) -----------------------------
Add-EventReference -EventId 1 -EventName "Process Create" `
    -LogSource "Microsoft-Windows-Sysmon/Operational" -AuditOrSensorDependency "Sysmon installed; ProcessCreate rule (enabled in every baseline config)" `
    -SecurityMeaning "Process creation with full command line, hashes, and parent/child relationship - richer than 4688 and independent of native audit policy." `
    -NormalFrequency "Very high" -TriagePriority "Critical" `
    -CrimsonTidePhase "Phase 3 - Execution" `
    -ExampleSuspiciousPattern "explorer.exe spawning powershell.exe -enc, or an Office process spawning cmd.exe" `
    -ValidationMethod "Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath '*[System[(EventID=1)]]'"

Add-EventReference -EventId 3 -EventName "Network Connection" `
    -LogSource "Microsoft-Windows-Sysmon/Operational" -AuditOrSensorDependency "Sysmon NetworkConnect rule enabled and tuned (off by default in most baseline configs)" `
    -SecurityMeaning "Per-process outbound/inbound TCP connections, including source/destination IP and port." `
    -NormalFrequency "High once enabled" -TriagePriority "High" `
    -CrimsonTidePhase "Phase 4/6 - Lateral Movement / Command and Control" `
    -ExampleSuspiciousPattern "powershell.exe or a LOLBin connecting to a rare external IP on an unusual port" `
    -ValidationMethod "Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath '*[System[(EventID=3)]]'"

Add-EventReference -EventId 7 -EventName "Image Loaded" `
    -LogSource "Microsoft-Windows-Sysmon/Operational" -AuditOrSensorDependency "Sysmon ImageLoad rule enabled (noisy - requires heavy filtering)" `
    -SecurityMeaning "DLL/module load events; detects DLL side-loading and unsigned or unusual modules loaded into sensitive processes." `
    -NormalFrequency "Very high - must be filtered to be usable" -TriagePriority "Medium" `
    -CrimsonTidePhase "Phase 3 - Execution / Defense Evasion" `
    -ExampleSuspiciousPattern "An unsigned DLL loaded from %TEMP% into lsass.exe or a signed system binary" `
    -ValidationMethod "Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath '*[System[(EventID=7)]]'"

Add-EventReference -EventId 11 -EventName "File Create" `
    -LogSource "Microsoft-Windows-Sysmon/Operational" -AuditOrSensorDependency "Sysmon FileCreate rule enabled, scoped to high-value paths" `
    -SecurityMeaning "Files written to disk; the primary signal for ransomware drop activity and persistence artifacts placed in autorun locations." `
    -NormalFrequency "High - filter to Startup/System32/Temp/user-writable paths" -TriagePriority "Medium-High" `
    -CrimsonTidePhase "Phase 6/7 - Ransomware Deployment / Persistence" `
    -ExampleSuspiciousPattern "An executable written to a Startup folder, or a burst of files renamed with a ransomware extension" `
    -ValidationMethod "Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath '*[System[(EventID=11)]]'"

Add-EventReference -EventId 13 -EventName "Registry Event (Value Set)" `
    -LogSource "Microsoft-Windows-Sysmon/Operational" -AuditOrSensorDependency "Sysmon RegistryEvent rule enabled" `
    -SecurityMeaning "Registry value changes; the primary signal for Run-key and service-based persistence." `
    -NormalFrequency "Medium" -TriagePriority "High" `
    -CrimsonTidePhase "Phase 7 - Persistence" `
    -ExampleSuspiciousPattern "A new value under HKLM\...\CurrentVersion\Run pointing to an executable in %AppData% or %Temp%" `
    -ValidationMethod "Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath '*[System[(EventID=13)]]'"

Add-EventReference -EventId 22 -EventName "DNS Query" `
    -LogSource "Microsoft-Windows-Sysmon/Operational" -AuditOrSensorDependency "Sysmon DnsQuery rule enabled (Sysmon 11+)" `
    -SecurityMeaning "Per-process DNS resolution; reveals C2 domains, DGA-generated hostnames, and exfiltration channels." `
    -NormalFrequency "Very high - filter to non-browser, non-service processes" -TriagePriority "High" `
    -CrimsonTidePhase "Phase 6 - Command and Control / Exfiltration" `
    -ExampleSuspiciousPattern "powershell.exe or rundll32.exe resolving a freshly-registered or DGA-looking domain" `
    -ValidationMethod "Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath '*[System[(EventID=22)]]'"

# --- Save reference and summarize --------------------------------------------------
$Report = [PSCustomObject]@{
    Timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    Events    = $Events
}
$Report | ConvertTo-Json -Depth 6 | Set-Content -Path $OutputPath -Encoding UTF8

$SecurityCount   = ($Events | Where-Object { $_.log_source -eq "Security" }).Count
$PowerShellCount = ($Events | Where-Object { $_.log_source -like "*PowerShell*" }).Count
$SysmonCount     = ($Events | Where-Object { $_.log_source -like "*Sysmon*" }).Count

Write-Output "Security events mapped: $SecurityCount"
Write-Output "PowerShell events mapped: $PowerShellCount"
Write-Output "Sysmon events mapped: $SysmonCount"
Write-Output "Total events documented: $($Events.Count)"
Write-Output "Reference saved to: $OutputPath"
