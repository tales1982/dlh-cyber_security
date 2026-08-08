<#
    Script name : 10-sysmon_tune.ps1
    Purpose     : MedDefense Health Systems - Windows Fortress (2x01), Task 10.
                  The SwiftOnSecurity baseline deployed in 9-sysmon_deploy.ps1
                  is generic. MedDefense has specific threats: Crimson Tide
                  used Rclone for exfiltration (Phase 4), PsExec for lateral
                  movement (Phase 3), encoded PowerShell for execution
                  (Phase 3), and shadow-copy deletion ahead of encryption
                  (ransomware pre-encryption). This script appends 5
                  MedDefense-specific detection rules to sysmonconfig.xml,
                  reloads the running Sysmon configuration, then proves each
                  rule actually fires by executing a safe, non-destructive
                  trigger and checking the Sysmon log for the matching
                  event.
                  Makes configuration changes: rewrites sysmonconfig.xml and
                  reloads the live Sysmon configuration. Triggers are
                  intentionally non-destructive (vssadmin is invoked with
                  /? only - it never actually deletes shadow copies; the
                  PsExec and scheduled-task triggers create and immediately
                  remove harmless artifacts).
    Author      : Tales
    Date        : 2026-08-08
#>

[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot "sysmonconfig.xml")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# --- Load the current Sysmon configuration --------------------------------------------
[xml]$Config = Get-Content -Path $ConfigPath -Raw
Write-Output "[*] Loading Sysmon config... OK"

$EventFiltering = $Config.Sysmon.EventFiltering

# --- Add 5 custom detection rules, grouped under one RuleGroup ------------------------
Write-Output "[*] Adding custom rules..."

[xml]$CustomRuleGroupXml = @"
<RuleGroup name="MedDefense Custom Detections" groupRelation="or">
  <ProcessCreate onmatch="include">
    <Rule name="Rule1-RcloneExfiltration" groupRelation="or">
      <Image condition="end with">rclone.exe</Image>
    </Rule>
    <Rule name="Rule3-EncodedPowerShell" groupRelation="and">
      <Image condition="end with">powershell.exe</Image>
      <CommandLine condition="contains">-enc</CommandLine>
    </Rule>
    <Rule name="Rule4-ShadowCopyDeletion" groupRelation="and">
      <Image condition="end with">vssadmin.exe</Image>
      <CommandLine condition="contains">delete shadows</CommandLine>
    </Rule>
    <Rule name="Rule5-ScheduledTaskPersistence" groupRelation="and">
      <Image condition="end with">schtasks.exe</Image>
      <CommandLine condition="contains">/create</CommandLine>
    </Rule>
  </ProcessCreate>
  <RegistryEvent onmatch="include">
    <Rule name="Rule2-PsExecServiceInstall" groupRelation="or">
      <TargetObject condition="contains">PSEXESVC</TargetObject>
    </Rule>
  </RegistryEvent>
</RuleGroup>
"@

$ImportedRuleGroup = $Config.ImportNode($CustomRuleGroupXml.RuleGroup, $true)
$EventFiltering.AppendChild($ImportedRuleGroup) | Out-Null

Write-Output "    Rule 1: Rclone detection                [ADDED]"
Write-Output "    Rule 2: PsExec service installation     [ADDED]"
Write-Output "    Rule 3: Encoded PowerShell               [ADDED]"
Write-Output "    Rule 4: Shadow deletion (vssadmin)      [ADDED]"
Write-Output "    Rule 5: Scheduled task persistence      [ADDED]"

$Config.Save($ConfigPath)

# --- Reload the running Sysmon configuration ------------------------------------------
$SysmonService = Get-CimInstance -ClassName Win32_Service -Filter "Name = 'Sysmon64'" -ErrorAction SilentlyContinue
$SysmonExePath = if ($SysmonService) { ($SysmonService.PathName -split '"')[1] } else { $null }
if (-not $SysmonExePath -or -not (Test-Path -Path $SysmonExePath)) {
    throw "Sysmon64 service/binary not found - run 9-sysmon_deploy.ps1 first."
}
& $SysmonExePath -c $ConfigPath | Out-Null
Write-Output "[*] Updating Sysmon config... OK"

# --- Trigger-and-verify each rule with a safe, non-destructive trigger ----------------
Write-Output "[*] Trigger-and-Verify..."

function Test-SysmonRule {
    param(
        [scriptblock]$Trigger,
        [int]$EventId,
        [string]$MessagePattern
    )
    $before = (Get-Date).AddSeconds(-2)
    & $Trigger
    Start-Sleep -Seconds 3
    $match = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 200 -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -eq $EventId -and $_.TimeCreated -ge $before -and $_.Message -like "*$MessagePattern*" } |
        Select-Object -First 1
    return [bool]$match
}

$Results = [System.Collections.Generic.List[object]]::new()

# Rule 1: rclone.exe - copy a harmless signed binary to a file literally named
# rclone.exe and execute it briefly; the rule matches on Image name only.
$RcloneTestPath = "C:\Windows\Temp\rclone.exe"
Copy-Item -Path "C:\Windows\System32\whoami.exe" -Destination $RcloneTestPath -Force
$rule1Pass = Test-SysmonRule -EventId 1 -MessagePattern "rclone.exe" -Trigger {
    Start-Process -FilePath $RcloneTestPath -ArgumentList "/all" -WindowStyle Hidden -Wait
}
Remove-Item -Path $RcloneTestPath -Force -ErrorAction SilentlyContinue
Write-Output "    Rule 1: rclone.exe detection            $(if ($rule1Pass) { '[PASS]' } else { '[FAIL]' })"
$Results.Add($rule1Pass)

# Rule 2: PsExec service installation - manually create the PSEXESVC service
# registry key PsExec itself creates, without running PsExec at all.
$PsExecKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\PSEXESVC"
$rule2Pass = Test-SysmonRule -EventId 13 -MessagePattern "PSEXESVC" -Trigger {
    New-Item -Path $PsExecKeyPath -Force | Out-Null
    New-ItemProperty -Path $PsExecKeyPath -Name "Start" -Value 3 -PropertyType DWord -Force | Out-Null
}
Remove-Item -Path $PsExecKeyPath -Recurse -Force -ErrorAction SilentlyContinue
Write-Output "    Rule 2: PsExec registry key              $(if ($rule2Pass) { '[PASS]' } else { '[FAIL]' })"
$Results.Add($rule2Pass)

# Rule 3: encoded PowerShell - run a harmless -enc command.
$rule3Pass = Test-SysmonRule -EventId 1 -MessagePattern "-enc" -Trigger {
    $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('Write-Host "MedDefense Sysmon rule test"'))
    powershell.exe -NoProfile -enc $encoded | Out-Null
}
Write-Output "    Rule 3: Encoded PowerShell               $(if ($rule3Pass) { '[PASS]' } else { '[FAIL]' })"
$Results.Add($rule3Pass)

# Rule 4: shadow copy deletion - vssadmin.exe delete shadows /? only prints
# usage; the command line still literally contains "delete shadows", so the
# rule fires without a single shadow copy actually being touched.
$rule4Pass = Test-SysmonRule -EventId 1 -MessagePattern "delete shadows" -Trigger {
    Start-Process -FilePath "vssadmin.exe" -ArgumentList "delete shadows /?" -WindowStyle Hidden -Wait
}
Write-Output "    Rule 4: vssadmin execution               $(if ($rule4Pass) { '[PASS]' } else { '[FAIL]' })"
$Results.Add($rule4Pass)

# Rule 5: scheduled task creation - create a harmless task, then remove it.
$TaskName = "MedDefenseSysmonRuleTest"
$rule5Pass = Test-SysmonRule -EventId 1 -MessagePattern "/create" -Trigger {
    schtasks /create /tn $TaskName /tr "cmd.exe /c exit" /sc once /st 23:59 /f | Out-Null
}
schtasks /delete /tn $TaskName /f 2>$null | Out-Null
Write-Output "    Rule 5: schtasks /create                 $(if ($rule5Pass) { '[PASS]' } else { '[FAIL]' })"
$Results.Add($rule5Pass)

$PassCount = ($Results | Where-Object { $_ }).Count
Write-Output "Custom rules: 5 added | Tests: $PassCount/5 PASS"
