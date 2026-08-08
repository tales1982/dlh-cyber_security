<#
    Script name : 6-powershell_security.ps1
    Purpose     : MedDefense Health Systems - Windows Fortress (2x01), Task 6.
                  Neutralizes PowerShell as a post-exploitation tool by
                  deploying Script Block Logging (decoded script content,
                  Event ID 4104), Module Logging (which cmdlets ran, Event
                  ID 4103) and Transcription (a full session record under
                  C:\PSTranscripts) via GPO, then verifies AMSI is active
                  and proves the pipeline end-to-end by running an encoded
                  command and confirming it shows up decoded in the
                  PowerShell Operational log. Crimson Tide's Phase 3 used
                  powershell.exe -enc [base64]; without Script Block
                  Logging that payload is invisible no matter how good the
                  process-creation telemetry is.
                  Makes configuration changes: creates/links a GPO, writes
                  PowerShell logging registry policy into it, and runs a
                  local encoded-command test.
    Author      : Tales
    Date        : 2026-08-08
#>

[CmdletBinding()]
param(
    [string]$GpoName = "MedDefense - PowerShell Security"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory
Import-Module GroupPolicy

$Domain    = Get-ADDomain
$DomainDN  = $Domain.DistinguishedName

# --- Create the GPO ------------------------------------------------------------------
$existingGpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
if ($existingGpo) {
    $Gpo = $existingGpo
    Write-Output "[*] Creating GPO: `"$GpoName`"... ALREADY EXISTS"
} else {
    $Gpo = New-GPO -Name $GpoName -Comment "MedDefense Windows Fortress - PowerShell Script Block Logging, Module Logging, Transcription (Task 6)."
    Write-Output "[*] Creating GPO: `"$GpoName`"... CREATED"
}

# --- Script Block Logging -------------------------------------------------------------
# Event ID 4104 in Microsoft-Windows-PowerShell/Operational carries the full,
# de-obfuscated script block text - including content reconstructed after
# Base64/-EncodedCommand decoding - regardless of how the attacker obscured it.
Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -ValueName "EnableScriptBlockLogging" -Type DWord -Value 1 | Out-Null
Write-Output "[*] Configuring Script Block Logging..."
Write-Output "    EnableScriptBlockLogging = 1           [SET]"
Write-Output "    -> Event ID 4104 captures decoded scripts"

# --- Module Logging ---------------------------------------------------------------------
# Event ID 4103 records every cmdlet/parameter invoked in a pipeline, across all
# modules ("*"), so even non-script-block activity (dot-sourced cmdlets, module
# functions) leaves a trail.
Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
    -ValueName "EnableModuleLogging" -Type DWord -Value 1 | Out-Null
Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" `
    -ValueName "*" -Type String -Value "*" | Out-Null
Write-Output "[*] Configuring Module Logging..."
Write-Output "    EnableModuleLogging = 1, ModuleNames = *  [SET]"
Write-Output "    -> Event ID 4103 captures module invocations"

# --- Transcription -----------------------------------------------------------------------
# A complete, timestamped, human-readable session record - the fallback when
# an analyst needs full context rather than individual event records.
$TranscriptDir = "C:\PSTranscripts"
Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription" `
    -ValueName "EnableTranscripting" -Type DWord -Value 1 | Out-Null
Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription" `
    -ValueName "EnableInvocationHeader" -Type DWord -Value 1 | Out-Null
Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription" `
    -ValueName "OutputDirectory" -Type String -Value $TranscriptDir | Out-Null
if (-not (Test-Path -Path $TranscriptDir)) {
    New-Item -Path $TranscriptDir -ItemType Directory -Force | Out-Null
}
Write-Output "[*] Configuring Transcription..."
Write-Output "    OutputDirectory = C:\PSTranscripts     [SET]"

# --- Verify AMSI is active ----------------------------------------------------------------
# The Antimalware Scan Interface hooks amsi.dll into the PowerShell host process;
# if it is loaded in the current session, AMSI is actively scanning script content
# before it executes - the layer that catches obfuscated/deobfuscated payloads
# that logging alone only records after the fact.
$AmsiLoaded = [bool]((Get-Process -Id $PID).Modules | Where-Object { $_.ModuleName -eq "amsi.dll" })
if ($AmsiLoaded) {
    Write-Output "[*] Verifying AMSI... AMSI DLL loaded     [OK]"
} else {
    Write-Output "[*] Verifying AMSI... AMSI DLL NOT loaded     [FAIL]"
}

# --- Link the GPO to the domain root and force an update ---------------------------------
$existingLink = (Get-GPInheritance -Target $DomainDN).GpoLinks | Where-Object { $_.GpoId -eq $Gpo.Id }
if (-not $existingLink) {
    New-GPLink -Guid $Gpo.Id -Target $DomainDN -LinkEnabled Yes -Enforced Yes | Out-Null
}
gpupdate /target:computer /force | Out-Null
Write-Output "[*] Linking GPO and forcing update... COMPLETE"

# --- Test: run an encoded command and confirm it decodes into Event ID 4104 --------------
Write-Output "[*] Testing encoded command..."
$TestCommand      = 'Write-Host "Test"'
$EncodedTestCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($TestCommand))
Write-Output "    Input: powershell -enc $EncodedTestCommand"

powershell.exe -NoProfile -EncodedCommand $EncodedTestCommand | Out-Null
Start-Sleep -Seconds 2

$Decoded4104 = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 50 -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -eq 4104 -and $_.Message -like "*$TestCommand*" } |
    Select-Object -First 1

if ($Decoded4104) {
    Write-Output "    Event ID 4104 found: `"$TestCommand`"  [VERIFIED]"
} else {
    Write-Output "    Event ID 4104 NOT found for decoded command  [FAIL]"
}
