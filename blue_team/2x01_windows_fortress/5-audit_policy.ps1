<#
    Script name : 5-audit_policy.ps1
    Purpose     : MedDefense Health Systems - Windows Fortress (2x01), Task 5.
                  Closes the visibility gaps identified in
                  2-eventlog_assessment.ps1 by deploying the Advanced Audit
                  Policy Configuration via GPO: per-subcategory Success/
                  Failure auditing for credential validation, Kerberos,
                  logon/logoff, account management, privilege use, object
                  access and process creation; full command-line capture on
                  4688; Security log clearing restricted to Domain Admins;
                  and a 1 GB Security log so evidence survives long enough
                  to be collected. This is what turns Windows Event Logs
                  from noise into evidence - without it, Event ID 4688 is
                  never generated and every process an attacker runs is
                  invisible.
                  Makes configuration changes: creates/links a GPO and
                  writes Advanced Audit Policy (audit.csv), Security
                  Settings (GptTmpl.inf) and registry-based policy values
                  into it.
    Author      : Tales
    Date        : 2026-08-08
#>

[CmdletBinding()]
param(
    [string]$GpoName        = "MedDefense - Advanced Audit Policy",
    [int]$SecurityLogMaxSizeKB = 1048576   # 1 GB
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory
Import-Module GroupPolicy

# CSE GUID pairs that must appear in gPCMachineExtensionNames for each policy
# area to actually be processed by a domain controller / client on refresh.
$AdvancedAuditCse = "{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}{FC715823-C5FB-11D1-9EEF-00A0C90347FF}"
$SecEditCse       = "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}"

function Add-GpoMachineCse {
    <#
        Bumps GPT.INI's Version and merges a CSE GUID pair into the GPO's
        gPCMachineExtensionNames without clobbering CSEs already registered
        there (e.g. the Registry CSE that Set-GPRegistryValue adds on its
        own) - required for any policy area not covered by a supported
        Set-GP*Value cmdlet (Advanced Audit Policy, Security Settings).
    #>
    param(
        [string]$SysvolPath,
        [string]$GpoDistinguishedName,
        [string]$CseGuidPair
    )
    $gptIniPath = Join-Path $SysvolPath "GPT.INI"
    $gptIni = Get-Content -Path $gptIniPath -Raw
    $newVersion = if ($gptIni -match 'Version=(\d+)') { [int]$Matches[1] + 1 } else { 1 }
    Set-Content -Path $gptIniPath -Value ($gptIni -replace 'Version=\d+', "Version=$newVersion") -Encoding ASCII

    $gpoObject = Get-ADObject -Identity $GpoDistinguishedName -Properties gPCMachineExtensionNames
    $current = $gpoObject.gPCMachineExtensionNames
    $updated = if ([string]::IsNullOrEmpty($current)) {
        "[$CseGuidPair]"
    } elseif ($current -notlike "*$CseGuidPair*") {
        "$current[$CseGuidPair]"
    } else {
        $current
    }
    Set-ADObject -Identity $GpoDistinguishedName -Replace @{ versionNumber = $newVersion; gPCMachineExtensionNames = $updated }
}

$Domain    = Get-ADDomain
$DomainDNS = $Domain.DNSRoot
$DomainDN  = $Domain.DistinguishedName

# --- Create the GPO ------------------------------------------------------------------
$existingGpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
if ($existingGpo) {
    $Gpo = $existingGpo
    Write-Output "[*] Creating GPO: `"$GpoName`"... ALREADY EXISTS"
} else {
    $Gpo = New-GPO -Name $GpoName -Comment "MedDefense Windows Fortress - Advanced Audit Policy Configuration (Task 5)."
    Write-Output "[*] Creating GPO: `"$GpoName`"... CREATED"
}

$GpoGuid    = "{$($Gpo.Id.ToString().ToUpper())}"
$GpoDN      = "CN=$GpoGuid,CN=Policies,CN=System,$DomainDN"
$SysvolPath = "\\$DomainDNS\SYSVOL\$DomainDNS\Policies\$GpoGuid"

# --- Advanced Audit Policy Configuration (audit.csv) ----------------------------------
# Category > subcategory map, per the Windows Fortress target audit policy:
#   Account Logon:      Credential Validation (S/F), Kerberos Authentication (S/F)
#   Logon/Logoff:        Logon (S/F), Logoff (S), Special Logon (S)
#   Account Management: User Account Management (S/F)
#   Privilege Use:       Sensitive Privilege Use (S/F)
#   Object Access:       File System (S/F), Registry (S/F)
#   Process Tracking:   Process Creation (S)
# Subcategory GUID pairs are per Microsoft's published Advanced Audit Policy
# reference. Success (1) / Failure (2) / Success and Failure (3) map to the
# numeric Setting Value the CSE actually consumes; Inclusion Setting is the
# human-readable mirror of it.
$AuditCategories = @(
    [PSCustomObject]@{ Name = "Credential Validation";   Guid = "{0CCE923F-69AE-11D9-BED3-505054503030}"; Success = $true;  Failure = $true }
    [PSCustomObject]@{ Name = "Kerberos Authentication";  Guid = "{0CCE9242-69AE-11D9-BED3-505054503030}"; Success = $true;  Failure = $true }
    [PSCustomObject]@{ Name = "Logon";                    Guid = "{0CCE9215-69AE-11D9-BED3-505054503030}"; Success = $true;  Failure = $true }
    [PSCustomObject]@{ Name = "Logoff";                   Guid = "{0CCE9216-69AE-11D9-BED3-505054503030}"; Success = $true;  Failure = $false }
    [PSCustomObject]@{ Name = "Special Logon";            Guid = "{0CCE921B-69AE-11D9-BED3-505054503030}"; Success = $true;  Failure = $false }
    [PSCustomObject]@{ Name = "User Account Management";  Guid = "{0CCE9235-69AE-11D9-BED3-505054503030}"; Success = $true;  Failure = $true }
    [PSCustomObject]@{ Name = "Sensitive Privilege Use";  Guid = "{0CCE9228-69AE-11D9-BED3-505054503030}"; Success = $true;  Failure = $true }
    [PSCustomObject]@{ Name = "File System";              Guid = "{0CCE921D-69AE-11D9-BED3-505054503030}"; Success = $true;  Failure = $true }
    [PSCustomObject]@{ Name = "Registry";                 Guid = "{0CCE921E-69AE-11D9-BED3-505054503030}"; Success = $true;  Failure = $true }
    [PSCustomObject]@{ Name = "Process Creation";         Guid = "{0CCE922B-69AE-11D9-BED3-505054503030}"; Success = $true;  Failure = $false }
)

$AuditCsvLines = New-Object System.Collections.Generic.List[string]
$AuditCsvLines.Add("Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value")
foreach ($cat in $AuditCategories) {
    $settingValue = ([int]$cat.Success) + (2 * [int]$cat.Failure)
    $inclusionText = switch ($settingValue) {
        3 { "Success and Failure" }
        1 { "Success" }
        2 { "Failure" }
        default { "No Auditing" }
    }
    $AuditCsvLines.Add(",System,$($cat.Name),$($cat.Guid),$inclusionText,,$settingValue")
}

$AuditDir = Join-Path $SysvolPath "MACHINE\Microsoft\Windows NT\Audit"
New-Item -Path $AuditDir -ItemType Directory -Force | Out-Null
Set-Content -Path (Join-Path $AuditDir "audit.csv") -Value $AuditCsvLines -Encoding ASCII
Add-GpoMachineCse -SysvolPath $SysvolPath -GpoDistinguishedName $GpoDN -CseGuidPair $AdvancedAuditCse

Write-Output "[*] Configuring Audit Categories..."
foreach ($cat in $AuditCategories) {
    $label = if ($cat.Failure) { "Success, Failure" } else { "Success" }
    Write-Output ("    {0}:{1}{2}   [SET]" -f $cat.Name, (" " * [Math]::Max(1, 27 - $cat.Name.Length - 1)), $label)
}

# Subcategory audit settings are ignored unless legacy category-level auditing is
# disabled in favor of the granular subcategories configured above.
Set-GPRegistryValue -Name $GpoName -Key "HKLM\System\CurrentControlSet\Control\Lsa" `
    -ValueName "SCENoApplyLegacyAuditPolicy" -Type DWord -Value 1 | Out-Null

# --- Command-line logging on process creation (adds full command line to Event ID 4688) -
Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    -ValueName "ProcessCreationIncludeCmdLine_Enabled" -Type DWord -Value 1 | Out-Null
Write-Output "[*] Enabling command-line in process creation events...   [SET]"

# --- Restrict Security log clearing to Domain Admins only ----------------------------
# SeSecurityPrivilege ("Manage auditing and security log") is what actually gates
# clearing the Security log (and configuring audit policy); granting it solely to
# Domain Admins removes every other default holder, so log clearing is restricted
# to Domain Admins only.
$DomainAdminsSid = (Get-ADGroup -Identity "Domain Admins").SID.Value
$PrivilegeSecEditDir  = Join-Path $SysvolPath "MACHINE\Microsoft\Windows NT\SecEdit"
$PrivilegeGptTmplPath = Join-Path $PrivilegeSecEditDir "GptTmpl.inf"
New-Item -Path $PrivilegeSecEditDir -ItemType Directory -Force | Out-Null

$PrivilegeGptTmplContent = @"
[Unicode]
Unicode=yes
[Privilege Rights]
SeSecurityPrivilege = *$DomainAdminsSid
[Version]
signature="`$CHICAGO`$"
Revision=1
"@
Set-Content -Path $PrivilegeGptTmplPath -Value $PrivilegeGptTmplContent -Encoding Unicode
Add-GpoMachineCse -SysvolPath $SysvolPath -GpoDistinguishedName $GpoDN -CseGuidPair $SecEditCse
Write-Output "[*] Restricting Security log clearing...                  [SET]"

# --- Security log maximum size (1 GB) -------------------------------------------------
Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\Windows\EventLog\Security" `
    -ValueName "MaxSize" -Type DWord -Value $SecurityLogMaxSizeKB | Out-Null
Write-Output "[*] Setting Security log max size to 1 GB...              [SET]"

# --- Link the GPO to the domain root and force an update -----------------------------
$existingLink = (Get-GPInheritance -Target $DomainDN).GpoLinks | Where-Object { $_.GpoId -eq $Gpo.Id }
if (-not $existingLink) {
    New-GPLink -Guid $Gpo.Id -Target $DomainDN -LinkEnabled Yes -Enforced Yes | Out-Null
}
gpupdate /target:computer /force | Out-Null
Write-Output "[*] Linking GPO and forcing update... COMPLETE"

# --- Verify with auditpol -------------------------------------------------------------
Write-Output "[*] Verifying effective audit policy..."
$Verification = auditpol /get /category:* /r | ConvertFrom-Csv
foreach ($cat in $AuditCategories) {
    $row = $Verification | Where-Object { $_.Subcategory -eq $cat.Name }
    $effective = if ($row) { $row.'Inclusion Setting' } else { "UNKNOWN" }
    Write-Output "    $($cat.Name): $effective"
}
