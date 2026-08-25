$ErrorActionPreference = 'Stop'

try {

#================================================================
# 1. SYSTEM INFORMATION                                         |
#================================================================

$HOSTNAME = hostname
$OS_BUILD = (Get-ComputerInfo).OsBuildNumber
$PATCH_LEVEL = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR

#================================================================
# 2. INSTALLED PACKAGES                                         |
#================================================================

$OS_PRODUCT_TYPE = (Get-CimInstance Win32_OperatingSystem).ProductType

if ($OS_PRODUCT_TYPE -eq 1) {
    # Workstation (client)
    $INSTALLED_FEATURE_COUNT = (Get-WindowsOptionalFeature -Online | Where-Object State -eq "Enabled").Count
}
else {
    # Server or Domain Controller
    $INSTALLED_FEATURE_COUNT = (Get-WindowsFeature | Where-Object Installed).Count
}

#================================================================
# 3. RUNNING SERVICES                                           |
#================================================================
$RUNNING_SERVICES = (Get-Service | Where-Object Status -eq "Running" | Select-Object Name, DisplayName, Status)

#================================================================
# 4. LOCAL USER ACCOUNT                                         |
#================================================================
$LOCAL_USERS_ACCOUNT = Get-LocalUser

#================================================================
# 5. FIREWALL STATUS                                            |
#================================================================
$FIREWALL_STATUS = Get-NetFirewallProfile | Select-Object Name, Enabled

#================================================================
# 6. AUDIT POLICY                                               |
#================================================================
$AUDIT_POLICY = auditpol /get /category:*

#================================================================
# 7. SYSMON SERVICE                                             |
#================================================================
$SYSMON_SERVICE = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue | Select-Object -First 1

$SYSMON_VERSION = $null
$SYSMON_CHANNEL_SIZE = $null

if ($SYSMON_SERVICE) {
    $imagePath = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$($SYSMON_SERVICE.Name)" -ErrorAction SilentlyContinue).ImagePath

    if ($imagePath) {
        $exePath = ($imagePath -replace '^"?([^"]+\.exe)"?.*$', '$1')

        if (Test-Path $exePath) {
            $SYSMON_VERSION = (Get-Item $exePath).VersionInfo.ProductVersion
        }
    }

    $sysmonLog = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue

    if ($sysmonLog) {
        $SYSMON_CHANNEL_SIZE = $sysmonLog.FileSize
    }
}

#================================================================
# 8. POWERSHELL LOGGING STATE                                   |
#================================================================
 $SCRIPT_BLOCK_LOGGING = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging

#================================================================
# 9. ACCOUNT POLICY                                             |
#================================================================
$ACCOUNT_POLICY = net accounts


#================================================================
# PRINT                                                         |
#================================================================
$RESULT = [PSCustomObject]@{
        hostname                = $HOSTNAME
        os_build                = $OS_BUILD
        patch_level             = $PATCH_LEVEL
        installed_feature_count = $INSTALLED_FEATURE_COUNT
        running_services        = $RUNNING_SERVICES
        local_users_account     = $LOCAL_USERS_ACCOUNT
        firewall_status         = $FIREWALL_STATUS
        audit_policy            = $AUDIT_POLICY
        sysmon_present          = [bool]$SYSMON_SERVICE
        sysmon_service          = $SYSMON_SERVICE
        sysmon_version          = $SYSMON_VERSION
        sysmon_channel_size     = $SYSMON_CHANNEL_SIZE
        script_block_logging    = $SCRIPT_BLOCK_LOGGING
        account_policy          = $ACCOUNT_POLICY

}

}
catch {
    Write-Error "Environment error: $($_.Exception.Message)"
    exit 2
}

if ([string]::IsNullOrWhiteSpace($HOSTNAME) -or [string]::IsNullOrWhiteSpace($OS_BUILD)) {
    Write-Error "Failed to capture core system information."
    exit 1
}

$RESULT | ConvertTo-Json -Depth 5

exit 0
