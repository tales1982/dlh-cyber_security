#================================================================
# 1. SYSTEM INFORMATION                                         |
#================================================================

$HOSTNAME = hostname
$OS_BUILD = (Get-ComputerInfo).OsBuildNumber
$PATCH_LEVEL = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR

#================================================================
# 2. INSTALLED PACKAGES                                         |
#================================================================
$INSTALLED_FEATURE_COUNT = (Get-WindowsOptionalFeature -Online | Where-Object State -eq "Enabled").Count

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
$SYSMON_SERVICE = Get-Service Sysmon -ErrorAction SilentlyContinue

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
        sysmon_service          = $SYSMON_SERVICE
        script_block_logging    = $SCRIPT_BLOCK_LOGGING
        account_policy          = $ACCOUNT_POLICY                                                                                                   

}

$RESULT | ConvertTo-Json -Depth 5
