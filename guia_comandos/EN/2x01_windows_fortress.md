# 2x01 – Windows Fortress

## Task - 0-domain_baseline.ps1
What it does: Captures the complete, unhardened baseline of the meddefense.local AD domain before any GPO hardening work begins — accounts, groups, service accounts, GPOs, password/lockout policy, Kerberos encryption types, and privileged group membership. This is the reference every later hardening task is measured against.
How to use: Run as a Domain Administrator in PowerShell, on a Domain Controller (read-only, makes no changes).
Commands:
- `Import-Module ActiveDirectory` — loads the Active Directory module's cmdlets into the session.
- `Import-Module GroupPolicy` — loads the Group Policy module's cmdlets into the session.
- `Get-ADDomain` — returns domain-level info (functional level, DN, NetBIOS name).
- `Get-ADForest` — returns forest-level info (forest functional level).
- `Get-ADDomainController -Filter *` — lists all domain controllers.
- `Get-ADUser -Filter * -Properties Enabled,LastLogonDate,PasswordLastSet,...` — enumerates AD user accounts with the given attributes.
- `Get-ADGroup -Filter *` — enumerates all AD groups.
- `Get-ADGroupMember -Identity <group>` — lists the members of an AD group.
- `Get-GPO -All` — lists every Group Policy Object in the domain.
- `Get-ADOrganizationalUnit -Filter * -Properties LinkedGroupPolicyObjects` — lists OUs and the GPOs linked to each.
- `Get-ADDefaultDomainPasswordPolicy` — reads the domain's default password/lockout policy.
- `Get-ADFineGrainedPasswordPolicy -Filter *` — lists any fine-grained (per-group) password policies configured.
- `Get-ADComputer -Identity <name> -Properties msDS-SupportedEncryptionTypes` — reads a computer object's supported Kerberos encryption types attribute.
- `Get-SmbServerConfiguration` — reads the local SMB server configuration, including whether SMBv1 is enabled.

## Task - 1-domain_findings.ps1
What it does: Turns the raw baseline from script 0 into an actionable risk inventory — every finding (severity, category, evidence, risk, recommended remediation, and mapped task) is documented individually. This is the punch list the rest of the Windows Fortress project works down.
How to use: Run as a Domain Administrator in PowerShell, after running 0-domain_baseline.ps1 (read-only).
Commands:
- `auditpol /get /category:* /r` — lists every configured audit subcategory on the host, as parseable CSV.
- `Get-ItemProperty -Path <key> -Name <value>` — reads a specific Windows registry value (here, PowerShell Script Block Logging status).
- `Get-Service -Name <name>` — queries the status of a Windows service (here, Sysmon).

## Task - 2-eventlog_assessment.ps1
What it does: Quantifies the gap between what the domain can currently see and what it needs to see — cross-checks every critical Event ID (4624, 4625, 4648, 4688, 4720, 4726, 4732, 4672, 1102) against the audit subcategory that generates it and against real occurrences in the last 24 hours.
How to use: Run as an Administrator in PowerShell, on a Domain Controller (read-only).
Commands:
- `Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=<date>; Id=<list>}` — queries the Event Viewer by log, time window, and specific event IDs.

## Task - 3-telemetry_reference.ps1
What it does: Builds a static, machine-readable reference connecting every event this project cares about (Security, PowerShell Operational, Sysmon logs) to its audit/sensor dependency, its security meaning, and the matching Crimson Tide attack phase.
How to use: Run on any PowerShell-capable machine to generate the JSON reference file (does not query the live domain and makes no changes).
Commands:
- (no new command — static reference data; documents the use of `Get-WinEvent`, already listed in script 2, as the validation method for each event).

## Task - 4-password_policy.ps1
What it does: Deploys a CIS-aligned password and account lockout policy (14-character minimum, complexity, 24-password history, lockout after 5 attempts), creating/linking a real GPO and applying the same values via Set-ADDefaultDomainPasswordPolicy.
How to use: Run as a Domain Administrator in PowerShell, on a Domain Controller (makes changes).
Commands:
- `New-GPO -Name <name> -Comment <text>` — creates a new, empty Group Policy Object.
- `New-Item -Path <path> -ItemType Directory -Force` — creates a directory at the given path.
- `Set-Content -Path <file> -Value <content> -Encoding <enc>` — writes content to a file; here, used to hand-write the GPO's security templates (GptTmpl.inf, GPT.INI).
- `Get-Content -Path <file> -Raw` — reads a file's full content as a single string (used to re-read GPT.INI before bumping its version).
- `Set-ADObject -Identity <DN> -Replace @{versionNumber=...; gPCMachineExtensionNames=...}` — directly modifies AD object attributes, used here to bump a GPO's version and register its CSEs.
- `Set-ADDefaultDomainPasswordPolicy -Identity <domain> -MinPasswordLength <n> -ComplexityEnabled $true ...` — sets the domain's effective password/lockout policy.
- `Get-GPInheritance -Target <DN>` — reads GPO links and inheritance at an AD container.
- `New-GPLink -Guid <id> -Target <DN> -LinkEnabled Yes -Enforced Yes` — links a GPO to a domain or OU.
- `gpupdate /target:computer /force` — forces an immediate Group Policy refresh on the host.

## Task - 5-audit_policy.ps1
What it does: Closes the visibility gaps found by script 2 by deploying the Advanced Audit Policy Configuration via GPO — per-subcategory auditing, command-line capture on Event ID 4688, restricting who can clear the Security log, and a 1 GB Security log.
How to use: Run as a Domain Administrator in PowerShell, on a Domain Controller (makes changes).
Commands:
- `Get-ADObject -Identity <DN> -Properties gPCMachineExtensionNames` — reads raw AD object attributes, used here to read the CSEs currently registered on a GPO.
- `Set-GPRegistryValue -Name <gpo> -Key <path> -ValueName <name> -Type DWord -Value <value>` — writes a registry-based value inside a GPO.
- `wevtutil sl Security /ms:<bytes>` — sets the Security event log's maximum size immediately on the local host.

## Task - 6-powershell_security.ps1
What it does: Neutralizes PowerShell as a post-exploitation tool by deploying Script Block Logging, Module Logging, and Transcription via GPO, verifies AMSI is active, and validates the pipeline end-to-end by running an encoded test command.
How to use: Run as a Domain Administrator in PowerShell, on a Domain Controller (makes changes and runs a local test).
Commands:
- `Get-Process -Id $PID` — queries the current process, used here to check whether amsi.dll is loaded (AMSI active).
- `powershell.exe -NoProfile -EncodedCommand <base64>` — runs a Base64-encoded PowerShell command, used as a test to validate Script Block Logging.

## Task - 7-auth_hardening.ps1
What it does: Blocks Kerberoasting and legacy-protocol credential theft — clears the UseDESKeyOnly flag on service accounts, restricts the domain to AES128/AES256 Kerberos tickets, refuses NTLMv1, and reports Credential Guard readiness.
How to use: Run as a Domain Administrator in PowerShell, on a Domain Controller (makes changes).
Commands:
- `Set-ADAccountControl -Identity <DN> -UseDESKeyOnly $false` — changes UserAccountControl flags on an AD account; here, clears the DES requirement.
- `Set-ADUser -Identity <name> -Replace @{'msDS-SupportedEncryptionTypes'=<value>}` — directly modifies an AD user account's attributes; here, krbtgt's supported Kerberos encryption types.
- `Set-ADComputer -Identity <DN> -Replace @{'msDS-SupportedEncryptionTypes'=<value>}` — directly modifies an AD computer object's attributes (same encryption types, on each DC).
- `Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard` — queries a WMI/CIM class; here, checks Credential Guard status.

## Task - 8-smb_hardening.ps1
What it does: Eliminates SMBv1 (the protocol behind EternalBlue/WannaCry/NotPetya), enforces required SMB signing, enables SMB encryption, and disables the legacy name-resolution protocols (NetBIOS and LLMNR) that tools like Responder abuse for credential capture.
How to use: Run as a Domain Administrator in PowerShell, on a Domain Controller (makes changes).
Commands:
- `Get-SmbClientConfiguration` — reads the local SMB client configuration.
- `Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force` — reconfigures the local SMB server; here, disables SMBv1 (and later enforces signing and enables encryption).
- `Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol"` — disables a Windows optional feature; here, the SMB1 protocol.
- `Set-ItemProperty -Path <key> -Name <value> -Type DWord -Value <value>` — directly sets a Windows registry value.
- `Set-SmbClientConfiguration -RequireSecuritySignature $true -Force` — reconfigures the local SMB client to require signing.
- `Invoke-CimMethod -InputObject <adapter> -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=2}` — invokes a WMI method on a CIM instance; here, disables NetBIOS over TCP/IP.

## Task - 9-sysmon_deploy.ps1
What it does: Downloads and installs Sysmon with a detection-optimized configuration (SwiftOnSecurity baseline), then verifies the service/driver are active and that events are actually being generated.
How to use: Run as a local Administrator in PowerShell, on the host where Sysmon will be installed (makes changes; requires internet access).
Commands:
- `Invoke-WebRequest -Uri <url> -OutFile <file> -UseBasicParsing` — downloads a file from a URL; here, the Sysmon binary and the SwiftOnSecurity config.
- `Expand-Archive -Path <zip> -DestinationPath <folder> -Force` — extracts a .zip archive.
- `Sysmon64.exe -accepteula -i <config>` — installs the Sysmon service and driver with a given configuration file.
- `Remove-Item -Path <path> -Force` — removes a file or item; here, the test file used to validate FileCreate telemetry.

## Task - 10-sysmon_tune.ps1
What it does: Appends 5 MedDefense-specific detection rules (Rclone, PsExec, encoded PowerShell, shadow-copy deletion, scheduled-task persistence) to sysmonconfig.xml, reloads the live configuration, and validates each rule with a safe, non-destructive trigger.
How to use: Run as a local Administrator in PowerShell, after 9-sysmon_deploy.ps1 (makes changes).
Commands:
- `Sysmon64.exe -c <config>` — reloads the running Sysmon configuration without reinstalling the service.
- `Copy-Item -Path <source> -Destination <destination> -Force` — copies a file; here, used to simulate attack artifacts (e.g. renaming whoami.exe to rclone.exe) in safe tests.
- `Start-Process -FilePath <exe> -ArgumentList <args> -WindowStyle Hidden -Wait` — starts a process; used to fire each rule's test trigger.
- `New-ItemProperty -Path <key> -Name <value> -Value <value> -PropertyType DWord -Force` — creates a new registry value; here, simulates PsExec's service installation.
- `schtasks /create /tn <name> /tr <command> /sc once /st <time> /f` — creates a Windows scheduled task; used as the persistence-detection test trigger.
- `schtasks /delete /tn <name> /f` — removes a scheduled task, cleaning up the test artifact.

## Task - 11-firewall_hardening.ps1
What it does: Implements endpoint-level network segmentation — default-deny inbound on all three firewall profiles, with narrow allow rules for exactly the services a Domain Controller must expose (RDP/WinRM from the management subnet, SMB from the server subnet, DNS/LDAP/Kerberos), and logs everything dropped.
How to use: Run as a local Administrator in PowerShell, on the host being hardened (makes changes).
Commands:
- `Get-NetFirewallProfile -All` — reads the current state of the Windows Firewall profiles (Domain/Private/Public).
- `Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow` — configures the firewall profiles; here, with default-deny inbound.
- `Get-NetFirewallRule -Name <name>` — reads a specific firewall rule by name.
- `New-NetFirewallRule -Name <name> -Direction Inbound -Action Allow -Protocol <proto> -LocalPort <port> -Profile Domain` — creates a new inbound firewall rule.
- `Disable-NetFirewallRule -Name <name>` — disables an existing firewall rule; here, the legacy rules that conflict with the new default-deny posture.

## Task - 12-applocker_config.ps1
What it does: Deploys AppLocker application allow-listing via GPO in audit-only mode, allowing Windows/Program Files binaries and the clinical DicomViewer.exe application; everything else is denied by AppLocker's own default behavior.
How to use: Run as a Domain Administrator in PowerShell, on a Domain Controller (makes changes).
Commands:
- `Import-Module AppLocker` — loads the AppLocker module's cmdlets.
- `Set-Service -Name "AppIDSvc" -StartupType Automatic` — sets a Windows service's startup type; here, the Application Identity service required by AppLocker.
- `Start-Service -Name "AppIDSvc"` — starts a Windows service.
- `Set-AppLockerPolicy -XmlPolicy <xml> -Ldap <path>` — writes an AppLocker policy directly into a GPO's AppLocker store.
- `Test-AppLockerPolicy -PolicyObject <xml> -Path <file> -User <user>` — evaluates whether a file would be allowed or denied under an AppLocker policy, without executing it.
- `Export-AppLockerPolicy -ALPolicy <object> -Xml` — exports an AppLocker policy object to XML.

## Task - 13-rdp_hardening.ps1
What it does: Closes RDP as a lateral-movement entry point — requires NLA (pre-auth before a session starts), restricts session access to the G_IT_Admins group, bounds idle/session time, forces the highest encryption level, and disables clipboard/drive redirection and Remote Assistance.
How to use: Run as a Domain Administrator in PowerShell, on a Domain Controller (makes changes).
Commands:
- `Remove-ADGroupMember -Identity <group> -Members <member> -Confirm:$false` — removes a member from an AD group; here, strips unauthorized accounts from "Remote Desktop Users".
- `Add-ADGroupMember -Identity <group> -Members <member>` — adds a member to an AD group; here, adds G_IT_Admins to "Remote Desktop Users".

## Task - 14-service_accounts.ps1
What it does: Audits every MedDefense service account (excessive privileges, ancient passwords, unconstrained delegation) and remediates the findings, marking accounts as "sensitive and cannot be delegated," denying interactive logon via GPO, and removing privileged group membership.
How to use: Run as a Domain Administrator in PowerShell, on a Domain Controller (makes changes).
Commands:
- (no new command — reuses `Set-ADAccountControl`, `Get-ADGroupMember`, `Remove-ADGroupMember`, `New-GPO`, `Set-ADObject`, `Get-Content`/`Set-Content`, among others already listed).

## Task - 15-master_validation.ps1
What it does: Runs the weekly compliance checklist — reads every setting deployed by scripts 4 through 14, compares each against its expected value, and prints a PASS/WARN/FAIL dashboard; exits 1 if any critical check fails.
How to use: Run as a Domain Administrator in PowerShell, on a Domain Controller, ideally as a weekly scheduled task (read-only).
Commands:
- (no new command — reuses `Get-ADDefaultDomainPasswordPolicy`, `auditpol`, `Get-ItemProperty`, `Get-Service`, `Get-SmbServerConfiguration`, `Get-NetFirewallProfile`, `Get-ADGroupMember`, among others already listed).

## Task - 16-hardened_state_export.ps1
What it does: Exports the final hardened domain state — every control built across Tasks 4-14 (GPOs, audit policy, PowerShell logging, Sysmon, firewall, AppLocker, RDP, authentication protocols, service accounts) — into a single structured JSON evidence package.
How to use: Run as a Domain Administrator in PowerShell, on a Domain Controller, after the other scripts (read-only).
Commands:
- `Get-GPOReport -Guid <id> -ReportType Xml` — generates an XML report of all of a GPO's settings.
- `Get-AppLockerPolicy -Effective -Xml` — reads the AppLocker policy actually in effect on the local machine.
