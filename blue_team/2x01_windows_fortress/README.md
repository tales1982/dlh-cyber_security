# 2x01 - Windows Fortress

Active Directory and Windows hardening for MedDefense Health Systems. Where
[2x00_locking_the_gates](../2x00_locking_the_gates) hardened the 3 Linux
servers, this project locks down the `meddefense.local` Active Directory
domain: 280 workstations, 2 domain controllers and every login for 2,000
staff. The Crimson Tide advisory (1x05) showed that a compromised domain
controller and a single malicious GPO are enough to push ransomware to every
Windows endpoint in under 90 minutes - this project is the defense against
that exact playbook.

Every script is PowerShell. Every hardening change is deployed through Group
Policy. Every detection capability is built to generate the Windows Events
that Module 3 later exports and analyzes.

## Lab environment

| Parameter | Value |
|---|---|
| Lab Name | DC01 |
| Operating System | Windows Server 2022 |
| Domain | meddefense.local |
| Privileges | Domain Admin |
| Access Method | Direct VM login |
| Tools Used | PowerShell and Windows GUI tools |

## Scripts

| Script | Task | Purpose |
|---|---|---|
| [0-domain_baseline.ps1](0-domain_baseline.ps1) | 0 | Read-only security baseline of the domain: accounts, groups, service accounts, GPOs, password/lockout policy, Kerberos encryption types and privileged group membership, with a severity-ranked findings summary. |
| [1-domain_findings.ps1](1-domain_findings.ps1) | 1 | Turns the baseline into an actionable risk inventory - each finding carries id, severity, category, asset, evidence, risk, recommended remediation and the task that fixes it. |
| [2-eventlog_assessment.ps1](2-eventlog_assessment.ps1) | 2 | Checks which critical Event IDs (4624-4732, 4672, 1102) the domain is actually capable of generating today, against `auditpol` and the live Security log. |
| [3-telemetry_reference.ps1](3-telemetry_reference.ps1) | 3 | Machine-readable reference mapping every Security, PowerShell and Sysmon event this project uses to log source, audit/sensor dependency, detection meaning, Crimson Tide phase and validation method. |
| [4-password_policy.ps1](4-password_policy.ps1) | 4 | Deploys the CIS-aligned password and account lockout policy (14-char minimum, complexity, 24-password history, 5-attempt lockout) via GPO. Makes changes. |
| [5-audit_policy.ps1](5-audit_policy.ps1) | 5 | Deploys the Advanced Audit Policy Configuration via GPO: credential validation, Kerberos, logon/logoff, account management, privilege use, object access, process creation with command-line capture, restricted log clearing, 1 GB Security log. Makes changes. |
| [6-powershell_security.ps1](6-powershell_security.ps1) | 6 | Deploys Script Block Logging, Module Logging and Transcription via GPO, verifies AMSI is active, and proves the pipeline by running an encoded command and confirming it decodes in Event ID 4104. Makes changes. |
| [7-auth_hardening.ps1](7-auth_hardening.ps1) | 7 | Clears UseDESKeyOnly on flagged accounts, restricts the domain to AES128/AES256 Kerberos only, disables NTLMv1, and reports Credential Guard readiness. Makes changes. |
| [8-smb_hardening.ps1](8-smb_hardening.ps1) | 8 | Disables SMBv1 (client + server), enforces required SMB signing and encryption, disables NetBIOS over TCP/IP and LLMNR. Makes changes. |
| [9-sysmon_deploy.ps1](9-sysmon_deploy.ps1) | 9 | Downloads and installs Sysmon with [sysmonconfig.xml](sysmonconfig.xml), verifies the service/driver/telemetry, and proves FileCreate detection (Event ID 11). Makes changes. |
| [10-sysmon_tune.ps1](10-sysmon_tune.ps1) | 10 | Adds 5 MedDefense-specific Sysmon detection rules (Rclone, PsExec service install, encoded PowerShell, shadow copy deletion, scheduled task persistence) to `sysmonconfig.xml`, reloads Sysmon, and trigger-and-verifies each rule with a safe, non-destructive test. Makes changes. |

## Requirements

- All scripts have a `.ps1` extension and a comment header with script name,
  purpose, author and date.
- All scripts use `Set-StrictMode -Version Latest` and
  `$ErrorActionPreference = "Stop"`.
- Scripts are read-only unless explicitly stated otherwise; hardening
  changes are applied via GPO, not by mutating live objects directly from a
  script.

## Usage

```powershell
.\0-domain_baseline.ps1        [-OutputPath <path>]
.\1-domain_findings.ps1        [-OutputPath <path>]
.\2-eventlog_assessment.ps1
.\3-telemetry_reference.ps1    [-OutputPath <path>]
.\4-password_policy.ps1        # creates/links a GPO and sets the domain password/lockout policy
.\5-audit_policy.ps1           # creates/links a GPO and sets the Advanced Audit Policy
.\6-powershell_security.ps1    # creates/links a GPO and enables PowerShell logging
.\7-auth_hardening.ps1         # creates/links a GPO and hardens Kerberos/NTLM
.\8-smb_hardening.ps1          # creates/links a GPO and hardens SMB/NetBIOS/LLMNR
.\9-sysmon_deploy.ps1          # downloads and installs Sysmon with sysmonconfig.xml
.\10-sysmon_tune.ps1           # adds custom detection rules to sysmonconfig.xml
```

Run directly on `DC01` as `analyst` (Domain Admin). Tasks 0-3 are read-only
and produce a console summary plus a JSON report. Tasks 4-10 make real
changes - GPOs, local security policy, service accounts, or the Sysmon
service/driver - review the parameters before running against a domain
that isn't the lab. 9 and 10 additionally require outbound internet access
to Sysinternals/GitHub (9 falls back to the local `sysmonconfig.xml` if
that fails); 10's triggers are intentionally non-destructive (e.g.
`vssadmin delete shadows /?`, never a real deletion).
