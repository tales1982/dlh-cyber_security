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
.\0-domain_baseline.ps1 [-OutputPath <path>]
```

Run directly on `DC01` as `analyst` (Domain Admin). Produces a console
summary and a JSON report (default `domain_baseline_report.json`) capturing
the full domain state.
