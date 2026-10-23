# Rule Validation Report: IR-2026-0414-01

- **Analyst:** Tales Lima
- **Date:** 2026-10-23
- **Script:** `./validate_rules.sh` (run from `ir_dfir_playbook/5x03_post_incident_review/`)
- **Rules tested:**
  - R1 `sigma_powershell_msbuild_lolbin.yml` (process_creation, T1127.001)
  - R2 `sigma_msbuild_network_connection.yml` (network_connection, T1071.001 / T1127.001)
- **Samples:**
  - `incident_sysmon.jsonl`: 17 Sysmon events, WST-WS-031 / WST-WS-017 / LIS-WSIDE-01, 2026-04-14 02:40Z to 04:00Z
  - `clean_sysmon.jsonl`: 21 Sysmon events, 30-day baseline (2026-03-17 to 2026-04-12), includes developer builds on WST-WS-042 / WST-WS-051
- **False positive target:** under 0.1 % of total events in the clean sample
- **Syntax:** `sigma check` (sigma-cli 3.1.0) on both rules: 0 errors, 0 condition errors, 0 issues

## Method

`validate_rules.sh` loads each Sigma rule, maps the Sigma fields to the JSONL fields (`Image` -> `image`, `ParentImage` -> `parent_image`, `DestinationIp` -> `dst_ip`, `DestinationHostname` -> `dst_hostname`, `Initiated` -> `initiated`) and the logsource category to the Sysmon event ID (`process_creation` = 1, `network_connection` = 3), then evaluates the detection and condition on every event. For the clean sample of a rule that has `filter_*` blocks, it runs the rule twice: once with the filters disabled (the original rule) and once as tuned, so the false positives removed by tuning stay visible.

## Results

| Rule | Sample | Total events | Matches | Rate | Verdict |
|---|---|---|---|---|---|
| R1 | incident_sysmon.jsonl | 17 | 2 | 11.765 % | PASS |
| R1 | clean_sysmon.jsonl | 21 | 0 | 0.000 % | PASS |
| R2 | incident_sysmon.jsonl | 17 | 2 | 11.765 % | PASS |
| R2 (original) | clean_sysmon.jsonl | 21 | 14 | 66.667 % | REVIEW |
| R2 (tuned) | clean_sysmon.jsonl | 21 | 0 | 0.000 % | PASS |

The match rates on the incident sample are high only because the sample is small (17 events); what matters is that each expected attack event is hit.

### R1: PowerShell spawning trusted developer utility

**Did the rule fire on the incident data?** Yes, on both expected events:

- 2026-04-14T02:46:58Z, WST-WS-031, `powershell.exe` (PID 7812) -> `MSBuild.exe` PID 8104, `msbuild.exe C:\Users\dmarsh\AppData\Local\Temp\update.xml` (matches ART-002-M01)
- 2026-04-14T03:27:13Z, WST-WS-017, `powershell.exe` (PID 4402) -> `MSBuild.exe` PID 5108, same command line (matches ART-003-M01)

**False positive rate on the clean baseline:** 0.000 % (0 of 21). The legitimate MSBuild run in the baseline (2026-03-17T14:22:41Z, WST-WS-042, user kpatel) has `devenv.exe` as parent, and the developer `build.ps1` run on 2026-03-18 starts `dotnet.exe`, not MSBuild, so neither matches.

**Tuning:** none needed. Rule unchanged from Task 3.

### R2: Trusted developer utility outbound connection to public IP

**Did the rule fire on the incident data?** Yes, on both C2 connections:

- 2026-04-14T02:47:02Z, WST-WS-031, `MSBuild.exe` PID 8104 -> 185.220.101.47:443, no hostname (ART-002-M02, Tor exit)
- 2026-04-14T03:27:15Z, WST-WS-017, `MSBuild.exe` PID 5108 -> 91.234.99.107:443, no hostname (ART-003-M01, Cobalt Strike cluster)

**False positive rate on the clean baseline:**

- Original rule (selection on image + `Initiated: true`, private ranges excluded): **14 of 21 events = 66.667 %**, far over the 0.1 % target.
- Pattern: all 14 matches are `MSBuild.exe` connections to `168.62.42.37:443` with `DestinationHostname = api.nuget.org`, from the two developer workstations WST-WS-042 (10 events, user kpatel) and WST-WS-051 (4 events). This is NuGet package restore during normal Visual Studio builds.
- Tuned rule: **0 of 21 = 0.000 %**. PASS.

## Tuning changes

| Rule | Change | Reason | Effect on incident detection |
|---|---|---|---|
| R2 | Added `filter_nuget: DestinationHostname\|endswith: '.nuget.org'` and changed the condition from `selection and not filter_private` to `selection and not 1 of filter_*` | Removes the 14 NuGet restore connections, the only false positive pattern in the 30-day baseline | None: both C2 connections have no destination hostname (direct-to-IP), so the filter does not apply to them; incident matches stay at 2 of 2 |
| R2 | Added `modified: 2026-10-23` and documented the tuning in `description` | Sigma convention for a changed rule; keeps the history inside the rule | None |
| R2 | Filtered on hostname, not on IP 168.62.42.37 | NuGet is served from Azure CDN and its IPs change; an IP filter would break or open an allow-listed hole on shared Azure address space | None |

The tuned file replaces the original `sigma_msbuild_network_connection.yml`. R1 was not modified.

## Residual risk and follow-up

- **Hostname spoofing:** an attacker could use C2 hosted under a hostname ending in `.nuget.org` only by controlling that domain, which is unlikely; but domain fronting through a CDN could pass the filter. Mitigation: keep the WDAC MSBuild block (HRD-002) as the preventive control; R2 is a detection backstop.
- **Sample size:** the clean sample has 21 events. Before production, rerun `validate_rules.sh` against a full 30-day SIEM export of the clinical workstation class (expected hundreds of thousands of events) and confirm the false positive rate stays under 0.1 %.
- **Deployment:** convert both rules with `sigma convert -t <backend>` for the Wazuh/SIEM pipeline, deploy R1 and R2 at level high, and verify they fire with an Atomic Red Team test for T1127.001 on a lab host.
