# Evidence Preservation Runbook: IR-2026-0414-01

Evidence store: /evidence/IR-2026-0414-01/ (on forensic server soc-evid01, SMB share `\\soc-evid01\evidence$\IR-2026-0414-01\`)
Hash algorithm: SHA-256
Hash manifest: /evidence/IR-2026-0414-01/hashes.txt (the IR-2026-0414-01-hashes.txt manifest, format `<sha256>  <relative_path>`)
Operator: Tales Lima, on-call SOC (from IR jumpbox soc-jump01)
Target host: WST-WS-031 (10.42.118.31), user MEDDEFENSE\dmarsh
Alert window: 2026-04-13T02:47:00Z to 2026-04-14T02:47:00Z (24 h before alert)

Rules for every step:

- Never write tools or output to the local disk of WST-WS-031; run tools from the read-only IR tool share and write straight to the evidence share.
- Hash at the source when possible (`certutil`) and again on the evidence server (`sha256sum`); both values must match before the next step.
- After hashing, set the file read-only: `chmod 0440 <file>`.
- Log each artifact as an EVIDENCE entry in incident_timeline.md (hash + path).
- Order follows volatility (RFC 3227): memory → processes → network → on-disk payloads → server-side logs.
- **No containment action (VLAN move, process kill, firewall block, password reset, session revocation) until step 9 passes.**

## 0. Initialize the evidence store

- what: tamper-evident directory tree + seeded hash manifest
- how: `EVIDENCE_ROOT=/evidence bash evidence_store_init.sh` on soc-evid01 (run once; the script aborts if the incident directory already exists, protecting chain of custody)
- where: /evidence/IR-2026-0414-01/{memory,disk,process_tree,network,endpoint_telemetry,siem,proxy_dns,authentication,malware,correlation}/ + hashes.txt
- hash cmd: n/a (manifest created here)
- ordering: every later step writes into this tree; must exist first
- note: the script line `INCIDENT_DIR="${EVIDENCE_ROOT}/${INCIDENCE_ID:-${INCIDENT_ID}}"` contains a typo (`INCIDENCE_ID`). It falls back correctly to IR-2026-0414-01, but run `unset INCIDENCE_ID` first so a stray environment variable cannot redirect the store.

## 1. Volatile memory, WST-WS-031

- what: full physical memory dump. Highest priority: EDR shows MSBuild.exe PID 8104 holding a PAGE_EXECUTE_READWRITE region with an MZ header (2026-04-14T02:47:14Z), meaning an in-memory payload that exists nowhere on disk
- how (live-response shell from soc-jump01, tool run from the IR share):
  `\\soc-evid01\irtools$\winpmem_mini_x64_rc2.exe \\soc-evid01\evidence$\IR-2026-0414-01\memory\wst-ws-031.raw`
- where: /evidence/IR-2026-0414-01/memory/wst-ws-031.raw
- hash cmd (source): `certutil -hashfile \\soc-evid01\evidence$\IR-2026-0414-01\memory\wst-ws-031.raw SHA256`
- hash cmd (store): `cd /evidence/IR-2026-0414-01 && sha256sum memory/wst-ws-031.raw | tee -a hashes.txt`
- ordering: MUST precede any process kill, host isolation, reboot or power-off. Killing PID 8104 or powering off destroys the injected payload, C2 configuration, decrypted strings and Kerberos tickets cached in LSASS. Capturing memory first also keeps later commands (steps 2–3) from overwriting memory pages.

## 2. Running process list (PIDs, command lines, parent PIDs)

- what: full process table with PID, PPID, image path, command line, owner, start time; expected chain explorer.exe 5920 → update.exe 7204 → powershell.exe 7812 → MSBuild.exe 8104
- how:
  `Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate,@{n='Owner';e={(Invoke-CimMethod -InputObject $_ -MethodName GetOwner).User}} | Export-Csv \\soc-evid01\evidence$\IR-2026-0414-01\process_tree\wst-ws-031_processes.csv -NoTypeInformation`
  `tasklist /v /fo csv > \\soc-evid01\evidence$\IR-2026-0414-01\process_tree\wst-ws-031_tasklist.csv`
- where: /evidence/IR-2026-0414-01/process_tree/wst-ws-031_processes.csv, wst-ws-031_tasklist.csv
- hash cmd: `certutil -hashfile <file> SHA256`; on store `sha256sum process_tree/* | tee -a hashes.txt`
- ordering: before any process kill; process termination and isolation change the process table and PID-to-connection mapping

## 3. Active network connections at time of capture

- what: TCP/UDP sockets with owning PID (expected: PID 8104 → 185.220.101.47:443), DNS client cache, ARP table, routing table
- how:
  `netstat -anob > \\soc-evid01\evidence$\IR-2026-0414-01\network\wst-ws-031_netstat.txt`
  `Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,CreationTime | Export-Csv \\soc-evid01\evidence$\IR-2026-0414-01\network\wst-ws-031_tcp.csv -NoTypeInformation`
  `ipconfig /displaydns > \\soc-evid01\evidence$\IR-2026-0414-01\network\wst-ws-031_dnscache.txt`
  `arp -a > \\soc-evid01\evidence$\IR-2026-0414-01\network\wst-ws-031_arp.txt`
  `route print > \\soc-evid01\evidence$\IR-2026-0414-01\network\wst-ws-031_route.txt`
- where: /evidence/IR-2026-0414-01/network/
- hash cmd: `certutil -hashfile <file> SHA256`; on store `sha256sum network/* | tee -a hashes.txt`
- ordering: before VLAN move and firewall block; isolation tears down the ESTABLISHED C2 socket and flushes the DNS/ARP state that ties the process to the C2 infrastructure

## 4. On-disk payloads and persistence (supplementary)

- what: C:\Users\dmarsh\Downloads\update.zip (EDR sha256 3c2a1b9e…2b1a), C:\Users\dmarsh\AppData\Local\Temp\update.xml (a4f1e9b4…c2d3), C:\Users\dmarsh\AppData\Local\Temp\update.exe (5a4b3c2d…5a4b), scheduled task {7B4F2D81-19E2-4A8C-9E67-A1F0DE2C7B3A}, Run value HKCU\…\Run\WindowsUpdateSvc
- how:
  `Copy-Item C:\Users\dmarsh\Downloads\update.zip,C:\Users\dmarsh\AppData\Local\Temp\update.xml,C:\Users\dmarsh\AppData\Local\Temp\update.exe \\soc-evid01\evidence$\IR-2026-0414-01\malware\`
  `schtasks /query /tn "{7B4F2D81-19E2-4A8C-9E67-A1F0DE2C7B3A}" /xml > \\soc-evid01\evidence$\IR-2026-0414-01\malware\schtask_7B4F2D81.xml`
  `reg export HKU\<dmarsh_SID>\Software\Microsoft\Windows\CurrentVersion\Run \\soc-evid01\evidence$\IR-2026-0414-01\malware\hkcu_run.reg`
- where: /evidence/IR-2026-0414-01/malware/
- hash cmd: `certutil -hashfile <file> SHA256` and compare with the EDR-recorded hashes; on store `sha256sum malware/* | tee -a hashes.txt`
- ordering: isolation does not destroy these files, but the attacker can delete them as long as C2 is live, and eradication will; capture after volatile state, before containment

## 5. Endpoint telemetry export, WST-WS-031, 24 h before alert

- what: WazuhEDR events for WST-WS-031 from 2026-04-13T02:47:00Z to 2026-04-14T02:47:30Z (process, file, registry, scheduled-task, network, memory-region events)
- how: SIEM export (Splunk REST):
  `curl -sk -u svc_ir_export https://splunk.meddefense.local:8089/services/search/jobs/export --data-urlencode search='search index=edr_wazuh host="WST-WS-031"' -d earliest_time=2026-04-13T02:47:00Z -d latest=2026-04-14T02:47:30Z -d output_mode=json > /evidence/IR-2026-0414-01/endpoint_telemetry/edr_wst_ws_031_24h.jsonl`
  (prepared export already available as edr_wst_ws_031_24h.jsonl)
- where: /evidence/IR-2026-0414-01/endpoint_telemetry/edr_wst_ws_031_24h.jsonl
- hash cmd: `sha256sum endpoint_telemetry/edr_wst_ws_031_24h.jsonl | tee -a hashes.txt`. Reference value: `f7e404df7556b47bb97f08d10746cad73db374622c4d84035ce23317a8a6c325`
- ordering: endpoint containment can interrupt sensor upload and later host rebuild wipes the local agent buffer; export before both

## 6. SIEM alert record (JSON)

- what: full alert A-20260414-9841 with enrichment and correlated events
- how: `curl -sk -u svc_ir_export "https://splunk.meddefense.local:8089/services/search/jobs/export" --data-urlencode search='search index=notable alert_id="A-20260414-9841"' -d output_mode=json > /evidence/IR-2026-0414-01/siem/alert_A-20260414-9841.json`
- where: /evidence/IR-2026-0414-01/siem/alert_A-20260414-9841.json
- hash cmd: `sha256sum siem/alert_A-20260414-9841.json | tee -a hashes.txt`. Reference value: `535f02ef55927decc138e5542ad825dea3754a7370c6ee05f58f7d8480eaf6db`
- ordering: alert status/enrichment changes as analysts work it; freeze the as-fired record before containment updates the notable

## 7. Proxy and DNS logs, dmarsh / 10.42.118.31, 24 h before alert

- what: proxy log (phishing click 2026-04-13T18:14:02Z, credential POST 18:14:41Z, update.zip download 18:14:43Z, CONNECTs to 185.220.101.47) and internal DNS resolver queries from 10.42.118.31
- how:
  proxy: copy the soc-evidence-collector export (exported 2026-04-14T02:52:18Z) → `cp proxy_24h_dmarsh.log /evidence/IR-2026-0414-01/proxy_dns/`
  DNS: `curl -sk -u svc_ir_export https://splunk.meddefense.local:8089/services/search/jobs/export --data-urlencode search='search index=dns src_ip="10.42.118.31"' -d earliest_time=2026-04-13T02:47:00Z -d latest=2026-04-14T02:47:00Z -d output_mode=json > /evidence/IR-2026-0414-01/proxy_dns/dns_24h_wst-ws-031.json`
- where: /evidence/IR-2026-0414-01/proxy_dns/
- hash cmd: `sha256sum proxy_dns/* | tee -a hashes.txt`. Reference value (proxy): `7738cd69ce3c726273fa6ca1a3eac54bef3d22b63859af071a203cb90b80f303`
- ordering: server-side, not destroyed by host isolation; captured before the proxy/DNS block of the phishing domain (block events would mix into the window) and before log retention rollover

## 8. Authentication events, dmarsh, 24 h before alert (Active Directory + Azure AD)

- what: AD Kerberos/logon events from ms-dc01 and ms-dc02 (4624, 4634, 4648, 4768, 4769, 4771, 4776, 4800) and Azure AD sign-ins. Key record: Azure AD sign-in from 45.63.9.88 (RU) at 2026-04-13T18:14:41Z, MFA satisfied, impossibleTravel risk not promoted
- how:
  normalized export: copy soc-evidence-collector export authlog-dmarsh-20260414024730 → `cp auth_24h_dmarsh.json /evidence/IR-2026-0414-01/authentication/`
  raw DC logs: `wevtutil epl Security \\soc-evid01\evidence$\IR-2026-0414-01\authentication\ms-dc01_security.evtx /r:ms-dc01 /q:"*[System[TimeCreated[@SystemTime>='2026-04-13T02:47:00.000Z']]]"` (repeat with /r:ms-dc02)
  Azure AD: `Get-MgAuditLogSignIn -All -Filter "userPrincipalName eq 'dmarsh@meddefense.local' and createdDateTime ge 2026-04-13T02:47:00Z" | ConvertTo-Json -Depth 10 | Out-File \\soc-evid01\evidence$\IR-2026-0414-01\authentication\aad_signins_dmarsh.json`
- where: /evidence/IR-2026-0414-01/authentication/
- hash cmd: `sha256sum authentication/* | tee -a hashes.txt`. Reference value (normalized export): `398aae6da40893af8c41da489b875c96e1cb74d9d3c5a6485645811031a92ced`
- ordering: PB-CRED-001 requires auth logs before the AD password reset and Azure AD logs before session revocation; reset/revocation generate new events and the account-containment step follows isolation directly

## 9. Verification

- All artifacts re-hashed from the evidence store:
  `cd /evidence/IR-2026-0414-01 && grep -v '^#' hashes.txt | sha256sum -c - | tee correlation/verify_$(date -u +%Y%m%dT%H%M%SZ).txt`
- Hash values compared to original capture values: every line must read `OK`; source-side `certutil` values (steps 1–4) compared with store-side values; malware hashes compared with EDR-recorded hashes
- Manifest itself hashed and locked: `sha256sum hashes.txt > hashes.txt.sha256 && chmod 0440 hashes.txt hashes.txt.sha256`
- Mismatches logged to the incident timeline as OBSERVATION entries (certainty=confirmed) and the artifact re-acquired if the source still exists; containment is blocked until verification passes or the IR Commander accepts the gap in a DECISION entry
- Successful verification logged as an ACTION entry; this is the gate that releases containment (containment_decision.md)
