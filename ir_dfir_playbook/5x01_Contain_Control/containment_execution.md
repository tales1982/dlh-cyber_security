# Containment Execution: IR-2026-0414-01

Strategy executed: A (quarantine VLAN) + D (account containment), see containment_decision.md
Approved by: James Chen, IR Commander, 2026-04-14T03:12:40Z
Executed by: Tales Lima, on-call SOC, from IR jumpbox soc-jump01 (10.42.200.10)
Target: WST-WS-031 (10.42.118.31), MEDDEFENSE\dmarsh
Precondition met: evidence preservation verified at 2026-04-14T03:20:40Z (evidence_preservation.md step 9)

Format: timestamp | actor | command or console action | expected result | observed result | deviation notes

- 2026-04-14T03:24:10Z | Tales Lima | NAC console: switchport of WST-WS-031 (sw-west-lab-02 Gi1/0/31) reassigned VLAN 118 -> VLAN 999 (quarantine ACL: permit soc-jump01 + EDR manager only) | host reachable only from jumpbox and EDR manager | port up on VLAN 999 at 03:24:12Z; DHCP lease 10.99.0.31 issued | no deviation

- 2026-04-14T03:24:55Z | Tales Lima | perimeter firewall: `deny ip any host 185.220.101.47` (outbound, all sources, logged), rule IR-2026-0414-01-01 | no new flow to 185.220.101.47 from any MedDefense host | rule committed 03:24:58Z; deny counter 0 (host already cut by VLAN move) | no deviation

- 2026-04-14T03:25:40Z | Tales Lima | proxy + DNS: block and sinkhole ms0365-support[.]login-verification[.]click (all subdomains) | requests to the phishing domain denied for all users | proxy category override active 03:25:44Z; DNS returns sinkhole 10.42.250.53 | no deviation

- 2026-04-14T03:26:30Z | Tales Lima | WazuhEDR console: device containment flag SET on WST-WS-031 | only analyst tooling (live response, agent channel) permitted | 1st attempt failed: agent reconnecting after VLAN change, policy not applied; 2nd attempt 03:27:15Z succeeded, console shows "Contained" | deviation: 45 s delay; VLAN 999 ACL already blocked egress during the gap, no exposure

- 2026-04-14T03:28:05Z | Tales Lima | netflow query: src 10.42.118.31/10.99.0.31 dst 185.220.101.47, 02:40Z–03:28Z | flows until isolation, zero after 03:24:10Z | last flow 10.42.118.31:54918 -> 185.220.101.47:443 ended 03:24:08Z (FIN not seen, cut by VLAN move); 0 packets 03:24:10Z–03:28:00Z; no flow from any other internal host to 185.220.101.47 in the window | no deviation (C2 severed confirmed)

- 2026-04-14T03:29:00Z | Tales Lima | verify isolation: ping + TCP 445/3389 to 10.99.0.31 from soc-jump01 and from user VLAN host WST-WS-030 | jumpbox succeeds, user VLAN fails | jumpbox: ping 4/4, WinRM 5985 open; WST-WS-030: ping 0/4 timeout, 445 filtered | no deviation

- 2026-04-14T03:30:20Z | Tales Lima | `Set-ADAccountPassword -Identity dmarsh -Reset` + `Set-ADUser dmarsh -ChangePasswordAtLogon $true` | stolen password no longer valid on-prem | ms-dc01 event 4724 at 03:30:21Z, replicated to ms-dc02 03:30:36Z | deviation: Kerberos TGT issued 2026-04-14T02:44:02Z (10 h lifetime) and any derived TGS are NOT invalidated by a password reset; risk logged, dmarsh TGS requests under watch

- 2026-04-14T03:31:00Z | Tales Lima | `Revoke-MgUserSignInSession -UserId dmarsh@meddefense.local` | all Azure AD refresh tokens and sessions revoked | cmdlet returned True; sign-in log shows no dmarsh session after 03:31:00Z | no deviation

- 2026-04-14T03:31:40Z | Tales Lima | phone call to West Campus lab supervisor | Daniel Marsh working from spare workstation, LIS result entry continuing | supervisor confirmed spare workstation in use; dmarsh needs helpdesk for new password + MFA re-enrolment | no deviation
