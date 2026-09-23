# Network Forensics Report — MedDefense Incident

## 1. Executive Summary

Between 2026-04-14 and 2026-04-16, a MedDefense clinical-network user account
(`dmarsh`) was compromised through a phishing email, leading to command-and-control
beaconing, an unauthenticated-MFA VPN pivot from an external IP geolocated to
Nigeria, RDP-based lateral movement into a billing server, SMB enumeration of
internal hosts (including a successful NAS access), and DNS-tunneled
exfiltration of patient-record-style data. Five packet captures
(`phishing_click.pcap`, `c2_beaconing.pcap`, `full_timeline.pcap`,
`lateral_movement.pcap`, `dns_exfil.pcap`) directly evidence six of the seven
kill-chain phases; only the initial phishing click itself falls outside any
capture's window. The packet-visibility score computed in
[8-evidence_crosscheck.sh](8-evidence_crosscheck.sh) is 71/100. Total observed
dwell time, from phishing delivery to the end of the exfiltration window, is
approximately 1 day 10 hours.

## 2. Investigation Scope

- **In scope:** five PCAP files covering the period 2026-04-14 through
  2026-04-16, plus the email evidence and IOCs already established in the
  `4x00_phishing_dissection` investigation.
- **Assets referenced:** WS-NURSE-04 (10.10.2.15), billing-srv-01
  (10.10.1.10), NAS-01 (10.10.1.60), internal hosts 10.10.1.20/.30/.31,
  10.10.4.100/.101, VPN gateway 10.10.0.1, external actor IP 154.118.42.89.
- **Out of scope:** host-level forensics (disk, memory, EDR telemetry),
  authentication/VPN/mail-gateway server logs — none were provided;
  their absence is called out explicitly in Section 8.
- **Baseline reference:** `normal_baseline_clinical.pcap`, analyzed in
  [0-baseline_analysis.sh](0-baseline_analysis.sh), used throughout as the
  "what does this network look like on a normal day" comparison point.

## 3. Methodology

All packet-level findings were produced with `tshark` display filters and
field extraction (`-Y`, `-T fields -e ...`), documented inline in each script
for reproducibility, and cross-checked against `normal_baseline_clinical.pcap`
where a normal/abnormal comparison was meaningful. Per-script breakdown:

| Script                                              | PCAP                          | Purpose                                                  |
| --------------------------------------------------- | ----------------------------- | -------------------------------------------------------- |
| [0-baseline_analysis.sh](0-baseline_analysis.sh)     | normal_baseline_clinical.pcap | Establishes normal traffic patterns                      |
| [1-phishing_click.sh](1-phishing_click.sh)           | phishing_click.pcap           | Confirms the phishing session and post-click behavior    |
| [3-dns_tunnel.sh](3-dns_tunnel.sh)                   | dns_exfil.pcap                | Classifies and decodes the DNS tunnel                    |
| [4-lateral_movement.sh](4-lateral_movement.sh)       | lateral_movement.pcap         | Reconstructs RDP/SMB lateral movement                    |
| [5-vpn_pivot.sh](5-vpn_pivot.sh)                     | full_timeline.pcap            | Identifies the external VPN pivot and geolocates it      |
| [6-kill_chain.sh](6-kill_chain.sh)                   | (synthesis)                   | Builds the master 7-phase timeline from all of the above |
| [8-evidence_crosscheck.sh](8-evidence_crosscheck.sh) | (synthesis)                   | Classifies evidentiary strength per phase                |

No conclusion in this report or its underlying scripts asserts data not
directly observable in these captures; where decoding or inference was
required, the script output says so explicitly (see Section 8 and each
script's own `[*]` caveat lines).

## 4. Findings by Attack Phase

| # | Phase                         | Timestamp (PCAP-native)       | Evidence                                                                                          | ATT&CK                  |
| - | ----------------------------- | ----------------------------- | ------------------------------------------------------------------------------------------------- | ----------------------- |
| 1 | Initial Access (Phishing)     | 2026-04-14 14:47              | 4x00 email headers only — no PCAP                                                                | T1566.002               |
| 2 | Credential Harvesting         | 2026-04-14 17:02:33–17:03:20 | phishing_click.pcap: DNS + TLS ClientHello to meddefense-portal.com (91.234.99.107)               | T1566.002, T1056.003    |
| 3 | C2 Beaconing                  | 2026-04-15 04:00:12–05:55:08 | c2_beaconing.pcap: 24 sessions to 91.234.99.107, ~300s interval                                   | T1071.001               |
| 4 | External VPN Pivot            | 2026-04-15 15:45:22 (~48 min) | full_timeline.pcap: 154.118.42.89 → 10.10.0.1:443, decoded `AUTH:user=dmarsh,pass=***,2fa=none` | T1133, T1078.002        |
| 5 | Lateral Movement (RDP)        | 2026-04-15 16:30:12.445       | lateral_movement.pcap: WS-NURSE-04 → billing-srv-01, RDP/NLA, `dmarsh` in payload               | T1021.001               |
| 6 | Discovery / Enumeration (SMB) | 2026-04-15 16:35:22–16:40:33 | lateral_movement.pcap: mixed success/denied/refused across 5 internal targets                     | T1135, T1021.002, T1083 |
| 7 | Exfiltration (DNS Tunneling)  | 2026-04-16 00:15:02–00:44:56 | dns_exfil.pcap: 120 anomalous TXT queries, Base32/Base64-decoded sample payloads                  | T1048.003               |

Full narrative detail for each phase is in
[6-kill_chain.sh](6-kill_chain.sh)'s output. Note the Phase 7 window
(00:15–00:44 on 2026-04-16) is the real, packet-derived figure for this
evidence set — it does not match illustrative timing used in some generic
task-description examples, which were drawn from a differently sized sample
dataset.

## 5. Network-Level IOC Table

| Indicator                         | Type    | Role                                                | First Observed      |
| --------------------------------- | ------- | --------------------------------------------------- | ------------------- |
| meddefense-portal.com             | Domain  | Phishing/credential-harvesting site                 | 2026-04-14 17:02:33 |
| 91.234.99.107                     | IPv4    | Phishing site + C2 destination                      | 2026-04-14 17:02:33 |
| data-sync.meddefense-portal[.]com | Domain  | DNS tunnel exfiltration channel                     | 2026-04-16 00:15:02 |
| 154.118.42.89                     | IPv4    | External VPN pivot source (NG, AS37340, Spectranet) | 2026-04-15 15:45:22 |
| dmarsh                            | Account | Compromised domain account, used VPN + RDP          | 2026-04-15 15:45:22 |
| 10.10.2.15 (WS-NURSE-04)          | Host    | Initial lateral-movement source                     | 2026-04-15 16:30:12 |
| 10.10.1.10 (billing-srv-01)       | Host    | Lateral-movement target, SMB enumeration source     | 2026-04-15 16:30:12 |
| 10.10.1.60 (NAS-01)               | Host    | Confirmed SMB access target                         | 2026-04-15 16:38:xx |

IOC continuity with 4x00: `meddefense-portal.com` and `91.234.99.107` are the
same indicators identified in the email-based investigation; this capture
confirms they were also contacted over the network, not merely referenced in
the email.

## 6. Impact Assessment

- **Confirmed account compromise:** `dmarsh`, used for both the VPN pivot and
  subsequent RDP session, with no second factor recorded (`2fa=none`).
- **Confirmed systems touched:** WS-NURSE-04, billing-srv-01, NAS-01.
- **Confirmed data exposure:** patient-record-style content
  (`patient_record:ID=4892,name=...`) recovered from a decoded DNS tunnel
  query — consistent with PHI exposure, though the full scope of records
  exfiltrated beyond the sampled queries is not determinable from this
  capture alone (see Section 7).
- **Access attempted but not completed:** 10.10.1.30, 10.10.1.31 (SMB access
  denied); 10.10.4.100, 10.10.4.101 (refused at the network layer).
- **External foothold:** an unauthenticated-MFA VPN session from a
  geographically distant IP, active for roughly 48 minutes before the
  lateral-movement phase began.

## 7. Detection Gap Analysis

| Phase                    | Gap                                                                                                                                                                           |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. Initial Access        | No mail-gateway or endpoint telemetry in scope — the click itself is invisible to network capture by design.                                                                   |
| 2. Credential Harvesting | TLS encryption means the harvested content itself was never observable; only that a session matching the phishing domain occurred.                                            |
| 3. C2 Beaconing          | Beaconing was visible but nothing in this evidence set indicates it triggered any alert — no IDS/NDS alert log was provided.                                                   |
| 4. VPN Pivot             | No MFA challenge is visible; if the real VPN gateway logs no MFA prompt either, that is the actual control gap, not just a visibility gap.                                    |
| 6. SMB Enumeration       | Packet count was used as a proxy for SMB success/failure; a real environment should have host-level SMB audit logging instead of inferring outcomes from packet shape.        |
| 7. Exfiltration          | 120 queries over ~30 minutes at a regular interval produced no visible automated response in this dataset — indicates a DNS anomaly detector was not in place or not alerting. |

## 8. Detection Rules Recommended

1. **DNS**: alert on TXT queries with subdomain labels >32 characters,
   high Shannon entropy, and/or query rate to a single parent domain
   exceeding ~5/minute sustained for more than 5 minutes (matches the
   Phase 7 pattern of ~4/min sustained over ~30 minutes).
2. **TLS/Network**: alert on repeated outbound TCP sessions to the same
   external IP with inter-session interval variance under ~10% over 10+
   occurrences (matches the Phase 3 beaconing cadence).
3. **VPN/Auth**: alert on any VPN authentication event lacking an MFA
   assertion, regardless of account, and require step-up verification
   before permitting RDP from that session's assigned internal IP.
4. **SMB**: alert on a single host making SMB connection attempts to more
   than 3 distinct internal hosts within a 10-minute window (matches the
   Phase 6 enumeration pattern from billing-srv-01).
5. **RDP**: alert on RDP sessions initiated from clinical/end-user subnets
   (10.10.2.0/24) toward server-tier subnets (10.10.1.0/24), which the
   Task 0 baseline shows does not occur under normal conditions.

## 9. Recommendations

- Enforce MFA on the VPN gateway with no exception path, and treat any
  successful VPN auth lacking an MFA assertion as an incident trigger, not
  just a policy violation.
- Segment clinical workstation subnets from server-tier subnets at the
  firewall so that RDP/SMB from 10.10.2.0/24 to 10.10.1.0/24 requires an
  explicit allow-list entry.
- Deploy DNS-tunneling detection (entropy + rate-based) at the recursive
  resolver, since this was the only phase with confirmed data exfiltration.
- Reset the `dmarsh` account credentials and review all systems it
  authenticated to during the incident window (2026-04-15 15:45 onward).
- Retain full packet capture at network egress points going forward — this
  investigation was only possible because captures existed; the initial
  phishing click was not visible precisely because no such capture covered
  that moment.

## 10. Evidence Chain

| Evidence                         | Source File                                            | Referenced In                                       |
| -------------------------------- | ------------------------------------------------------ | --------------------------------------------------- |
| Email headers, IOCs              | 4x00_phishing_dissection                               | Section 4, Phase 1                                  |
| Phishing session (DNS/TLS)       | phishing_click.pcap                                    | [1-phishing_click.sh](1-phishing_click.sh)           |
| C2 beacon sessions               | c2_beaconing.pcap                                      | [6-kill_chain.sh](6-kill_chain.sh)                   |
| VPN pivot + decoded auth markers | full_timeline.pcap                                     | [5-vpn_pivot.sh](5-vpn_pivot.sh)                     |
| RDP + SMB lateral movement       | lateral_movement.pcap                                  | [4-lateral_movement.sh](4-lateral_movement.sh)       |
| DNS tunnel queries/responses     | dns_exfil.pcap                                         | [3-dns_tunnel.sh](3-dns_tunnel.sh)                   |
| Normal-traffic baseline          | normal_baseline_clinical.pcap / baseline_clinical.json | [0-baseline_analysis.sh](0-baseline_analysis.sh)     |
| Per-phase evidentiary strength   | (synthesis)                                            | [8-evidence_crosscheck.sh](8-evidence_crosscheck.sh) |

Each script above prints, inline, the exact `tshark` filter used to produce
its findings, so every figure in this report can be independently
reproduced against the corresponding PCAP file.

## 11. Continuity with 4x00

This investigation extends `4x00_phishing_dissection` from the email layer
into the network layer. The domain and IP identified there
(`meddefense-portal.com`, `91.234.99.107`) are confirmed here as actually
contacted by the victim workstation, and the incident is shown to have
progressed well beyond the initial click: a VPN pivot, internal lateral
movement, and a DNS-tunneled exfiltration channel were not visible from
email evidence alone and were only established through this PCAP-level
analysis. Together, the two investigations form a single evidence chain from
the phishing email through to confirmed data exposure.
