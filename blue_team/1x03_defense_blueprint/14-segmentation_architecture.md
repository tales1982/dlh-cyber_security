# 14. The Segmentation Architecture — MedDefense Health Systems

**Analyst:** Security Analyst
**Date:** Current

**Design principle governing this entire architecture:** default-deny between zones. Any zone-to-zone path not explicitly listed as ALLOW in Part 2 is denied by default — the 10 rules below are the complete allow-list plus the highest-value explicit deny statements worth calling out by name; everything else is closed by the baseline policy, not left open by omission (unlike the current flat network, which is open by omission everywhere).

## Part 1: Zone Definition

### Zone 1 — Server Zone (VLAN 10)

- **IP Range:** `10.20.10.0/24`
- **Systems:** `ehr-srv-01`, `ehr-db-01`, `billing-srv-01`, `ad-dc-01`/`02`, `file-srv-01`, `print-srv-01`, `backup-srv-01`, `NAS-01`, `web-srv-01`, `pacs-srv-01`
- **Allowed outbound:** DNS/NTP to Management Zone; `web-srv-01` specifically permitted outbound to the Internet on 443 (Patient Portal); backup traffic to `NAS-01` within-zone
- **Allowed inbound:** From Clinical Workstation Zone on 443/tcp only (EHR, Patient Portal, print services); from Medical Device Zone to `pacs-srv-01` specifically on DICOM ports only; from Management Zone on administrative ports; from the Internet to `web-srv-01` specifically on 443 only — **no other host in this zone is directly reachable from the Internet**, closing the exposure that let `billing-srv-01` be compromised twice.

### Zone 2 — Clinical Workstation Zone (VLAN 20)

- **IP Range:** `10.20.20.0/24`
- **Systems:** Nurse station workstations, physician workstations, reception, admin workstations, general radiology workstations (excluding the MRI control workstation, see Zone 3)
- **Allowed outbound:** HTTPS (443) to the Server Zone (EHR, Patient Portal, print services only); DNS/NTP to Management Zone
- **Allowed inbound:** Nothing unsolicited from any other zone, except RDP from Management Zone for IT support, gated by MFA (Task 11)

### Zone 3 — Medical Device Zone (VLAN 30)

- **IP Range:** `10.20.30.0/24`
- **Systems:** Philips IntelliVue monitor fleet, BD Alaris pump fleet, `WS-RAD-01` (MRI control workstation), nurse call system
- **Allowed outbound:** DICOM/HL7 traffic to `pacs-srv-01` in the Server Zone only, on its specific ports
- **Allowed inbound:** From designated radiology/nursing workstations in the Clinical Workstation Zone, narrowly scoped to monitor-dashboard viewing ports only; from Management Zone for IT/biomedical engineering administrative and patching access

### Zone 4 — Management Zone (VLAN 40)

- **IP Range:** `10.20.40.0/24`
- **Systems:** IT administrator workstations, the SIEM (Wazuh) server, the FortiGate management interface, badge reader/physical security infrastructure, and the sole permitted path to `NAS-01`'s DSM management interface
- **Allowed outbound:** To all other zones, on administrative ports only (SSH 22, RDP 3389, HTTPS management interfaces, SIEM log-collection ports) — this is the one zone with broad reach, by design, since it is the trusted administrative plane, and every session into it is MFA-gated at the identity layer (Task 11).
- **Allowed inbound:** Only from registered administrator accounts/devices, via VPN with MFA enforced

### Zone 5 — Guest/IoT Zone (VLAN 50)

- **IP Range:** `10.20.50.0/24`
- **Systems:** Visitor WiFi devices, any non-clinical IoT device with no documented business need to reach internal systems
- **Allowed outbound:** Internet only, ports 80/443
- **Allowed inbound:** Nothing from any internal zone — this resolves the ambiguity the 1x00 Asset Registry itself flagged: a guest network that was "logically labeled" but never confirmed as actually segmented.

*Remote sites (Westside Clinic, Corporate HQ) connect via the FortiGate's site-to-site VPN into the **same five-zone model**, not into a flat pass-through — a Westside workstation lands in a Westside-local Clinical Workstation Zone equivalent, not directly into Central's Server Zone.*

## Part 2: Firewall Rules

```
1.  Clinical-WS-Zone      -> Server-Zone (443/tcp)                : ALLOW
    Permits EHR/Patient Portal access, the only connectivity
    ordinary clinical staff need to the server zone.

2.  Clinical-WS-Zone      -> Medical-Device-Zone (any/any)         : DENY
    Prevents a compromised workstation from directly reaching
    monitors or pumps -- breaks Kill Chain #4's lateral-movement step.

3.  Medical-Device-Zone   -> Server-Zone:pacs-srv-01 (4242,11112/tcp): ALLOW
    Permits DICOM traffic to PACS specifically, and nothing else in
    the Server Zone.

4.  Medical-Device-Zone   -> any zone except PACS host + Mgmt (any) : DENY
    Prevents a compromised medical device from reaching billing, EHR,
    or AD directly, even though those hosts share the same physical
    network today.

5.  Guest-IoT-Zone        -> any internal zone (any/any)           : DENY
    Enforces the guest network as genuinely isolated, not just an
    addressing convention -- directly resolves the ambiguity flagged
    in the 1x00 Asset Registry about whether guest traffic was ever
    truly segmented.

6.  Management-Zone       -> all zones (22, 3389, mgmt-ports/tcp)  : ALLOW
    The one intentionally broad-reach zone, restricted to
    administrative ports only and gated by MFA at the identity layer.

7.  Server-Zone:ehr-db-01 -> any host except ehr-srv-01 (5432/tcp) : DENY
    Directly remediates 1x02 Finding 003 -- the patient database no
    longer accepts connections from the whole /16, only from the one
    application server that needs it.

8.  any zone except Mgmt  -> Server-Zone:NAS-01 (5000,5001/tcp)    : DENY
    Directly remediates 1x02 Finding 015 -- the backup repository's
    management interface is reachable only from the trusted admin
    plane, not the entire network.

9.  Internet              -> Server-Zone:web-srv-01 (443/tcp)      : ALLOW
    The single legitimate direct-Internet path into the Server Zone --
    the Patient Portal, and nothing else.

10. Internet              -> Server-Zone: all other hosts (any/any): DENY
    Closes the Internet-facing exposure on billing-srv-01 that
    enabled both prior real compromises (ransomware, then a
    cryptominer) -- there is no legitimate reason for this host to be
    reachable from outside MedDefense at all.
```

## Part 3: Kill Chain Impact

**Walking through Kill Chain #1 ("Phishing to Domain-Wide Ransomware," 1x01 Task 10) against this architecture:**

- **Step 1 (Initial Access — spear phishing to Sarah Park):** Not disrupted. Segmentation is a network control; it does nothing against a phishing email landing in an inbox. This step succeeds exactly as before — it is a Protect/Awareness gap (CIS Control 14), not a network architecture gap, and this design does not claim otherwise.
- **Step 2 (Establish Foothold — scheduled-task C2 beacon):** Not disrupted by segmentation alone. Egress filtering/DNS-based C2 blocking would address this, but that is a separate control from pure zone segmentation and is not claimed here.
- **Step 3 (Discovery — network mapping the entire flat range from a single workstation):** **Disrupted.** Sarah's workstation now sits in the Clinical Workstation Zone, which under Rule 1 can reach only port 443 on the Server Zone — nothing else. Network discovery commands run from the compromised workstation would find almost nothing reachable; the entire premise of Kill Chain #1 Step 3 ("map the entire flat 10.10.0.0/16 range from a single HQ workstation") no longer holds.
- **Step 4 (Credential Access/Lateral Movement — Mimikatz + pass-the-hash to `ad-dc-01`):** **Disrupted as a direct consequence of Step 3 failing** — the attacker never gains network line-of-sight to `ad-dc-01` to attempt this in the first place. Independently, the MFA control (Task 11, RISK-002a) would also block this step even if network reachability existed, providing genuine defense in depth rather than a single point of failure.
- **Step 5 (Exfiltration — `ehr-db-01` and `file-srv-01` data pulled via Rclone):** **Disrupted.** With Domain Admin never obtained (Steps 3-4 blocked) and Rule 7 independently restricting `ehr-db-01` to `ehr-srv-01` only, there is no path to this data even under a partial-bypass scenario.
- **Step 6 (Impact — `NAS-01` backup deletion + domain-wide GPO ransomware push):** **Disrupted.** Rule 8 means `NAS-01`'s management interface is unreachable from anywhere the attacker could plausibly be standing, and domain-wide GPO push requires the Domain Admin access Step 4 already failed to obtain.

**This kill chain breaks decisively at Step 3**, with two additional independent backstops (MFA at Step 4, NAS-01 restriction at Step 6) if Step 3 were somehow bypassed by a future, more sophisticated technique. Steps 1-2 remain fully viable — this design is honest that segmentation is not a substitute for email security and awareness training.

**Estimated disruption across the top 5 kill chains:**

| Kill Chain | Disrupted by this design? | Where |
|---|---|---|
| KC1 — Phishing to Domain-Wide Ransomware | Yes | Step 3 (Discovery) |
| KC2 — VPN Credential Compromise to Domain Takeover | Yes | Step 3 (network scan from VPN session no longer reaches `ad-dc-01` directly) |
| KC3 — Insider Data Exfiltration via Legitimate Access | **No** | Uses access the insider is already authorized to have — no network boundary applies, by definition |
| KC4 — Unpatched Web Server to Medical Device Exposure | Yes | Step 3 (Server Zone cannot reach Medical Device Zone by default) |
| KC5 — Vendor Compromise to Direct Patient Data Access | Yes | Step 3 (Rule 7 blocks `ehr-db-01` reachability beyond `ehr-srv-01`) |

**4 of 5 kill chains (80%) are disrupted by this segmentation design.** The one exception, Kill Chain #3, is not a design gap — it is a structurally different problem. An insider using their own already-authorized access has no network boundary to cross in the first place, which is exactly why RISK-004's controls (Task 6, Task 11) are DLP/export monitoring and automated deprovisioning, not segmentation. This is the expected, correct division of labor between a network architecture control and an access-governance control, not a shortfall in this design.

## Repo

- **GitHub repository:** `dlh-cyber_security`
- **Directory:** `blue_team/1x03_defense_blueprint`
- **File:** `14-segmentation_architecture.md`
