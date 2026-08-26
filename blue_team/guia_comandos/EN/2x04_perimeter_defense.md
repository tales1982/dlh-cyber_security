# 2x04 – Perimeter Defense

## Task - 0-network_baseline.sh

What it does: Collects a complete network baseline of the host — interfaces, routes, ARP table, listening sockets, established connections and DNS configuration — straight from the system's own tools, with no changes made. Serves as the objective reference point to justify every firewall rule written afterward.
How to use it: `sudo ./0-network_baseline.sh [output.json]`
Commands:

- `date -u +%Y-%m-%dT%H:%M:%SZ` — generates a UTC timestamp to mark when the baseline was collected.
- `hostname` — identifies the host being mapped in the report.
- `ip -j addr show` — lists network interfaces, MAC, link state and assigned IP addresses.
- `ip -j route show` — shows the routing table, including the default gateway, to know where traffic exits.
- `ip -j neigh show` — lists the ARP/neighbor table (IP, MAC, state) to identify hosts already known on the local network.
- `ss -tulnpH` — lists all listening TCP/UDP sockets with owning process and PID, the base data for attack-surface mapping.
- `ss -tnpH state established` — lists already established TCP connections with owning process and PID, showing who the host is already talking to.
- `grep -E '^nameserver' /etc/resolv.conf` — extracts the DNS servers configured on the host.
- `systemctl is-active --quiet systemd-resolved` — checks whether systemd-resolved is active before querying its status.
- `resolvectl status --no-pager` — shows per-interface DNS resolution configuration when systemd-resolved is in use.

## Task - 1-attack_surface.sh

What it does: Reads the baseline produced by script 0 and classifies each listening socket with a function (database, web, ssh, etc.) and a criticality level, flagging dangerous exposures — a database/RPC service bound to 0.0.0.0, or an inherently insecure protocol (telnet, ftp, snmp v1/v2c, rlogin, nfs v2/v3). Falls back to a few extra lookup methods before giving up on identifying a process.
How to use it: `sudo ./1-attack_surface.sh [network_baseline.json] [output.json]`
Commands:

- `readlink -f /proc/$pid/exe` — resolves the real path of the binary that opened the socket, to identify the exact executable.
- `pgrep -x "$process"` — looks up a process's PID by exact name, used as a fallback when the baseline didn't record a PID.
- `pidof "$process"` — another way to find a process's PID by name, tried if `pgrep` comes up empty.
- `which "$process"` — locates a command's binary path on `$PATH`, a last resort before scanning fixed directories (`/usr/sbin`, `/usr/bin`, etc.).
- `dpkg -S "$binary_path"` — finds which installed package owns a binary, tying the exposed service back to its origin.
- `grep -oP '[a-zA-Z0-9_.-]+\.service' /proc/$pid/cgroup` — extracts the systemd unit name associated with the process from its cgroup.
- `systemctl show -p Id --value name.service` — queries the Id of a specific systemd unit, to confirm it really exists before attributing it to the process.
- `systemctl list-units --type=service --no-pager` — lists every loaded systemd service unit, used as a last resort to find the right unit by a similar name.

## Task - 2-segmentation_rules.sh

What it does: Generates MedDefense's network segmentation "contract" — the four zones (DMZ, INTERNAL, MGMT, MEDDEV) with their CIDR and default policy, the list of allowed cross-zone flows (port, protocol, justification) and explicit `deny_all` rules for every zone pair with no allowed flow. Touches nothing on the network — it only produces the JSON that exercises 4 and 6 will consume as their source of truth.
How to use it: `./2-segmentation_rules.sh [output.json]`
Commands: no system command — the script is pure jq, it just assembles the zones/flows/denies structure straight into JSON.

## Task - 4-nftables_config.sh

What it does: Reads `segmentation_rules.json` and renders a real `nftables.conf` (an `inet meddefense` table with one CIDR set per zone and `input`/`forward`/`output` chains), validates the syntax before applying, backs up the current ruleset for rollback, and only then applies everything atomically — without locking out the current SSH session.
How to use it: `sudo ./4-nftables_config.sh [--render-only] [segmentation_rules.json]`
Commands:

- `ip -o -4 addr show` — lists the host's IPv4 addresses one line per interface, used to figure out which zone the host belongs to and detect the management (SSH) interface to exempt from the block.
- `nft -c -f file.conf` — does a check-only parse of an nftables rules file without applying anything, to catch syntax errors before touching the real firewall.
- `nft list ruleset` — lists the nftables ruleset currently loaded on the system, used here to generate the rollback backup before applying the new one.
- `nft -f file.conf` — applies an nftables rules file atomically (all or nothing).
- `nft -a list table inet meddefense` — lists the loaded rules of a specific table along with their "handles" (IDs), used to check whether the applied rule count matches the expected total.

## Task - 6-windows_firewall.ps1

What it does: Mirrors the same `segmentation_rules.json` onto Windows Firewall — sets the default policy to block inbound/allow outbound on all 3 profiles (Domain/Private/Public), recreates the `MedDefense-*` rules from scratch (idempotent, removes the old ones first) only for the flows that terminate on the current host's zone, enables logging of blocked connections, and exports the result as JSON to compare later against the Linux side (nftables).
How to use it: `.\6-windows_firewall.ps1` (PowerShell as Administrator)
Commands:

- `Get-Content -Path file -Raw | ConvertFrom-Json` — reads a text file and converts the JSON content into a PowerShell object.
- `Set-NetFirewallProfile -Profile X -DefaultInboundAction Block -DefaultOutboundAction Allow -LogBlocked True -LogFileName path` — sets the default policy (block inbound, allow outbound) and enables logging of blocked connections for a Windows Firewall profile.
- `Get-NetFirewallRule -DisplayName "pattern*"` — lists existing firewall rules whose name matches a pattern, used here to find the old rules before recreating them.
- `Remove-NetFirewallRule` — removes one or more firewall rules received via the pipeline.
- `Get-NetIPAddress -AddressFamily IPv4` — lists the IPv4 addresses configured on the host, used to figure out which segmentation zone the host belongs to.
- `New-NetFirewallRule -DisplayName name -Direction Inbound -Action Allow -Protocol proto -LocalPort port -RemoteAddress source -Profile Any` — creates a firewall rule allowing inbound traffic from a specific address/port/protocol.
- `ConvertTo-Json -Depth N | Set-Content -Path file` — converts a PowerShell object into JSON text and writes the result to a file.

## Task - 8-suricata_setup.sh

What it does: Installs Suricata and jq (if not already present), copies the lab's ruleset into `/var/lib/suricata/rules/`, renders a minimal `suricata.yaml` in replay mode (no live interface, no daemon), and proves the engine works by running a config test and a smoke-test PCAP replay.
How to use it: `sudo ./8-suricata_setup.sh [output.json]`
Commands:

- `apt-get install -y suricata jq` — installs the suricata and jq packages via apt, non-interactively.
- `suricata --build-info` — shows Suricata's build info, including the installed version.
- `find directory -maxdepth 1 -name '*.rules'` — lists the `.rules` files present in a directory (without descending into subfolders), used to build the `rule-files` list in `suricata.yaml`.
- `suricata -T -c ./suricata.yaml -v` — runs Suricata in "test config" mode (`-T`), only validating the configuration file and the rules, without processing any traffic.
- `suricata -c ./suricata.yaml -r pcap -l directory` — runs Suricata in offline replay mode, reading a PCAP file (`-r`) instead of a live interface, and saves the logs/alerts (`eve.json`) to the given directory (`-l`).

## Task - 9-suricata_analysis.sh

What it does: Replays a PCAP with mixed traffic through Suricata, filters `eve.json` down to just the "alert" event type, extracts the relevant fields from each alert, and builds an aggregated report — total alerts, unique signatures, severity distribution, category distribution (reconnaissance, exploit, lateral_movement, exfiltration, malware_c2, policy_violation, other) and top source/destination IPs.
How to use it: `sudo ./9-suricata_analysis.sh [pcap]`
Commands: no new command — reuses `suricata -c ... -r ... -l ...` (already seen in exercise 8) to run the replay; the rest is pure jq over `eve.json`.

## Task - 10-rule_validation.sh

What it does: Proves that each custom rule in `meddefense.rules` actually fires against the labeled PCAP built specifically for it — runs Suricata with the rules injected for each PCAP, counts how many alerts matched the expected sid in `eve.json`, and fails (non-zero exit) if any rule doesn't fire.
How to use it: `sudo ./10-rule_validation.sh`
Commands: no new command — reuses `suricata -c ... -r ... -l ...` and `readlink -f` (already seen earlier) for each of the 6 labeled PCAPs.

## Task - 11-pcap_investigation.sh

What it does: Investigates a PCAP by hand — no rule, no signature — extracting TCP/UDP conversation statistics, DNS queries, HTTP requests, TLS SNI, file-transfer indicators and the protocol distribution, all consolidated into a single JSON report.
How to use it: `sudo ./11-pcap_investigation.sh [pcap]`
Commands:

- `capinfos -c -u pcap` — shows general statistics for a capture file (packet count, duration), used here to get the duration and total packet count.
- `tshark -q -z conv,tcp -r pcap` — TCP conversation statistics (source/destination pairs, packets, bytes) for a capture, in "quiet" mode (just the summary report, no packet-by-packet listing).
- `tshark -q -z conv,udp -r pcap` — the same conversation statistics, for UDP instead.
- `tshark -Y 'dns.flags.response==0' -T fields -e frame.time_epoch -e ip.src -e dns.qry.name -e dns.qry.type -r pcap` — extracts only the DNS queries (not the responses) with timestamp, source, queried name and record type.
- `tshark -Y http.request -T fields -e frame.time_epoch -e ip.src -e ip.dst -e http.host -e http.request.method -e http.request.uri -r pcap` — extracts HTTP requests with source, destination, host, method and URI.
- `tshark -Y 'tls.handshake.type==1' -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tls.handshake.extensions_server_name -r pcap` — extracts the SNI (requested server name) from every TLS ClientHello handshake (type 1).
- `tshark -Y 'http.content_type or smb2.filename' -T fields -e frame.time_epoch -e ip.src -e ip.dst -e http.content_type -e smb2.filename -r pcap` — extracts file-transfer indicators via HTTP (content-type) or SMB2 (filename).
- `tshark -q -z io,phs -r pcap` — shows the protocol hierarchy/distribution of the capture (how much of it is tcp, udp, icmp, etc.).

## Task - 13-dns_filtering.sh

What it does: Configures dnsmasq as a local DNS filter — forwards everything to the configured upstream resolver, sinkholes (answers 0.0.0.0) every domain on the blocklist, enables logging of every query, restarts the service, and validates with `dig` that an allowed domain resolves normally, a blocked one returns 0.0.0.0, and a neutral domain (in neither list) also resolves normally.
How to use it: `sudo ./13-dns_filtering.sh`
Commands:

- `dnsmasq --version` — shows the installed dnsmasq version.
- `systemctl restart dnsmasq` — restarts the dnsmasq service to apply the new configuration.
- `dig @127.0.0.1 domain A` — queries a specific DNS server (here, the local dnsmasq on loopback) for a domain's A record, used in all 3 validations (allowed / sinkholed / neutral).
