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
What it does: Reads the baseline produced by script 0 and classifies each listening socket with a function (database, web, ssh, etc.) and a criticality level, flagging dangerous exposures — a database/RPC service bound to 0.0.0.0, or an inherently insecure protocol (telnet, ftp, snmp v1/v2c, rlogin, nfs v2/v3).
How to use it: `sudo ./1-attack_surface.sh [network_baseline.json] [output.json]`
Commands:
- `readlink -f /proc/$pid/exe` — resolves the real path of the binary that opened the socket, to identify the exact executable.
- `dpkg -S "$exec_path"` — finds which installed package owns the binary, tying the exposed service back to its origin.
- `grep -oE '[a-zA-Z0-9@._-]+\.service' /proc/$pid/cgroup` — extracts the systemd unit name associated with the process from its cgroup.
- `systemctl show "$candidate" --no-pager -p LoadState` — confirms the discovered systemd unit is actually loaded, validating the service attribution.
