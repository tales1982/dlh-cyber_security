# Reverse DNS Expected Behavior

`reverse_dns(ip: str) -> str` should call `socket.setdefaulttimeout(3)`, attempt `socket.gethostbyaddr(ip)`, return hostname on success, return `NXDOMAIN` on `socket.herror`, and return `TIMEOUT` on `socket.timeout`.

Most documentation IPs used in the lab will return `NXDOMAIN`. This is expected. Playbooks must not fail if reverse DNS returns `NXDOMAIN` or `TIMEOUT`.

| IP | Expected Stable Behavior |
|---|---|
| `198.51.100.42` | `NXDOMAIN` |
| `203.0.113.99` | `NXDOMAIN` |
| `192.168.1.100` | `NXDOMAIN` |
| `8.8.8.8` | resolver dependent; verdict still ALLOW due benign list |
