# 4x01 – Wire Shark Territory

Network-forensics follow-up to 4x00: the same MedDefense phishing incident, now traced through packet captures instead of email headers — from the initial phishing click through C2 beaconing, an external VPN pivot, RDP lateral movement, SMB enumeration, and DNS-tunneled exfiltration. Every script is built on `tshark` display filters and field extraction, with an explicit, recurring discipline of never inventing a finding a capture doesn't actually support.

## Task - 0-baseline_analysis.sh

What it does: Takes a `.pcap` and profiles what "normal" traffic on the clinical network segment looks like — protocol distribution (TCP/UDP/ICMP), application breakdown by well-known port, top talkers by byte volume, top destinations by connection count, DNS query profile (rate, top domains, record-type mix), TCP connection-duration buckets, observed TLS SNI/version/certificate issuers, and a 5-minute-bucketed temporal volume pattern — then explicitly checks two known-bad IOCs (an IP and a DNS domain) against the capture and writes everything to `baseline_clinical.json` for later tasks to compare against.
How to use it: `./0-baseline_analysis.sh <capture.pcap>`
Commands:

- `tshark -r "$PCAP" -q -z io,phs` then `grep`/`awk` on the protocol-hierarchy-statistics output — tshark's built-in protocol-tree summary parsed with plain text tools instead of tshark's own (much harder to script against) JSON output mode.
- One `tshark -Y "<display filter>" | wc -l` invocation per application/port of interest (443, 53, 88, 389, 1514, 123, 9100, 445) — the simplest possible per-category counting idiom, run once per category rather than one pass classifying every packet.
- `awk '{bin = int($1/300); count[bin]++} ...'` on `frame.time_relative` — buckets every frame into 5-minute windows by integer division, the same fixed-width temporal histogram technique used throughout this project's baselining work (e.g. 3x01's `8-baseline_temporal.sh`), just applied to raw packets instead of security events.
- A `for IOC_IP in ...; do tshark -Y "ip.addr==$IOC_IP" ...` loop checking known-bad indicators directly against this capture — the network-analysis equivalent of a Sigma rule's IOC watchlist check, run once per named indicator.

## Task - 1-phishing_click.sh

What it does: Reconstructs, packet by packet, the moment `dmarsh@meddefense.com`'s workstation clicked the phishing link — the DNS query/response that resolved `meddefense-portal.com`, the TCP SYN/SYN-ACK and TLS ClientHello to the resulting IP (noting no Certificate/ServerHello is present, so this evidence set only shows the connection attempt, not what came back), byte counts and largest-record-size metadata for the encrypted exchange (used to infer "this looked like a small form submission," never claimed as proven), the user's subsequent DNS lookup of the *real* portal minutes later, and a final cross-check confirming the observed IP/domain match the IOCs from the 4x00 email investigation.
How to use it: `./1-phishing_click.sh <capture.pcap>`
Commands:

- `tshark -T fields -e frame.time_epoch ... | awk '{split($1,p,"."); ms=substr(p[2],1,3); print strftime(...)"."ms}'` — repeated throughout this whole module: splits epoch seconds from fractional milliseconds and reformats with `awk`'s `strftime`, since tshark's own `-t ad` time format doesn't give the same millisecond-precision, script-friendly output.
- A `cname[...]` lookup array mapping raw TLS cipher-suite hex codes (`0x1301`, `0xc02b`, ...) to their human-readable names — a small hardcoded table that keeps the script's output readable without depending on tshark's dissector version for names it may or may not resolve.
- Explicitly printing `"[*] ... no Certificate/ServerHello ... capture appears to include only ClientHello"` rather than silently treating a missing response as "connection succeeded" — the same discipline as this module's other scripts: the script states exactly what evidence is and isn't present rather than filling a narrative gap.
- The closing "[*] Analysis" block reasoning from TLS record *size* alone (no decryption) to a plausible conclusion, explicitly labeled as metadata-based inference — a template for every later "packet size/timing implies X" argument in this module.

## Task - 3-dns_tunnel.sh

What it does: Confirms and characterizes DNS tunneling from `billing-srv-01` to `data-sync.meddefense-portal.com` — classifies every DNS query from that host as normal vs. matching the tunnel domain, profiles the anomalous queries' record type, inter-query interval, and subdomain-label length/encoding, *attempts* to actually Base32-decode sample query labels and Base64-decode a sample TXT response (printing exactly what decoded and what didn't, never inventing a plausible-looking payload when decoding fails), estimates raw exfiltrated bytes from the base32 5-bytes-per-8-characters ratio, and closes with a side-by-side comparison against Task 0's baseline.
How to use it: `./3-dns_tunnel.sh <capture.pcap>`
Commands:

- `python3 -c "import base64; ... base64.b32decode(padded)"` invoked from inside a bash loop, one subdomain label at a time, wrapped in `try/except` reporting a decode *failure* honestly ("label length is not a clean base32 group boundary... No data invented") instead of only ever showing successful decodes.
- `RAW_BYTES = n * avg * 5/8` — the specific numeric ratio for Base32's 5-raw-bytes-per-8-encoded-characters expansion, used to turn "N queries of average label length L" into an estimated exfiltrated byte count without needing every query's exact payload.
- A `DETECTION COMPARISON` table explicitly labeled as reproducing Task 0's already-saved `baseline_clinical.json` figures rather than re-measuring them — avoids two different scripts silently drifting into two different "normal" numbers for the same network.

## Task - 4-lateral_movement.sh

What it does: Reconstructs the attacker's movement from the compromised clinical workstation into the server tier — cross-subnet connection counts, an authentication-events table built by classifying RDP (SYN present = success, per this dataset) and SMB (packet-count heuristic: 1 packet = refused, ~10 = access denied, ~12+ = success) attempts, a 4-step attack-path narrative (RDP in, SMB probing out, denied/refused probes against restricted hosts, successful NAS access) each tagged with a MITRE technique, an access-effectiveness summary, and a baseline comparison confirming none of this matches Task 0's "normal."
How to use it: `./4-lateral_movement.sh <capture.pcap>`
Commands:

- `tcp contains "dmarsh"` as a tshark display filter — searches raw TCP payload bytes for a literal string, the blunt but effective way to confirm which account name appears in an unencrypted exchange without needing a protocol-specific RDP/SMB credential dissector.
- The SMB packet-count heuristic (`COUNT -le 1` → refused, `-ge 12` → success, else → denied) documented inline with the exact request/response round-trip reasoning behind each threshold — turns an indirect signal (how many packets an exchange took) into a three-way classification, with the reasoning shown rather than the thresholds left unexplained.
- Distinguishing a TCP RST that comes *from the target host itself* versus one that comes from an intermediate gateway (checking `ip.src` on the reset packet, not the original destination) — the packet-level tell for "the destination host said no" versus "a firewall in between said no," a real and useful distinction for scoping which systems the attacker actually reached.
- A `for TARGET in ...; do ...; done` loop re-querying each distinct destination's full conversation packet count to decide if it was a completed exchange or a lone SYN — the same "count packets in the stream" technique as the SMB classification, reused for a different judgment (target reached vs. never responded).

## Task - 5-vpn_pivot.sh

What it does: Identifies the external VPN session that gave the attacker network access, reads its TLS SNI, attempts to decode an application-layer `AUTH:` marker present in this dataset's payload (explicitly noting this is *not* what a real encrypted VPN handshake would expose, and is evidence of this specific synthetic capture, not a general technique), runs a live `whois` lookup against the source IP for country/ASN/organization, correlates the VPN session's timing against the first RDP connection from Task 4, and closes with an explicit Limitations section stating exactly what is proven by metadata versus what would require a real credential exposure to prove.
How to use it: `./5-vpn_pivot.sh <capture.pcap>`
Commands:

- `timeout 5 whois "$VPN_SRC"` with the result parsed by `grep -im1 '^country:'` etc., and an explicit fallback path (`"WHOIS lookup unavailable ... not fabricated"`) when the registry doesn't answer — a *live* OSINT lookup performed as part of the script (unlike 4x00's deliberately passive/manual-only approach), but one that fails safely and says so instead of inventing a plausible country.
- `tcp contains "AUTH"` piped through `xxd -r -p | strings | grep "^AUTH:"` — converts a hex-encoded tshark payload field back to raw bytes, then filters for a specific plaintext marker, one more application of the "search raw payload for something specific" technique from Task 4.
- A dedicated `=== LIMITATIONS ===` closing section — the module's clearest single example of drawing a hard line between "what this specific evidence set happens to show" and "what a real attacker's encrypted traffic would actually expose," so the technique doesn't get mistaken for something that works against real TLS.

## Task - 6-kill_chain.sh

What it does: Takes no pcap argument of its own — synthesizes the full 7-phase attack timeline purely by citing the already-verified findings from 4x00 (Phase 1) and Tasks 1/3/4/5 (Phases 2, 4-7), analyzing exactly one new capture inline for the phase with no dedicated script (`c2_beaconing.pcap` for Phase 3's beaconing-interval statistics), computing total dwell time, naming the three key pivot points, and closing with a per-phase "packet visibility" scorecard (confirmed / not visible / metadata+marker only) that is explicit about the difference between "the traffic pattern is confirmed" and "every claim about it is independently proven."
How to use it: `./6-kill_chain.sh` (no arguments; reads `pcap/c2_beaconing.pcap` relative to the script and cites the other tasks' already-produced findings)
Commands:

- A header comment naming exactly which prior scripts each phase's numbers come from, and stating plainly that nothing here is re-derived except Phase 3 — makes the script's own evidentiary chain auditable instead of presenting seven phases as if they were all freshly computed by this one script.
- `[ -f "$C2_PCAP" ] || echo "[!] ... phase not analyzed, nothing fabricated"` — the module's recurring discipline applied at the phase level: a missing input produces an honest gap in the timeline, never an invented Phase 3.
- Interval statistics (`min`, `max`, `avg` gap between connection starts) computed with a single `awk` pass over sorted SYN timestamps — the exact numeric evidence ("low-jitter ~300s interval") that later becomes Task 7's C2-beaconing detection rule's test scenario.

## Task - 7-detection_rules.sh

What it does: A pure detection-engineering design document (no pcap argument, no live analysis) proposing 6 concrete detection rules — one per major finding in the kill chain (C2 beaconing, DNS query-length anomaly, VPN geo-anomaly, cross-role RDP, DNS tunneling rate, TLS to a lookalike domain) — each with a stated detection type, the actual alerting logic, realistic implementation options (SIEM correlation rule, Zeek script, scheduled Python job, NetFlow analytics), the real data source each would need, a test scenario using this module's own already-measured numbers (not the task prompt's illustrative example figures), which kill-chain phase it covers, and its expected false-positive sources. Closes by explicitly scoring before/after detection coverage and naming the two gaps no network-layer rule can close.
How to use it: `./7-detection_rules.sh` (no arguments; design document referencing this module's own findings)
Commands:

- A header comment stating every "test scenario" number below is pulled from the module's own already-verified scripts, not the task prompt's illustrative example — keeps a detection-design document honest about which numbers are real measurements versus placeholder examples.
- Naming the *required data source* for each rule as its own explicit field, including one rule (VPN geo-anomaly) that states outright it "must live at the VPN gateway or IdP, not in network capture" — a detection idea is only actionable once someone knows which system would actually have to run it.
- An "Expected false positives" line on every single rule — treats false-positive analysis as a mandatory part of proposing a detection, not an afterthought, matching this project's Module 3 emphasis (3x02's whole `10-fp_baseline.sh`/`13-rule_quality.sh` chain) on measuring noise before trusting a rule.
- The closing coverage tally (6 phases covered out of 7, 2 named residual gaps) — makes explicit that detection engineering closes most, not all, of a kill chain, and says exactly which piece still needs a different data source (mail-gateway/endpoint telemetry) instead of overclaiming full coverage.

## Task - 8-evidence_crosscheck.sh

What it does: Re-examines all 7 kill-chain phases from Task 6 under a deliberately stricter evidentiary bar, classifying each as CONFIRMED (the packets directly prove it), STRONG INFERENCE (packets show strong supporting evidence but not direct proof — e.g. TLS metadata implying credential harvest without ever seeing plaintext), or NOT VISIBLE IN PCAP (Phase 1, which rests entirely on 4x00's email evidence), naming exactly what additional evidence source (endpoint logs, VPN AAA logs, file-server audit logs) would be needed to upgrade each STRONG INFERENCE to CONFIRMED, then computes a weighted 0-100 "packet-visibility score" and closes with an explicit lesson on what packet capture can and cannot prove versus logs.
How to use it: `./8-evidence_crosscheck.sh` (no arguments; re-examines Task 6's findings under a stricter standard)
Commands:

- A four-tier evidentiary scale (CONFIRMED / STRONG INFERENCE / UNCONFIRMED / NOT VISIBLE) with a fixed weight per tier (1.0 / 0.5 / 0.25 / 0.0) folded into one `awk` expression to produce a single 0-100 score — the same idea as this project's severity-to-numeric-score idiom (3x01's `16-rank_anomalies.sh`, 3x05's deviation markers) applied to *evidence quality* instead of finding severity.
- Explicitly downgrading Phase 4 (VPN pivot) from Task 6's "CONFIRMED" to this task's "STRONG INFERENCE," with the specific reason spelled out — a real encrypted VPN handshake wouldn't expose this dataset's plaintext `AUTH:` marker, so the finding is honest that this particular evidence artifact is specific to the synthetic capture, not a technique that would work on real traffic.
- The closing "packets answer what was sent and when; logs answer what the system decided" framing — the single clearest statement in the whole curriculum of the boundary between network forensics and log-based forensics, and why a real investigation needs both.

## Task - 11-network_forensics_report.md

What it does: The final synthesis report pulling together every finding from Tasks 0-8 (baseline, phishing click, lateral movement, VPN pivot, DNS tunneling, kill chain, detection rules, evidence crosscheck) into one document meant for the same SOC-lead/HC3 audience as 4x00's final report, cross-referencing the two modules' conclusions (email-level IOCs from 4x00, network-level confirmation from 4x01) into a single, doubly-evidenced narrative of the same incident.
How to use it: read `11-network_forensics_report.md`
Commands:

- Citing specific figures back to the exact script that produced them (e.g. "see 3-dns_tunnel.sh Exfiltration Rate section") rather than restating numbers as fresh claims — the same pointer-graph synthesis discipline as 4x00's `13-phishing_investigation_report.md`.
- Explicitly joining this module's network-level evidence to 4x00's email-level evidence for the same incident (same phishing domain, same IP, same compromised account) — demonstrating that the two modules investigate one continuous incident from two different evidence types, not two unrelated exercises.
