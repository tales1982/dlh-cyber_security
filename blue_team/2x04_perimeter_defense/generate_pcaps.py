#!/usr/bin/env python3
"""
generate_pcaps.py

MedDefense Health Systems - Perimeter and Network Defense (2x04)

Builds every synthetic PCAP the Suricata/tshark tasks (T8-T11) need.
Not a project deliverable itself - this is the fixture-authoring tool used
because the lab ships no real PCAPs for this module. Requires python3-scapy.

Usage: python3 generate_pcaps.py <output_dir>
"""
import sys
import os
import random
from scapy.all import (
    Ether, IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap, PcapWriter
)

random.seed(1337)

MAC_A = "08:00:27:ab:b5:ad"
MAC_B = "08:00:27:81:84:e2"


def tcp_session(src, sport, dst, dport, client_payloads=None, server_payloads=None, isn_c=1000, isn_s=5000):
    """A minimal but flow-complete TCP session: handshake, optional payload
    exchange, teardown. Enough for Suricata's flow/stream tracking to treat
    it as an established, closed connection."""
    pkts = []
    seq_c, seq_s = isn_c, isn_s
    pkts.append(Ether(src=MAC_A, dst=MAC_B) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S", seq=seq_c))
    seq_c += 1
    pkts.append(Ether(src=MAC_B, dst=MAC_A) / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="SA", seq=seq_s, ack=seq_c))
    seq_s += 1
    pkts.append(Ether(src=MAC_A, dst=MAC_B) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=seq_c, ack=seq_s))

    for payload in (client_payloads or []):
        pkts.append(Ether(src=MAC_A, dst=MAC_B) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA", seq=seq_c, ack=seq_s) / Raw(load=payload))
        seq_c += len(payload)
        pkts.append(Ether(src=MAC_B, dst=MAC_A) / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="A", seq=seq_s, ack=seq_c))

    for payload in (server_payloads or []):
        pkts.append(Ether(src=MAC_B, dst=MAC_A) / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="PA", seq=seq_s, ack=seq_c) / Raw(load=payload))
        seq_s += len(payload)
        pkts.append(Ether(src=MAC_A, dst=MAC_B) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=seq_c, ack=seq_s))

    pkts.append(Ether(src=MAC_A, dst=MAC_B) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="FA", seq=seq_c, ack=seq_s))
    seq_c += 1
    pkts.append(Ether(src=MAC_B, dst=MAC_A) / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="FA", seq=seq_s, ack=seq_c))
    seq_s += 1
    pkts.append(Ether(src=MAC_A, dst=MAC_B) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=seq_c, ack=seq_s))
    return pkts


def tls_client_hello(sni_hostname):
    """A hand-built, minimal-but-valid TLS 1.2 ClientHello record carrying
    an SNI extension - enough for tshark's tls.handshake dissector to parse
    tls.handshake.type==1 and extract tls.handshake.extensions_server_name,
    without pulling in a TLS-capable scapy extension."""
    hostname = sni_hostname.encode()
    sni_entry = b"\x00" + len(hostname).to_bytes(2, "big") + hostname          # name_type=host_name(0)
    sni_list = len(sni_entry).to_bytes(2, "big") + sni_entry
    ext_sni = (0x0000).to_bytes(2, "big") + len(sni_list).to_bytes(2, "big") + sni_list
    extensions = ext_sni
    session_id = b""
    cipher_suites = bytes.fromhex("c02f c030 009e 009f 002f 0035")  # a few common TLS 1.2 suites
    compression = b"\x00"
    body = (
        bytes.fromhex("0303") +                              # client_version = TLS 1.2
        bytes([random.randint(0, 255) for _ in range(32)]) +  # random
        bytes([len(session_id)]) + session_id +
        len(cipher_suites).to_bytes(2, "big") + cipher_suites +
        bytes([len(compression)]) + compression +
        len(extensions).to_bytes(2, "big") + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body   # handshake type 1 = ClientHello
    record = b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake  # content type 22 = handshake
    return record


def dns_query(src, dst, qname, qtype="A", sport=None):
    sport = sport or random.randint(20000, 60000)
    return (Ether(src=MAC_A, dst=MAC_B) / IP(src=src, dst=dst) /
            UDP(sport=sport, dport=53) / DNS(rd=1, qd=DNSQR(qname=qname, qtype=qtype)))


def http_request(src, sport, dst, dport, host, path, method="GET"):
    body = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: MedDefenseAgent/1.0\r\nConnection: close\r\n\r\n".encode()
    resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\nMedDefenseApp"
    return tcp_session(src, sport, dst, dport, client_payloads=[body], server_payloads=[resp])


def main():
    out_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    labels_dir = os.path.join(out_dir, "labels")
    os.makedirs(labels_dir, exist_ok=True)

    # --- smoke.pcap: tiny, guaranteed >=1 community.rules alert (telnet) ----
    smoke = tcp_session("10.10.5.20", 33211, "10.10.1.10", 23, client_payloads=[b"admin\r\n", b"password123\r\n"])
    wrpcap(os.path.join(out_dir, "smoke.pcap"), smoke)

    # --- mixed_traffic.pcap: benign + recon + SMB lateral + DNS tunnel -----
    mixed = []
    # benign background: a couple of normal HTTPS-looking / DNS lookups
    mixed += tcp_session("10.10.2.11", 44201, "10.10.1.10", 443, client_payloads=[b"\x16\x03\x01\x00\x2f"])
    mixed += [dns_query("10.10.1.10", "10.10.20.5", "billing.meddefense.local.")]
    mixed += [dns_query("10.10.2.11", "10.10.20.5", "ehr.meddefense.local.")]

    # reconnaissance: rapid SYN scan from 10.10.1.99 against 10.10.1.10 across many ports
    scan_src, scan_dst = "10.10.1.99", "10.10.1.10"
    seq = 9000
    for port in range(1, 25):
        mixed.append(Ether(src=MAC_A, dst=MAC_B) / IP(src=scan_src, dst=scan_dst) /
                     TCP(sport=random.randint(1024, 65000), dport=port, flags="S", seq=seq))
        seq += 1

    # lateral movement: PsExec-style SMB install from a compromised workstation
    mixed += tcp_session(scan_src, 51000, scan_dst, 445,
                          client_payloads=[b"\x00\x00\x00\x54\xffSMBu\x00\x00\x00\x00\x18PSEXESVC install request"])

    # exfiltration: DNS tunneling - long leftmost labels to an external resolver
    tunnel_label = "".join(random.choice("abcdef0123456789") for _ in range(58))
    for i in range(3):
        mixed.append(dns_query(scan_dst, "8.8.8.8", f"{tunnel_label}{i}.c2.example.com."))

    wrpcap(os.path.join(out_dir, "mixed_traffic.pcap"), mixed)

    # --- suspicious_session.pcap: the T11 investigation target --------------
    susp = []
    c2_ip = "185.220.101.42"
    susp += tcp_session("10.10.1.10", 52344, c2_ip, 443, client_payloads=[tls_client_hello("update.crimson-tide-ops.xyz")])
    susp += [dns_query("10.10.1.10", "8.8.8.8", "c2.crimson-tide-ops.xyz.")]
    tunnel_label = "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(58))
    susp += [dns_query("10.10.1.10", "8.8.8.8", f"{tunnel_label}.crimson-tide-ops.xyz.")]
    susp += tcp_session("10.10.1.10", 52401, "10.10.1.50", 445, client_payloads=[b"\xffSMBshare-enum"])
    susp += http_request("10.10.1.10", 52500, c2_ip, 80, "update.crimson-tide-ops.xyz", "/beacon?id=billing-srv-01")
    wrpcap(os.path.join(out_dir, "suspicious_session.pcap"), susp)

    # --- labeled PCAPs, one per meddefense.rules sid -------------------------
    # sid 9000001/9000002: MEDDEV -> Internet, TCP (any port) + UDP (not 123)
    meddev_egress = tcp_session("10.10.4.5", 40100, "93.184.216.34", 443, client_payloads=[b"GET / HTTP/1.1\r\n\r\n"])
    meddev_egress.append(Ether(src=MAC_A, dst=MAC_B) / IP(src="10.10.4.5", dst="93.184.216.34") /
                          UDP(sport=40200, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com.")))
    wrpcap(os.path.join(labels_dir, "meddev_egress.pcap"), meddev_egress)

    # sid 9000003: guest -> HOME_NET SMB
    guest_smb = tcp_session("10.10.5.30", 41100, "10.10.1.10", 445, client_payloads=[b"\xffSMB guest session setup"])
    wrpcap(os.path.join(labels_dir, "guest_smb.pcap"), guest_smb)

    # sid 9000004: >50MB single-flow outbound from the server zone
    big_payload = bytes([random.randint(0, 255) for _ in range(1)]) * 65000
    n_chunks = 820  # ~53MB total, comfortably over the 50MB stream_size threshold
    large_out = []
    src, dst, sport, dport = "10.10.1.10", "198.51.100.7", 55010, 8443
    seq_c, seq_s = 2000, 8000
    large_out.append(Ether(src=MAC_A, dst=MAC_B) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S", seq=seq_c)); seq_c += 1
    large_out.append(Ether(src=MAC_B, dst=MAC_A) / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="SA", seq=seq_s, ack=seq_c)); seq_s += 1
    large_out.append(Ether(src=MAC_A, dst=MAC_B) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=seq_c, ack=seq_s))
    pcap_writer = PcapWriter(os.path.join(labels_dir, "large_outbound.pcap"), append=False, sync=False)
    for p in large_out:
        pcap_writer.write(p)
    for i in range(n_chunks):
        pkt = (Ether(src=MAC_A, dst=MAC_B) / IP(src=src, dst=dst) /
               TCP(sport=sport, dport=dport, flags="PA", seq=seq_c, ack=seq_s) / Raw(load=big_payload))
        pcap_writer.write(pkt)
        seq_c = (seq_c + len(big_payload)) % 4294967296
        if i % 40 == 0:
            pcap_writer.write(Ether(src=MAC_B, dst=MAC_A) / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="A", seq=seq_s, ack=seq_c))
    pcap_writer.write(Ether(src=MAC_A, dst=MAC_B) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="FA", seq=seq_c, ack=seq_s))
    pcap_writer.close()

    # sid 9000005: DNS tunneling long label
    tun2 = "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(58))
    dns_tunnel = [dns_query("10.10.1.10", "8.8.8.8", f"{tun2}.tunnel.example.net.") for _ in range(5)]
    wrpcap(os.path.join(labels_dir, "dns_tunnel.pcap"), dns_tunnel)

    # sid 9000006: clinical workstation -> unauthorized DB host (not 10.10.1.10)
    clinical_wrong = tcp_session("10.10.2.44", 42100, "10.10.1.77", 3306, client_payloads=[b"\x4a\x00\x00\x00\x0a8.0.35"])
    wrpcap(os.path.join(labels_dir, "clinical_wrong_db.pcap"), clinical_wrong)

    # sid 9000007: telnet cleartext to a medical device
    telnet_meddev = tcp_session("10.10.20.9", 43100, "10.10.4.5", 23, client_payloads=[b"admin\r\n", b"meddev123\r\n"])
    wrpcap(os.path.join(labels_dir, "telnet_meddev.pcap"), telnet_meddev)

    print("PCAPs written to:", out_dir)


if __name__ == "__main__":
    main()
