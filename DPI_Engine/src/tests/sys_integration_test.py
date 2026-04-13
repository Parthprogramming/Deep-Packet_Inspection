"""
generate_test_pcaps.py
Generates 8 malicious pcap files to validate each detection rule.
Run: python3 generate_test_pcaps.py
"""

import os
import struct

# Disable IPv6 BEFORE scapy loads — avoids KeyError: 'scope' crash
# in restricted environments where /proc IPv6 tables are incomplete.
os.environ["SCAPY_IPV6_ENABLED"] = "0"
from scapy.config import conf
conf.ipv6_enabled = False

from scapy.layers.l2   import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet      import Raw
from scapy.utils       import wrpcap

CLIENT_IP  = "192.168.1.100"
SERVER_IP  = "185.220.101.50"
BAD_IP     = "101.126.129.179"
BAD_DOMAIN = "dnscat.com"
DNS_SERVER = "192.168.1.1"
CLIENT_PORT = 54321
SERVER_PORT = 8080


def dns_query_bytes(domain: str, txid: int = 0x1234) -> bytes:
    """
    Build raw DNS query bytes (header + question section).
    We build this manually to avoid importing scapy.layers.dns
    which transitively imports the broken IPv6 module.

    DNS wire format:
      [2] Transaction ID
      [2] Flags: 0x0100 = standard query, recursion desired
      [2] Questions = 1
      [2] Answers = 0
      [2] Authority = 0
      [2] Additional = 0
      [N] QNAME: each label = length_byte + ascii, ended by 0x00
      [2] QTYPE  = 0x0001 (A record)
      [2] QCLASS = 0x0001 (Internet)
    """
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(lbl)]) + lbl.encode()
                     for lbl in domain.split(".")) + b"\x00"
    return header + qname + struct.pack("!HH", 1, 1)


def eth(src, dst):
    return Ether() / IP(src=src, dst=dst)


# ── TEST 1: SYN FLOOD ─────────────────────────────────────────
# 25 pure SYN packets, no SYN+ACK ever — triggers SYN flood rule
def gen_syn_flood():
    pkts = [eth(CLIENT_IP, SERVER_IP) /
            TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="S", seq=1000+i)
            for i in range(25)]
    wrpcap("./test_pcap_files/test_syn_flood.pcap", pkts)
    print("[OK] test_syn_flood.pcap      -> TCP_FLAG_ABUSE (SYN flood)  DANGER")


# ── TEST 2: NULL SCAN ─────────────────────────────────────────
# All TCP flags = 0x00 — impossible in legitimate traffic
def gen_null_scan():
    pkts = [eth(CLIENT_IP, SERVER_IP) /
            TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags=0, seq=2000+i)
            for i in range(5)]
    wrpcap("./test_pcap_files/test_null_scan.pcap", pkts)


# ── TEST 3: XMAS SCAN ─────────────────────────────────────────
# FIN(0x01)+PSH(0x08)+URG(0x20) = 0x29 — never in real traffic
def gen_xmas_scan():
    pkts = [eth(CLIENT_IP, SERVER_IP) /
            TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags=0x29, seq=3000+i)
            for i in range(5)]
    wrpcap("./test_pcap_files/test_xmas_scan.pcap", pkts)


# ── TEST 4: FIN SCAN ──────────────────────────────────────────
# FIN packets with no prior SYN or SYN+ACK
def gen_fin_scan():
    pkts = [eth(CLIENT_IP, SERVER_IP) /
            TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="F", seq=4000+i)
            for i in range(5)]
    wrpcap("./test_pcap_files/test_fin_scan.pcap", pkts)


# ── TEST 5: DNS TUNNELING ─────────────────────────────────────
# DNS packets over 512 bytes — abnormally large for DNS
def gen_dns_tunnel():
    # Normal DNS packet to establish flow direction
    normal = dns_query_bytes("google.com")
    reply  = dns_query_bytes("google.com", txid=0x5678)

    # Large DNS query: long subdomain + padding to exceed 512 bytes
    long_domain = ("aaaaaaaabbbbbbbbccccccccdddddddd"
                   "eeeeeeeefffffff0000000011111111"
                   ".dnscat.com")
    large = dns_query_bytes(long_domain) + b"X" * 400

    pkts = [
        eth(CLIENT_IP, DNS_SERVER) / UDP(sport=54444, dport=53) / Raw(normal),
        eth(DNS_SERVER, CLIENT_IP) / UDP(sport=53, dport=54444) / Raw(reply),
        eth(CLIENT_IP, DNS_SERVER) / UDP(sport=54444, dport=53) / Raw(normal),
        eth(CLIENT_IP, DNS_SERVER) / UDP(sport=54444, dport=53) / Raw(large),
    ]
    wrpcap("./test_pcap_files/test_dns_tunnel.pcap", pkts)
    print("[OK] test_dns_tunnel.pcap     -> DNS_TUNNELING              SUSPICIOUS")


# ── TEST 6: BEACONING ─────────────────────────────────────────
# 55 packets, alternating fwd/bwd — near-symmetrical ratio
def gen_beaconing():
    pkts = []
    # 3-way handshake first (so synAckSeen=true, avoids SYN flood alert)
    pkts.append(eth(CLIENT_IP, SERVER_IP) /
                TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="S", seq=100))
    pkts.append(eth(SERVER_IP, CLIENT_IP) /
                TCP(sport=SERVER_PORT, dport=CLIENT_PORT, flags="SA", seq=200, ack=101))
    pkts.append(eth(CLIENT_IP, SERVER_IP) /
                TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="A", seq=101, ack=201))
    # 52 alternating data packets (26 each direction)
    for i in range(26):
        pkts.append(eth(CLIENT_IP, SERVER_IP) /
                    TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="PA",
                        seq=101+i*10, ack=201) / Raw(b"\x00beacon"))
        pkts.append(eth(SERVER_IP, CLIENT_IP) /
                    TCP(sport=SERVER_PORT, dport=CLIENT_PORT, flags="PA",
                        seq=201+i*10, ack=111+i*10) / Raw(b"\x00ack"))
    wrpcap("./test_pcap_files/test_beaconing.pcap", pkts)
    print("[OK] test_beaconing.pcap      -> BEACONING                  SUSPICIOUS")


# ── TEST 7: MALICIOUS IP ──────────────────────────────────────
# TCP connection to an IP that is in bad_ips.txt
def gen_malicious_ip():
    pkts = [
        eth(CLIENT_IP, BAD_IP) / TCP(sport=CLIENT_PORT, dport=4444, flags="S", seq=500),
        eth(BAD_IP, CLIENT_IP) / TCP(sport=4444, dport=CLIENT_PORT, flags="SA", seq=600, ack=501),
        eth(CLIENT_IP, BAD_IP) / TCP(sport=CLIENT_PORT, dport=4444, flags="A", seq=501, ack=601),
        eth(CLIENT_IP, BAD_IP) / TCP(sport=CLIENT_PORT, dport=4444, flags="PA",
                                      seq=501, ack=601) / Raw(b"GET / HTTP/1.0\r\n\r\n"),
        eth(BAD_IP, CLIENT_IP) / TCP(sport=4444, dport=CLIENT_PORT, flags="PA",
                                      seq=601, ack=520) / Raw(b"HTTP/1.0 200 OK\r\n"),
    ]
    wrpcap("./test_pcap_files/test_malicious_ip.pcap", pkts)
    print("[OK] test_malicious_ip.pcap   -> MALICIOUS_IP               DANGER")


# ── TEST 8: MALICIOUS DOMAIN ──────────────────────────────────
# DNS query for a subdomain of dnscat.com (tests suffix matching)
def gen_malicious_domain():
    # "stage1.dnscat.com" — tests that suffix matching works:
    # engine walks up: stage1.dnscat.com → dnscat.com → MATCH
    subdomain_query = dns_query_bytes("stage1.dnscat.com")
    direct_query    = dns_query_bytes("dnscat.com")
    pkts = [
        eth(CLIENT_IP, DNS_SERVER) / UDP(sport=55555, dport=53) / Raw(subdomain_query),
        eth(CLIENT_IP, DNS_SERVER) / UDP(sport=55556, dport=53) / Raw(direct_query),
    ]
    wrpcap("./test_pcap_files/test_malicious_domain.pcap", pkts)
    print("[OK] test_malicious_domain.pcap -> MALICIOUS_DOMAIN         DANGER")


if __name__ == "__main__":
    print("=" * 58)
    print("  DPI Engine — Test PCAP Generator")
    print("=" * 58)
    print(f"  Client IP  : {CLIENT_IP}")
    print(f"  Bad IP     : {BAD_IP}  (from bad_ips.txt)")
    print(f"  Bad Domain : {BAD_DOMAIN}  (from bad_domains.txt)")
    print("=" * 58)
    print()
    gen_syn_flood()
    gen_null_scan()
    gen_xmas_scan()
    gen_fin_scan()
    gen_dns_tunnel()
    gen_beaconing()
    gen_malicious_ip()
    gen_malicious_domain()
    print()
    print("=" * 58)
    print("  All 8 pcap files generated.")
    print()
    print("  Run each test:")
    print("  ./dpi_engine -r test_syn_flood.pcap")
    print("  ./dpi_engine -r test_null_scan.pcap")
    print("  ./dpi_engine -r test_xmas_scan.pcap")
    print("  ./dpi_engine -r test_fin_scan.pcap")
    print("  ./dpi_engine -r test_dns_tunnel.pcap")
    print("  ./dpi_engine -r test_beaconing.pcap")
    print("  ./dpi_engine -r test_malicious_ip.pcap")
    print("  ./dpi_engine -r test_malicious_domain.pcap")
    print("=" * 58)