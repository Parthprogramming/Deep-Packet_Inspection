"""
fin_scan_sim.py
─────────────────────────────────────────────────────────────────────────────
PURPOSE : Simulate an nmap -sF FIN scan so the DPI engine's
          checkTCPFlagAbuse() FIN scan rule fires.

HOW IT WORKS (mapped directly to your C++ code):

  Your detection condition (behavior_engine.cpp line 648):
      flow.finCount > 0   → at least one pure FIN (0x01) packet
      flow.synCount == 0  → NO SYN was ever sent in this flow
      flow.synAckSeen == false → handshake never completed

  WHY THIS DETECTS ATTACKS:
  Legitimate TCP ALWAYS follows: SYN → SYN+ACK → ACK → data → FIN+ACK
  A bare FIN with no prior SYN means the sender is probing ports.
  Open ports on Linux silently drop the FIN (no response).
  Closed ports reply with RST — attacker maps which ports are open by
  seeing which FINs get NO response.

  This technique bypasses STATELESS firewalls that only block SYN packets.
  Your DPI engine catches it because it tracks FLAGS per flow, not just SYN.

WHAT WE SEND:
  - TCP flags = 0x01 (FIN only, NOT FIN+ACK which is 0x11)
  - No SYN is ever sent before these FINs
  - Multiple destination ports = realistic port scan sweep

USAGE:
  Terminal 1:  sudo executables/dpi_engine lo
  Terminal 2:  sudo python3 tests/fin_scan_sim.py

NOTE: No nc listener needed. FIN scan works on CLOSED ports — that's the point.
"""

import time
import sys
import random

try:
    from scapy.all import IP, TCP, send, conf
except ImportError:
    print("[ERROR] scapy not installed. Run: pip install scapy")
    sys.exit(1)

conf.verb = 0

# ── Configuration ─────────────────────────────────────────────────────────
TARGET_IP    = "127.0.0.1"
SOURCE_PORT  = random.randint(10000, 60000)   # attacker source port

# Ports to scan — nmap -sF sweeps many ports to find open ones
# Each destination port = a different flow key in your engine
# We scan the same port multiple times first to build finCount > 0
TARGET_PORTS = [22, 23, 80, 443, 3306, 8080, 8443, 9200, 5432, 6379]

PACKETS_PER_PORT = 3     # send 3 FINs per port
                         # finCount=3 → evidence shows more than 1 probe
INTERVAL         = 0.1   # 100ms between packets

# ── Sanity check: what flags=0x01 means ───────────────────────────────────
# 0x01 = FIN only
# 0x11 = FIN + ACK  ← DO NOT USE THIS, finCount won't increment
# 0x02 = SYN        ← DO NOT SEND THIS, synCount must stay 0
# Your updateTCPFlags() checks: (flags & 0x11) == 0x01
# So 0x01 passes, 0x11 does NOT pass. Pure FIN only.

print(f"[*] FIN Scan Simulator for DPI Engine")
print(f"[*] Technique  : nmap -sF equivalent")
print(f"[*] Target     : {TARGET_IP}")
print(f"[*] Src port   : {SOURCE_PORT}")
print(f"[*] Ports      : {TARGET_PORTS}")
print(f"[*] Flag sent  : 0x01 (FIN only — NOT FIN+ACK)")
print(f"[*] No SYN sent → flow.synCount will stay 0 → FIN scan detected")
print(f"[*] Starting in 3 seconds...\n")
time.sleep(3)

pkt_num = 0
for dport in TARGET_PORTS:
    for rep in range(PACKETS_PER_PORT):
        pkt_num += 1

        pkt = IP(src=TARGET_IP, dst=TARGET_IP) / TCP(
            sport=SOURCE_PORT,
            dport=dport,
            flags=0x01,           # ← PURE FIN. This is what your engine counts.
            seq=random.randint(1000, 9999999)
                                  # random seq = realistic (attacker doesn't
                                  # have a real sequence number — no handshake)
        )

        send(pkt)
        print(f"  [PKT {pkt_num:03d}] FIN → {TARGET_IP}:{dport} "
              f"| flags=0x01 | sport={SOURCE_PORT}")

        time.sleep(INTERVAL)

print(f"\n[+] Done. {pkt_num} FIN packets sent across {len(TARGET_PORTS)} ports.")
print(f"[+] Expected alert : TCP_FLAG_ABUSE | Severity: SUSPICIOUS")
print(f"[+] Detection rule : finCount>0 AND synCount==0 AND synAckSeen==false")
print(f"[+] Each port = a separate flow key in your engine.")
print(f"[+] Each flow will fire its own FIN scan alert.")