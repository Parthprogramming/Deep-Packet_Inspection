"""
null_scan_sim.py
─────────────────────────────────────────────────────────────────────────────
PURPOSE : Simulate an nmap -sN NULL scan so the DPI engine's
          checkTCPFlagAbuse() NULL scan rule fires.

HOW IT WORKS (mapped directly to your C++ code):

  Detection in updateTCPFlags() — behavior_engine.cpp line 533:
      if (flags == 0x00)       ← exact equality, not a bitmask
          flow.nullCount++;

  Detection in checkTCPFlagAbuse() — line 599:
      if (flow.nullCount >= config.nullScanThreshold)  ← threshold = 1
          → fire TCP_FLAG_ABUSE | DANGER

  ONE PACKET IS ENOUGH. nullScanThreshold=1 means the very first
  zero-flag packet fires the alert immediately.

WHY NULL SCAN IS ALWAYS DANGER (not SUSPICIOUS like FIN scan):
  The TCP specification (RFC 793) REQUIRES at least one flag to be set.
  No legitimate OS, driver, or application ever sends flags=0x00.
  There is literally no false positive scenario. One null packet = attack.

HOW nmap -sN WORKS IN REAL LIFE:
  - Attacker sends TCP with ALL flags cleared (0x00)
  - OPEN port   → Linux silently drops it (no response)
  - CLOSED port → Linux replies with RST
  - Attacker maps open ports by seeing which probes get NO response
  - This bypasses stateless firewalls that only inspect SYN packets

WHAT WE SEND:
  - TCP flags = 0x00 (all bits zero — the null packet)
  - Multiple destination ports = realistic port sweep
  - No SYN, no handshake, no listener needed

USAGE:
  Terminal 1:  sudo executables/dpi_engine lo
  Terminal 2:  sudo python3 tests/null_scan_sim.py
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
TARGET_IP   = "127.0.0.1"
SOURCE_PORT = random.randint(10000, 60000)

# Port sweep — same pattern real nmap uses
# Each port = separate flow key = separate alert in your engine
TARGET_PORTS = [22, 23, 25, 53, 80, 110, 135, 139, 443, 445,
                3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017]

PACKETS_PER_PORT = 2     # 2 null packets per port — shows nullCount accumulating
INTERVAL         = 0.05  # 50ms between packets — realistic scan speed

print(f"[*] NULL Scan Simulator for DPI Engine")
print(f"[*] Technique  : nmap -sN equivalent")
print(f"[*] Target     : {TARGET_IP}")
print(f"[*] Src port   : {SOURCE_PORT}")
print(f"[*] Flag sent  : 0x00 (ALL flags cleared)")
print(f"[*] Threshold  : nullScanThreshold=1 → fires on FIRST packet")
print(f"[*] Severity   : DANGER (zero false-positive risk)")
print(f"[*] Ports      : {len(TARGET_PORTS)} ports → {len(TARGET_PORTS)} alerts expected")
print(f"[*] Starting in 3 seconds...\n")
time.sleep(3)

pkt_num = 0
for dport in TARGET_PORTS:
    for rep in range(PACKETS_PER_PORT):
        pkt_num += 1

        pkt = IP(src=TARGET_IP, dst=TARGET_IP) / TCP(
            sport=SOURCE_PORT,
            dport=dport,
            flags=0x00,                       # ← THE NULL PACKET
                                              # Scapy allows this even though
                                              # no real OS would generate it.
                                              # That's exactly why it's suspicious.
            seq=random.randint(1000, 9999999)
        )

        send(pkt)
        print(f"  [PKT {pkt_num:03d}] NULL → {TARGET_IP}:{dport:<5} "
              f"| flags=0x00 | sport={SOURCE_PORT} | rep={rep+1}/{PACKETS_PER_PORT}")

        time.sleep(INTERVAL)

print(f"\n[+] Done. {pkt_num} NULL packets sent across {len(TARGET_PORTS)} ports.")
print(f"[+] Expected alert : TCP_FLAG_ABUSE | Severity : DANGER")
print(f"[+] Detection rule : nullCount >= 1 (fires on packet 1 per flow)")
print(f"[+] Alerts expected: {len(TARGET_PORTS)} (one per destination port/flow)")