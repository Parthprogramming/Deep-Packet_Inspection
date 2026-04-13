"""
xmas_scan_sim.py
─────────────────────────────────────────────────────────────────────────────
PURPOSE : Simulate an nmap -sX XMAS scan so the DPI engine's
          checkTCPFlagAbuse() XMAS scan rule fires.

HOW IT WORKS (mapped directly to your C++ code):

  Detection in updateTCPFlags() — behavior_engine.cpp line 538:
      if ((flags & 0x29) == 0x29)   ← bitmask, not exact equality
          flow.xmasCount++;

  0x29 breakdown:
      FIN = 0x01  (bit 0)
      PSH = 0x08  (bit 3)
      URG = 0x20  (bit 5)
      ─────────────
      XOR = 0x29  ← "Christmas tree" — three flags lit up simultaneously

  Detection in checkTCPFlagAbuse() — line 624:
      if (flow.xmasCount >= config.xmasScanThreshold)  ← threshold = 1
          → fire TCP_FLAG_ABUSE | DANGER

  IMPORTANT SIDE EFFECT:
      0x29 also passes the FIN counter check:
          (0x29 & 0x11) == 0x01  → TRUE → finCount also increments
      So you will see TWO alerts per flow:
          1. TCP_FLAG_ABUSE (XMAS scan)
          2. TCP_FLAG_ABUSE (FIN scan)
      Both are correct. An XMAS packet IS also an illegal FIN.

WHY XMAS = DANGER (same as NULL, not SUSPICIOUS like FIN):
  FIN+PSH+URG simultaneously is physically impossible in legitimate TCP.
  PSH means "push data to app immediately" — only valid with a payload.
  URG means "urgent pointer is valid" — only valid in an established conn.
  FIN means "close connection" — only valid after a handshake.
  All three together with no handshake = impossible outside an attack tool.

HOW nmap -sX WORKS IN REAL LIFE:
  Sends FIN+PSH+URG to each target port.
  OPEN port on Linux   → silently dropped (no response)
  CLOSED port on Linux → RST sent back
  Attacker identifies open ports by which probes get no response.
  Same evasion goal as NULL scan — bypasses stateless SYN-only firewalls.

USAGE:
  Terminal 1:  sudo executables/dpi_engine lo
  Terminal 2:  sudo python3 tests/xmas_scan_sim.py
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

TARGET_PORTS = [22, 23, 25, 53, 80, 110, 135, 139, 443, 445,
                3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017]

PACKETS_PER_PORT = 2
INTERVAL         = 0.05   # 50ms — realistic scan speed

# ── Flag breakdown printed for learning ───────────────────────────────────
XMAS_FLAG = 0x29
print(f"[*] XMAS Scan Simulator for DPI Engine")
print(f"[*] Technique  : nmap -sX equivalent")
print(f"[*] Target     : {TARGET_IP}")
print(f"[*] Src port   : {SOURCE_PORT}")
print(f"[*] Flag sent  : 0x{XMAS_FLAG:02X}  →  FIN(0x01) + PSH(0x08) + URG(0x20)")
print(f"[*] Detection  : (flags & 0x29) == 0x29 → xmasCount++")
print(f"[*] Threshold  : xmasScanThreshold=1 → fires on FIRST packet")
print(f"[*] Severity   : DANGER")
print(f"[*] Side effect: FIN counter also increments → expect FIN scan")
print(f"[*]              alert too (correct behaviour, not a bug)")
print(f"[*] Ports      : {len(TARGET_PORTS)} → {len(TARGET_PORTS)} XMAS + "
      f"{len(TARGET_PORTS)} FIN alerts expected")
print(f"[*] Starting in 3 seconds...\n")
time.sleep(3)

pkt_num = 0
for dport in TARGET_PORTS:
    for rep in range(PACKETS_PER_PORT):
        pkt_num += 1

        pkt = IP(src=TARGET_IP, dst=TARGET_IP) / TCP(
            sport=SOURCE_PORT,
            dport=dport,
            flags=0x29,                       # FIN + PSH + URG
                                              # 0x29 & 0x29 == 0x29 → xmasCount++
                                              # 0x29 & 0x11 == 0x01 → finCount++
                                              # Both checks pass simultaneously
            seq=random.randint(1000, 9999999)
        )

        send(pkt)
        print(f"  [PKT {pkt_num:03d}] XMAS → {TARGET_IP}:{dport:<5} "
              f"| flags=0x29 (FIN+PSH+URG) | sport={SOURCE_PORT} "
              f"| rep={rep+1}/{PACKETS_PER_PORT}")

        time.sleep(INTERVAL)

print(f"\n[+] Done. {pkt_num} XMAS packets sent across {len(TARGET_PORTS)} ports.")
print(f"[+] Expected alerts per flow:")
print(f"[+]   1. TCP_FLAG_ABUSE | DANGER    | XMAS scan (xmasCount >= 1)")
print(f"[+]   2. TCP_FLAG_ABUSE | SUSPICIOUS| FIN scan  (finCount>0, "
      f"synCount==0, synAckSeen==false)")
print(f"[+] Total expected: {len(TARGET_PORTS)*2} alerts "
      f"({len(TARGET_PORTS)} XMAS + {len(TARGET_PORTS)} FIN)")