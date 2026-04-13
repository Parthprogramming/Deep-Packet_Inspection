"""
beacon_simulator.py
────────────────────────────────────────────────────────────────────────────
PURPOSE : Generate synthetic beaconing traffic on localhost so the DPI engine's
          checkBeaconing() rule fires and can be verified.

HOW IT WORKS (learn this — it maps directly to your C++ code):
  Your checkBeaconing() measures the INTER-ARRIVAL TIME (IAT) between packets
  in the same flow. If the standard deviation of IAT is LOW (packets arrive
  at suspiciously regular intervals), it flags it as beaconing.

  This script sends periodic TCP connections to 127.0.0.1 at a fixed interval.
  The DPI engine on the 'lo' interface will see these flows and compute IAT.

USAGE:
  Terminal 1 — start DPI engine on loopback:
      sudo ./dpi_engine lo

  Terminal 2 — run this simulator:
      python3 beacon_simulator.py

  After ~60 packets (your ruleConfig.beaconingMinPackets = 50),
  the engine will fire a BEACONING alert.

REQUIREMENTS:
    pip install scapy

NOTE: Run with sudo or as root — raw socket / scapy needs it.
      This only talks to 127.0.0.1. No external traffic is generated.
"""

import time
import random
import sys

try:
    from scapy.all import IP, TCP, send, conf
except ImportError:
    print("[ERROR] scapy not installed. Run: pip install scapy")
    sys.exit(1)

# ── Configuration ────────────────────────────────────────────────────────────
TARGET_IP       = "127.0.0.1"   # loopback — matches your 'lo' interface
TARGET_PORT     = 8080          # destination port (any closed port is fine)
SOURCE_PORT     = 54321          # fixed src port → keeps it in one flow
BEACON_INTERVAL = 2.0            # seconds between beacons (fixed = low IAT stddev)
TOTAL_BEACONS   = 60             # send 60 packets — your threshold is 50
JITTER          = 0.05           # ±50ms jitter — real beacons are almost never
                                 # perfectly timed; this keeps it realistic

# ── Suppress scapy's verbose output ─────────────────────────────────────────
conf.verb = 0

# ── What your DPI engine will see ───────────────────────────────────────────
# Each packet = SYN to the same dst IP:port from the same src IP:port.
# This creates a single flow key: "127.0.0.1:54321 -> 127.0.0.1:8080"
# After 50+ packets with low IAT stddev → checkBeaconing() fires DANGER alert.

print(f"[*] Beacon Simulator for DPI Engine")
print(f"[*] Target     : {TARGET_IP}:{TARGET_PORT}")
print(f"[*] Interval   : {BEACON_INTERVAL}s ± {JITTER*1000:.0f}ms jitter")
print(f"[*] Total PKTs : {TOTAL_BEACONS}")
print(f"[*] Flow key   : {TARGET_IP}:{SOURCE_PORT} -> {TARGET_IP}:{TARGET_PORT}")
print(f"[*] Your DPI engine threshold = 50 packets. Alert fires after ~50 sends.")
print(f"[*] Starting in 3 seconds... (make sure DPI engine is running on 'lo')\n")
time.sleep(3)

for i in range(1, TOTAL_BEACONS + 1):
    # Build packet: IP layer + TCP SYN
    # SYN flag = 0x02. This mimics a C2 beacon checking in to its server.
    pkt = IP(dst=TARGET_IP) / TCP(
        sport=SOURCE_PORT,
        dport=TARGET_PORT,
        flags="S",          # SYN only — no handshake needed, just traffic
        seq=random.randint(1000, 9999999)
    )

    send(pkt)

    # ── Why jitter matters for your DPI engine ───────────────────────────
    # checkBeaconing() computes stddev of inter-arrival times.
    # Zero jitter = stddev of 0.0 → immediately suspicious.
    # Small jitter = stddev stays LOW but nonzero → still flags beaconing.
    # High jitter = mimics normal traffic → evades detection.
    # Your engine catches low-jitter beacons. High jitter = evasion technique.
    sleep_time = BEACON_INTERVAL + random.uniform(-JITTER, JITTER)

    print(f"  [{i:03d}/{TOTAL_BEACONS}] Beacon sent → {TARGET_IP}:{TARGET_PORT} "
          f"| next in {sleep_time:.3f}s")

    if i < TOTAL_BEACONS:
        time.sleep(sleep_time)

print(f"\n[+] Done. {TOTAL_BEACONS} beacons sent.")
print(f"[+] Check your DPI engine terminal for a BEACONING alert.")
print(f"[+] Expected alert type : BEACONING | Severity : DANGER")
print(f"[+] Flow key in report  : 10.255.255.254:{SOURCE_PORT} -> {TARGET_IP}:{TARGET_PORT}")