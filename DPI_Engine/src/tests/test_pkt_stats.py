"""
test_pkt_stats.py
=================
Tests the Packet Size Statistics block printed by the compiled main.cpp binary.

HOW IT WORKS:
  1. Uses scapy to create a real .pcap file with known packet sizes
  2. Runs the compiled binary:  ./dpi_engine -r <pcap_file>
  3. Captures stdout and parses the "Packet Size Statistics" block
  4. Computes the expected values independently in Python
  5. Asserts the binary's output matches expected values

USAGE:
  # Step 1 — compile your binary first (from your project root):
  #   g++ -o dpi_engine main.cpp behavior_engine.cpp -lpcap
  #
  # Step 2 — run this test, pointing to the binary:
  #   python3 test_pkt_stats.py --binary ./dpi_engine
  #
  # Or just:
  #   python3 test_pkt_stats.py          (looks for ./dpi_engine by default)

REQUIREMENTS:
  pip install scapy
"""

import argparse
import math
import os
import re
import subprocess
import sys
import tempfile

# scapy is used only to write .pcap files — no root/capturing needed
from scapy.utils import wrpcap
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw


# ──────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────

def build_packet(payload_size: int) -> Ether:
    """
    Build a minimal valid Ethernet/IP/TCP packet whose total wire-length
    equals a controlled size.

    header overhead = 14 (Eth) + 20 (IP) + 20 (TCP) = 54 bytes
    payload_size    = desired total - 54
    """
    overhead = 14 + 20 + 20          # Ethernet + IP + TCP
    pad = max(0, payload_size - overhead)
    pkt = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src="aa:bb:cc:dd:ee:ff")
        / IP(src="192.168.1.10", dst="8.8.8.8")
        / TCP(sport=12345, dport=80)
        / Raw(load=b"\x00" * pad)
    )
    return pkt


def write_pcap(packets: list, path: str):
    """Write a list of scapy packets to a pcap file."""
    wrpcap(path, packets)


def run_binary(binary_path: str, pcap_path: str) -> str:
    """
    Run:  <binary> -r <pcap>
    and return its full stdout as a string.
    """
    if not os.path.isfile(binary_path):
        raise FileNotFoundError(
            f"Binary not found: {binary_path}\n"
            f"Compile first:  g++ -o dpi_engine main.cpp behavior_engine.cpp -lpcap"
        )

    result = subprocess.run(
        [binary_path, "-r", pcap_path],
        capture_output=True,
        text=True,
    )
    return result.stdout + result.stderr


def parse_stats_block(output: str) -> dict:
    """
    Parse the Packet Size Statistics block from main.cpp stdout:

        ── Packet Size Statistics ──────────────────────
          Packets analysed : 4
          Min size         : 64 bytes
          Max size         : 1500 bytes
          Avg size         : 465.00 bytes
          Variance         : 359675.00
          Std Deviation    : 599.73 bytes
        ────────────────────────────────────────────────

    Returns a dict: { count, min, max, avg, variance, stddev }
    Raises ValueError if the block is not found in the output.
    """
    patterns = {
        "count":    r"Packets analysed\s*:\s*(\d+)",
        "min":      r"Min size\s*:\s*(\d+)",
        "max":      r"Max size\s*:\s*(\d+)",
        "avg":      r"Avg size\s*:\s*([\d.]+)",
        "variance": r"Variance\s*:\s*([\d.]+)",
        "stddev":   r"Std Deviation\s*:\s*([\d.]+)",
    }
    parsed = {}
    for key, pattern in patterns.items():
        m = re.search(pattern, output)
        if not m:
            raise ValueError(
                f"Could not find '{key}' in binary output.\n"
                f"--- binary output ---\n{output}\n---------------------"
            )
        parsed[key] = float(m.group(1))
    return parsed


def expected_stats(wire_sizes: list) -> dict:
    """
    Compute the exact same values that main.cpp computes from wire sizes.
    These are the ground-truth values we compare the binary's output against.
    """
    count  = len(wire_sizes)
    total  = sum(wire_sizes)
    sum_sq = sum(s * s for s in wire_sizes)
    avg    = total / count
    var    = (sum_sq / count) - avg * avg
    stddev = math.sqrt(var)
    return {
        "count":    float(count),
        "min":      float(min(wire_sizes)),
        "max":      float(max(wire_sizes)),
        "avg":      avg,
        "variance": var,
        "stddev":   stddev,
    }


def approx(a: float, b: float, tol=0.05) -> bool:
    """Tolerance for binary's printf("%.2f") rounding vs Python float."""
    return abs(a - b) <= tol


def assert_stats(label: str, got: dict, want: dict):
    """Compare binary's parsed output against Python-computed expected values."""
    for key in ("count", "min", "max", "avg", "variance", "stddev"):
        g, w = got[key], want[key]
        if not approx(g, w):
            raise AssertionError(
                f"[{label}] MISMATCH on '{key}': "
                f"binary printed {g:.4f}, Python expected {w:.4f}"
            )
    print(f"PASS  {label}")


# ──────────────────────────────────────────────────────────────
# Test cases — each one:
#   1. Builds packets with scapy  →  writes a real .pcap file
#   2. Runs the C++ binary with -r <that pcap>
#   3. Parses the "Packet Size Statistics" block from its stdout
#   4. Compares against Python-computed expected values
# ──────────────────────────────────────────────────────────────

def test_single_packet(binary: str):
    """One packet — avg == size, variance == stddev == 0."""
    pkts = [build_packet(100)]
    wire = [len(bytes(p)) for p in pkts]

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        path = f.name
    try:
        write_pcap(pkts, path)
        output = run_binary(binary, path)
        got    = parse_stats_block(output)
        want   = expected_stats(wire)
        assert_stats("test_single_packet", got, want)
    finally:
        os.unlink(path)


def test_identical_packets(binary: str):
    """50 identical-size packets — variance and stddev must be 0."""
    pkts = [build_packet(512)] * 50
    wire = [len(bytes(pkts[0]))] * 50

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        path = f.name
    try:
        write_pcap(pkts, path)
        output = run_binary(binary, path)
        got    = parse_stats_block(output)
        want   = expected_stats(wire)
        assert_stats("test_identical_packets", got, want)
    finally:
        os.unlink(path)


def test_mixed_sizes(binary: str):
    """
    4 packets with very different sizes.
    Python computes expected min/max/avg/variance and checks the binary matches.
    """
    target_sizes = [64, 128, 512, 1400]
    pkts = [build_packet(s) for s in target_sizes]
    wire = [len(bytes(p)) for p in pkts]   # actual wire sizes scapy produces

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        path = f.name
    try:
        write_pcap(pkts, path)
        output = run_binary(binary, path)
        got    = parse_stats_block(output)
        want   = expected_stats(wire)
        assert_stats("test_mixed_sizes", got, want)
    finally:
        os.unlink(path)


def test_min_max_boundaries(binary: str):
    """Smallest and largest packet — checks min/max tracking at boundaries."""
    pkts = [build_packet(64), build_packet(1500)]
    wire = [len(bytes(p)) for p in pkts]

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        path = f.name
    try:
        write_pcap(pkts, path)
        output = run_binary(binary, path)
        got    = parse_stats_block(output)
        want   = expected_stats(wire)
        assert_stats("test_min_max_boundaries", got, want)
    finally:
        os.unlink(path)


def test_large_packet_count(binary: str):
    """
    1000 packets — stress-tests the long long accumulators in main.cpp.
    All same size so expected values are easily verifiable.
    """
    single = build_packet(200)
    pkts   = [single] * 1000
    wire   = [len(bytes(single))] * 1000

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        path = f.name
    try:
        write_pcap(pkts, path)
        output = run_binary(binary, path)
        got    = parse_stats_block(output)
        want   = expected_stats(wire)
        assert_stats("test_large_packet_count", got, want)
    finally:
        os.unlink(path)


def test_realistic_traffic(binary: str):
    """
    Mixed realistic traffic: ACKs + DNS + HTTP + bulk data.
    Python independently computes expected stats and cross-checks
    against what the C++ binary actually prints.
    """
    import random
    random.seed(42)

    profile = [64]*100 + [80]*30 + [512]*50 + [900]*40 + [1400]*30
    random.shuffle(profile)

    pkts = [build_packet(s) for s in profile]
    wire = [len(bytes(p)) for p in pkts]

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        path = f.name
    try:
        write_pcap(pkts, path)
        output = run_binary(binary, path)
        got    = parse_stats_block(output)
        want   = expected_stats(wire)
        assert_stats("test_realistic_traffic", got, want)
    finally:
        os.unlink(path)


# ──────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Integration tests for the Packet Size Statistics block "
            "printed by the compiled main.cpp binary."
        )
    )
    parser.add_argument(
        "--binary",
        default="./dpi_engine",
        help="Path to compiled binary (default: ./dpi_engine)",
    )
    args = parser.parse_args()

    print("=" * 56)
    print("  Packet Size Statistics — Integration Tests")
    print(f"  Binary under test : {args.binary}")
    print("=" * 56)
    print(
        "  Flow:\n"
        "    scapy writes .pcap  →  binary reads it  →\n"
        "    Python parses stdout  →  asserts values match\n"
    )

    tests = [
        test_single_packet,
        test_identical_packets,
        test_mixed_sizes,
        test_min_max_boundaries,
        test_large_packet_count,
        test_realistic_traffic,
    ]

    passed, failed = 0, 0
    for t in tests:
        try:
            t(args.binary)
            passed += 1
        except (AssertionError, ValueError, FileNotFoundError) as e:
            print(f"FAIL  {t.__name__}")
            print(f"      {e}")
            failed += 1

    print("=" * 56)
    print(f"  Results: {passed} passed, {failed} failed")
    print("=" * 56)
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()