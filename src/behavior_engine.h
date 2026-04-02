#pragma once
#include <string>
#include <map>
#include <vector>
#include <ctime>
#include <unordered_set>  // needed for blocklist sets
#include <optional>    // needed for checkMaliciousDomain/IP return type
#include <cstdint>

enum class Severity {
    SAFE,
    SUSPICIOUS,
    DANGER
};

enum class AlertType {
    NONE,
    PORT_SCAN,
    DNS_TUNNELING,
    BEACONING,
    DATA_EXFILTRATION,
    UNKNOWN_TLS,
    HIGH_PACKET_RATE,
    NON_STANDARD_PORT,
    MALICIOUS_DOMAIN,   // Layer 2: DNS query matched known-bad domain list
    MALICIOUS_IP,       // Layer 2: flow to/from a known-bad IP
    TCP_FLAG_ABUSE      // Layer 2: SYN flood, NULL scan, XMAS scan, FIN scan
};

struct Alert {
    AlertType   type;
    Severity    severity;
    std::string flowKey;
    std::string srcIP;
    std::string dstIP;
    int         srcPort = 0;
    int         dstPort = 0;
    std::string message;
    std::string evidence;
};

struct FlowStats {
    std::string srcIP;           // always CLIENT ip
    std::string dstIP;           // always SERVER ip
    int         srcPort         = 0;
    int         dstPort         = 0;
    int         protocol        = 0;
    int         packetCount     = 0;
    int         forwardPackets  = 0;
    int         backwardPackets = 0;
    long        forwardBytes    = 0;
    long        backwardBytes   = 0;
    time_t      firstSeen       = 0;
    time_t      lastSeen        = 0;
    std::string detectedSNI     = "";
    std::string detectedDomain  = "";
    std::string detectedApp     = "";

    // ── Layer 2: TCP flag counters ────────────────────────────
    // Incremented in packetHandler() on every TCP packet.
    // Read by checkTCPFlagAbuse() in behavior_engine.cpp.
    //
    // WHY STORE IN FlowStats?
    // analyzeFlow() only receives a FlowStats — it has no access
    // to the raw packet. So per-packet flag data must be
    // aggregated here as each packet arrives, then evaluated
    // as a whole when analyzeFlow() runs.
    int  synCount    = 0;   // pure SYN (0x02), no ACK — new connection attempt
    int  rstCount    = 0;   // RST (0x04) — hard connection reset
    int  finCount    = 0;   // pure FIN (0x01), no ACK — close attempt with no handshake
    int  nullCount   = 0;   // all flags = 0x00 — nmap NULL scan
    int  xmasCount   = 0;   // FIN+PSH+URG = 0x29 — nmap XMAS scan
    bool synAckSeen  = false; // true once we see a SYN+ACK (handshake completed)
};

struct IPProfile {
    std::string                  ip;
    std::map<std::string, int>   dstPortsContacted;
    int                          totalFlows = 0;
    time_t                       firstSeen  = 0;
    time_t                       lastSeen   = 0;
};

struct RuleConfig {
    // ── Existing rules ────────────────────────────────────────
    int    portScanThreshold          = 10;
    int    dnsTunnelingByteLimit      = 512;
    int    beaconingMinPackets        = 50;
    double beaconingRatioMin          = 0.4;
    double beaconingRatioMax          = 0.6;
    double exfilRatioThreshold        = 3.0;
    int    highPacketRateThreshold    = 500;
    int    minPacketsForAnalysis      = 3;
    long   minBytesBeforeExfilCheck   = 2000;

    // ── Layer 2: TCP flag abuse thresholds ────────────────────
    // synFloodThreshold: how many pure SYNs from one IP on one
    //   flow before we call it a flood. 20 is conservative —
    //   a real SYN flood sends thousands per second. Lower for testing.
    int  synFloodThreshold  = 20;

    // nullScanThreshold / xmasScanThreshold: even 1 is conclusive.
    // The TCP spec forbids zero-flag and FIN+PSH+URG packets in
    // legitimate traffic. There is no false positive risk here.
    int  nullScanThreshold  = 1;
    int  xmasScanThreshold  = 1;
};

// ============================================================
// LAYER 2: THREAT INTELLIGENCE BLOCKLISTS
//
// Declared extern here — DEFINED in behavior_engine.cpp.
// main.cpp calls loadThreatIntel() once at startup.
//
// WHY unordered_set and not vector?
// vector.find() is O(n). With 100,000 IPs and 10,000 packets/sec
// that's 1 billion comparisons per second. unordered_set uses
// a hash table — lookup is O(1) regardless of list size.
// ============================================================
extern std::unordered_set<std::string> badDomains;
extern std::unordered_set<std::string> badIPs;

// ── Function declarations ─────────────────────────────────────

std::string severityToString(Severity s);
std::string alertTypeToString(AlertType t);
void printAlert(const Alert& alert);

// Load blocklist files at startup. Call once in main() before pcap_loop.
// Files are plain text, one entry per line, # = comment.
void loadThreatIntel(
    const std::string& domainsFile = "../assets/bad_domains.txt",
    const std::string& ipsFile     = "../assets/bad_ips.txt"
);

// Called from packetHandler() on every TCP packet.
// tcpFlags = the raw flags byte from the TCP header (tcpHeader->th_flags).
// Updates the synCount, rstCount etc. fields in the flow.
void updateTCPFlags(FlowStats& flow, uint8_t tcpFlags);

// Called from packetHandler() after DNS extraction — fires on packet 1 if matched.
// Does NOT wait for minPacketsForAnalysis like analyzeFlow() does.
std::optional<Alert> checkMaliciousDomain(
    const FlowStats& flow,
    const std::string& domain
);

// Called from packetHandler() on new flow creation — checks both src and dst IP.
std::optional<Alert> checkMaliciousIP(
    const FlowStats& flow,
    const std::string& ip
);

std::vector<Alert> analyzeFlow(
    const FlowStats& flow,
    int              packetSizeBytes,
    bool             isDNS,
    bool             isTLS,
    const RuleConfig& config
);

void updateIPProfile(
    std::map<std::string, IPProfile>& profiles,
    const FlowStats& flow
);

std::vector<Alert> checkPortScan(
    const std::map<std::string, IPProfile>& profiles,
    const RuleConfig& config
);

void resetFiredAlerts();