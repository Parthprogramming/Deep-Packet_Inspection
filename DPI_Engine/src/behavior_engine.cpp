// ============================================================
// behavior_engine.cpp
// ============================================================

#include "behavior_engine.h"
#include <iostream>
#include <optional>
#include <sstream>
#include <cmath>
#include <set>
#include <fstream>      // for reading blocklist files
#include <algorithm>    // for std::transform (lowercase)

// ============================================================
// LAYER 2: THREAT INTELLIGENCE BLOCKLIST DEFINITIONS
// Declared extern in behavior_engine.h, defined here.
// ============================================================
std::unordered_set<std::string> badDomains;
std::unordered_set<std::string> badIPs;

// ============================================================
// loadThreatIntel()
// Called once from main() before pcap_loop().
//
// FILE FORMAT: plain text, one entry per line.
//   Lines starting with # are comments — skipped.
//   Blank lines are skipped.
//   Windows line endings (\r\n) are handled automatically.
//
// Both files are OPTIONAL — if missing, the engine continues
// with the blocklist simply empty (no matches possible).
// This prevents a startup crash from breaking your capture.
// ============================================================
void loadThreatIntel(const std::string& domainsFile,
                     const std::string& ipsFile)
{
    // ── Load bad domains ──────────────────────────────────────
    {
        std::ifstream f(domainsFile);
        if (!f.is_open()) {
            std::cerr << "[ThreatIntel] WARNING: '" << domainsFile
                      << "' not found — domain blocklist empty.\n";
        } else {
            std::string line;
            int count = 0;
            while (std::getline(f, line)) {
                // Skip comments and blank lines
                if (line.empty() || line[0] == '#') continue;
                // Strip Windows carriage return and trailing spaces
                while (!line.empty() && (line.back() == '\r' || line.back() == ' '))
                    line.pop_back();
                // Domains are case-insensitive — normalize to lowercase
                std::transform(line.begin(), line.end(), line.begin(), ::tolower);
                if (!line.empty()) { badDomains.insert(line); count++; }
            }
            std::cout << "[ThreatIntel] Loaded " << count
                      << " malicious domains.\n";
        }
    }

    // ── Load bad IPs ──────────────────────────────────────────
    {
        std::ifstream f(ipsFile);
        if (!f.is_open()) {
            std::cerr << "[ThreatIntel] WARNING: '" << ipsFile
                      << "' not found — IP blocklist empty.\n";
        } else {
            std::string line;
            int count = 0;
            while (std::getline(f, line)) {
                if (line.empty() || line[0] == '#') continue;
                while (!line.empty() && (line.back() == '\r' || line.back() == ' '))
                    line.pop_back();
                if (!line.empty()) { badIPs.insert(line); count++; }
            }
            std::cout << "[ThreatIntel] Loaded " << count
                      << " malicious IPs.\n";
        }
    }
}

// ============================================================
// KNOWN SAFE SERVER WHITELIST (existing — unchanged)
// ============================================================
static bool isKnownSafeServer(const std::string& ip) {
    if (ip.rfind("13.107.", 0) == 0) return true;
    if (ip.rfind("13.67.",  0) == 0) return true;
    if (ip.rfind("20.",     0) == 0) return true;
    if (ip.rfind("52.",     0) == 0) return true;
    if (ip.rfind("40.",     0) == 0) return true;
    if (ip.rfind("142.250.",0) == 0) return true;
    if (ip.rfind("172.217.",0) == 0) return true;
    if (ip.rfind("35.223.", 0) == 0) return true;
    if (ip.rfind("35.186.", 0) == 0) return true;
    if (ip.rfind("34.",     0) == 0) return true;
    if (ip.rfind("104.16.", 0) == 0) return true;
    if (ip.rfind("104.17.", 0) == 0) return true;
    if (ip.rfind("104.18.", 0) == 0) return true;
    if (ip.rfind("104.19.", 0) == 0) return true;
    if (ip.rfind("104.20.", 0) == 0) return true;
    if (ip.rfind("104.21.", 0) == 0) return true;
    if (ip.rfind("104.22.", 0) == 0) return true;
    if (ip.rfind("104.26.", 0) == 0) return true;
    if (ip.rfind("172.64.", 0) == 0) return true;
    if (ip.rfind("172.67.", 0) == 0) return true;
    if (ip.rfind("23.217.", 0) == 0) return true;
    if (ip.rfind("2.16.",   0) == 0) return true;
    return false;
}

// ============================================================
// ALERT DEDUPLICATION (existing — unchanged)
// ============================================================
static std::set<std::string> firedAlerts;

// Forward-declare alertTypeToString so hasAlreadyFired can use it.
// The full definition is below in the HELPERS section.
std::string alertTypeToString(AlertType t);

static bool hasAlreadyFired(const std::string& dedupKey, AlertType type) {
    std::string key = dedupKey + ":" + alertTypeToString(type);
    return firedAlerts.count(key) > 0;
}

static void markAsFired(const std::string& dedupKey, AlertType type) {
    std::string key = dedupKey + ":" + alertTypeToString(type);
    firedAlerts.insert(key);
}

void resetFiredAlerts() {
    firedAlerts.clear();
}

// Build a consistent dedup key from a flow's client/server identity.
static std::string makeDedupKey(const FlowStats& flow) {
    return flow.srcIP + ":" + std::to_string(flow.srcPort)
         + "-" + flow.dstIP + ":" + std::to_string(flow.dstPort);
}

// ============================================================
// HELPERS
// ============================================================
std::string severityToString(Severity s) {
    switch (s) {
        case Severity::SAFE:       return "SAFE";
        case Severity::SUSPICIOUS: return "SUSPICIOUS";
        case Severity::DANGER:     return "DANGER";
        default:                   return "UNKNOWN";
    }
}

std::string alertTypeToString(AlertType t) {
    switch (t) {
        case AlertType::PORT_SCAN:         return "PORT_SCAN";
        case AlertType::DNS_TUNNELING:     return "DNS_TUNNELING";
        case AlertType::BEACONING:         return "BEACONING";
        case AlertType::DATA_EXFILTRATION: return "DATA_EXFILTRATION";
        case AlertType::UNKNOWN_TLS:       return "UNKNOWN_TLS";
        case AlertType::HIGH_PACKET_RATE:  return "HIGH_PACKET_RATE";
        case AlertType::NON_STANDARD_PORT: return "NON_STANDARD_PORT";
        case AlertType::MALICIOUS_DOMAIN:  return "MALICIOUS_DOMAIN";
        case AlertType::MALICIOUS_IP:      return "MALICIOUS_IP";
        case AlertType::TCP_FLAG_ABUSE:    return "TCP_FLAG_ABUSE";
        case AlertType::NONE:              return "NONE";
        default:                           return "UNKNOWN";
    }
}

void printAlert(const Alert& alert) {
    std::string prefix;
    switch (alert.severity) {
        case Severity::SAFE:       prefix = "[  SAFE  ]"; break;
        case Severity::SUSPICIOUS: prefix = "[WARNING ]"; break;
        case Severity::DANGER:     prefix = "[ DANGER ]"; break;
    }
    std::cout << "\n" << prefix
              << " " << alertTypeToString(alert.type) << "\n"
              << "  Flow    : " << alert.flowKey  << "\n"
              << "  Message : " << alert.message  << "\n"
              << "  Evidence: " << alert.evidence << "\n";
}

// ============================================================
// EXISTING RULES (1–5) — unchanged
// ============================================================

static std::optional<Alert> checkDNSTunneling(
    const FlowStats& flow, int packetSizeBytes,
    bool isDNS, const RuleConfig& config,
    const PacketSizeStats& pktStats)
{
    if (!isDNS) return std::nullopt;
    if (packetSizeBytes <= config.dnsTunnelingByteLimit) return std::nullopt;
    std::string dedupKey = flow.srcIP + "-" + flow.dstIP + "-dns";
    if (hasAlreadyFired(dedupKey, AlertType::DNS_TUNNELING)) return std::nullopt;

    // Packet size reinforcement:
    // Normal DNS: avg ≈ 60–120B, low variance.
    // Tunneling:  avg spikes (encoded payload), variance goes high.
    // If both conditions align, escalate to DANGER.
    bool sizePatternConfirms = (pktStats.count >= 3)
                            && (pktStats.avg    > 300.0)
                            && (pktStats.variance > 10000.0);

    Alert a;
    a.type     = AlertType::DNS_TUNNELING;
    a.severity = sizePatternConfirms ? Severity::DANGER : Severity::SUSPICIOUS;
    a.flowKey  = flow.srcIP + " -> " + flow.dstIP;
    a.srcIP    = flow.srcIP;  a.dstIP  = flow.dstIP;
    a.srcPort  = flow.srcPort; a.dstPort = flow.dstPort;
    a.message  = sizePatternConfirms
        ? "DNS tunneling CONFIRMED — packet size statistics match encoded-payload pattern. "
          "Avg size and variance both abnormally high for DNS traffic."
        : "DNS packet is abnormally large. Possible DNS tunneling — "
          "data encoded inside DNS to evade firewall inspection.";
    std::ostringstream oss;
    oss << "Size=" << packetSizeBytes << "B (limit: " << config.dnsTunnelingByteLimit << "B)"
        << " | Avg=" << (int)pktStats.avg << "B"
        << " | Var=" << (int)pktStats.variance
        << " | StdDev=" << (int)pktStats.stddev << "B";
    if (!flow.detectedDomain.empty()) oss << " | Domain: " << flow.detectedDomain;
    a.evidence = oss.str();
    markAsFired(dedupKey, AlertType::DNS_TUNNELING);
    return a;
}

static std::optional<Alert> checkBeaconing(
    const FlowStats& flow, const RuleConfig& config)
{
    if (flow.packetCount < config.beaconingMinPackets) return std::nullopt;
    double fwdRatio = (double)flow.forwardPackets / flow.packetCount;
    if (fwdRatio < config.beaconingRatioMin || fwdRatio > config.beaconingRatioMax)
        return std::nullopt;
    
    // ── EXCLUDE SYN FLOODS ─────────────────────────────────────
    // SYN floods have high packet counts with asymmetric forward/backward
    // ratio (all SYN packets). Don't misclassify as beaconing.
    // If synCount >= synFloodThreshold and NO handshake completed,
    // it's a SYN flood attack, not C2 beaconing.
    if (flow.synCount >= config.synFloodThreshold && !flow.synAckSeen)
        return std::nullopt;
    
    // ── EXCLUDE OTHER TCP FLAG ATTACKS ─────────────────────────
    // NULL scans, XMAS scans, and FIN scans also produce asymmetric
    // traffic patterns. Don't misclassify these as beaconing either.
    if (flow.nullCount >= config.nullScanThreshold) return std::nullopt;
    if (flow.xmasCount >= config.xmasScanThreshold) return std::nullopt;
    if (flow.finCount > 0 && !flow.synAckSeen && flow.synCount == 0) 
        return std::nullopt;
    
    std::string dk = makeDedupKey(flow);
    if (hasAlreadyFired(dk, AlertType::BEACONING)) return std::nullopt;

    Alert a;
    a.type     = AlertType::BEACONING;
    a.severity = (flow.packetCount > 200) ? Severity::DANGER : Severity::SUSPICIOUS;
    a.flowKey  = flow.srcIP + " -> " + flow.dstIP;
    a.srcIP    = flow.srcIP;  a.dstIP  = flow.dstIP;
    a.srcPort  = flow.srcPort; a.dstPort = flow.dstPort;
    a.message  = "High packet count with near-symmetrical forward/backward ratio. "
                 "Matches C2 beaconing or malware keep-alive pattern.";
    std::ostringstream oss;
    oss << "Packets=" << flow.packetCount
        << " | Fwd=" << flow.forwardPackets << " | Bwd=" << flow.backwardPackets
        << " | Ratio=" << (int)(fwdRatio * 100) << "%";
    a.evidence = oss.str();
    markAsFired(dk, AlertType::BEACONING);
    return a;
}

static std::optional<Alert> checkDataExfiltration(
    const FlowStats& flow, const RuleConfig& config,
    const PacketSizeStats& pktStats)
{
    if (flow.packetCount < config.minPacketsForAnalysis)       return std::nullopt;
    if (flow.forwardBytes  < config.minBytesBeforeExfilCheck)  return std::nullopt;
    if (flow.backwardBytes < config.minBytesBeforeExfilCheck)  return std::nullopt;
    double ratio = (double)flow.forwardBytes / flow.backwardBytes;
    if (ratio < config.exfilRatioThreshold) return std::nullopt;
    std::string dk = makeDedupKey(flow);
    if (hasAlreadyFired(dk, AlertType::DATA_EXFILTRATION)) return std::nullopt;

    // Packet size reinforcement:
    // Exfiltration: attacker sends large packets stuffed with stolen data.
    // max > 1200B means full-sized frames being pushed out.
    // High variance means a mix of control + bulk data packets — typical of exfil.
    bool sizePatternConfirms = (pktStats.count >= 5)
                            && (pktStats.maxSize  > 1200)
                            && (pktStats.variance > 50000.0);

    Alert a;
    a.type     = AlertType::DATA_EXFILTRATION;
    // Escalate if BOTH the byte ratio AND size pattern confirm it
    bool isDanger = (ratio > config.exfilRatioThreshold * 3) || sizePatternConfirms;
    a.severity = isDanger ? Severity::DANGER : Severity::SUSPICIOUS;
    a.flowKey  = flow.srcIP + " -> " + flow.dstIP;
    a.srcIP    = flow.srcIP;  a.dstIP  = flow.dstIP;
    a.srcPort  = flow.srcPort; a.dstPort = flow.dstPort;
    a.message  = sizePatternConfirms
        ? "Data exfiltration CONFIRMED — high forward ratio AND large packet sizes detected. "
          "Bulk data transfer pattern consistent with file theft."
        : "Device sending far more data than receiving after handshake. "
          "Asymmetry suggests data upload or exfiltration.";
    std::ostringstream oss;
    oss << "Fwd=" << flow.forwardBytes << "B | Bwd=" << flow.backwardBytes
        << "B | Ratio=" << (int)ratio << "x (threshold: " << (int)config.exfilRatioThreshold << "x)"
        << " | PktMax=" << pktStats.maxSize << "B"
        << " | PktVar=" << (int)pktStats.variance
        << " | PktAvg=" << (int)pktStats.avg << "B";
    a.evidence = oss.str();
    markAsFired(dk, AlertType::DATA_EXFILTRATION);
    return a;
}

static std::optional<Alert> checkUnknownTLS(
    const FlowStats& flow, bool isTLS, const RuleConfig& config)
{
    bool isTLSPort = (flow.dstPort == 443 || flow.srcPort == 443);
    if (!isTLSPort) return std::nullopt;
    if (flow.packetCount < config.minPacketsForAnalysis) return std::nullopt;
    if (!flow.detectedSNI.empty()) return std::nullopt;
    if (flow.detectedApp != "Unknown" && !flow.detectedApp.empty()) return std::nullopt;
    if (isKnownSafeServer(flow.dstIP)) return std::nullopt;
    if (isKnownSafeServer(flow.srcIP)) return std::nullopt;
    std::string dk = makeDedupKey(flow);
    if (hasAlreadyFired(dk, AlertType::UNKNOWN_TLS)) return std::nullopt;

    Alert a;
    a.type     = AlertType::UNKNOWN_TLS;
    a.severity = Severity::SUSPICIOUS;
    a.flowKey  = flow.srcIP + " -> " + flow.dstIP;
    a.srcIP    = flow.srcIP;  a.dstIP  = flow.dstIP;
    a.srcPort  = flow.srcPort; a.dstPort = flow.dstPort;
    a.message  = "HTTPS to unknown server with no SNI. Could be evasion, "
                 "misconfigured client, or malware C2.";
    std::ostringstream oss;
    oss << "DST=" << flow.dstIP << ":443 | Packets=" << flow.packetCount
        << " | No SNI | App=Unknown";
    a.evidence = oss.str();
    markAsFired(dk, AlertType::UNKNOWN_TLS);
    return a;
}

static std::optional<Alert> checkHighPacketRate(
    const FlowStats& flow, const RuleConfig& config)
{
    if (flow.packetCount < config.highPacketRateThreshold) return std::nullopt;
    std::string dk = makeDedupKey(flow);
    if (hasAlreadyFired(dk, AlertType::HIGH_PACKET_RATE)) return std::nullopt;

    Alert a;
    a.type     = AlertType::HIGH_PACKET_RATE;
    a.severity = Severity::SUSPICIOUS;
    a.flowKey  = flow.srcIP + " -> " + flow.dstIP;
    a.srcIP    = flow.srcIP;  a.dstIP  = flow.dstIP;
    a.srcPort  = flow.srcPort; a.dstPort = flow.dstPort;
    a.message  = "Exceptional packet count on single flow — flood, scanner, or bulk transfer.";
    std::ostringstream oss;
    oss << "Count=" << flow.packetCount
        << " (threshold: " << config.highPacketRateThreshold << ")";
    a.evidence = oss.str();
    markAsFired(dk, AlertType::HIGH_PACKET_RATE);
    return a;
}

// ============================================================
// LAYER 2 — RULE 6: MALICIOUS DOMAIN
//
// LOGIC:
// After extractDomain() gives us a domain string, we check it
// against the badDomains set using suffix matching.
//
// SUFFIX MATCHING — why it matters:
// If the list contains "evil.com" and the query is for
// "c2.stage1.evil.com", a direct lookup misses it.
// We must walk UP the domain tree:
//   check "c2.stage1.evil.com" → not in set
//   check "stage1.evil.com"    → not in set
//   check "evil.com"           → FOUND → DANGER
//
// How we walk up: find the first dot, take everything after it.
// Stop when no more dots remain (we're at the TLD — "com" alone
// matching would block the entire internet).
//
// CALLED FROM: packetHandler() directly — NOT via analyzeFlow().
// Reason: analyzeFlow() has a minPackets guard. We want this
// to fire on packet 1. One DNS query to a known-bad domain
// is conclusive — no threshold needed.
// ============================================================
std::optional<Alert> checkMaliciousDomain(
    const FlowStats& flow,
    const std::string& domain)
{
    if (domain.empty() || badDomains.empty()) return std::nullopt;

    // Lowercase the query (domains are case-insensitive)
    std::string d = domain;
    std::transform(d.begin(), d.end(), d.begin(), ::tolower);

    // Walk up the domain tree doing suffix matching
    std::string current = d;
    bool matched = false;
    std::string matchedEntry;

    while (true) {
        if (badDomains.count(current) > 0) {
            matched = true;
            matchedEntry = current;
            break;
        }
        size_t dot = current.find('.');
        if (dot == std::string::npos) break;   // reached bare TLD — stop
        current = current.substr(dot + 1);
        if (current.find('.') == std::string::npos) break;  // don't match bare TLDs
    }

    if (!matched) return std::nullopt;

    // Dedup key: use the domain itself so we alert once per unique domain
    std::string dedupKey = "domain-" + d;
    if (hasAlreadyFired(dedupKey, AlertType::MALICIOUS_DOMAIN)) return std::nullopt;

    Alert a;
    a.type     = AlertType::MALICIOUS_DOMAIN;
    a.severity = Severity::DANGER;
    a.flowKey  = flow.srcIP + " -> " + flow.dstIP;
    a.srcIP    = flow.srcIP;  a.dstIP  = flow.dstIP;
    a.srcPort  = flow.srcPort; a.dstPort = flow.dstPort;
    a.message  = "DNS query matched known-malicious domain blocklist. "
                 "Device may be infected or attempting C2 communication.";
    a.evidence = "Queried: " + d + " | Matched blocklist entry: " + matchedEntry;
    markAsFired(dedupKey, AlertType::MALICIOUS_DOMAIN);
    return a;
}

// ============================================================
// LAYER 2 — RULE 7: MALICIOUS IP
//
// LOGIC:
// On every new flow, check BOTH the client IP and server IP
// against the badIPs set. Direct O(1) hash lookup.
//
// TWO DIRECTIONS — both matter:
//   Client IP in blocklist → your machine is INFECTED and calling home.
//   Server IP in blocklist → an attacker is TARGETING your machine.
// The evidence string records which direction it is.
//
// CALLED FROM: packetHandler() on new flow creation only.
// Checking every packet is wasteful — the IPs don't change
// mid-flow, so one check per flow is sufficient.
// ============================================================
std::optional<Alert> checkMaliciousIP(
    const FlowStats& flow,
    const std::string& ip)
{
    if (ip.empty() || badIPs.empty()) return std::nullopt;
    if (badIPs.count(ip) == 0) return std::nullopt;

    // Dedup key: per unique bad IP (not per flow — same IP may appear in many flows)
    std::string dedupKey = "ip-" + ip;
    if (hasAlreadyFired(dedupKey, AlertType::MALICIOUS_IP)) return std::nullopt;

    bool isSource = (ip == flow.srcIP);

    Alert a;
    a.type     = AlertType::MALICIOUS_IP;
    a.severity = Severity::DANGER;
    a.flowKey  = flow.srcIP + " -> " + flow.dstIP;
    a.srcIP    = flow.srcIP;  a.dstIP  = flow.dstIP;
    a.srcPort  = flow.srcPort; a.dstPort = flow.dstPort;
    a.message  = isSource
        ? "Local device is CONNECTING TO a known-malicious IP. "
          "Possible infected machine calling home to C2 server."
        : "Known-malicious IP is CONNECTING TO your network. "
          "Possible inbound attack, scan, or exploitation attempt.";
    a.evidence = "Malicious IP: " + ip
               + " | Direction: " + (isSource ? "outbound (we initiated)" : "inbound (they initiated)");
    markAsFired(dedupKey, AlertType::MALICIOUS_IP);
    return a;
}

// ============================================================
// LAYER 2 — updateTCPFlags()
//
// Called from packetHandler() on every TCP packet.
// Reads the raw flags byte from the TCP header and increments
// the appropriate counters in FlowStats.
//
// HOW TO READ TCP FLAGS:
// The TCP flags are one byte in the TCP header. Each bit = one flag:
//
//   Bit 0 (0x01) = FIN  — no more data from sender
//   Bit 1 (0x02) = SYN  — synchronize sequence numbers (new connection)
//   Bit 2 (0x04) = RST  — reset connection immediately (hard close)
//   Bit 3 (0x08) = PSH  — push data to application right now
//   Bit 4 (0x10) = ACK  — acknowledgement field is valid
//   Bit 5 (0x20) = URG  — urgent pointer field is valid
//
// We use bitwise AND (&) to test specific bits:
//   flags & 0x02      → true if SYN bit set
//   (flags & 0x12) == 0x12 → true if BOTH SYN and ACK are set (SYN+ACK)
//   flags == 0x00     → true if ALL flags are zero (NULL scan)
//   (flags & 0x29) == 0x29 → FIN+PSH+URG all set (XMAS scan)
//
// HOW TO CALL THIS FROM packetHandler():
//   const struct tcphdr* tcpHeader = ...;
//   uint8_t flags = (uint8_t)tcpHeader->th_flags;
//   updateTCPFlags(currentFlow, flags);
//
// If th_flags doesn't compile on your platform, use:
//   uint8_t flags = ((const uint8_t*)tcpHeader)[13];
//   (The flags byte is always at byte offset 13 in the TCP header)
// ============================================================
void updateTCPFlags(FlowStats& flow, uint8_t flags) {

    // Pure SYN (NOT SYN+ACK) = new connection attempt, no reply yet
    // SYN+ACK = 0x12. Masking with 0x12 and comparing to 0x02
    // ensures we only count SYN-without-ACK.
    if ((flags & 0x12) == 0x02)
        flow.synCount++;

    // RST — hard connection reset
    if (flags & 0x04)
        flow.rstCount++;

    // Pure FIN (NOT FIN+ACK) with no prior handshake = suspicious
    // Masking with 0x11 (FIN+ACK) and comparing to 0x01 (FIN only)
    if ((flags & 0x11) == 0x01)
        flow.finCount++;

    // NULL scan: all flags are zero
    // Legitimate TCP NEVER sends a zero-flag packet. This is always an attack.
    if (flags == 0x00)
        flow.nullCount++;

    // XMAS scan: FIN(0x01) + PSH(0x08) + URG(0x20) = 0x29
    // "Lights up like a Christmas tree." Never legitimate.
    if ((flags & 0x29) == 0x29)
        flow.xmasCount++;

    // Track handshake completion: SYN+ACK means server accepted the connection.
    // Used to distinguish legitimate SYN bursts from SYN floods.
    if ((flags & 0x12) == 0x12)
        flow.synAckSeen = true;
}

// ============================================================
// LAYER 2 — RULE 8: TCP FLAG ABUSE
//
// Reads the flag counters accumulated by updateTCPFlags()
// and fires alerts for four distinct attack patterns.
//
// This is called from analyzeFlow() — so it runs on every packet
// after the minPackets guard passes. But TCP flag counters are
// populated from packet 1, so by the time this runs there is
// already enough data.
// ============================================================
static std::vector<Alert> checkTCPFlagAbuse(
    const FlowStats& flow,
    const RuleConfig& config)
{
    std::vector<Alert> alerts;
    std::string dk = makeDedupKey(flow);

    // ── A: SYN FLOOD ─────────────────────────────────────────
    // Many SYN packets, zero SYN+ACK responses.
    // A SYN flood is a denial-of-service attack. The attacker
    // sends thousands of SYNs to exhaust the server's half-open
    // connection table (TCP backlog). Legitimate connections
    // always complete: SYN → SYN+ACK → ACK. If we see 20+ SYNs
    // and synAckSeen is still false, the handshake never finished.
    if (flow.synCount >= config.synFloodThreshold && !flow.synAckSeen) {
        std::string synDk = dk + "-synflood";
        if (!hasAlreadyFired(synDk, AlertType::TCP_FLAG_ABUSE)) {
            Alert a;
            a.type     = AlertType::TCP_FLAG_ABUSE;
            a.severity = Severity::DANGER;
            a.flowKey  = flow.srcIP + " -> " + flow.dstIP;
            a.srcIP    = flow.srcIP;  a.dstIP  = flow.dstIP;
            a.srcPort  = flow.srcPort; a.dstPort = flow.dstPort;
            a.message  = "SYN flood detected. High volume of SYN packets with "
                         "no handshake completion — classic denial-of-service attack.";
            std::ostringstream oss;
            oss << "SYN count=" << flow.synCount
                << " (threshold: " << config.synFloodThreshold << ")"
                << " | SYN+ACK seen: NO";
            a.evidence = oss.str();
            markAsFired(synDk, AlertType::TCP_FLAG_ABUSE);
            alerts.push_back(a);
        }
    }

    // ── B: NULL SCAN ─────────────────────────────────────────
    // All TCP flags = 0x00. This is IMPOSSIBLE in legitimate traffic.
    // The TCP spec mandates at least one flag must be set.
    // nmap uses -sN (NULL scan) to probe ports on Unix targets —
    // open ports silently ignore the packet, closed ports send RST.
    // Even ONE null packet is conclusive. Threshold = 1.
    if (flow.nullCount >= config.nullScanThreshold) {
        std::string nullDk = dk + "-nullscan";
        if (!hasAlreadyFired(nullDk, AlertType::TCP_FLAG_ABUSE)) {
            Alert a;
            a.type     = AlertType::TCP_FLAG_ABUSE;
            a.severity = Severity::DANGER;
            a.flowKey  = flow.srcIP + " -> " + flow.dstIP;
            a.srcIP    = flow.srcIP;  a.dstIP  = flow.dstIP;
            a.srcPort  = flow.srcPort; a.dstPort = flow.dstPort;
            a.message  = "NULL scan detected (all TCP flags = 0). "
                         "Legitimate TCP never sends zero-flag packets. "
                         "This is an nmap -sN port scan technique.";
            std::ostringstream oss;
            oss << "NULL packets=" << flow.nullCount << " | SRC=" << flow.srcIP;
            a.evidence = oss.str();
            markAsFired(nullDk, AlertType::TCP_FLAG_ABUSE);
            alerts.push_back(a);
        }
    }

    // ── C: XMAS SCAN ─────────────────────────────────────────
    // FIN + PSH + URG flags all set simultaneously = 0x29.
    // "Christmas tree packet" — all the lights are on.
    // Never appears in real traffic. Used by nmap -sX.
    // Response behaviour same as NULL scan.
    if (flow.xmasCount >= config.xmasScanThreshold) {
        std::string xmasDk = dk + "-xmasscan";
        if (!hasAlreadyFired(xmasDk, AlertType::TCP_FLAG_ABUSE)) {
            Alert a;
            a.type     = AlertType::TCP_FLAG_ABUSE;
            a.severity = Severity::DANGER;
            a.flowKey  = flow.srcIP + " -> " + flow.dstIP;
            a.srcIP    = flow.srcIP;  a.dstIP  = flow.dstIP;
            a.srcPort  = flow.srcPort; a.dstPort = flow.dstPort;
            a.message  = "XMAS scan detected (FIN+PSH+URG flags set simultaneously). "
                         "Never legitimate. nmap -sX port scan technique.";
            std::ostringstream oss;
            oss << "XMAS packets=" << flow.xmasCount << " | SRC=" << flow.srcIP;
            a.evidence = oss.str();
            markAsFired(xmasDk, AlertType::TCP_FLAG_ABUSE);
            alerts.push_back(a);
        }
    }

    // ── D: FIN SCAN ──────────────────────────────────────────
    // FIN packets present, but no SYN and no SYN+ACK.
    // Legitimate FIN only appears AFTER a full handshake.
    // FIN with no prior SYN means there was never a real connection.
    // nmap -sF sends FIN packets to bypass stateless firewalls.
    if (flow.finCount > 0 && !flow.synAckSeen && flow.synCount == 0) {
        std::string finDk = dk + "-finscan";
        if (!hasAlreadyFired(finDk, AlertType::TCP_FLAG_ABUSE)) {
            Alert a;
            a.type     = AlertType::TCP_FLAG_ABUSE;
            a.severity = Severity::SUSPICIOUS;
            a.flowKey  = flow.srcIP + " -> " + flow.dstIP;
            a.srcIP    = flow.srcIP;  a.dstIP  = flow.dstIP;
            a.srcPort  = flow.srcPort; a.dstPort = flow.dstPort;
            a.message  = "FIN scan detected — FIN packet with no prior SYN or handshake. "
                         "Used by nmap -sF to bypass stateless firewalls.";
            std::ostringstream oss;
            oss << "FIN count=" << flow.finCount << " | SYN count=" << flow.synCount
                << " | Handshake completed: NO";
            a.evidence = oss.str();
            markAsFired(finDk, AlertType::TCP_FLAG_ABUSE);
            alerts.push_back(a);
        }
    }

    return alerts;
}

// ============================================================
// IP PROFILE + PORT SCAN (existing — unchanged)
// ============================================================
void updateIPProfile(
    std::map<std::string, IPProfile>& profiles,
    const FlowStats& flow)
{
    IPProfile& profile = profiles[flow.srcIP];
    if (profile.ip.empty()) {
        profile.ip        = flow.srcIP;
        profile.firstSeen = flow.firstSeen;
    }
    profile.totalFlows++;
    profile.lastSeen = flow.lastSeen;
    std::string dstKey = flow.dstIP + ":" + std::to_string(flow.dstPort);
    profile.dstPortsContacted[dstKey]++;
}

std::vector<Alert> checkSYNFlood(
    const std::map<std::string, FlowStats>& flowTable,
    const std::map<std::string, IPProfile>& profiles,
    const RuleConfig& config)
{
    std::vector<Alert> alerts;

    // Build a per-attacker-IP summary: count half-open flows going
    // to the SAME destination IP:port (the victim).
    // Key = "attackerIP -> victimIP:port"
    // Value = count of half-open SYN flows with no SYN+ACK
    struct FloodSummary {
        int    halfOpenCount = 0;
        int    totalSYNs     = 0;
        std::string srcIP;
        std::string dstIP;
        int    dstPort = 0;
    };
    std::map<std::string, FloodSummary> summaries;

    for (const auto& [key, flow] : flowTable) {
        // Only TCP flows with at least one SYN and no completed handshake
        if (flow.synCount == 0) continue;
        if (flow.synAckSeen) continue;

        // Group by "attacker -> victim:port"
        std::string groupKey = flow.srcIP + "->" 
                             + flow.dstIP + ":" 
                             + std::to_string(flow.dstPort);
        FloodSummary& s = summaries[groupKey];
        s.srcIP   = flow.srcIP;
        s.dstIP   = flow.dstIP;
        s.dstPort = flow.dstPort;
        s.halfOpenCount++;
        s.totalSYNs += flow.synCount;
    }

    for (const auto& [gkey, s] : summaries) {
        if (s.halfOpenCount < config.synFloodThreshold) continue;

        std::string dk = s.srcIP + "-synflood-ip";
        if (hasAlreadyFired(dk, AlertType::TCP_FLAG_ABUSE)) continue;

        Alert a;
        a.type     = AlertType::TCP_FLAG_ABUSE;
        a.severity = Severity::DANGER;
        a.flowKey  = s.srcIP + " -> " + s.dstIP;
        a.srcIP    = s.srcIP;
        a.dstIP    = s.dstIP;
        a.srcPort  = 0;
        a.dstPort  = s.dstPort;
        a.message  = "SYN flood detected. One source IP is hammering a single "
                     "destination with SYN packets across many flows — "
                     "no handshakes complete. Classic DoS attack.";
        std::ostringstream oss;
        oss << "Attacker=" << s.srcIP
            << " | Victim=" << s.dstIP << ":" << s.dstPort
            << " | Half-open flows=" << s.halfOpenCount
            << " | Total SYNs=" << s.totalSYNs
            << " (threshold: " << config.synFloodThreshold << ")";
        a.evidence = oss.str();
        markAsFired(dk, AlertType::TCP_FLAG_ABUSE);
        alerts.push_back(a);
    }
    return alerts;
}

std::vector<Alert> checkPortScan(
    const std::map<std::string, IPProfile>& profiles,
    const RuleConfig& config)
{
    std::vector<Alert> alerts;
    for (const auto& [ip, profile] : profiles) {
        if ((int)profile.dstPortsContacted.size() >= config.portScanThreshold) {
            std::string dk = ip + "-portscan";
            if (hasAlreadyFired(dk, AlertType::PORT_SCAN)) continue;
            Alert a;
            a.type     = AlertType::PORT_SCAN;
            a.severity = Severity::DANGER;
            a.srcIP    = ip;  a.dstIP = "multiple";
            a.flowKey  = ip + " -> multiple destinations";
            a.message  = "IP contacted many distinct destination ports — strong port scan signal.";
            std::ostringstream oss;
            oss << "Unique dst ports: " << profile.dstPortsContacted.size()
                << " (threshold: " << config.portScanThreshold << ")"
                << " | Total flows: " << profile.totalFlows;
            a.evidence = oss.str();
            markAsFired(dk, AlertType::PORT_SCAN);
            alerts.push_back(a);
        }
    }
    return alerts;
}


std::vector<Alert> analyzeFlow(
    const FlowStats& flow,
    int              packetSizeBytes,
    bool             isDNS,
    bool             isTLS,
    const RuleConfig& config,
    const PacketSizeStats& pktStats)
{
    std::vector<Alert> alerts;

    auto flagAlerts = checkTCPFlagAbuse(flow, config);
    alerts.insert(alerts.end(), flagAlerts.begin(), flagAlerts.end());

    // All other rules need enough packets to be statistically meaningful.
    if (flow.packetCount < config.minPacketsForAnalysis) return alerts;

    auto r1 = checkDNSTunneling(flow, packetSizeBytes, isDNS, config, pktStats);
    if (r1.has_value()) alerts.push_back(r1.value());

    auto r2 = checkBeaconing(flow, config);
    if (r2.has_value()) alerts.push_back(r2.value());

    auto r3 = checkDataExfiltration(flow, config, pktStats);
    if (r3.has_value()) alerts.push_back(r3.value());

    auto r4 = checkUnknownTLS(flow, isTLS, config);
    if (r4.has_value()) alerts.push_back(r4.value());

    auto r5 = checkHighPacketRate(flow, config);
    if (r5.has_value()) alerts.push_back(r5.value());

    return alerts;
}