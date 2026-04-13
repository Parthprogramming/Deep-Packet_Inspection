#include <pcap.h>
#include <iostream>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <map>
#include <string>
#include <cstring>
#include <algorithm>
#include <csignal>  
#include <fstream>   // for writing the CSV file
#include <sstream>   // for building CSV field strings safely
#include <cmath>    // for std::sqrt()
#include <iomanip>  // for std::fixed, std::setprecision

#include "behavior_engine.h"

static pcap_t* g_handle = nullptr;

static void onSignal(int signum) {
    (void)signum;  // suppress unused parameter warning
    if (g_handle) pcap_breakloop(g_handle);
}

std::vector<Alert> allAlerts;

std::map<std::string, FlowStats>  flowTable;
std::map<std::string, IPProfile>  ipProfiles;
RuleConfig                        ruleConfig;

static long long  pktStatCount       = 0;
static long long  pktStatSum         = 0;
static long long  pktStatSumSquares  = 0;
static uint32_t   pktStatMin         = UINT32_MAX;
static uint32_t   pktStatMax         = 0;

struct FlowSizeAccum {
    long long count        = 0;
    long long sum          = 0;
    long long sumOfSquares = 0;
    uint32_t  minSize      = UINT32_MAX;
    uint32_t  maxSize      = 0;
};


// ── TCP Behavioral Metrics (accumulated per flow in main.cpp) ────────────
// Tracks retransmissions, out-of-order packets, and connection state.
// Lives here (not in FlowStats) because tcpHeader is only visible in
// packetHandler — same pattern as FlowSizeAccum.
struct TCPBehaviorAccum {
    // ── Retransmission & Out-of-Order ─────────────────────────
    uint32_t lastSeq          = 0;       // last sequence number seen
    bool     firstPacket      = true;    // skip comparison on first packet
    uint32_t retransmissions  = 0;       // seq <= lastSeq → likely retransmit
    uint32_t outOfOrder       = 0;       // seq < lastSeq  → arrived late

    // ── Connection State Machine ──────────────────────────────
    // States: 0=INIT, 1=SYN_SENT, 2=SYN_ACK_SEEN, 3=ESTABLISHED, 4=CLOSED
    int      connState        = 0;
    uint32_t rstCount         = 0;       // RST instead of FIN = abnormal close
    uint32_t finCount         = 0;       // normal teardown
    bool     handshakeComplete = false;
};

std::map<std::string, TCPBehaviorAccum> tcpBehavior;

std::map<std::string, FlowSizeAccum> flowSizeStats;

std::string detectApp(const std::string& domain, const std::string& sni = "") {
    const std::string& target = !sni.empty() ? sni : domain;
    if (target.find("youtube")    != std::string::npos) return "YouTube";
    if (target.find("google")     != std::string::npos) return "Google";
    if (target.find("whatsapp")   != std::string::npos) return "WhatsApp";
    if (target.find("facebook")   != std::string::npos) return "Facebook";
    if (target.find("instagram")  != std::string::npos) return "Instagram";
    if (target.find("microsoft")  != std::string::npos) return "Microsoft";
    if (target.find("msn")        != std::string::npos) return "Microsoft";
    if (target.find("vscode")     != std::string::npos) return "VSCode";
    if (target.find("codeium")    != std::string::npos) return "Codeium";
    if (target.find("cloudflare") != std::string::npos) return "Cloudflare";
    if (target.find("amazonaws")  != std::string::npos) return "AWS";
    if (target.find("buyhatke")   != std::string::npos) return "BuyHatke";
    if (target.find("unleash")    != std::string::npos) return "Codeium";
    return "Unknown";
}

std::string extractDomain(const u_char* query, int maxLen) {
    std::string domain = "";
    int i = 0;
    while (i < maxLen && query[i] != 0) {
        int len = query[i]; i++;
        if (i + len > maxLen) return "";
        for (int j = 0; j < len; j++) { domain += (char)query[i]; i++; }
        domain += '.';
    }
    if (!domain.empty()) domain.pop_back();
    return domain;
}

std::string extractSNI(const u_char* data, int len) {
    if (len < 5 || data[0] != 0x16) return "";
    int recordLen = (data[3] << 8) | data[4];
    if (5 + recordLen > len || len < 9 || data[5] != 0x01) return "";
    int offset = 9 + 2 + 32;
    if (offset >= len) return "";
    int sessionIDLen = data[offset]; offset += 1 + sessionIDLen;
    if (offset + 2 > len) return "";
    int cipherLen = (data[offset] << 8) | data[offset+1]; offset += 2 + cipherLen;
    if (offset + 1 > len) return "";
    int compLen = data[offset]; offset += 1 + compLen;
    if (offset + 2 > len) return "";
    int extLen = (data[offset] << 8) | data[offset+1]; offset += 2;
    int extEnd = offset + extLen;
    if (extEnd > len) return "";
    while (offset + 4 <= extEnd) {
        int extType = (data[offset] << 8) | data[offset+1];
        int eLen    = (data[offset+2] << 8) | data[offset+3]; offset += 4;
        if (offset + eLen > extEnd) return "";
        if (extType == 0x0000) {
            if (offset + 5 > extEnd || data[offset+2] != 0) return "";
            int nameLen = (data[offset+3] << 8) | data[offset+4]; offset += 5;
            if (offset + nameLen > extEnd) return "";
            return std::string(reinterpret_cast<const char*>(data + offset), nameLen);
        }
        offset += eLen;
    }
    return "";
}

std::string extractQUICSNI(const u_char* data, int len) {
    if (len < 7 || (data[0] & 0xC0) != 0xC0) return "";
    int offset = 5;
    if (offset >= len) return "";
    int dcidLen = data[offset++]; offset += dcidLen;
    if (offset >= len) return "";
    int scidLen = data[offset++]; offset += scidLen;
    if (offset >= len) return "";
    int tokenLen = data[offset] & 0x3F; offset += 1 + tokenLen;
    if (offset + 2 >= len) return "";
    offset += 3;
    while (offset + 3 < len) {
        if (data[offset] == 0x06) {
            offset += 2;
            if (offset + 2 > len) return "";
            int cryptoLen = (data[offset] << 8) | data[offset+1]; offset += 2;
            if (offset + cryptoLen > len) return "";
            return extractSNI(data + offset, cryptoLen);
        }
        offset++;
    }
    return "";
}

bool isPrivateIP(const std::string& ip) {
    if (ip.rfind("10.", 0) == 0)      return true;
    if (ip.rfind("192.168.", 0) == 0) return true;
    if (ip == "127.0.0.1")            return true;
    if (ip.rfind("172.", 0) == 0) {
        size_t dot2 = ip.find('.', 4);
        if (dot2 != std::string::npos) {
            int oct2 = std::stoi(ip.substr(4, dot2 - 4));
            return (oct2 >= 16 && oct2 <= 31);
        }
    }
    return false;
}

bool determineDirection(
    const std::string& srcIP, int srcPort,
    const std::string& dstIP, int dstPort,
    std::string& clientIP, int& clientPort,
    std::string& serverIP, int& serverPort){
    bool srcPrivate = isPrivateIP(srcIP);
    bool dstPrivate = isPrivateIP(dstIP);

    // ICMP and portless protocols — both ports are 0
    // Direction determined by IP alone, not port number
    if (srcPort == 0 && dstPort == 0) {
        if (srcPrivate && !dstPrivate) {
            clientIP = srcIP;  clientPort = 0;
            serverIP = dstIP;  serverPort = 0;
            return true;
        }
        if (!srcPrivate && dstPrivate) {
            clientIP = dstIP;  clientPort = 0;
            serverIP = srcIP;  serverPort = 0;
            return false;
        }
        // Both private or both public: treat src as client
        clientIP = srcIP;  clientPort = 0;
        serverIP = dstIP;  serverPort = 0;
        return true;
    }

    // TCP / UDP — original logic using IP + port
    if (srcPrivate && !dstPrivate) {
        clientIP = srcIP;  clientPort = srcPort;
        serverIP = dstIP;  serverPort = dstPort;
        return true;
    }
    if (!srcPrivate && dstPrivate) {
        clientIP = dstIP;  clientPort = dstPort;
        serverIP = srcIP;  serverPort = srcPort;
        return false;
    }
    // Both same type — lower port = server's well-known port
    if (srcPort <= dstPort) {
        serverIP = srcIP;  serverPort = srcPort;
        clientIP = dstIP;  clientPort = dstPort;
        return false;
    }
    clientIP = srcIP;  clientPort = srcPort;
    serverIP = dstIP;  serverPort = dstPort;
    return true;
}

// ============================================================
// HELPER: fire an alert immediately (print + store)
// ============================================================
static void fireAlert(const Alert& a) {
    printAlert(a);
    allAlerts.push_back(a);
}

static std::string csvField(const std::string& s) {
    std::string out = "\"";
    for (char c : s) {
        if (c == '"') out += '"'; // escape " by doubling it
        out += c;
    }
    out += '"';
    return out;
}

void packetHandler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {

    int linkType    = *(int*)user;
    int etherOffset = 14;  // default: standard Ethernet II

    uint32_t sz = header->len;
    pktStatCount++;
    pktStatSum        += sz;
    pktStatSumSquares += (long long)sz * sz;
    if (sz < pktStatMin) pktStatMin = sz;
    if (sz > pktStatMax) pktStatMax = sz;
    
    if      (linkType == DLT_NULL || linkType == DLT_LOOP) etherOffset = 4;
    else if (linkType == DLT_LINUX_SLL)                    etherOffset = 16;
    else if (linkType == 276)                              etherOffset = 20;


    if (header->caplen < (u_int)(etherOffset + 20)) return;

    

    const struct ip* ipHeader = (struct ip*)(packet + etherOffset);
    if (ipHeader->ip_p != IPPROTO_TCP  && ipHeader->ip_p != IPPROTO_UDP  && ipHeader->ip_p != IPPROTO_ICMP) return;

    std::string protocol = "UNKNOWN";
    if (ipHeader->ip_p == IPPROTO_ICMP) protocol = "ICMP";

    char srcBuf[INET_ADDRSTRLEN], dstBuf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ipHeader->ip_src), srcBuf, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), dstBuf, INET_ADDRSTRLEN);
    std::string srcIP(srcBuf), dstIP(dstBuf);

    int ipHeaderLen = ipHeader->ip_hl * 4;
    if (ipHeaderLen < 20) return;

    int srcPort = 0, dstPort = 0;
    std::string sni = "", domain = "";
    bool isDNS = false, isTLS = false;

    // ── TCP ──────────────────────────────────────────────────
    // Store the tcpHeader pointer at this scope so we can use it
    // for updateTCPFlags() after the flow table is updated.
    const struct tcphdr* tcpHeader = nullptr;

    if (ipHeader->ip_p == IPPROTO_TCP) {
        if (header->caplen < (u_int)(etherOffset + ipHeaderLen + 20)) return;

        tcpHeader = (struct tcphdr*)(packet + etherOffset + ipHeaderLen);
        srcPort   = ntohs(tcpHeader->source);
        dstPort   = ntohs(tcpHeader->dest);
        protocol  = "TCP";

        if (dstPort == 443 || srcPort == 443) {
            isTLS = true;
            int payloadOffset = etherOffset + ipHeaderLen + tcpHeader->doff * 4;
            if ((int)header->caplen > payloadOffset)
                sni = extractSNI(packet + payloadOffset,
                                 (int)header->caplen - payloadOffset);
        }
    }
    // ── UDP ──────────────────────────────────────────────────
    else if (ipHeader->ip_p == IPPROTO_UDP) {
        if (header->caplen < (u_int)(etherOffset + ipHeaderLen + 8)) return;

        const struct udphdr* udpHeader =
            (struct udphdr*)(packet + etherOffset + ipHeaderLen);
        srcPort = ntohs(udpHeader->source);
        dstPort = ntohs(udpHeader->dest);

        if (dstPort == 443 || srcPort == 443) {
            protocol = "QUIC"; isTLS = true;
            int off = etherOffset + ipHeaderLen + sizeof(struct udphdr);
            if ((int)header->caplen > off)
                sni = extractQUICSNI(packet + off, (int)header->caplen - off);
        }
        else if (srcPort == 53 || dstPort == 53) {
            protocol = "UDP"; isDNS = true;
            int dnsOff = etherOffset + ipHeaderLen + sizeof(struct udphdr) + 12;
            if ((int)header->caplen > dnsOff)
                domain = extractDomain(packet + dnsOff,
                                       (int)header->caplen - dnsOff);
        }
        else { protocol = "UDP"; }
    }

    else if (ipHeader->ip_p == IPPROTO_ICMP) {
    protocol = "ICMP";
    // ICMP has no ports — srcPort/dstPort remain 0
    // Read the ICMP type byte to show what kind of ping message this is
    // ICMP header starts right after the IP header
    const u_char* icmpHeader = packet + etherOffset + ipHeaderLen;
    if (header->caplen >= (u_int)(etherOffset + ipHeaderLen + 1)) {
        uint8_t icmpType = icmpHeader[0];
        // Type 8 = Echo Request (ping sent)
        // Type 0 = Echo Reply  (ping response)
        if (icmpType == 8) protocol = "ICMP_ECHO_REQUEST";
        if (icmpType == 0) protocol = "ICMP_ECHO_REPLY";
    }
}

    // ── Direction + flow key ─────────────────────────────────
    std::string clientIP, serverIP;
    int clientPort = 0, serverPort = 0;
    bool isForward = determineDirection(srcIP, srcPort, dstIP, dstPort,
                                        clientIP, clientPort, serverIP, serverPort);
    std::string flowKey = serverIP + ":" + std::to_string(serverPort) + "-"
                        + clientIP + ":" + std::to_string(clientPort);

    FlowSizeAccum& accum = flowSizeStats[flowKey];
    uint32_t packetSize  = header->len;
    accum.count++;
    accum.sum          += packetSize;
    accum.sumOfSquares += (long long)packetSize * packetSize;
    if (packetSize < accum.minSize) accum.minSize = packetSize;
    if (packetSize > accum.maxSize) accum.maxSize = packetSize;


    // ── TCP Behavioral Metrics update ────────────────────────
    // Only runs for TCP packets — tcpHeader is null for UDP/ICMP.
    if (tcpHeader != nullptr) {
        TCPBehaviorAccum& tb = tcpBehavior[flowKey];
        uint32_t seq   = ntohl(tcpHeader->th_seq);
        uint8_t  flags = (uint8_t)tcpHeader->th_flags;

        // ── 1. Retransmission & Out-of-Order detection ────────
        // Skip the very first packet — nothing to compare against yet.
        if (!tb.firstPacket) {
            if (seq <= tb.lastSeq) {
                // Sequence number did not advance.
                // Could be a retransmit (exact repeat) or out-of-order arrival.
                // We count both here; refine later if needed.
                tb.retransmissions++;
            }
            if (seq < tb.lastSeq) {
                // Strictly less: packet arrived *behind* where we expect.
                // This is classic out-of-order delivery.
                tb.outOfOrder++;
            }
        }
        tb.firstPacket = false;
        tb.lastSeq     = seq;

        // ── 2. Connection State Machine ───────────────────────
        bool isSYN = (flags & TH_SYN) && !(flags & TH_ACK);
        bool isSYN_ACK = (flags & TH_SYN) && (flags & TH_ACK);
        bool isACK = (flags & TH_ACK) && !(flags & TH_SYN);
        bool isRST = (flags & TH_RST);
        bool isFIN = (flags & TH_FIN);

        if (isRST) {
            // RST = abnormal termination regardless of current state
            tb.rstCount++;
            tb.connState = 4; // CLOSED abnormally
        } else if (isFIN) {
            tb.finCount++;
            tb.connState = 4; // CLOSED normally
        } else if (isSYN && tb.connState == 0) {
            tb.connState = 1; // SYN_SENT
        } else if (isSYN_ACK && tb.connState == 1) {
            tb.connState = 2; // SYN_ACK_SEEN
        } else if (isACK && tb.connState == 2) {
            tb.connState = 3; // ESTABLISHED
            tb.handshakeComplete = true;
        }
    }



    // ── Flow table update ─────────────────────────────────────
    bool isNewFlow = (flowTable.find(flowKey) == flowTable.end());

    if (isNewFlow) {
        FlowStats nf;
        nf.srcIP = clientIP; nf.dstIP = serverIP;
        nf.srcPort = clientPort; nf.dstPort = serverPort;
        nf.protocol = ipHeader->ip_p;
        nf.packetCount = 1;
        nf.forwardPackets  = isForward ? 1 : 0;
        nf.backwardPackets = isForward ? 0 : 1;
        nf.forwardBytes    = isForward ? header->len : 0;
        nf.backwardBytes   = isForward ? 0 : header->len;
        nf.firstSeen = nf.lastSeen = time(nullptr);
        nf.detectedSNI    = sni;
        nf.detectedDomain = domain;
        nf.detectedApp    = detectApp(domain, sni);
        flowTable[flowKey] = nf;
        updateIPProfile(ipProfiles, nf);

        // ── LAYER 2: Malicious IP check (new flows only) ─────
        // Check both ends of the new connection against the IP blocklist.
        // We check both because:
        //   clientIP in blocklist → infected machine calling home
        //   serverIP in blocklist → known-bad server being contacted
        auto ipAlert1 = checkMaliciousIP(flowTable[flowKey], clientIP);
        if (ipAlert1.has_value()) fireAlert(ipAlert1.value());


    



        auto ipAlert2 = checkMaliciousIP(flowTable[flowKey], serverIP);
        if (ipAlert2.has_value()) fireAlert(ipAlert2.value());

    } else {
        FlowStats& f = flowTable[flowKey];
        f.packetCount++;
        if (isForward) { f.forwardPackets++;  f.forwardBytes  += header->len; }
        else           { f.backwardPackets++; f.backwardBytes += header->len; }
        f.lastSeen = time(nullptr);
        if (f.detectedSNI.empty() && !sni.empty()) {
            f.detectedSNI = sni;
            f.detectedApp = detectApp(f.detectedDomain, sni);
        }
        if (f.detectedDomain.empty() && !domain.empty()) {
            f.detectedDomain = domain;
            if (f.detectedApp == "Unknown")
                f.detectedApp = detectApp(domain, f.detectedSNI);
        }
    }

    FlowStats& cur = flowTable[flowKey];

    // ── LAYER 2: TCP flag update (every TCP packet) ───────────
    // We update AFTER the flow is created/updated so cur is valid.
    // updateTCPFlags() just increments counters — it never fires alerts.
    // The actual TCP flag abuse rules run inside analyzeFlow() below.
    if (tcpHeader != nullptr) {
        uint8_t flags = (uint8_t)tcpHeader->th_flags;
        updateTCPFlags(cur, flags);
    }

    // ── LAYER 2: Malicious domain check (every DNS packet) ───
    // Runs immediately when a domain is extracted — no minPackets guard.
    // One DNS query to a known-bad domain is conclusive.
    if (!domain.empty()) {
        auto domainAlert = checkMaliciousDomain(cur, domain);
        if (domainAlert.has_value()) fireAlert(domainAlert.value());
    }


    PacketSizeStats pktStats;
    if (accum.count > 0) {
        pktStats.count    = accum.count;
        pktStats.minSize  = accum.minSize;
        pktStats.maxSize  = accum.maxSize;
        pktStats.avg      = (double)accum.sum / accum.count;
        pktStats.variance = ((double)accum.sumOfSquares / accum.count)
                          - (pktStats.avg * pktStats.avg);
        pktStats.stddev   = std::sqrt(pktStats.variance);
    }
    std::vector<Alert> alerts = analyzeFlow(cur, header->len, isDNS, isTLS, ruleConfig, pktStats);
    for (const Alert& a : alerts) fireAlert(a);

    // Port scan check every 10 new flows
    if (isNewFlow && (ipProfiles.size() % 10 == 0)) {
        for (const Alert& a : checkPortScan(ipProfiles, ruleConfig)) fireAlert(a);
    }

    static long long printCounter = 0;
printCounter++;
if (printCounter % 1000 == 0) {


    // ── Console output ────────────────────────────────────────
    std::string app = cur.detectedApp.empty() ? "Unknown" : cur.detectedApp;
std::cout << "\nApp: " << app << "\n";
if (!sni.empty())    std::cout << "TLS SNI: " << sni << "\n";
if (!domain.empty()) std::cout << "DNS Query: " << domain << "\n";
std::cout << "Packet captured! Length: " << header->len << " bytes\n"
          << "SRC: " << srcIP  << ":" << srcPort  << "\n"
          << "DST: " << dstIP  << ":" << dstPort  << "\n"
          << "Protocol: " << protocol << "\n";
if (isNewFlow) std::cout << "New Flow Created!\n";
std::cout << "Flow Key: "      << flowKey << "\n"
          << "Client: "        << clientIP << ":" << clientPort << "\n"
          << "Server: "        << serverIP << ":" << serverPort << "\n"
          << "Total Packets: " << cur.packetCount << "\n"
          << "Fwd (c->s): "    << cur.forwardPackets
          << "  Fwd bytes: "   << cur.forwardBytes  << "\n"
          << "Bwd (s->c): "    << cur.backwardPackets
          << "  Bwd bytes: "   << cur.backwardBytes << "\n";

    
    
    double avg      = (double)accum.sum / accum.count;
    double variance = ((double)accum.sumOfSquares / accum.count) - (avg * avg);
    double stddev   = std::sqrt(variance);
    std::cout << std::fixed << std::setprecision(2)
              << "Pkt Min: "  << accum.minSize << " bytes"
              << "  Max: "    << accum.maxSize << " bytes"
              << "  Avg: "    << avg           << " bytes"
              << "  Var: "    << variance
              << "  StdDev: " << stddev        << " bytes\n";



    

        // ── TCP Behavioral Metrics console output ─────────────────
    if (tcpHeader != nullptr) {
        const TCPBehaviorAccum& tb = tcpBehavior[flowKey];
        const char* stateStr[] = {"INIT","SYN_SENT","SYN_ACK_SEEN","ESTABLISHED","CLOSED"};
        std::cout << "TCP Retransmissions: " << tb.retransmissions
                  << "  Out-of-Order: "      << tb.outOfOrder
                  << "  RST: "               << tb.rstCount
                  << "  FIN: "               << tb.finCount
                  << "  State: "             << stateStr[tb.connState]
                  << (tb.handshakeComplete ? " [Handshake OK]" : "") << "\n";

    // ── Behavioral analysis (existing + Layer 2 TCP flag rules) ─
    std::vector<Alert> alerts = analyzeFlow(cur, header->len, isDNS, isTLS, ruleConfig);
    for (const Alert& a : alerts) fireAlert(a);

    // Port scan check every 10 new flows
    if (isNewFlow && (ipProfiles.size() % 10 == 0)) {
        for (const Alert& a : checkPortScan(ipProfiles, ruleConfig)) fireAlert(a);

    }

    std::cout << "------------------------\n";
}

}





static void exportFlowsToCSV(const std::string& filename) {

    std::ofstream f(filename , std::ios::app);
    if (!f.is_open()) {
        std::cerr << "[CSV] ERROR: cannot open '" << filename << "' for writing.\n";
        return;
    }

    // Write header row
    f.seekp(0, std::ios::end);
    if(f.tellp()==0){
        f << "flow_id,src_ip,dst_ip,src_port,dst_port,protocol,"

  << "packet_count,fwd_bytes,bwd_bytes,app,sni,domain,"
  << "pkt_min,pkt_max,pkt_avg,pkt_variance,pkt_stddev,"
  << "tcp_retransmissions,tcp_out_of_order,tcp_rst_count,tcp_fin_count,"
  << "tcp_conn_state,tcp_handshake_ok,"
  << "threat,severity,evidence\n";

      << "packet_count,fwd_bytes,bwd_bytes,app,sni,domain,"
      << "threat,severity,evidence\n";

    }

    int flowId = 1;
    {
        std::ifstream countFile(filename);
        std::string line;
        while(std::getline(countFile, line)) flowId++;
        if (flowId > 1) flowId-- ;
    }

    for (const auto& [key, flow] : flowTable) {

        // ── Collect all alerts for this flow ─────────────────
        // Build pipe-separated strings for threat, severity, evidence
        // so multiple alerts on one flow stay in one row.
        std::string threatStr   = "";
        std::string severityStr = "";
        std::string evidenceStr = "";
        Severity    worstSev    = Severity::SAFE;
        bool        hasAlert    = false;

        for (const Alert& a : allAlerts) {
            if (a.flowKey != (flow.srcIP + " -> " + flow.dstIP)) continue;

            hasAlert = true;

            // Append alert type
            if (!threatStr.empty()) threatStr += " | ";
            threatStr += alertTypeToString(a.type);

            // Append evidence
            if (!evidenceStr.empty()) evidenceStr += " | ";
            evidenceStr += a.evidence;

            // Track worst severity
            if (a.severity == Severity::DANGER)
                worstSev = Severity::DANGER;
            else if (a.severity == Severity::SUSPICIOUS && worstSev != Severity::DANGER)
                worstSev = Severity::SUSPICIOUS;
        }

        if (hasAlert) {
            severityStr = severityToString(worstSev);
        }
        // Flows with no alerts get empty threat/severity/evidence columns

        // ── Resolve protocol number to name ──────────────────
        std::string protoName;
        switch (flow.protocol) {
            case IPPROTO_TCP:  protoName = "TCP";  break;
            case IPPROTO_UDP:  protoName = "UDP";  break;
            case IPPROTO_ICMP: protoName = "ICMP"; break;
            default:           protoName = std::to_string(flow.protocol);
        }

        // ── Write one CSV row ─────────────────────────────────

        const FlowSizeAccum& acc = flowSizeStats[key];
    double avg = 0.0, variance = 0.0, stddev = 0.0;
    if (acc.count > 0) {
        avg      = (double)acc.sum / acc.count;
        variance = ((double)acc.sumOfSquares / acc.count) - (avg * avg);
        stddev   = std::sqrt(variance);
    }
    uint32_t minSz = (acc.count > 0) ? acc.minSize : 0;
    uint32_t maxSz = acc.maxSize;

    const TCPBehaviorAccum& tb = tcpBehavior[key];
        const char* stateStr[] = {"INIT","SYN_SENT","SYN_ACK_SEEN","ESTABLISHED","CLOSED"};

        f << std::fixed << std::setprecision(2);
        f << flowId++                                      << ","
          << csvField(flow.srcIP)                          << ","
          << csvField(flow.dstIP)                          << ","
          << flow.srcPort                                  << ","
          << flow.dstPort                                  << ","
          << csvField(protoName)                           << ","
          << flow.packetCount                              << ","
          << flow.forwardBytes                             << ","
          << flow.backwardBytes                            << ","
          << csvField(flow.detectedApp)                    << ","
          << csvField(flow.detectedSNI)                    << ","
          << csvField(flow.detectedDomain)                 << ","
          << minSz                                         << ","
          << maxSz                                         << ","
          << avg                                           << ","
          << variance                                      << ","
          << stddev                                        << ","
          << tb.retransmissions                            << ","
          << tb.outOfOrder                                 << ","
          << tb.rstCount                                   << ","
          << tb.finCount                                   << ","
          << csvField(std::string(stateStr[tb.connState])) << ","
          << (tb.handshakeComplete ? 1 : 0)                << ","
          << csvField(threatStr)                           << ","
          << csvField(severityStr)                         << ","
          << csvField(evidenceStr)                         << "\n";

        f << flowId++                         << ","
          << csvField(flow.srcIP)             << ","
          << csvField(flow.dstIP)             << ","
          << flow.srcPort                     << ","
          << flow.dstPort                     << ","
          << csvField(protoName)              << ","
          << flow.packetCount                 << ","
          << flow.forwardBytes                << ","
          << flow.backwardBytes               << ","
          << csvField(flow.detectedApp)       << ","
          << csvField(flow.detectedSNI)       << ","
          << csvField(flow.detectedDomain)    << ","
          << csvField(threatStr)              << ","
          << csvField(severityStr)            << ","
          << csvField(evidenceStr)            << "\n";

    }

    f.close();
    std::cout << "[CSV] Flow report written to: " << filename
              << "  (" << (flowId - 1) << " flows)\n";
}

int main(int argc, char* argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];

    // ── Interface selection ───────────────────────────────────
    // Default to "eth0" if no argument given.
    // On WSL2, eth0 is the virtual Ethernet adapter — it captures
    // all traffic generated from inside the WSL2 environment
    // (curl, ping, wget, apt, etc.) but NOT Windows host traffic.
    //
    // Usage:
    //   sudo ./dpi_engine          → captures on eth0 (default)
    //   sudo ./dpi_engine eth0     → same
    //   sudo ./dpi_engine lo       → loopback only
    //   ./dpi_engine -r file.pcap  → read from pcap file (no sudo needed)
    const char* interface = (argc >= 2) ? argv[1] : "eth0";
    bool        liveMode  = true;

    // ── Rule thresholds ───────────────────────────────────────
    ruleConfig.beaconingMinPackets     = 50;
    ruleConfig.dnsTunnelingByteLimit   = 512;
    ruleConfig.exfilRatioThreshold     = 3.0;
    ruleConfig.portScanThreshold       = 10;
    ruleConfig.highPacketRateThreshold = 500;
    ruleConfig.minPacketsForAnalysis   = 3;

    ruleConfig.synFloodThreshold       = 10;

    ruleConfig.synFloodThreshold       = 20;

    ruleConfig.nullScanThreshold       = 1;
    ruleConfig.xmasScanThreshold       = 1;

    loadThreatIntel("../assets/bad_domains.txt", "../assets/bad_ips.txt");

    // ── Open capture source ───────────────────────────────────
    // Two modes depending on the argument:
    //   -r <file>   → offline pcap file (no sudo, no NAT issues)
    //   <interface> → live capture from NIC (needs sudo)
    if (argc >= 3 && std::string(argv[1]) == "-r") {
        // Offline mode: ./dpi_engine -r dpi.pcap
        liveMode  = false;
        interface = argv[2];
        g_handle  = pcap_open_offline(interface, errbuf);
        if (!g_handle) {
            std::cerr << "Error opening pcap file '" << interface
                      << "': " << errbuf << "\n";
            return 1;
        }
        std::cout << "Mode     : OFFLINE (reading from file)\n";
        std::cout << "File     : " << interface << "\n";

    } else {
        // Live mode: sudo ./dpi_engine eth0
        // pcap_open_live() arguments:
        //   interface — NIC name ("eth0", "lo", "any")
        //   65535     — snaplen: capture full packet, nothing truncated
        //   1         — promiscuous mode ON: see all packets on the wire
        //               (not just those addressed to this machine)
        //   1000      — read timeout ms: pcap_loop() wakes up every 1s
        //               even with no packets — keeps Ctrl+C responsive

        g_handle = pcap_create(interface, errbuf);
if (!g_handle) {
    std::cerr << "Error creating pcap handle: " << errbuf << "\n";
    return 1;
}
pcap_set_snaplen(g_handle, 65535);
pcap_set_promisc(g_handle, 1);
pcap_set_timeout(g_handle, 1000);
pcap_set_buffer_size(g_handle, 64 * 1024 * 1024);  // 64MB ring buffer
if (pcap_activate(g_handle) != 0) {
    std::cerr << "Error activating pcap: " << pcap_geterr(g_handle) << "\n";
    return 1;
}
std::cout << "Mode     : LIVE capture\n";
std::cout << "Interface: " << interface << "\n";

        g_handle = pcap_open_live(interface, 65535, 1, 1000, errbuf);
        if (!g_handle) {
            std::cerr << "Error opening interface '" << interface
                      << "': " << errbuf << "\n";
            std::cerr << "Hint: run with sudo, or check: ip link show\n";
            return 1;
        }
        std::cout << "Mode     : LIVE capture\n";
        std::cout << "Interface: " << interface << "\n";

    }

    // ── Register Ctrl+C handler ───────────────────────────────
    // pcap_breakloop() tells pcap_loop() to stop cleanly after
    // the current packet. Without this, Ctrl+C kills the process
    // immediately and the final report and CSV never write.
    signal(SIGINT, onSignal);

    int linkType = pcap_datalink(g_handle);
    std::cout << "Link type: " << linkType << "  |  Ether offset: "
              << ((linkType == DLT_NULL || linkType == DLT_LOOP) ? 4  :
                  (linkType == DLT_LINUX_SLL)                    ? 16 :
                  (linkType == 276)                              ? 20 : 14)
              << " bytes\n";

    if (liveMode)
        std::cout << "Press Ctrl+C to stop capture and write the report.\n\n";
    else
        std::cout << "Reading packets...\n\n";

    // ── Capture loop ──────────────────────────────────────────
    // 0 = run forever (live) or until end-of-file (offline).
    // Stops when: file ends (offline), Ctrl+C (live), or error.
    pcap_loop(g_handle, 0, packetHandler, (u_char*)&linkType);

    if (pktStatCount > 0) {
    double avg      = (double)pktStatSum / pktStatCount;
    double variance = ((double)pktStatSumSquares / pktStatCount) - (avg * avg);
    double stddev   = std::sqrt(variance);   // add <cmath> to includes

    std::cout << "\n── Packet Size Statistics ──────────────────────\n";
    std::cout << "  Packets analysed : " << pktStatCount          << "\n";
    std::cout << "  Min size         : " << pktStatMin << " bytes\n";
    std::cout << "  Max size         : " << pktStatMax << " bytes\n";
    std::cout << std::fixed << std::setprecision(2);  // add <iomanip>
    std::cout << "  Avg size         : " << avg        << " bytes\n";
    std::cout << "  Variance         : " << variance               << "\n";
    std::cout << "  Std Deviation    : " << stddev     << " bytes\n";
    std::cout << "────────────────────────────────────────────────\n";
}

    // ── Post-capture analysis ─────────────────────────────────
    for (const Alert& a : checkPortScan(ipProfiles, ruleConfig))
        allAlerts.push_back(a);


    for (const Alert& a : checkSYNFlood(flowTable, ipProfiles, ruleConfig))
        allAlerts.push_back(a);



    int dangerCount = 0, suspiciousCount = 0;
    for (const Alert& a : allAlerts) {
        if (a.severity == Severity::DANGER)     dangerCount++;
        if (a.severity == Severity::SUSPICIOUS) suspiciousCount++;
    }

    std::cout << "\n####################################################\n";
    std::cout << "#           DEEP PACKET INSPECTION REPORT         #\n";
    std::cout << "####################################################\n";
    std::cout << "  Flows analysed : " << flowTable.size()  << "\n";
    std::cout << "  IPs tracked    : " << ipProfiles.size() << "\n";
    std::cout << "  Total alerts   : " << allAlerts.size()  << "\n";
    std::cout << "  DANGER         : " << dangerCount       << "\n";
    std::cout << "  SUSPICIOUS     : " << suspiciousCount   << "\n";
    std::cout << "####################################################\n";

    if (dangerCount > 0) {
        std::cout << "\n[ DANGER ALERTS — Immediate Attention Required ]\n";
        std::cout << "--------------------------------------------------\n";
        for (const Alert& a : allAlerts) {
            if (a.severity != Severity::DANGER) continue;
            std::cout << "  Type     : " << alertTypeToString(a.type) << "\n";
            std::cout << "  Flow     : " << a.flowKey                 << "\n";
            std::cout << "  Message  : " << a.message                 << "\n";
            std::cout << "  Evidence : " << a.evidence                << "\n";
            std::cout << "  --\n";
        }
    }

    if (suspiciousCount > 0) {
        std::cout << "\n[ SUSPICIOUS ALERTS — Investigate Further ]\n";
        std::cout << "--------------------------------------------\n";
        for (const Alert& a : allAlerts) {
            if (a.severity != Severity::SUSPICIOUS) continue;
            std::cout << "  Type     : " << alertTypeToString(a.type) << "\n";
            std::cout << "  Flow     : " << a.flowKey                 << "\n";
            std::cout << "  Message  : " << a.message                 << "\n";
            std::cout << "  Evidence : " << a.evidence                << "\n";
            std::cout << "  --\n";
        }
    }

    if (allAlerts.empty())
        std::cout << "\n  No anomalies detected.\n";

    std::cout << "\n####################################################\n";

    exportFlowsToCSV("dpi_report.csv");
    pcap_close(g_handle);
    return 0;
}