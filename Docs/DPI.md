**Deep Packet Inspection**

_Concept :_
In DPI We are capturing packets from the network interface , and Analyzing those packets After categorizing those packets in terms of :
DANGER
SUSPICIOUS
SAFE
Depending on the behavior of the packets .

_Actual Work :_

1. Capturing Packets from the interface via wireshark
2. Making a PCAP file
3. Analyzing the PCAP file using C++
4. Analyzing the flow of the packets
   And Detecting the Information About Those packets such as :

App: Google
DNS Query: www.google-analytics.com
Packet captured! Length: 100 bytes
SRC: 192.168.1.1:53
DST: 192.168.1.2:52166
Protocol: UDP
Flow Key: 192.168.1.1:53-192.168.1.2:52166
Total Packets: 2
Forward: 1
Backward: 1

**How we are able to capture the packets and extract information ? :**

1️⃣ Packet Capture – How We Capture Packets

Your engine uses the packet capture library libpcap.

Purpose

It allows a program to directly read packets from the network interface (like eth0).

Key Functions Used
pcap_open_live()

Opens a network interface for live packet capture.

Example:

pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

What it does:

Connects your program to the network interface
Enables packet sniffing
Promiscuous mode allows capturing all packets
pcap_open_offline()

Reads packets from a PCAP file instead of the network.

Your current code uses:

pcap_open_offline("dpi.pcap", errbuf);

This means:

Packets are replayed from a stored file
Useful for testing attack scenarios
pcap_loop()

Continuously reads packets and sends them to a callback function.

Example:

pcap_loop(handle, 0, packetHandler, (u_char\*)&linkType);

Meaning:

Every captured packet is processed by packetHandler().
2️⃣ Packet Processing – Where Extraction Happens

Every packet goes into the function:

packetHandler(...)

Inside this function the DPI extracts network layer, transport layer, and application layer data.

3️⃣ Network Layer Extraction (IP Layer)

Library used:

<netinet/ip.h>

Example:

const struct ip* ipHeader = (struct ip*)(packet + etherOffset);

Extracts:

Source IP
Destination IP
Protocol type

Then converted to readable format using:

inet_ntop(AF_INET, &(ipHeader->ip_src), srcBuf, INET_ADDRSTRLEN);

This gives:

192.168.1.5 → 142.250.182.46
4️⃣ Transport Layer Extraction (TCP / UDP)

Libraries used:

<netinet/tcp.h>
<netinet/udp.h>

Example:

const struct tcphdr* tcpHeader =
(struct tcphdr*)(packet + etherOffset + ipHeaderLen);

Extracts:

Source Port
Destination Port
TCP flags

Example:

srcPort = ntohs(tcpHeader->source);
dstPort = ntohs(tcpHeader->dest);

These identify the service being accessed.

Example:

443 → HTTPS
53 → DNS
80 → HTTP
5️⃣ Application Layer Extraction

Your DPI goes deeper than packet headers.

DNS Domain Extraction

Function used:

extractDomain(...)

It reads the DNS query and extracts the domain name.

Example result:

DNS Query: google.com
TLS SNI Extraction

For encrypted HTTPS traffic.

Function used:

extractSNI(...)

This reads the TLS handshake and extracts the Server Name Indication (SNI).

Example:

TLS SNI: youtube.com

Even though the traffic is encrypted, this metadata is still visible.

QUIC TLS Extraction

For modern HTTP/3 traffic.

Function used:

extractQUICSNI(...)

This extracts SNI from QUIC packets.

6️⃣ Flow Reconstruction

Instead of analyzing packets individually, your DPI builds flows.

A flow represents:

clientIP:clientPort → serverIP:serverPort

Stored using:

std::map<std::string, FlowStats> flowTable;

Each flow tracks:

packet count
bytes transferred
protocol
detected application

These fields are stored in FlowStats .

7️⃣ Intelligence Layer (Threat Detection)

After extraction, the data is analyzed using rule functions such as:

checkMaliciousIP()
checkMaliciousDomain()
checkTCPFlagAbuse()

These detect attacks like:

SYN flood
port scans
DNS tunneling
malicious IP communication

The alerts are stored using the Alert structure .

8️⃣ Full DPI Pipeline (How Everything Works)

Your engine works like this:

Network Interface / PCAP file
│
▼
libpcap capture
│
▼
packetHandler()
│
▼
Header Parsing
(IP / TCP / UDP)
│
▼
Application Extraction
(DNS / TLS SNI)
│
▼
Flow Reconstruction
│
▼
Threat Detection Rules
