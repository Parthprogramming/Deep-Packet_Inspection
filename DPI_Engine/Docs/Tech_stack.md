Language : C++
OS : Linux via WSL (Windows Subsystem Linux)

Packet Capturing : 
WireShark for Offline Packet Capture (generating a pcap file)

Libraries : 

1️⃣ <pcap.h>

Primary library for packet capture.

It comes from libpcap, which allows programs to read raw packets from a network interface or from .pcap files.

What it provides

Functions for:

opening network interfaces
reading packets
processing packets
Important functions
pcap_open_live()
pcap_open_offline()
pcap_loop()
pcap_close()
In your DPI

It is responsible for:

Network interface → packets → your program

Without this library, your program cannot sniff packets.

2️⃣ <iostream>

Provides input and output streams for C++.

What it provides

Objects like:

std::cout
std::cin
std::cerr
In your DPI

Used for printing packet information:

std::cout << "Packet captured!" << std::endl;

So it is mainly used for console output and debugging logs.

3️⃣ <netinet/ip.h>

Defines the IP header structure.

What it provides

The structure:

struct ip

Which represents the IPv4 packet header.

Fields include:

source IP
destination IP
protocol
header length
In your DPI

You use it like this:

struct ip* ipHeader = (struct ip*)(packet + etherOffset);

This lets you extract:

Source IP
Destination IP
Protocol

So this library enables network-layer packet parsing.

4️⃣ <arpa/inet.h>

Provides functions for IP address conversion and network byte order operations.

Why this is needed

IP addresses inside packets are stored in binary format.

Example inside packet:

0xC0A80101

Humans cannot read this.

Important functions
inet_ntop()

Converts binary IP → readable string.

Example:

inet_ntop(AF_INET, &(ipHeader->ip_src), srcBuf, INET_ADDRSTRLEN);

Result:

192.168.1.1
ntohs()

Converts network byte order → host byte order.

Example:

srcPort = ntohs(tcpHeader->source);

Without this conversion, ports would appear wrong.

5️⃣ <netinet/tcp.h>

Defines the TCP header structure.

What it provides

The structure:

struct tcphdr

Which contains fields like:

source port
destination port
sequence number
acknowledgement
TCP flags
In your DPI

Used like:

struct tcphdr* tcpHeader =
(struct tcphdr*)(packet + etherOffset + ipHeaderLen);

This lets your engine detect:

SYN
ACK
RST
FIN

Which is required for detecting attacks like:

SYN flood
NULL scan
XMAS scan
6️⃣ <netinet/udp.h>

Defines the UDP header structure.

What it provides
struct udphdr

Fields include:

source port
destination port
length
checksum
In your DPI

Used to extract DNS traffic:

const struct udphdr* udpHeader =
(struct udphdr*)(packet + etherOffset + ipHeaderLen);

This allows your engine to detect:

DNS traffic
QUIC traffic
7️⃣ <map>

Provides the C++ ordered associative container std::map.

What it does

Stores key-value pairs.

Example:

key → value
In your DPI
std::map<std::string, FlowStats> flowTable;

This stores:

Flow key → flow statistics

Example:

142.250.190.46:443-192.168.1.5:51422

Mapped to:

packet count
bytes transferred
application detected

So it helps track network flows.

8️⃣ <string>

Provides the C++ string class.

Instead of C-style arrays like:

char name[50]

You use:

std::string
In your DPI

Used everywhere:

IP addresses
domains
SNI values
flow keys

Example:

std::string srcIP(srcBuf);
9️⃣ <cstring>

Provides C-style string manipulation functions.

Examples include:

memcpy()
memcmp()
strlen()
strcmp()
In your DPI

Mostly used when handling raw packet data buffers.

Example operations:

copy packet payload
compare byte sequences

This is important when reading raw network packets.

🔟 <algorithm>

Provides common algorithms for containers and strings.

Examples:

std::transform
std::find
std::sort
In your DPI

You use:

std::transform(domain.begin(), domain.end(), domain.begin(), ::tolower);

This converts domains to lowercase before checking blocklists.

Why?

Because domain names are case-insensitive.

1️⃣1️⃣ <csignal>

Provides support for signal handling.

Signals are OS notifications such as:

SIGINT  (Ctrl+C)
SIGTERM (terminate)
Example use
signal(SIGINT, handler);
In DPI systems

Used to:

gracefully stop packet capture
close files
flush logs
1️⃣2️⃣ <fstream>

Provides file input/output streams.

Used to read or write files.

Important classes
std::ifstream  (read files)
std::ofstream  (write files)
In your DPI

Used to:

write flow data to CSV
read threat intelligence lists

Example:

std::ofstream csv("flows.csv");
1️⃣3️⃣ <sstream>

Provides string stream processing.

It allows strings to behave like streams.

Example
std::ostringstream oss;
oss << "Packets=" << flow.packetCount;

Result:

"Packets=120"
In your DPI

Used to construct:

alert messages
evidence strings
log lines


**Architecture :** 
behavior_engine.h - This file contains the variables , arrays etc which are used by other files 
behavior_engine.cpp - Contains the main logic of the Determining whether the packets are safe , suspicious , danger 
main.cpp - Responsible for the work of Packet capturing . 
