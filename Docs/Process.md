https://chatgpt.com/c/69bf6226-d7e0-8320-b5c0-5ddbdf873ed3


Packet Has the following structure : 
[ Ethernet Header ][ IP Header ][ TCP/UDP ][ Data ]

1) Ethernet header : 
📦 What it contains
    Destination MAC
    Source MAC
    Type (IPv4 / IPv6)
Example:
    DEST MAC: aa:bb:cc:dd:ee:ff
    SRC MAC : 11:22:33:44:55:66
    TYPE    : IPv4 (0x0800)

    - Ethernet is not useful for your DPI goals.
    - Problem:
        MAC addresses:
        only work inside local network (LAN)
        change at every router hop
        are NOT useful for identifying internet traffic

    That's Why we are not parsing this Segment of the packet .


2) IP Header :

📦 What it contains
    Source IP
    Destination IP
    Protocol (TCP/UDP)
    TTL
    Header length
Example:
    SRC IP: 192.168.1.5
    DST IP: 142.250.182.206
    PROTO: TCP
    TTL  : 64
🧠 Purpose
    Identifies who is talking to whom globally (Internet level)

Packet : 
------------------------
    Packet captured!
    Length: 54 bytes
    SRC IP: 202.94.162.201
    DST IP: 192.168.1.4
    *Protocol: TCP*
    *SRC PORT: 443*
    *DST PORT: 53243*
------------------------


3) Flow : 
A flow is a group of packets that belong to the same connection.

Defined by 5-tuple:
SRC IP
DST IP
SRC PORT
DST PORT
PROTOCOL

Packet : 
------------------------
        Packet captured!
        Length: 546 bytes
        SRC IP: 192.168.1.1
        DST IP: 192.168.1.4
        Protocol: UDP
        *Flow: 192.168.1.1:53-192.168.1.4:62468*
        *Packets in Flow: 0*
-------------------------


4) BIDIRECTIONAL FLOW : 

Packet : 
------------------------
    Packet captured!
    Length: 74 bytes
    SRC IP: 192.168.1.4
    DST IP: 192.168.1.1
    Protocol: UDP
    SRC PORT: 62468
    DST PORT: 53
    Flow: 192.168.1.1:53-192.168.1.4:62468
    *Total Packets: 9*
    *Forward: 4*
    *Backward: 5*
-------------------------

5) DNS PARSING (FIRST REAL DPI INTELLIGENCE) Port : 53

Right now you know:

192.168.1.4 → 192.168.1.1:53

👉 That means:

"This is a DNS request"

But you DON’T know:

Which domain? ❌
🧠 Goal

Extract:

youtube.com
google.com
facebook.com

FROM raw packets.

----------------------------------------------------------------------------------
🧠 Step-by-Step (What EXACTLY happens)
1️⃣ Packet arrives (raw bytes)

What you receive:

packet → 0x45 0x00 0x00 0x3c ...

👉 This is just a byte array

2️⃣ You skip Ethernet
packet + 14

Why?

First 14 bytes = Ethernet header

Now you are at:

IP header start
3️⃣ You parse IP header
const struct ip* ipHeader = (struct ip*)(packet + 14);

Now you can read:

SRC IP
DST IP
Protocol (TCP/UDP)
4️⃣ You check protocol
if (ipHeader->ip_p == IPPROTO_UDP)

👉 DNS uses:

UDP protocol
5️⃣ You move to UDP header
packet + 14 + ipHeaderLen

Now you read:

srcPort
dstPort
🔥 6️⃣ THIS is the key detection step
if (srcPort == 53 || dstPort == 53)

👉 Why this works:

Port 53 = DNS traffic

So you conclude:

"This packet contains DNS data"
⚠️ Important clarity

You are NOT “magically detecting DNS”.

You are doing:

Protocol + Port-based identification
7️⃣ Now you locate DNS payload
packet + 14 + ipHeaderLen + sizeof(udphdr)

Now pointer is at:

Start of DNS message
8️⃣ Skip DNS header

DNS header = 12 bytes

dnsStart + 12

Now you are at:

Query section
🔥 9️⃣ What is inside Query section

Not plain text.

It looks like:

07 youtube 03 com 00

In bytes:

7 'y''o''u''t''u''b''e' 3 'c''o''m' 0
🔟 Your function decodes it
int len = query[i];

Meaning:

Read 7 → next 7 characters = "youtube"
Read 3 → next 3 characters = "com"

Build:

youtube.com


Packet : 
------------------------
Packet captured!
Length: 546 bytes
DNS Query: assets.msn.com
SRC IP: 192.168.1.1
DST IP: 192.168.1.4
Protocol: UDP
SRC PORT: 53
DST PORT: 62468
Flow: 192.168.1.1:53-192.168.1.4:62468
Total Packets: 10
Forward: 5
Backward: 5
------------------------



*⚠️ But here’s the LIMITATION (important reality)*

Right now you depend on:

DNS → plaintext ❌ (not always true anymore)

Modern systems use:

DNS over HTTPS (DoH)

DNS over TLS (DoT)

👉 Which means:

No port 53
No readable DNS ❌
🔥 So how do real systems still detect domains?

👉 Answer:

TLS SNI (Server Name Indication)
🚀 NEXT STEP: TLS SNI EXTRACTION (VERY IMPORTANT)


6) TLS SNI EXTRACTION : 

Packet : 
App: Google
DNS Query: safebrowsing.googleapis.com
Packet captured! Length: 87 bytes
SRC: 192.168.1.2:58515
DST: 192.168.1.1:53
Protocol: UDP
New Flow Created!
Flow Key: 192.168.1.1:53-192.168.1.2:58515
Total Packets: 1
Forward: 0
Backward: 1


App Can be Unknown Because : 
1️⃣ Your mapping is too small (MOST COMMON)

Your function:

if (domain.find("youtube") != std::string::npos)

👉 This is very naive.

Real domains look like:

r5---sn-cvh76n7l.googlevideo.com
edge-mqtt.facebook.com
static.xx.fbcdn.net

👉 Your system sees:

googlevideo.com → Unknown ❌
fbcdn.net → Unknown ❌

But actually:

googlevideo → YouTube
fbcdn → Facebook
2️⃣ CDN / Infrastructure domains

Most apps don’t use clean domains.

Example:

assets.msn.com → Microsoft

But also:

azureedge.net
akamai.net
cloudfront.net

👉 These are shared infrastructure

So:

Same domain → multiple apps ❌
3️⃣ Encrypted traffic limitations

Sometimes:

No DNS
No SNI

👉 Then:

You have ZERO visibility ❌
4️⃣ Your SNI parser is basic

Your SNI extraction is:

Heuristic-based (not full TLS parser)

👉 So sometimes:

SNI not extracted → Unknown ❌
5️⃣ Background system traffic

Your OS generates traffic like:

windowsupdate.com
telemetry.microsoft.com
random CDN endpoints

👉 These may not map cleanly.


7) Adding Behaviorial Intelligence : (behavior_engine.cpp)

The behavior_engine.cpp can detect following attacks from the packets information : 

*Port scanning* (many New Flow Created to same DST IP, different ports)
*DNS tunneling* (abnormally large DNS packets like 548 bytes)
*Beaconing (same* flow, perfectly spaced keep-alives like the 35.223.238.178:443 flow with 230+ packets)
*Asymmetric flows* (forward vs backward ratio way off = data exfiltration)
*Unknown app on* :443 (encrypted traffic, no SNI detected = suspicious)


8) Packet Size Statistics : 
Collecting Information Like : 
── Packet Size Statistics ──────────────────────
  Packets analysed : 7795
  Min size         : 42 bytes
  Max size         : 18046 bytes
  Avg size         : 1414.65 bytes
  Variance         : 5118841.37
  Std Deviation    : 2262.49 bytes
────────────────────────────────────────────────

8️⃣ Why DPI Systems Use Packet Size Statistics

Packet-size patterns reveal network behavior.

Examples:

Port Scanning

Packets are tiny.

Typical stats:

min ≈ 40
max ≈ 60
avg ≈ 50
very low variance
Video Streaming

Packets are large.

Typical stats:

min ≈ 1300
max ≈ 1500
avg ≈ 1400
low variance
DNS Tunneling

Packets become abnormally large.

Example:

min ≈ 100
max ≈ 2000+
avg ≈ 900

This is suspicious because DNS normally uses very small packets.

Data Exfiltration

You may see:

large packets
high forward byte ratio
increasing variance
9️⃣ Why This Is Valuable for Your DPI

Even without complex ML models, packet size statistics allow you to detect:

abnormal payload sizes
unusual traffic patterns
protocol misuse
stealth scanning
tunneling


It adds behavioral intelligence to your DPI.


9) 3️⃣ TCP Behavioral Metrics

Since you already parse TCP flags, you could add deeper metrics.

how to obtain the data and how important it is :

1️⃣ Retransmissions
How to access this information

Retransmissions are detected using the TCP sequence number.

From the TCP header:

tcpHeader->seq

For each flow, store the last sequence number seen.

Logic:

if (current_seq <= last_seq_seen)
    retransmission detected

Why it works:

A retransmitted packet repeats the same sequence number because the sender thinks the previous packet was lost.

So you track in your flow structure:

last_seq_number
retransmission_count
Importance

Retransmissions indicate:

packet loss
unstable network
congestion
sometimes attack traffic

In security context they help detect:

TCP injection attempts
network manipulation
DoS behavior

Importance level: medium

2️⃣ Out-of-Order Packets
How to access this information

Again use the sequence number.

Normal order:

seq1 < seq2 < seq3

If a packet arrives like:

seq3 before seq2

Then it is out of order.

Logic:

if (current_seq < previous_seq)
    out_of_order_packet++

You track per flow:

last_seq
out_of_order_count
Importance

Out-of-order packets can indicate:

network congestion
packet reordering by routers
possible packet injection

They are useful in:

advanced intrusion detection
network troubleshooting

Importance level: medium

3️⃣ TCP Connection State (Handshake Tracking)
How to access this information

You already parse TCP flags.

TCP flags exist in:

tcpHeader->syn
tcpHeader->ack
tcpHeader->fin
tcpHeader->rst

The normal handshake sequence is:

Client → SYN
Server → SYN-ACK
Client → ACK

So per flow you track a state machine:

state = SYN_SENT
state = SYN_ACK_RECEIVED
state = ESTABLISHED

If you see:

SYN without ACK

repeated many times → SYN flood

If a connection ends with:

RST instead of FIN

→ abnormal termination.

Useful for:
 SYN flood detection 
 abnormal session termination

It adds behavioral intelligence to your DPI.

