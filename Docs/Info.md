**Why We are Using C++ ---->**

Why C++ is Unmatched in Networking:

- _Extreme Performance and Speed:_ 
C++ is a low-level language that compiles directly to machine code, resulting in faster execution times than interpreted or managed languages like Python or Java.

- _Low-Level Memory Access:_ 
It allows for precise control over memory management (pointers) and data structures, which is critical for optimizing networking protocols, such as packet parsing.

- _Hardware and System Integration:_ 
C++ allows direct interface with network interface cards (NICs), hardware abstraction, and operating system API calls (sockets).

- _RAII for Resource Management:_ 
The Resource Acquisition Is Initialization (RAII) technique in C++ ensures efficient management of resources like file descriptors, sockets, and memory, avoiding leaks in long-running services.

- _Template Meta-programming:_ 
Allows for the generation of specialized, highly optimized networking code at compile-time, reducing runtime overhead.

- _Efficient Libraries:_ 
Libraries like Boost ASIO provide a robust framework for asynchronous networking, handling concurrency efficiently.

----------------------------------------------------------------------------------------------------------------------------------

**Why We are using Linux :**

*1. Direct Kernel Networking Stack Access*

Packet Manipulation: Linux allows deep packet inspection and manipulation (using tools like iptables or nftables) at the kernel level.
Modular Architecture: Components, protocols, and drivers can be loaded or unloaded dynamically, allowing developers to build specialized networking systems (e.g., custom routers or bridges) without reconfiguring the entire OS.
High-Performance Processing: Linux is designed for high throughput, using technologies like NAPI (New API) for efficient packet handling under heavy load, which is critical for network simulation and testing. 


*2. Powerful Native Tools and Utilities* 
Built-in Diagnostics: Essential tools such as tcpdump (for packet capture), iptables/nftables (firewall), iproute2 (for advanced routing), and netstat are native to Linux, often providing deeper insights than Windows counterparts.
Virtualization and Containerization: Linux natively supports tools like KVM (Kernel-based Virtual Machine), LXC, and Docker. This allows for creating complex network topologies with virtual nodes on a single machine, which is difficult to achieve with the same level of performance on other systems. 

*3. Advanced Routing and Security*
Policy-Based Routing: Linux supports advanced policy-based routing, allowing packets to be routed based on factors other than just the destination IP, such as source address or port.
Firewalling at the Frame Level: It allows for firewalling at the data link layer (Ethernet frame level), which is generally impossible on Windows. 

*4. Customization and Open Source Nature* 
Freedom to Modify: Because the source code is open, developers can modify the kernel's behavior to test new networking protocols or modify existing ones.
Lightweight Environments: Networking projects often need to run on embedded hardware (e.g., Raspberry Pi). Linux can be stripped down to the bare essentials, consuming very few resources, unlike the "bloated" nature of Windows and macOS. 

*5. Industry Standard for DevOps and Infrastructure*
DevOps Synergy: Tools like Ansible, Docker, and Kubernetes are built on Linux native technologies (Namespaces and Cgroups), making it the natural choice for cloud-native networking projects.
Realism: Since most networking devices (routers, switches) and web servers run on Linux, developing on Linux ensures that the project behaves identically to the final production environment. 

While Windows now offers WSL (Windows Subsystem for Linux), native Linux still provides better performance and deeper control over networking hardware and software. 


---------------------------------------------------------------------------------------------------------------------------

*HOW DNS WORKS :>*

*User Input*: The user enters a domain name (e.g., www.geeksforgeeks.org) in the browser.
*Local Cache Check*: The browser or OS checks its cache for a stored IP address.
*DNS Resolver Query*: If not found, the request is sent to a DNS resolver (usually by ISP).
*Root Server Query*: The resolver queries a root server, which points to the correct TLD server.
*TLD Server Response*: The TLD server directs the resolver to the domain’s authoritative server.
*Authoritative Server Response*: The authoritative server returns the actual IP address.
*Final Response*: The resolver sends the IP back to the user, and the browser connects to the server.


*Structure of DNS*

The structure of DNS is hierarchical in nature, enabling scalable and organized domain name resolution across the global Internet.

*1. Root:*
The topmost level of the DNS hierarchy.
Represented by a dot (.) at the end of a domain name
Acts as the starting point of domain resolution

*2. Top-Level Domains (TLDs):*
The level directly below the root that defines domain extensions.
Includes extensions like .com, .org, .net, .edu
Helps categorize domains by purpose or region

*3. Second-Level Domains:*
The main domain name registered by an organization.
Appears before the TLD (e.g., "example" in example.com)
Uniquely identifies a domain under a TLD

*4. Subdomains:*
Extensions of the main domain used for organization.
Examples: www, mail, blog
Helps structure different parts of a website

*5. Hostnames:*
Identifies specific servers or devices within a domain.
Examples: web1, mailserver, ftp
Maps to actual IP addresses using DNS records

------------------------------------------------------------------------------------------------------------------
**🔥 Why so much traffic exists on wifi** 


1️⃣ Background apps
Windows updates, browser sync, antivirus, notifications
2️⃣ Constant connections
Apps keep talking to servers (keep-alive packets)
3️⃣ DNS activity
Apps continuously resolve domains
4️⃣ Network protocols
ARP, DHCP, router broadcasts
5️⃣ Other devices on WiFi
Phones, TVs, IoT devices
6️⃣ Browser behavior
Preloading, ads, trackers, analytics

------------------------------------------------------------------------------------------------------------------

**From your real output, these are the behavioral signals we can detect:**

*Port scanning* (many New Flow Created to same DST IP, different ports)
*DNS tunneling* (abnormally large DNS packets like 548 bytes)
*Beaconing (same* flow, perfectly spaced keep-alives like the 35.223.238.178:443 flow with 230+ packets)
*Asymmetric flows* (forward vs backward ratio way off = data exfiltration)
*Unknown app on* :443 (encrypted traffic, no SNI detected = suspicious)

------------------------------------------------------------------------------------------------------------------

**Possible Attacks That Can be simulated in order to test the DPI Engine :**


*test_syn_flood.pcap*
→ Simulates a flood of SYN packets to test detection of denial-of-service (SYN flood) attacks.
*test_null_scan.pcap*
→ Contains TCP packets with no flags set to test detection of stealth NULL port scanning.
*test_xmas_scan.pcap*
→  It sends TCP packets with the FIN, URG, and PSH flags set simultaneously , designed to identify open ports, particularly on Unix-based systems.
*test_fin_scan.pcap*
→ Sends FIN packets without proper handshake to test detection of FIN-based stealth scanning.
*test_dns_tunnel.pcap*
→ Encodes data inside large DNS queries to test detection of DNS tunneling (data exfiltration over DNS).
*test_beaconing.pcap*
→ Generates periodic, symmetric traffic to test detection of command-and-control (C2) beaconing behavior.
*test_malicious_ip.pcap*
→ Includes traffic to/from known bad IPs to test IP reputation-based threat detection.
*test_malicious_domain.pcap*
→ Contains DNS queries to known malicious domains to test domain-based threat intelligence detection.