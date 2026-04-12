1) sys_integration_test.py 
IN the testing file , It create the different pcap files to simulate different types of the attacks and then Applies on the executables like the dpi_engine : 
Below are different attacks which it simulates : 

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

2) test_pkt_stats.py 

To Test And Validate the Functionality of calculating , statistics about Packets in the Flow 
This compares own (test_pkt_stats.py) calculated values and actual resultant values . if the both are same , then the system is working correctly . 

3) unit_test.cpp
Tests Each and Every Function in the main.cpp like : 
std::string detectApp
std::string extractDomain
std::string extractSNI 
.....

--------------------------------------------------------------------------------------------------------------

1) SYN FLOODING TESTING 

(.linuxVenv) parth@LAPTOP-59VTE6KK:/mnt/d/Parth_folder/Deep-Packet-Inspection/src$ ip addr
lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    **inet 10.255.255.254**/32 brd 10.255.255.254 scope global lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever

**T-1**
g++ -std=c++17 -o ./executables/dpi_engine main.cpp behavior_engine.cpp -lpcap
sudo executables/dpi_engine lo

**T-2**
sudo hping3 -S -p 80 --flood 10.255.255.254 localhost IP from ip addr command


2) Beaconing Attack 

**T-1**
g++ -std=c++17 -o ./executables/dpi_engine main.cpp behavior_engine.cpp -lpcap
sudo executables/dpi_engine lo

**T-2**
Navigate to And Activate the Venv : (.linuxVenv) parth@LAPTOP-59VTE6KK:/mnt/d/Parth_folder/Deep-Packet-Inspection/src$  

sudo /mnt/d/Parth_folder/Deep-Packet-Inspection/src/.linuxVenv/bin/python tests/beaconing.py
