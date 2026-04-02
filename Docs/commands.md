sudo apt update
sudo apt install build-essential libpcap-dev tcpdump -y
sudo apt-get install libgtest-dev -y


//OS Level DPI Engine Deeply integrated into OS To Detect anomalies in the Network 

To Execute the main.cpp : 
g++ -std=c++17 main.cpp behavior_engine.cpp -lpcap -o dpi_engine
 ./dpi_engine

--------------------------------------------------------------------------------------------------
Till Now Captured Packets : 
--------------------------------------------------------------------------------------------------

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
------------------------
App: Google
DNS Query: www.google-analytics.com
Packet captured! Length: 163 bytes
SRC: 192.168.1.1:53
DST: 192.168.1.2:61417
Protocol: UDP
Flow Key: 192.168.1.1:53-192.168.1.2:61417
Total Packets: 2
Forward: 1
Backward: 1
------------------------
App: Unknown
Packet captured! Length: 453 bytes
SRC: 35.223.238.178:443
DST: 192.168.1.2:60223
Protocol: TCP
Flow Key: 192.168.1.2:60223-35.223.238.178:443
Total Packets: 21
Forward: 10
Backward: 11
------------------------
Packet captured! Length: 54 bytes
SRC: 192.168.1.2:60223
DST: 35.223.238.178:443
Protocol: TCP
Flow Key: 192.168.1.2:60223-35.223.238.178:443
Total Packets: 22
Forward: 11
Backward: 11
------------------------
Packet captured! Length: 54 bytes
SRC: 192.168.1.2:50803
DST: 13.67.9.5:443
Protocol: TCP
Flow Key: 13.67.9.5:443-192.168.1.2:50803
Total Packets: 37
Forward: 13
Backward: 24
------------------------
Packet captured! Length: 289 bytes
SRC: 192.168.1.8:5353
DST: 224.0.0.251:5353
Protocol: UDP
Flow Key: 192.168.1.8:5353-224.0.0.251:5353
Total Packets: 15
Forward: 15
Backward: 0
------------------------
Packet captured! Length: 55 bytes
SRC: 192.168.1.2:59153
DST: 192.178.211.188:5228
Protocol: TCP
Flow Key: 192.168.1.2:59153-192.178.211.188:5228
Total Packets: 49
Forward: 25
Backward: 24
------------------------
Packet captured! Length: 66 bytes
SRC: 192.178.211.188:5228
DST: 192.168.1.2:59153
Protocol: TCP
Flow Key: 192.168.1.2:59153-192.178.211.188:5228
Total Packets: 50
Forward: 25
Backward: 25
------------------------
Packet captured! Length: 90 bytes
SRC: 192.168.1.2:62576
DST: 185.125.190.56:123
Protocol: UDP
Flow Key: 185.125.190.56:123-192.168.1.2:62576
Total Packets: 3
Forward: 1
Backward: 2
------------------------
Packet captured! Length: 66 bytes
SRC: 192.168.1.2:49988
DST: 35.223.238.178:443
Protocol: TCP
New Flow Created!
Flow Key: 192.168.1.2:49988-35.223.238.178:443
Total Packets: 1
Forward: 1
Backward: 0
------------------------
Packet captured! Length: 66 bytes
SRC: 35.223.238.178:443
DST: 192.168.1.2:49988
Protocol: TCP
Flow Key: 192.168.1.2:49988-35.223.238.178:443
Total Packets: 2
Forward: 1
Backward: 1
