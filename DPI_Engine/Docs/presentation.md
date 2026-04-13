g++ -std=c++17 -o ./executables/dpi_engine main.cpp behavior_engine.cpp -lpcap
sudo executables/dpi_engine lo

sudo hping3 -S -p 80 --flood 10.255.255.254 --SYN FLOOD COMMAND lo - Localhost