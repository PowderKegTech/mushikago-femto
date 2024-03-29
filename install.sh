#!/bin/bash

# apt update and install required modules
apt update &&
apt upgrade -y &&
apt install build-essential g++ gcc make autoconf dh-autoreconf libpcap-dev sqlite3 libsqlite3-dev libssl-dev net-tools tshark python2-dev default-libmysqlclient-dev python3-dev unzip -y &&


# nmap install
mkdir -p src &&
cd src &&
git clone https://github.com/nmap/nmap.git &&
cd nmap &&
./configure && 
make &&
make install &&


# Proxychains-ng install
cd ../../ &&
cd src &&
git clone https://github.com/rofl0r/proxychains-ng &&
cd proxychains-ng &&
./configure --prefix=/usr --sysconfdir=/etc &&
make &&
make install &&


# impacket install
cd ../../ &&
cd src &&
git clone https://github.com/SecureAuthCorp/impacket &&


# arp-scan install
cd ../ &&
cd src &&
git clone https://github.com/royhills/arp-scan.git &&
cd arp-scan &&
autoreconf --install &&
./configure &&
make &&
make install &&


# arp-scan-windows install
cd ../../ &&
cd src &&
git clone https://github.com/QbsuranAlang/arp-scan-windows- &&


# naabu install
cd ../ &&
cd src &&
wget https://github.com/projectdiscovery/naabu/releases/download/v2.0.6/naabu_2.0.6_windows_386.zip &&
unzip naabu_2.0.6_windows_386.zip &&


# Metasploit install
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall &&
chmod 755 msfinstall &&
./msfinstall &&


# python packege install
apt install python3-pip -y &&
cd ../ &&
pip3 install -r requirements.txt
