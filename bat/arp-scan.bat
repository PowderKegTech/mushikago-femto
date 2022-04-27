@echo off
chcp 437
.\arp-scan.exe -t %1 > arp-scan.log
