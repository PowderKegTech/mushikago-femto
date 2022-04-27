@echo off
call naabu.exe -p 21,22,25,53,80,88,135,139,389,443,445,3389 -host %1 -o scan.log -silent
