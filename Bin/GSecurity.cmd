@echo off
mkdir C:\Windows\GSecurity
copy GSecurity.ps1 C:\Windows\GSecurity\GSecurity.ps1
schtasks /create /f /tn "StartGSecurityOnLogon" /tr "C:\Windows\GSecurity\GSecurity.ps1" /sc onlogon /ru "SYSTEM" /rl highest
