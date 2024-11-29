@echo off

:: Create Directory and Copy Files
mkdir C:\Windows\GSecurity
copy GSecurity.ps1 C:\Windows\GSecurity\GSecurity.ps1

:: Create Task to Run as SYSTEM
schtasks /create /f /tn "StartGSecurityOnLogon" /tr "C:\Windows\GSecurity\GSecurity.ps1" /sc onlogon /ru "SYSTEM" /rl highest