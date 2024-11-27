@echo off

:: Create Directory and Copy Files
mkdir C:\Windows\GSecurity
copy GSecurity.ps1 C:\Windows\GSecurity\GSecurity.ps1

:: Create Task to Run as SYSTEM
schtasks /create /f /tn "StartGSecurityOnLogon" /tr "C:\Windows\GSecurity\GSecurity.ps1" /sc onlogon /ru "SYSTEM" /rl highest

:: Take ownership of the gpsvc registry key
echo Taking ownership of gpsvc registry key...
takeown /f "HKLM\SYSTEM\CurrentControlSet\Services\gpsvc" /a /r /d y
icacls "HKLM\SYSTEM\CurrentControlSet\Services\gpsvc" /grant "%username%:F" /t /c

:: Disable the Group Policy Client service
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gpsvc" /v "Start" /t REG_DWORD /d "4" /f

:: Stop the Group Policy Client service
sc stop gpsvc