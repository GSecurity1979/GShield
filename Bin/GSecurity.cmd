@echo off
mkdir C:\Windows\GSecurity
copy GSecurity.ps1 C:\Windows\GSecurity\GSecurity.ps1
schtasks /create /f /tn "StartGSecurityOnLogon" /tr "C:\Windows\GSecurity\GSecurity.ps1" /sc onlogon /ru "SYSTEM" /rl highest
takeown /f "%SystemDrive%\Users\Public\Desktop" /r /d y
icacls "%SystemDrive%\Users\Public\Desktop" /inheritance:d /T /C
icacls "%SystemDrive%\Users\Public\Desktop" /grant:r %username%:(OI)(CI)F /t /l /q /c
takeown /f "%USERPROFILE%\Desktop" /r /d y
icacls "%USERPROFILE%\Desktop" /inheritance:d /T /C
icacls "%USERPROFILE%\Desktop" /grant:r %username%:(OI)(CI)F /t /l /q /c
