@echo off
Title GShield && Color 0b

:: Elevate
>nul 2>&1 fsutil dirty query %systemdrive% || echo CreateObject^("Shell.Application"^).ShellExecute "%~0", "ELEVATED", "", "runas", 1 > "%temp%\uac.vbs" && "%temp%\uac.vbs" && exit /b
DEL /F /Q "%temp%\uac.vbs"

:: Step 1: Initialize environment
setlocal EnableExtensions DisableDelayedExpansion

:: Step 2: Move to the script directory
cd /d %~dp0

:: Step 3: Move to the 'Bin' subfolder
cd Bin

:: Step 4: Set PowerShell Execution Policy to Bypass for current user
echo Setting PowerShell Execution Policy to Bypass for current user...
powershell -Command "Set-ExecutionPolicy Bypass -Force"

:: Step 5: Initialize enviroment 
setlocal EnableExtensions DisableDelayedExpansion

:: Step 6: Execute PowerShell (.ps1) files alphabetically
echo Executing PowerShell scripts...
for /f "tokens=*" %%A in ('dir /b /o:n *.ps1') do (
    echo Running %%A...
    powershell -ExecutionPolicy Bypass -File "%%A"
)

:: Step 7: Execute CMD (.cmd) files alphabetically
echo Executing CMD scripts...
for /f "tokens=*" %%B in ('dir /b /o:n *.cmd') do (
    echo Running %%B...
    call "%%B"
)

:: Step 8: Execute Registry (.reg) files alphabetically
echo Executing Registry files...
for /f "tokens=*" %%C in ('dir /b /o:n *.reg') do (
    echo Merging %%C...
    reg import "%%C"
)

:: Step 9: Install drivers
pnputil.exe /add-driver *.inf /subdirs /install

:: Step 10: Apply security baseline
lgpo /g ./

:: Step 11: Install MSI files quietly
echo Installing MSI files quietly...
for /f "tokens=*" %%D in ('dir /b /o:n *.msi') do (
    echo Installing %%D...
    msiexec /i "%%D" /quiet /norestart
)

echo Script completed successfully.
exit
