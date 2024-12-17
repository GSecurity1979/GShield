:: Elevate
>nul 2>&1 fsutil dirty query %systemdrive% || echo CreateObject^("Shell.Application"^).ShellExecute "%~0", "ELEVATED", "", "runas", 1 > "%temp%\uac.vbs" && "%temp%\uac.vbs" && exit /b
DEL /F /Q "%temp%\uac.vbs"

:: Move to the script directory
cd /d %~dp0

:Cleaner
emptystandbylist.exe workingsets
emptystandbylist.exe standbylist
timeout /t 10 /nobreak >nul
goto:Cleaner