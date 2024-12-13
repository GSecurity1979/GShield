@echo off
SETLOCAL ENABLEDELAYEDEXPANSION

echo Disabling PXE boot on all network adapters...

REM Loop through all network adapters and apply the DisablePXE setting
for /f "tokens=*" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /s /f "Name" /k 2^>nul') do (
    set "adapter=%%A"
    REM Extract the adapter GUID from the registry key path
    set "adapter_guid="
    for /f "tokens=3" %%B in ("!adapter!") do set adapter_guid=%%B

    REM Apply the DisablePXE registry key if the GUID is valid
    if defined adapter_guid (
        echo Setting DisablePXE for adapter: !adapter_guid!
        reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\!adapter_guid!" /v DisablePXE /t REG_DWORD /d 1 /f
    )
)

for /f "tokens=*" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces" /s /f "Name" /k 2^>nul') do (
    set "adapter=%%A"
    REM Extract the adapter GUID from the registry key path
    set "adapter_guid="
    for /f "tokens=3" %%B in ("!adapter!") do set adapter_guid=%%B

    REM Apply the DisablePXE registry key if the GUID is valid
    if defined adapter_guid (
        echo Setting DisablePXE for adapter: !adapter_guid!
        reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\!adapter_guid!" /v DisablePXE /t REG_DWORD /d 1 /f
    )
)
echo PXE boot disabled for all network adapters.

bcdedit /delete "{3512665e-b493-11ef-95ec-806e6f6e6963}"
bcdedit /delete "{3512665f-b493-11ef-95ec-806e6f6e6963}"
bcdedit /delete "{35126660-b493-11ef-95ec-806e6f6e6963}"
