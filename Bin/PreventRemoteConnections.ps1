# Prevent Remote Desktop Protocol (RDP)
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 1
Stop-Service -Name "TermService" -Force
Set-Service -Name "TermService" -StartupType Disabled

# Disable Remote Assistance
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -Value 0

# Block PowerShell Remoting
Disable-PSRemoting -Force
Stop-Service -Name "WinRM" -Force
Set-Service -Name "WinRM" -StartupType Disabled

# Disable Telnet (if enabled)
Disable-WindowsOptionalFeature -Online -FeatureName "TelnetClient" -NoRestart

# Block SMB (File Sharing)
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force

# Disable Wake-on-LAN (WOL)
Get-NetAdapter | ForEach-Object {
    Set-NetAdapterAdvancedProperty -Name $_.Name -DisplayName "Wake on Magic Packet" -DisplayValue "Disabled"
    Set-NetAdapterAdvancedProperty -Name $_.Name -DisplayName "Wake on Pattern Match" -DisplayValue "Disabled"
}

# Block SSH (if OpenSSH Server is installed)
Stop-Service -Name "sshd" -Force
Set-Service -Name "sshd" -StartupType Disabled

# Block VNC Services (if installed)
Get-Service -Name "*VNC*" | ForEach-Object {
    Stop-Service -Name $_.Name -Force
    Set-Service -Name $_.Name -StartupType Disabled
}

# Enforce Firewall Rules
# Disable RDP ports (3389)
New-NetFirewallRule -DisplayName "Block RDP" -Direction Inbound -LocalPort 3389 -Protocol TCP -Action Block

# Disable SMB ports (445, 139)
New-NetFirewallRule -DisplayName "Block SMB TCP 445" -Direction Inbound -LocalPort 445 -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block SMB TCP 139" -Direction Inbound -LocalPort 139 -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block SMB UDP 137-138" -Direction Inbound -LocalPort 137-138 -Protocol UDP -Action Block

# Block WinRM ports (5985, 5986)
New-NetFirewallRule -DisplayName "Block WinRM HTTP" -Direction Inbound -LocalPort 5985 -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block WinRM HTTPS" -Direction Inbound -LocalPort 5986 -Protocol TCP -Action Block

# Block Telnet port (23)
New-NetFirewallRule -DisplayName "Block Telnet" -Direction Inbound -LocalPort 23 -Protocol TCP -Action Block

# Disable UPnP
Get-Service -Name "SSDPSRV", "upnphost" | ForEach-Object {
    Stop-Service -Name $_.Name -Force
    Set-Service -Name $_.Name -StartupType Disabled
}

# Disable Remote Assistance firewall rule
Get-NetFirewallRule -DisplayName "Remote Assistance*" | Disable-NetFirewallRule
