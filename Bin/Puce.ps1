# Step 1: Stop the gpsvc service if running
$serviceName = "gpsvc"
$service = Get-Service -Name $serviceName

if ($service.Status -eq "Running") {
    Write-Host "Stopping $serviceName service..."
    Stop-Service -Name $serviceName -Force
} else {
    Write-Host "$serviceName service is already stopped."
}

# Step 2: Disable the gpsvc service
Write-Host "Disabling $serviceName service..."
Set-Service -Name $serviceName -StartupType Disabled

# Step 3: Deny null access device-wide

# Disable NULL sessions for SMB (Server Message Block)
Write-Host "Disabling NULL sessions for SMB..."
$nullSessionRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
$nullSessionValueName = "RestrictAnonymous"
$nullSessionValue = 1  # 1 = Deny null sessions

# Set registry key to restrict anonymous access
Set-ItemProperty -Path $nullSessionRegistryPath -Name $nullSessionValueName -Value $nullSessionValue
Write-Host "NULL session access restricted for SMB."

# Disable Anonymous SID in the registry (disabling anonymous logons and null access)
Write-Host "Disabling Anonymous logons and null access..."
$anonymousLogonPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$anonymousLogonValueName = "RestrictAnonymous"

# Setting to 1 denies all anonymous logons (including NULL sessions)
Set-ItemProperty -Path $anonymousLogonPath -Name $anonymousLogonValueName -Value 1
Write-Host "Anonymous logons restricted."

# Ensure that null access is denied to shared folders and other network resources
Write-Host "Ensuring null access is denied on network shares..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RestrictNullSessAccess" -Value 1

# Apply and force Group Policy update to apply the changes immediately
Write-Host "Forcing Group Policy update to apply settings..."
gpupdate /force

Write-Host "Service $serviceName disabled, stopped, and null access restricted device-wide."
