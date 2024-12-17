<#
    Script Name: GSecurity
    Author: Gorstak
    Description: Advanced script to detect and mitigate web servers, screen overlays, and keyloggers. 
                 Protects critical system processes and specific trusted drivers from termination.
    Version: 1.7
    License: Free for personal use
#>

# Logging utility
function Write-Log {
    param ([string]$Message)
    $logFile = "$env:USERPROFILE\Documents\GSecurity.log"
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $Message"
    Add-Content -Path $logFile -Value $logMessage
}

# Whitelist of critical system processes to protect
$protectedProcesses = @(
    "System", "smss", "csrss", "wininit", "services", "lsass", 
    "svchost", "dwm", "explorer", "taskhostw", "winlogon", 
    "conhost", "cmd", "powershell"
)

# Trusted driver vendors to exclude from termination
$trustedDriverVendors = @(
    "*Microsoft*", "*NVIDIA*", "*Intel*", "*AMD*", "*Realtek*"
)

# Detect and terminate web servers
function Detect-And-Terminate-WebServers {
    $ports = @(80, 443, 8080)  # Common web server ports
    $connections = Get-NetTCPConnection | Where-Object { $ports -contains $_.LocalPort }
    foreach ($connection in $connections) {
        $process = Get-Process -Id $connection.OwningProcess -ErrorAction SilentlyContinue
        if ($process -and -not ($protectedProcesses -contains $process.ProcessName)) {
            Write-Log "Web server detected: $($process.ProcessName) (PID: $($process.Id)) on Port $($connection.LocalPort)"
            Stop-Process -Id $process.Id -Force
            Write-Log "Web server process terminated: $($process.ProcessName)"
        }
    }
}

# Terminate suspicious web server services
function Detect-And-Terminate-WebServerServices {
    $webServices = @("w3svc", "apache2", "nginx")  # Known web server services
    foreach ($serviceName in $webServices) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq "Running") {
            Write-Log "Web server service detected: $($serviceName)"
            Stop-Service -Name $serviceName -Force
            Write-Log "Web server service stopped: $($serviceName)"
        }
    }
}

# Detect and terminate screen overlays
function Detect-And-Terminate-Overlays {
    $overlayProcesses = Get-Process | Where-Object { 
        $_.MainWindowTitle -ne "" -and (-not $protectedProcesses -contains $_.ProcessName)
    }
    foreach ($process in $overlayProcesses) {
        Write-Log "Suspicious overlay detected: $($process.ProcessName) (PID: $($process.Id))"
        Stop-Process -Id $process.Id -Force
        Write-Log "Overlay process terminated: $($process.ProcessName)"
    }
}

# Detect and terminate keyloggers
function Detect-And-Terminate-Keyloggers {
    $hooks = Get-WmiObject -Query "SELECT * FROM Win32_Process WHERE CommandLine LIKE '%hook%' OR CommandLine LIKE '%log%' OR CommandLine LIKE '%key%'"
    foreach ($hook in $hooks) {
        $process = Get-Process -Id $hook.ProcessId -ErrorAction SilentlyContinue
        if ($process -and -not ($protectedProcesses -contains $process.ProcessName)) {
            Write-Log "Keylogger activity detected: $($process.ProcessName) (PID: $($process.Id))"
            Stop-Process -Id $process.Id -Force
            Write-Log "Keylogger process terminated: $($process.ProcessName)"
        }
    }
}

# Detect and terminate untrusted drivers
function Detect-And-Terminate-SuspiciousDrivers {
    $drivers = Get-WmiObject Win32_SystemDriver | Where-Object {
        ($_.DisplayName -notlike $trustedDriverVendors) -and $_.Started -eq $true
    }
    foreach ($driver in $drivers) {
        Write-Log "Suspicious driver detected: $($driver.DisplayName)"
        Stop-Service -Name $driver.Name -Force
        Write-Log "Suspicious driver stopped: $($driver.DisplayName)"
    }
}


