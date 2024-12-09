# Desired settings for WebRTC, remote desktop, and plugins
$desiredSettings = @{
    "media_stream" = 2
    "webrtc"       = 2
    "remote" = @{
        "enabled" = $false
        "support" = $false
    }
}

# Function to check and apply WebRTC, remote settings, and plugins
function Check-And-Apply-Settings {
    param (
        [string]$browserName,
        [string]$prefsPath
    )

    if (Test-Path $prefsPath) {
        $prefsContent = Get-Content -Path $prefsPath -Raw | ConvertFrom-Json
        $settingsChanged = $false
        
        # Check and apply WebRTC and remote desktop settings
        if ($prefsContent.profile -and $prefsContent.profile["default_content_setting_values"]) {
            foreach ($key in $desiredSettings.Keys) {
                if ($prefsContent.profile["default_content_setting_values"][$key] -ne $desiredSettings[$key]) {
                    $prefsContent.profile["default_content_setting_values"][$key] = $desiredSettings[$key]
                    $settingsChanged = $true
                }
            }
        }

        # Check and apply remote desktop settings
        if ($prefsContent.remote) {
            foreach ($key in $desiredSettings["remote"].Keys) {
                if ($prefsContent.remote[$key] -ne $desiredSettings["remote"][$key]) {
                    $prefsContent.remote[$key] = $desiredSettings["remote"][$key]
                    $settingsChanged = $true
                }
            }
        }

        # Save the settings if changes were made
        if ($settingsChanged) {
            $prefsContent | ConvertTo-Json -Compress | Set-Content -Path $prefsPath
            Write-Output "${browserName}: Settings updated for WebRTC and remote desktop."
        } else {
            Write-Output "${browserName}: No changes detected for WebRTC and remote desktop settings."
        }

        # Disable plugins (assuming this is done through the preferences as well)
        if ($prefsContent.plugins) {
            foreach ($plugin in $prefsContent.plugins) {
                $plugin.enabled = $false
            }
            Write-Output "${browserName}: Plugins have been disabled."
        } else {
            Write-Output "${browserName}: No plugins found to disable."
        }
    } else {
        Write-Output "${browserName}: Preferences file not found at $prefsPath."
    }
}

# Function to configure Firefox settings
function Configure-Firefox {
    $firefoxProfilePath = "$env:APPDATA\Mozilla\Firefox\Profiles"
    
    if (Test-Path $firefoxProfilePath) {
        $firefoxProfiles = Get-ChildItem -Path $firefoxProfilePath -Directory

        foreach ($profile in $firefoxProfiles) {
            Write-Output "Processing Firefox profile: $($profile.FullName)"
            $prefsJsPath = "$($profile.FullName)\prefs.js"
            $pluginRegPath = "$($profile.FullName)\pluginreg.dat"

            # Backup prefs.js and pluginreg.dat
            if (Test-Path $prefsJsPath) {
                Copy-Item -Path $prefsJsPath -Destination "$prefsJsPath.bak" -Force
                Write-Output "Backed up prefs.js for profile: $($profile.FullName)"
            }
            if (Test-Path $pluginRegPath) {
                Copy-Item -Path $pluginRegPath -Destination "$pluginRegPath.bak" -Force
                Write-Output "Backed up pluginreg.dat for profile: $($profile.FullName)"
            }

            # Modify prefs.js to disable WebRTC
            if (Test-Path $prefsJsPath) {
                $prefsJsContent = Get-Content -Path $prefsJsPath

                # Disable WebRTC
                if ($prefsJsContent -notmatch 'user_pref\("media.peerconnection.enabled", false\)') {
                    Add-Content -Path $prefsJsPath 'user_pref("media.peerconnection.enabled", false);'
                    Write-Output "Firefox profile ${profile.FullName}: WebRTC has been disabled."
                } else {
                    Write-Output "Firefox profile ${profile.FullName}: WebRTC already disabled."
                }
            }

            # Clear pluginreg.dat to disable plugins
            if (Test-Path $pluginRegPath) {
                Clear-Content -Path $pluginRegPath
                Write-Output "Firefox profile ${profile.FullName}: Plugins have been disabled."
            } else {
                Write-Output "Firefox profile ${profile.FullName}: No plugin registry found."
            }
        }
    } else {
        Write-Output "Mozilla Firefox is not installed or profile path not found."
    }
}

# Detect installed browsers and manage settings
$browsers = @{
    "Chrome" = "$env:LOCALAPPDATA\Google\Chrome\User Data"
    "Brave" = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
    "Vivaldi" = "$env:LOCALAPPDATA\Vivaldi\User Data"
    "Edge" = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
    "Opera" = "$env:APPDATA\Opera Software\Opera Stable"
    "OperaGX" = "$env:APPDATA\Opera Software\Opera GX Stable"
}

foreach ($browser in $browsers.GetEnumerator()) {
    if (Test-Path $browser.Value) {
        # Check and apply WebRTC and remote desktop settings
        Check-And-Apply-Settings -browserName $browser.Key -prefsPath $browser.Value
    } else {
        Write-Output "${browser.Key} is not installed or profile path not found."
    }
}

# Handle Firefox separately
if (Test-Path "$env:APPDATA\Mozilla\Firefox") {
    Configure-Firefox
} else {
    Write-Output "Mozilla Firefox is not installed."
}

Write-Output "Script execution complete."

# Function to stop the Chrome Remote Desktop Host service
function Stop-CRDService {
    $serviceName = "chrome-remote-desktop-host"
    
    # Check if the service exists and stop it
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        Write-Host "Stopping Chrome Remote Desktop Host service..."
        Stop-Service -Name $serviceName -Force
        Set-Service -Name $serviceName -StartupType Disabled
        Write-Host "Chrome Remote Desktop Host service stopped and disabled."
    } else {
        Write-Host "Chrome Remote Desktop Host service is not found."
    }
}

# Function to block CRD-related processes in Chrome-based browsers
function Block-CRDBrowsers {
    $browsers = @("chrome.exe", "msedge.exe", "brave.exe", "vivaldi.exe", "opera.exe", "operagx.exe")
    
    foreach ($browser in $browsers) {
        $processes = Get-Process -Name $browser -ErrorAction SilentlyContinue
        if ($processes) {
            Write-Host "Terminating process: $browser"
            Stop-Process -Name $browser -Force
        }
    }
}

# Function to block CRD network ports (TCP 443)
function Block-CRDPorts {
    $ruleName = "Block CRD Ports"
    
    # Check if the firewall rule exists and remove it
    $existingRule = Get-NetFirewallRule | Where-Object { $_.DisplayName -eq $ruleName }
    if ($existingRule) {
        Write-Host "Firewall rule already exists. Removing the rule..."
        Remove-NetFirewallRule -DisplayName $ruleName
    }

    # Create a new rule to block incoming TCP connections on port 443 (used by CRD)
    Write-Host "Creating firewall rule to block incoming TCP port 443..."
    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort 443 -Action Block -Profile Any
    Write-Host "Firewall rule created to block Chrome Remote Desktop connections."
}

# Main function to block CRD
function Disable-CRD {
    # Stop and disable CRD service
    Stop-CRDService

    # Block CRD-related processes in Chrome-based browsers
    Block-CRDBrowsers

    # Block incoming connections to the CRD ports
    Block-CRDPorts
}

# Execute the script
Disable-CRD
