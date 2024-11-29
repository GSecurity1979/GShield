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
$browsers = @{}

# Chromium-based browsers and their profile paths
$browsers.Chrome = "$env:LOCALAPPDATA\Google\Chrome\User Data"
$browsers.Brave = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
$browsers.Vivaldi = "$env:LOCALAPPDATA\Vivaldi\User Data"
$browsers.Edge = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
$browsers.Opera = "$env:APPDATA\Opera Software\Opera Stable"
$browsers.OperaGX = "$env:APPDATA\Opera Software\Opera GX Stable"

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
