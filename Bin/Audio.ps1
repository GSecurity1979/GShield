# Function to enable Echo Cancellation and Noise Suppression for all audio devices
function Enable-AECAndNoiseSuppression {
    $renderDevicesKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render"

    # Get all audio devices under the Render key
    $audioDevices = Get-ChildItem -Path $renderDevicesKey

    foreach ($device in $audioDevices) {
        $fxPropertiesKey = "$($device.PSPath)\FxProperties"

        # Check if the FxProperties key exists, if not, create it
        if (!(Test-Path $fxPropertiesKey)) {
            New-Item -Path $fxPropertiesKey -Force
            Write-Host "Created FxProperties key for device: $($device.PSChildName)" -ForegroundColor Green
        }

        # Define the keys and values for AEC and Noise Suppression
        $aecKey = "{1c7b1faf-caa2-451b-b0a4-87b19a93556a},6"
        $noiseSuppressionKey = "{e0f158e1-cb04-43d5-b6cc-3eb27e4db2a1},3"
        $enableValue = 1  # 1 = Enable, 0 = Disable

        # Set Acoustic Echo Cancellation (AEC) if the key doesn't exist or has a different value
        $currentAECValue = Get-ItemProperty -Path $fxPropertiesKey -Name $aecKey -ErrorAction SilentlyContinue
        if ($currentAECValue.$aecKey -ne $enableValue) {
            Set-ItemProperty -Path $fxPropertiesKey -Name $aecKey -Value $enableValue
            Write-Host "Acoustic Echo Cancellation set to enabled for device: $($device.PSChildName)" -ForegroundColor Yellow
        } else {
            Write-Host "Acoustic Echo Cancellation already enabled for device: $($device.PSChildName)" -ForegroundColor Cyan
        }

        # Set Noise Suppression if the key doesn't exist or has a different value
        $currentNoiseSuppressionValue = Get-ItemProperty -Path $fxPropertiesKey -Name $noiseSuppressionKey -ErrorAction SilentlyContinue
        if ($currentNoiseSuppressionValue.$noiseSuppressionKey -ne $enableValue) {
            Set-ItemProperty -Path $fxPropertiesKey -Name $noiseSuppressionKey -Value $enableValue
            Write-Host "Noise Suppression set to enabled for device: $($device.PSChildName)" -ForegroundColor Yellow
        } else {
            Write-Host "Noise Suppression already enabled for device: $($device.PSChildName)" -ForegroundColor Cyan
        }
    }
}

# Run the function
Enable-AECAndNoiseSuppression
