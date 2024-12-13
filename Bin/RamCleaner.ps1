# Path to RAMMap executable
$rammapPath = "C:\Windows\GShield\RAMMap64.exe"

# Infinite loop
while ($true) {
    # Clear standby list
    Start-Process -FilePath $rammapPath -ArgumentList "-E" -NoNewWindow -Wait

    # Clear working sets
    Start-Process -FilePath $rammapPath -ArgumentList "-W" -NoNewWindow -Wait

    # Wait for 10 seconds
    Start-Sleep -Seconds 10
}
