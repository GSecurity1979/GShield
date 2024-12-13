# Path to RAMMap executable
$rammapPath = "C:\Windows\GShield\EmptyStandbyList.exe"

# Infinite loop
while ($true) {
    # Clear standby list
    Start-Process -FilePath $rammapPath -ArgumentList "standbylist" -NoNewWindow -Wait

    # Clear working sets
    Start-Process -FilePath $rammapPath -ArgumentList "workingsets" -NoNewWindow -Wait

    # Wait for 10 seconds
    Start-Sleep -Seconds 10
}
