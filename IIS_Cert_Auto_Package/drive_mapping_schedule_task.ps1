# Registers the file-share map as NT AUTHORITY\SYSTEM at startup.
# Copy drive_mapping.ps1, Security.Common.ps1, and iis-cert-automation.config.json to C:\Scripts first.
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-WindowStyle Hidden -NoProfile -ExecutionPolicy RemoteSigned -File "C:\Scripts\drive_mapping.ps1"'
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName "Map Drive As System" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force -Description "Maps the configured UNC path after startup. Requires C:\Scripts\iis-cert-automation.config.json."
