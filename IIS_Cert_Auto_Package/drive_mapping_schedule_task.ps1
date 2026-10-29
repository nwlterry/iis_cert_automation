$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-WindowStyle Hidden -ExecutionPolicy RemoteSigned -File "C:\Scripts\drive_mapping.ps1"'
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -GroupId "NT AUTHORITY\SYSTEM" -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet
Register-ScheduledTask -TaskName "Map Drive As System" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Maps the configured UNC path after startup. Requires C:\Scripts\iis-cert-automation.config.json."
