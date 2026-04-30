$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\Scripts\drive_mapping.ps1"'
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -GroupId "NT AUTHORITY\SYSTEM" -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet
Register-ScheduledTask -TaskName "ACME Map Drive As System" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Runs a PowerShell script after system startup."
