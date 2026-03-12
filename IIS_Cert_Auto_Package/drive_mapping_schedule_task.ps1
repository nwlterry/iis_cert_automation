$action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument '/c C:\Scripts\drive_mapping.bat'
$trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName "ACME Map Drive As System" -Action $action -Trigger $trigger -User "SYSTEM" -RunLevel Highest -Force
