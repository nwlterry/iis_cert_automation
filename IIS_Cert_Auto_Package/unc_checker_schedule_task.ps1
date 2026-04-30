$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\Scripts\unc_connectivity_checker.ps1"'
$trigger = New-ScheduledTaskTrigger -AtStartup
$tempTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 1)
$trigger.Repetition = $tempTrigger.Repetition
$principal = New-ScheduledTaskPrincipal -GroupId "NT AUTHORITY\SYSTEM" -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet
Register-ScheduledTask -TaskName "UNC Connectivity Checker" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Runs a PowerShell script hourly after system startup."
