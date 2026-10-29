# Registers the hourly UNC check, IIS reset, and HTTPS health check as NT AUTHORITY\SYSTEM.
# The action must be unc_connectivity_checker_w_status.ps1. The older checker script is not deployed.
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-WindowStyle Hidden -NoProfile -ExecutionPolicy RemoteSigned -File "C:\Scripts\unc_connectivity_checker_w_status.ps1"'
$trigger = New-ScheduledTaskTrigger -AtStartup
$tempTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 1)
$trigger.Repetition = $tempTrigger.Repetition
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName "UNC Connectivity Checker" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force -Description "Checks the configured UNC path hourly, then resets IIS and checks HTTPS."
