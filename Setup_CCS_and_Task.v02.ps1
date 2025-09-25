# PowerShell script to enable IIS Centralized Certificate Store (CCS) via registry without modifying existing settings,
# store PFX password in Credential Manager as SYSTEM using CredentialManager module,
# and set up a scheduled task to trigger on certificate renewal event (Event ID 1001 in Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational)
# to execute the provided export script. Logs all setup information to a file under C:\Logs with full timestamp.
#
# This script is designed for an air-gapped environment running Windows PowerShell 5.1 (Windows Server 2019/2022).
# It checks for the CredentialManager module and prompts for a .nupkg file path if not installed in interactive sessions,
# then extracts and installs the module to C:\Program Files\WindowsPowerShell\Modules.

param (
    [Parameter(Mandatory=$true)]
    [string]$CcsPhysicalPath,  # UNC path to the CCS file share, e.g., "\\file-server\IIS_Cert_Store"

    [Parameter(Mandatory=$true)]
    [securestring]$PfxPassword,  # PFX password to store in Credential Manager as SYSTEM

    [Parameter(Mandatory=$false)]
    [string]$ExportScriptPath,  # Path to the export script (prompted if not provided)

    [Parameter(Mandatory=$false)]
    [string]$TempLogDir = "C:\Logs",  # Directory for temporary task log files (default to C:\Logs)

    [Parameter(Mandatory=$false)]
    [string]$NupkgPath,  # Path to CredentialManager .nupkg file (prompted if not installed and interactive)

    [string]$TaskName = "Certificate Export on Renewal",

    [int]$EventId = 1001,  # Event ID for certificate renewal

    [string]$EventLogName = "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational"
)

# Define logging configuration
$currentDate = Get-Date -Format "yyyyMMdd_HHmmss"
$logPath = Join-Path -Path $TempLogDir -ChildPath "Setup_CCS_and_Task_$currentDate.log"

# Ensure log directory exists with correct permissions
if (-not (Test-Path $TempLogDir)) {
    try {
        New-Item -Path $TempLogDir -ItemType Directory -Force | Out-Null
        icacls $TempLogDir /grant "NT AUTHORITY\SYSTEM:(OI)(CI)(F)" /grant "Administrators:(OI)(CI)(F)" | Out-Null
        Write-SetupLog -Message "Created log directory: ${TempLogDir} with SYSTEM and Administrators permissions" -EventId 1058
    } catch {
        Write-SetupLog -Message "Failed to create log directory ${TempLogDir}: $($_.Exception.Message)" -Level "ERROR" -EventId 1059
        throw
    }
}

# Function to write log messages to file and console
function Write-SetupLog {
    param (
        [string]$Message,
        [string]$Level = "INFO",
        [int]$EventId = 1000
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Write to log file
    Add-Content -Path $logPath -Value $logMessage -ErrorAction SilentlyContinue
    
    # Write to console
    Write-Output $logMessage
}

# Function to convert SecureString to plain text (compatible with PowerShell 5.1)
function Convert-SecureStringToPlainText {
    param (
        [securestring]$SecureString
    )
    try {
        $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
        $plainText = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
        return $plainText
    } finally {
        if ($ptr -ne [IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
        }
    }
}

# Function to check if running in an interactive session
function Test-InteractiveSession {
    try {
        [void][System.Console]::WindowHeight
        return $true
    } catch {
        return $false
    }
}

# Function to log Task Scheduler events
function Log-TaskSchedulerEvents {
    param (
        [string]$TaskName
    )
    try {
        $events = Get-WinEvent -LogName "Microsoft-Windows-TaskScheduler/Operational" -MaxEvents 50 -ErrorAction Stop |
            Where-Object { $_.Message -like "*${TaskName}*" }
        if ($events) {
            Write-SetupLog -Message "Task Scheduler events for ${TaskName}:" -EventId 1001
            foreach ($event in $events) {
                Write-SetupLog -Message "Event ID: $($event.Id), Time: $($event.TimeCreated), Message: $($event.Message)" -EventId 1002
            }
        } else {
            Write-SetupLog -Message "No recent Task Scheduler events found for ${TaskName}" -EventId 1003
        }
    } catch {
        Write-SetupLog -Message "Failed to retrieve Task Scheduler events for ${TaskName}: $($_.Exception.Message)" -Level "WARNING" -EventId 1004
    }
}

# Function to find a SYSTEM-writable directory
function Find-SystemWritableDirectory {
    $dirs = @(
        "C:\Logs",
        "C:\Windows\Temp",
        [System.IO.Path]::GetTempPath(),
        "C:\Temp"
    )
    foreach ($dir in $dirs) {
        try {
            if (-not (Test-Path $dir)) {
                New-Item -Path $dir -ItemType Directory -Force | Out-Null
                icacls $dir /grant "NT AUTHORITY\SYSTEM:(OI)(CI)(F)" /grant "Administrators:(OI)(CI)(F)" | Out-Null
                Write-SetupLog -Message "Created directory ${dir} with SYSTEM and Administrators permissions" -EventId 1005
            }
            $acl = icacls $dir
            Write-SetupLog -Message "Permissions for ${dir}: $($acl -join ', ')" -EventId 1006
            $testFile = Join-Path -Path $dir -ChildPath "TestWrite_$(Get-Date -Format 'yyyyMMdd_HHmmss_fff').txt"
            $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c echo Test > ${testFile}"
            $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            $testTaskName = "TestWriteDir"
            Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
            Register-ScheduledTask -TaskName $testTaskName -Action $action -Principal $principal -ErrorAction Stop | Out-Null
            Write-SetupLog -Message "Registered test task ${testTaskName} to verify write permissions to ${dir}" -EventId 1007
            Start-ScheduledTask -TaskName $testTaskName -ErrorAction Stop
            Start-Sleep -Seconds 60
            Log-TaskSchedulerEvents -TaskName $testTaskName
            Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
            if (Test-Path $testFile) {
                Write-SetupLog -Message "SYSTEM can write to ${dir}" -EventId 1008
                Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
                return $dir
            } else {
                Write-SetupLog -Message "SYSTEM write test to ${dir} failed: No log file created" -Level "WARNING" -EventId 1009
            }
        } catch {
            Write-SetupLog -Message "Failed to test SYSTEM write permission to ${dir}: $($_.Exception.Message)" -Level "WARNING" -EventId 1010
        }
    }
    Write-SetupLog -Message "No SYSTEM-writable directory found. Falling back to C:\Windows\Temp." -Level "WARNING" -EventId 1011
    return "C:\Windows\Temp"
}

# Function to test directory write permissions for SYSTEM
function Test-SystemWritePermission {
    param (
        [string]$Path
    )
    try {
        if (-not $Path -or $Path -match "^\[.*") {
            Write-SetupLog -Message "Invalid path provided to Test-SystemWritePermission: ${Path}" -Level "ERROR" -EventId 1012
            return $false
        }
        # Sanitize path to avoid invalid characters
        $Path = [System.IO.Path]::GetFullPath($Path)
        $testFile = Join-Path -Path $Path -ChildPath "TestWrite_$(Get-Date -Format 'yyyyMMdd_HHmmss_fff').txt"
        $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c echo Test > ${testFile}"
        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $testTaskName = "TestWritePermission"
        Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $testTaskName -Action $action -Principal $principal -ErrorAction Stop | Out-Null
        Write-SetupLog -Message "Registered test task ${testTaskName} to verify write permissions to ${Path}" -EventId 1013
        Start-ScheduledTask -TaskName $testTaskName -ErrorAction Stop
        Start-Sleep -Seconds 60
        Log-TaskSchedulerEvents -TaskName $testTaskName
        if (Test-Path $testFile) {
            Write-SetupLog -Message "SYSTEM write permission test to ${Path} succeeded" -EventId 1014
            Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
            return $true
        } else {
            Write-SetupLog -Message "SYSTEM write permission test to ${Path} failed" -Level "WARNING" -EventId 1015
            return $false
        }
    } catch {
        Write-SetupLog -Message "Failed to test SYSTEM write permission to ${Path}: $($_.Exception.Message)" -Level "ERROR" -EventId 1016
        return $false
    }
}

# Function to test minimal SYSTEM execution with cmd.exe
function Test-MinimalSystemCmd {
    param (
        [string]$LogDir
    )
    try {
        if (-not $LogDir -or $LogDir -match "^\[.*") {
            Write-SetupLog -Message "Invalid log directory provided to Test-MinimalSystemCmd: ${LogDir}" -Level "ERROR" -EventId 1017
            return
        }
        $testLog = Join-Path -Path $LogDir -ChildPath "MinimalSystemCmdTest_$(Get-Date -Format 'yyyyMMdd_HHmmss_fff').log"
        $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c echo Test > ${testLog}"
        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $testTaskName = "TestMinimalSystemCmd"
        Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $testTaskName -Action $action -Principal $principal -ErrorAction Stop | Out-Null
        Write-SetupLog -Message "Registered minimal cmd test task ${testTaskName} to verify SYSTEM execution" -EventId 1018
        Start-ScheduledTask -TaskName $testTaskName -ErrorAction Stop
        Start-Sleep -Seconds 60
        Log-TaskSchedulerEvents -TaskName $testTaskName
        if (Test-Path $testLog) {
            $taskLog = Get-Content -Path $testLog -Raw
            Write-SetupLog -Message "Minimal SYSTEM cmd execution test log: ${taskLog}" -EventId 1019
            Remove-Item -Path $testLog -Force -ErrorAction SilentlyContinue
        } else {
            Write-SetupLog -Message "Minimal SYSTEM cmd execution test log not found at ${testLog}" -Level "WARNING" -EventId 1020
        }
        Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
    } catch {
        Write-SetupLog -Message "Failed to test minimal SYSTEM cmd execution: $($_.Exception.Message)" -Level "ERROR" -EventId 1021
    }
}

# Function to test minimal SYSTEM execution with PowerShell
function Test-MinimalSystemPowerShell {
    param (
        [string]$LogDir
    )
    try {
        if (-not $LogDir -or $LogDir -match "^\[.*") {
            Write-SetupLog -Message "Invalid log directory provided to Test-MinimalSystemPowerShell: ${LogDir}" -Level "ERROR" -EventId 1022
            return
        }
        $testLog = Join-Path -Path $LogDir -ChildPath "MinimalSystemTest_$(Get-Date -Format 'yyyyMMdd_HHmmss_fff').log"
        $tempScript = Join-Path -Path "C:\Windows\Temp" -ChildPath "MinimalSystemTest_$(Get-Date -Format 'yyyyMMdd_HHmmss_fff').ps1"
        $psCommand = @"
try {
    'Test' | Out-File -FilePath '${testLog}' -Append -ErrorAction Stop
} catch {
    for (`$i = 0; `$i -lt 3; `$i++) {
        try {
            "Error: `$($_.Exception.Message)" | Out-File -FilePath "${testLog}" -Append -ErrorAction Stop
            break
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }
}
"@
        Set-Content -Path $tempScript -Value $psCommand -Force
        icacls $tempScript /grant "NT AUTHORITY\SYSTEM:(F)" | Out-Null
        Write-SetupLog -Message "Set SYSTEM permissions on ${tempScript}" -EventId 1023
        $testCommand = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"${tempScript}`" > ${testLog} 2>&1"
        $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c ${testCommand}"
        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $testTaskName = "TestMinimalSystem"
        Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $testTaskName -Action $action -Principal $principal -ErrorAction Stop | Out-Null
        Write-SetupLog -Message "Registered minimal test task ${testTaskName} to verify SYSTEM execution" -EventId 1024
        Start-ScheduledTask -TaskName $testTaskName -ErrorAction Stop
        Start-Sleep -Seconds 60
        Log-TaskSchedulerEvents -TaskName $testTaskName
        if (Test-Path $testLog) {
            $taskLog = Get-Content -Path $testLog -Raw
            Write-SetupLog -Message "Minimal SYSTEM PowerShell execution test log: ${taskLog}" -EventId 1025
            Remove Item -Path $testLog -Force -ErrorAction SilentlyContinue
        } else {
            Write-SetupLog -Message "Minimal SYSTEM PowerShell execution test log not found at ${testLog}" -Level "WARNING" -EventId 1026
        }
        Remove-Item -Path $tempScript -Force -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
    } catch {
        Write-SetupLog -Message "Failed to test minimal SYSTEM PowerShell execution: $($_.Exception.Message)" -Level "ERROR" -EventId 1027
    }
}

# Function to test PowerShell error logging via cmd.exe
function Test-PowerShellError {
    param (
        [string]$LogDir
    )
    try {
        if (-not $LogDir -or $LogDir -match "^\[.*") {
            Write-SetupLog -Message "Invalid log directory provided to Test-PowerShellError: ${LogDir}" -Level "ERROR" -EventId 1028
            return
        }
        $testLog = Join-Path -Path $LogDir -ChildPath "PowerShellErrorTest_$(Get-Date -Format 'yyyyMMdd_HHmmss_fff').log"
        $tempScript = Join-Path -Path "C:\Windows\Temp" -ChildPath "PowerShellErrorTest_$(Get-Date -Format 'yyyyMMdd_HHmmss_fff').ps1"
        $psCommand = @"
try {
    throw 'Test error'
} catch {
    for (`$i = 0; `$i -lt 3; `$i++) {
        try {
            "Error: `$($_.Exception.Message)" | Out-File -FilePath "${testLog}" -Append -ErrorAction Stop
            break
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }
}
"@
        Set-Content -Path $tempScript -Value $psCommand -Force
        icacls $tempScript /grant "NT AUTHORITY\SYSTEM:(F)" | Out-Null
        Write-SetupLog -Message "Set SYSTEM permissions on ${tempScript}" -EventId 1029
        $testCommand = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"${tempScript}`" > ${testLog} 2>&1"
        $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c ${testCommand}"
        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $testTaskName = "TestPowerShellError"
        Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $testTaskName -Action $action -Principal $principal -ErrorAction Stop | Out-Null
        Write-SetupLog -Message "Registered test task ${testTaskName} to verify PowerShell error logging via cmd.exe" -EventId 1030
        Start-ScheduledTask -TaskName $testTaskName -ErrorAction Stop
        Start-Sleep -Seconds 60
        Log-TaskSchedulerEvents -TaskName $testTaskName
        if (Test-Path $testLog) {
            $taskLog = Get-Content -Path $testLog -Raw
            Write-SetupLog -Message "PowerShell error test log via cmd.exe: ${taskLog}" -EventId 1031
            Remove-Item -Path $testLog -Force -ErrorAction SilentlyContinue
        } else {
            Write-SetupLog -Message "PowerShell error test log not found at ${testLog}" -Level "WARNING" -EventId 1032
        }
        Remove-Item -Path $tempScript -Force -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
    } catch {
        Write-SetupLog -Message "Failed to test PowerShell error logging via cmd.exe: $($_.Exception.Message)" -Level "ERROR" -EventId 1033
    }
}

# Function to test PowerShell environment in SYSTEM context
function Test-PowerShellEnvironment {
    param (
        [string]$LogDir
    )
    try {
        if (-not $LogDir -or $LogDir -match "^\[.*") {
            Write-SetupLog -Message "Invalid log directory provided to Test-PowerShellEnvironment: ${LogDir}" -Level "ERROR" -EventId 1034
            return
        }
        $testLog = Join-Path -Path $LogDir -ChildPath "PowerShellEnvTest_$(Get-Date -Format 'yyyyMMdd_HHmmss_fff').log"
        $tempScript = Join-Path -Path "C:\Windows\Temp" -ChildPath "PowerShellEnvTest_$(Get-Date -Format 'yyyyMMdd_HHmmss_fff').ps1"
        $psCommand = @"
try {
    `$envInfo = "PSVersion: `$($PSVersionTable.PSVersion)"
    `$envInfo += "`nExecutionPolicy: `$(Get-ExecutionPolicy -Scope CurrentUser)"
    `$envInfo += "`nUser: `$($env:USERNAME)"
    `$envInfo += "`nPath: `$($env:PSModulePath)"
    `$envInfo += "`nSecurityPolicy: `$(Get-ExecutionPolicy -List | Out-String)"
    `$envInfo += "`nWhoAmI: `$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
    `$envInfo += "`nErrorActionPreference: `$($ErrorActionPreference)"
    `$envInfo += "`nAppLockerPolicy: `$(try { Get-AppLockerPolicy -Effective -Local | Out-String } catch { 'Error: ' + `$_.Exception.Message })"
    `$envInfo += "`nProcessToken: `$(try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Groups | ForEach-Object { `$_.Translate([System.Security.Principal.NTAccount]) } | Out-String } catch { 'Error: ' + `$_.Exception.Message })"
    `$envInfo | Out-File -FilePath "${testLog}" -Append -ErrorAction Stop
} catch {
    for (`$i = 0; `$i -lt 3; `$i++) {
        try {
            "Error: `$($_.Exception.Message)" | Out-File -FilePath "${testLog}" -Append -ErrorAction Stop
            break
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }
}
"@
        Set-Content -Path $tempScript -Value $psCommand -Force
        icacls $tempScript /grant "NT AUTHORITY\SYSTEM:(F)" | Out-Null
        Write-SetupLog -Message "Set SYSTEM permissions on ${tempScript}" -EventId 1035
        $testCommand = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"${tempScript}`" > ${testLog} 2>&1"
        $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c ${testCommand}"
        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $testTaskName = "TestPowerShellEnv"
        Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $testTaskName -Action $action -Principal $principal -ErrorAction Stop | Out-Null
        Write-SetupLog -Message "Registered test task ${testTaskName} to verify PowerShell environment in SYSTEM context" -EventId 1036
        Start-ScheduledTask -TaskName $testTaskName -ErrorAction Stop
        Start-Sleep -Seconds 60
        Log-TaskSchedulerEvents -TaskName $testTaskName
        if (Test-Path $testLog) {
            $taskLog = Get-Content -Path $testLog -Raw
            Write-SetupLog -Message "PowerShell environment test log: ${taskLog}" -EventId 1037
            Remove-Item -Path $testLog -Force -ErrorAction SilentlyContinue
        } else {
            Write-SetupLog -Message "PowerShell environment test log not found at ${testLog}" -Level "WARNING" -EventId 1038
        }
        Remove-Item -Path $tempScript -Force -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
    } catch {
        Write-SetupLog -Message "Failed to test PowerShell environment in SYSTEM context: $($_.Exception.Message)" -Level "ERROR" -EventId 1039
    }
}

# Function to verify credential storage in SYSTEM context
function Verify-CredentialStorage {
    param (
        [string]$LogDir
    )
    try {
        $testLog = Join-Path -Path $LogDir -ChildPath "CredentialVerify_$(Get-Date -Format 'yyyyMMdd_HHmmss_fff').log"
        $verifyScript = Join-Path -Path "C:\Windows\Temp" -ChildPath "CredentialVerify_$(Get-Date -Format 'yyyyMMdd_HHmmss_fff').ps1"
        $psCommand = @"
try {
    Import-Module CredentialManager -ErrorAction Stop
    `$credential = Get-StoredCredential -Target 'PFXCertPassword' -ErrorAction Stop
    if (`$credential) {
        'Credential found' | Out-File -FilePath '${testLog}' -Append -ErrorAction Stop
    } else {
        'Credential not found' | Out-File -FilePath '${testLog}' -Append -ErrorAction Stop
    }
} catch {
    "Error: `$($_.Exception.Message)" | Out-File -FilePath "${testLog}" -Append -ErrorAction Stop
}
"@
        Set-Content -Path $verifyScript -Value $psCommand -Force
        icacls $verifyScript /grant "NT AUTHORITY\SYSTEM:(F)" | Out-Null
        Write-SetupLog -Message "Set SYSTEM permissions on ${verifyScript}" -EventId 1040
        $verifyCommand = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"${verifyScript}`" > ${testLog} 2>&1"
        $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c ${verifyCommand}"
        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $testTaskName = "TestCredentialVerify"
        Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $testTaskName -Action $action -Principal $principal -ErrorAction Stop | Out-Null
        Write-SetupLog -Message "Registered test task ${testTaskName} to verify credential storage in SYSTEM context" -EventId 1041
        Start-ScheduledTask -TaskName $testTaskName -ErrorAction Stop
        Start-Sleep -Seconds 60
        Log-TaskSchedulerEvents -TaskName $testTaskName
        if (Test-Path $testLog) {
            $taskLog = Get-Content -Path $testLog -Raw
            Write-SetupLog -Message "Credential verification log: ${taskLog}" -EventId 1042
            Remove-Item -Path $testLog -Force -ErrorAction SilentlyContinue
            if ($taskLog -match "Credential found") {
                Write-SetupLog -Message "Credential verified in SYSTEM context" -EventId 1043
                return $true
            } else {
                Write-SetupLog -Message "Credential not found in SYSTEM context. Log content: ${taskLog}" -Level "ERROR" -EventId 1044
                return $false
            }
        } else {
            Write-SetupLog -Message "Credential verification log not found at ${testLog}" -Level "ERROR" -EventId 1045
            return $false
        }
    } catch {
        Write-SetupLog -Message "Failed to verify credential storage in SYSTEM context: $($_.Exception.Message)" -Level "ERROR" -EventId 1046
        return $false
    } finally {
        Remove-Item -Path $verifyScript -Force -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
    }
}

# Function to install CredentialManager from a .nupkg file
function Install-CredentialManagerFromNupkg {
    param (
        [string]$NupkgPath
    )
    try {
        if (-not (Test-Path $NupkgPath) -or $NupkgPath -notlike "*.nupkg") {
            Write-SetupLog -Message "Invalid or missing CredentialManager .nupkg file at ${NupkgPath}. Ensure the path points to a valid .nupkg file." -Level "ERROR" -EventId 1073
            throw "Invalid .nupkg file path"
        }
        $moduleDestination = "C:\Program Files\WindowsPowerShell\Modules\CredentialManager"
        # Create a temporary directory for extraction
        $tempExtractPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "CredentialManager_$(Get-Date -Format 'yyyyMMdd_HHmmss')")
        New-Item -Path $tempExtractPath -ItemType Directory -Force | Out-Null
        Write-SetupLog -Message "Extracting .nupkg file to ${tempExtractPath}" -EventId 1074
        # Rename .nupkg to .zip and extract
        $zipPath = Join-Path -Path $tempExtractPath -ChildPath "CredentialManager.zip"
        Copy-Item -Path $NupkgPath -Destination $zipPath -Force
        Expand-Archive -Path $zipPath -DestinationPath $tempExtractPath -Force -ErrorAction Stop
        # List extracted contents for debugging
        $extractedItems = Get-ChildItem -Path $tempExtractPath -Recurse | Select-Object -ExpandProperty FullName
        Write-SetupLog -Message "Extracted .nupkg contents: $($extractedItems -join ', ')" -EventId 1075
        # Find the module folder (case-insensitive match for CredentialManager)
        $moduleFolder = Get-ChildItem -Path $tempExtractPath -Directory | Where-Object { $_.Name -match "^CredentialManager" } | Select-Object -First 1
        if (-not $moduleFolder) {
            # Check if module files exist directly in the root
            $modulePsd1 = Get-ChildItem -Path $tempExtractPath -File | Where-Object { $_.Name -match "^CredentialManager\.psd1$" }
            if ($modulePsd1) {
                Write-SetupLog -Message "Found module files directly in .nupkg root. Creating CredentialManager folder." -EventId 1076
                $moduleFolder = Join-Path -Path $tempExtractPath -ChildPath "CredentialManager"
                New-Item -Path $moduleFolder -ItemType Directory -Force | Out-Null
                Get-ChildItem -Path $tempExtractPath -File | ForEach-Object {
                    if ($_.Name -notmatch "^CredentialManager\.zip$") {
                        Move-Item -Path $_.FullName -Destination $moduleFolder -Force
                    }
                }
            } else {
                Write-SetupLog -Message "Could not find CredentialManager module folder or .psd1 file in extracted .nupkg. Ensure the .nupkg contains the CredentialManager module." -Level "ERROR" -EventId 1077
                throw "Module folder or .psd1 file not found in .nupkg"
            }
        }
        # Move the module to the destination
        if (Test-Path $moduleDestination) {
            Remove-Item -Path $moduleDestination -Recurse -Force -ErrorAction SilentlyContinue
        }
        Move-Item -Path $moduleFolder -Destination $moduleDestination -Force -ErrorAction Stop
        Write-SetupLog -Message "Successfully installed CredentialManager module to ${moduleDestination}" -EventId 1078
        # Clean up temporary files
        Remove-Item -Path $tempExtractPath -Recurse -Force -ErrorAction SilentlyContinue
    } catch {
        Write-SetupLog -Message "Failed to install CredentialManager from ${NupkgPath}: $($_.Exception.Message)" -Level "ERROR" -EventId 1079
        throw
    }
}

try {
    # Check Task Scheduler service status
    $taskService = Get-Service -Name Schedule -ErrorAction Stop
    if ($taskService.Status -ne 'Running') {
        Write-SetupLog -Message "Task Scheduler service is not running. Current status: $($taskService.Status)" -Level "ERROR" -EventId 1047
        throw "Task Scheduler service is not running"
    }
    Write-SetupLog -Message "Task Scheduler service is running" -EventId 1048

    # Check PowerShell execution policy
    $executionPolicy = Get-ExecutionPolicy -Scope LocalMachine
    if ($executionPolicy -eq 'Restricted' -or $executionPolicy -eq 'AllSigned') {
        Write-SetupLog -Message "PowerShell execution policy is ${executionPolicy}. This may prevent tasks from running. Consider setting to RemoteSigned or Bypass." -Level "WARNING" -EventId 1049
    }
    Write-SetupLog -Message "PowerShell execution policy: ${executionPolicy}" -EventId 1050

    # Log module paths for SYSTEM context
    $modulePath = $env:PSModulePath
    Write-SetupLog -Message "PowerShell module path: ${modulePath}" -EventId 1051

    # Log security policy information
    try {
        $appLockerPolicy = Get-AppLockerPolicy -Effective -Local -ErrorAction Stop
        Write-SetupLog -Message "AppLocker policy: $($appLockerPolicy | Out-String)" -EventId 1052
    } catch {
        Write-SetupLog -Message "Failed to retrieve AppLocker policy: $($_.Exception.Message)" -Level "WARNING" -EventId 1053
    }
    try {
        $groupPolicy = gpresult /R /SCOPE COMPUTER
        Write-SetupLog -Message "Group Policy (Computer scope): $($groupPolicy -join ', ')" -EventId 1054
    } catch {
        Write-SetupLog -Message "Failed to retrieve Group Policy: $($_.Exception.Message)" -Level "WARNING" -EventId 1055
    }

    # Prompt for ExportScriptPath if not provided
    if (-not $ExportScriptPath) {
        Write-SetupLog -Message "ExportScriptPath parameter not provided. Prompting for input." -Level "WARNING" -EventId 1056
        if (Test-InteractiveSession) {
            $ExportScriptPath = Read-Host -Prompt "Enter the full path to the export script (e.g., C:\Scripts\Export_Cert_CCS_Secure.ps1)"
            if (-not $ExportScriptPath) {
                Write-SetupLog -Message "No export script path provided. A valid path is required." -Level "ERROR" -EventId 1057
                throw "Export script path not provided"
            }
        } else {
            Write-SetupLog -Message "ExportScriptPath parameter not provided and non-interactive session detected. A valid path is required." -Level "ERROR" -EventId 1057
            throw "Export script path not provided in non-interactive session"
        }
    }

    # Sanitize TempLogDir path
    $TempLogDir = [System.IO.Path]::GetFullPath($TempLogDir)
    
    # Ensure TempLogDir exists and is writable by SYSTEM
    if (-not (Test-Path $TempLogDir)) {
        try {
            New-Item -Path $TempLogDir -ItemType Directory -Force | Out-Null
            icacls $TempLogDir /grant "NT AUTHORITY\SYSTEM:(OI)(CI)(F)" /grant "Administrators:(OI)(CI)(F)" | Out-Null
            Write-SetupLog -Message "Created temporary log directory: ${TempLogDir} with SYSTEM and Administrators permissions" -EventId 1058
        } catch {
            Write-SetupLog -Message "Failed to create temporary log directory ${TempLogDir}: $($_.Exception.Message)" -Level "ERROR" -EventId 1059
            throw
        }
    }
    if (-not (Test-SystemWritePermission -Path $TempLogDir)) {
        Write-SetupLog -Message "SYSTEM account cannot write to ${TempLogDir}. Attempting to find a SYSTEM-writable directory." -Level "WARNING" -EventId 1060
        $TempLogDir = Find-SystemWritableDirectory
        Write-SetupLog -Message "Using SYSTEM-writable directory: ${TempLogDir}" -EventId 1061
    }
    $acl = icacls $TempLogDir
    Write-SetupLog -Message "Permissions for ${TempLogDir}: $($acl -join ', ')" -EventId 1062

    # Test minimal SYSTEM execution with cmd.exe
    Test-MinimalSystemCmd -LogDir $TempLogDir

    # Test minimal SYSTEM execution with PowerShell
    Test-MinimalSystemPowerShell -LogDir $TempLogDir

    # Test PowerShell error logging via cmd.exe
    Test-PowerShellError -LogDir $TempLogDir

    # Test PowerShell environment in SYSTEM context
    Test-PowerShellEnvironment -LogDir $TempLogDir

    # Verify Windows Server version (2019 or 2022)
    $osVersion = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
    if ($osVersion -notlike "*Windows Server 2019*" -and $osVersion -notlike "*Windows Server 2022*") {
        Write-SetupLog -Message "Unsupported operating system: ${osVersion}. This script is designed for Windows Server 2019 or 2022." -Level "ERROR" -EventId 1063
        throw "Unsupported operating system"
    }
    Write-SetupLog -Message "Running on ${osVersion}" -EventId 1064

    # Install Web-Scripting-Tools and Web-CertProvider features if not already installed
    $scriptingFeature = Get-WindowsFeature -Name Web-Scripting-Tools
    if (-not $scriptingFeature.Installed) {
        Write-SetupLog -Message "Installing Web-Scripting-Tools feature" -EventId 1065
        Install-WindowsFeature -Name Web-Scripting-Tools -ErrorAction Stop
        Write-SetupLog -Message "Web-Scripting-Tools feature installed" -EventId 1066
    } else {
        Write-SetupLog -Message "Web-Scripting-Tools feature is already installed" -EventId 1067
    }
    $ccsFeature = Get-WindowsFeature -Name Web-CertProvider
    if (-not $ccsFeature.Installed) {
        Write-SetupLog -Message "Installing Web-CertProvider feature" -EventId 1068
        Install-WindowsFeature -Name Web-CertProvider -ErrorAction Stop
        Write-SetupLog -Message "Web-CertProvider feature installed" -EventId 1069
    } else {
        Write-SetupLog -Message "Web-CertProvider feature is already installed" -EventId 1070
    }

    # Check for CredentialManager module
    if (-not (Get-Module -ListAvailable -Name CredentialManager)) {
        Write-SetupLog -Message "CredentialManager module not found." -Level "WARNING" -EventId 1071
        if (-not $NupkgPath -or -not (Test-Path $NupkgPath)) {
            if (Test-InteractiveSession) {
                Write-SetupLog -Message "Prompting for CredentialManager .nupkg file location." -EventId 1072
                $NupkgPath = Read-Host -Prompt "Enter the full path to the CredentialManager .nupkg file (e.g., C:\Packages\CredentialManager.2.0.nupkg)"
                if (-not $NupkgPath -or -not (Test-Path $NupkgPath)) {
                    Write-SetupLog -Message "Invalid or missing .nupkg file path provided: ${NupkgPath}. To obtain the .nupkg file, run 'Save-Module -Name CredentialManager -Path C:\Temp\Modules' on a machine with internet access and transfer the file to this server." -Level "ERROR" -EventId 1073
                    throw "CredentialManager module not installed and no valid .nupkg file provided"
                }
            } else {
                Write-SetupLog -Message "CredentialManager module not found and no valid .nupkg file path provided in non-interactive session. Please provide a valid CredentialManager .nupkg file path (e.g., C:\Packages\CredentialManager.2.0.nupkg)." -Level "ERROR" -EventId 1073
                Write-SetupLog -Message "To obtain the .nupkg file, run 'Save-Module -Name CredentialManager -Path C:\Temp\Modules' on a machine with internet access and transfer the file to this server." -Level "ERROR" -EventId 1074
                throw "CredentialManager module not installed and no valid .nupkg file provided in non-interactive session"
            }
        }
        Install-CredentialManagerFromNupkg -NupkgPath $NupkgPath
    } else {
        Write-SetupLog -Message "CredentialManager module is already installed" -EventId 1076
    }
    Import-Module CredentialManager -ErrorAction Stop
    Write-SetupLog -Message "Imported CredentialManager module" -EventId 1077

    # Verify CCS via registry without modifying existing settings
    $registryPath = "HKLM:\SOFTWARE\Microsoft\IIS\CentralCertProvider"
    try {
        $registryValues = Get-ItemProperty -Path $registryPath -ErrorAction Stop
        Write-SetupLog -Message "CCS registry key found: Enabled=$($registryValues.Enabled), PhysicalPath=$($registryValues.CertStoreLocation)" -EventId 1078
        if ($registryValues.Enabled -ne 1 -or $registryValues.CertStoreLocation -ne $CcsPhysicalPath) {
            Write-SetupLog -Message "CCS registry key values are incorrect (Enabled=$($registryValues.Enabled), PhysicalPath=$($registryValues.CertStoreLocation)). Expected Enabled=1 and PhysicalPath=$CcsPhysicalPath. Will not modify existing settings." -Level "ERROR" -EventId 1079
            throw "CCS registry configuration is invalid"
        }
    } catch {
        Write-SetupLog -Message "CCS registry key not found at ${registryPath}. Creating key." -Level "WARNING" -EventId 1080
        New-Item -Path $registryPath -Force | Out-Null
        New-ItemProperty -Path $registryPath -Name Enabled -Value 1 -PropertyType DWord -ErrorAction Stop | Out-Null
        New-ItemProperty -Path $registryPath -Name CertStoreLocation -Value $CcsPhysicalPath -PropertyType String -ErrorAction Stop | Out-Null
        Write-SetupLog -Message "Created CCS registry key: Enabled=1, PhysicalPath=$CcsPhysicalPath" -EventId 1081
    }

    # Verify CCS path accessibility as SYSTEM
    try {
        $testPath = Test-Path $CcsPhysicalPath -ErrorAction Stop
        if (-not $testPath) {
            Write-SetupLog -Message "CCS path ${CcsPhysicalPath} is not accessible. Ensure the share is configured to allow access by the computer account." -Level "ERROR" -EventId 1082
            throw "CCS path inaccessible"
        }
        Write-SetupLog -Message "CCS path ${CcsPhysicalPath} is accessible" -EventId 1083
    } catch {
        Write-SetupLog -Message "Error accessing CCS path ${CcsPhysicalPath}: $($_.Exception.Message)" -Level "ERROR" -EventId 1084
        throw
    }

    # Store PFX password in Credential Manager as SYSTEM using CredentialManager module
    $tempTaskName = "TempStoreCredential"
    $tempLogPath = Join-Path -Path $TempLogDir -ChildPath "TempStoreCredential_$((Get-Date -Format 'yyyyMMdd_HHmmss_fff')).log"
    $psPassword = Convert-SecureStringToPlainText -SecureString $PfxPassword
    $storeScript = Join-Path -Path "C:\Windows\Temp" -ChildPath "StoreCredential_$((Get-Date -Format 'yyyyMMdd_HHmmss_fff')).ps1"
    $psCommand = @"
try {
    Import-Module CredentialManager -ErrorAction Stop
    New-StoredCredential -Target 'PFXCertPassword' -UserName 'PFXUser' -Password '${psPassword}' -Persist LocalMachine -ErrorAction Stop
    'Credential stored successfully' | Out-File -FilePath '${tempLogPath}' -Append -ErrorAction Stop
} catch {
    "Error: `$($_.Exception.Message)" | Out-File -FilePath "${tempLogPath}" -Append -ErrorAction Stop
}
"@
    try {
        Set-Content -Path $storeScript -Value $psCommand -Force
        icacls $storeScript /grant "NT AUTHORITY\SYSTEM:(F)" | Out-Null
        Write-SetupLog -Message "Set SYSTEM permissions on ${storeScript}" -EventId 1085
        $storeCommand = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"${storeScript}`" > ${tempLogPath} 2>&1"
        $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c ${storeCommand}"
        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Unregister-ScheduledTask -TaskName $tempTaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $tempTaskName -Action $action -Principal $principal -ErrorAction Stop | Out-Null
        Write-SetupLog -Message "Temporary task ${tempTaskName} created to store credential as SYSTEM" -EventId 1086
    } catch {
        Write-SetupLog -Message "Failed to register temporary task ${tempTaskName}: $($_.Exception.Message)" -Level "ERROR" -EventId 1087
        throw
    }

    # Run the temp task and verify execution
    try {
        Start-ScheduledTask -TaskName $tempTaskName -ErrorAction Stop
        Write-SetupLog -Message "Started temporary task ${tempTaskName}" -EventId 1088
        Start-Sleep -Seconds 60
        Log-TaskSchedulerEvents -TaskName $tempTaskName
        if (Test-Path $tempLogPath) {
            $taskLog = Get-Content -Path $tempLogPath -Raw
            if ($taskLog -match "Credential stored successfully") {
                Write-SetupLog -Message "Temporary task ${tempTaskName} executed successfully. Log content: ${taskLog}" -EventId 1089
            } else {
                Write-SetupLog -Message "Temporary task ${tempTaskName} failed. Log content: ${taskLog}" -Level "ERROR" -EventId 1090
                throw "Temporary task execution failed"
            }
        } else {
            Write-SetupLog -Message "Temporary task log file not found at ${tempLogPath}. Credential storage failed." -Level "ERROR" -EventId 1091
            throw "Credential storage failed"
        }
    } catch {
        Write-SetupLog -Message "Error running temporary task ${tempTaskName}: $($_.Exception.Message)" -Level "ERROR" -EventId 1092
        throw
    } finally {
        # Clean up temporary files and task
        Remove-Item -Path $tempLogPath -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $storeScript -Force -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $tempTaskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-SetupLog -Message "Temporary task ${tempTaskName} and files removed" -EventId 1093
    }

    # Verify credential storage in SYSTEM context with retries
    $retryCount = 3
    $retryDelay = 5
    $credentialVerified = $false
    for ($i = 0; $i -lt $retryCount; $i++) {
        try {
            $credentialVerified = Verify-CredentialStorage -LogDir $TempLogDir
            if ($credentialVerified) {
                break
            } else {
                Write-SetupLog -Message "Attempt $($i + 1) to verify credential failed. Retrying after ${retryDelay} seconds." -Level "WARNING" -EventId 1094
                if ($i -lt $retryCount - 1) {
                    Start-Sleep -Seconds $retryDelay
                    continue
                }
            }
        } catch {
            Write-SetupLog -Message "Attempt $($i + 1) to verify credential failed: $($_.Exception.Message)" -Level "WARNING" -EventId 1095
            if ($i -lt $retryCount - 1) {
                Start-Sleep -Seconds $retryDelay
                continue
            }
        }
    }
    if (-not $credentialVerified) {
        Write-SetupLog -Message "Failed to verify stored credential for PFXCertPassword after $retryCount attempts. Credential is not found." -Level "ERROR" -EventId 1096
        Write-SetupLog -Message "Please manually store the credential as SYSTEM using: New-StoredCredential -Target 'PFXCertPassword' -UserName 'PFXUser' -Password '<YourPassword>' -Persist LocalMachine" -Level "ERROR" -EventId 1097
        throw "Credential storage failed"
    }

    # Verify export script exists
    if (-not (Test-Path $ExportScriptPath)) {
        Write-SetupLog -Message "Export script not found at ${ExportScriptPath}" -Level "ERROR" -EventId 1098
        throw "Export script missing"
    }

    # Set up the scheduled task for certificate renewal event using COM object
    try {
        $queryXml = @"
<QueryList>
  <Query Id="0" Path="$EventLogName">
    <Select Path="$EventLogName">*[System[(EventID=$EventId)]]</Select>
  </Query>
</QueryList>
"@
        $taskService = New-Object -ComObject Schedule.Service
        $taskService.Connect()
        $taskDefinition = $taskService.NewTask(0)
        $taskDefinition.RegistrationInfo.Description = "Triggers on certificate renewal event (Event ID $EventId) to run export script"
        $taskDefinition.Settings.Enabled = $true
        $taskDefinition.Settings.StartWhenAvailable = $true
        $taskDefinition.Settings.ExecutionTimeLimit = "PT1H"
        $taskDefinition.Settings.RestartCount = 3
        $taskDefinition.Settings.RestartInterval = "PT5M"
        $trigger = $taskDefinition.Triggers.Create(0) # 0 = Event trigger
        $trigger.Subscription = $queryXml
        $trigger.Enabled = $true
        $action = $taskDefinition.Actions.Create(0) # 0 = Execute action
        $action.Path = "cmd.exe"
        $action.Arguments = "/c powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$ExportScriptPath`""
        $principal = $taskDefinition.Principal
        $principal.UserId = "NT AUTHORITY\SYSTEM"
        $principal.LogonType = 3 # Service account
        $principal.RunLevel = 1 # Highest privileges
        $folder = $taskService.GetFolder("\")
        try {
            $folder.RegisterTaskDefinition($TaskName, $taskDefinition, 6, $null, $null, 3) | Out-Null
            Write-SetupLog -Message "Registered new scheduled task: ${TaskName}" -EventId 1099
        } catch {
            Write-SetupLog -Message "Updating existing scheduled task: ${TaskName}" -EventId 1100
            $folder.RegisterTaskDefinition($TaskName, $taskDefinition, 4, $null, $null, 3) | Out-Null
        }
    } catch {
        Write-SetupLog -Message "Failed to register or update scheduled task ${TaskName}: $($_.Exception.Message)" -Level "ERROR" -EventId 1101
        throw
    }

    Write-SetupLog -Message "Setup completed successfully" -EventId 1102
} catch {
    Write-SetupLog -Message "Error during setup: $($_.Exception.Message)" -Level "ERROR" -EventId 1103
    throw
}
