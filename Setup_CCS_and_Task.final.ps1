# PowerShell script to enable IIS Centralized Certificate Store (CCS) via registry without modifying existing settings,
# store PFX password in Credential Manager as SYSTEM using CredentialManager module,
# and set up a scheduled task to trigger on certificate renewal event (Event ID 1001 in Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational)
# to execute the provided export script. Runs IIS Manager after CCS configuration and cleans up Username and Password registry keys.
# Logs all setup information to a file under C:\Logs with full timestamp.
#
# This script is designed for both interactive and non-interactive execution in an air-gapped environment running Windows PowerShell 5.1 (Windows Server 2019/2022).
# In interactive sessions, it prompts for CcsPhysicalPath, PfxPassword, ExportScriptPath, and NupkgPath (if CredentialManager module is not installed).
# In non-interactive sessions, it requires CcsPhysicalPath, PfxPassword, and ExportScriptPath as parameters, with NupkgPath optional.
#
# Prerequisites: The Web-CertProvider feature must be installed (automatically attempted via Install-WindowsFeature Web-CertProvider).
# The WebAdministration module with Enable-WebCentralCertProvider cmdlet is required for CCS configuration.
# Folders C:\Logs, C:\Scripts, and C:\Temp must exist, and files C:\Scripts\Export_Cert_CCS_Secure.ps1 and C:\Temp\credentialmanager.2.0.0.nupkg should be present.
# In an air-gapped environment, ensure the Windows Server installation media is available or manually transfer the module and files.
#
# Note: For optimal prompt display, run this script in powershell.exe (ConsoleHost) instead of PowerShell ISE (Windows PowerShell ISE Host).

param (
    [Parameter(Mandatory=$true)]
    [string]$CcsPhysicalPath,  # UNC path to the CCS file share, e.g., "\\ocp-lab-srv-1.ocplab.net\IIS_Central_Cert_Store\Cert-IIS01-IIS02"

    [Parameter(Mandatory=$false)]
    [securestring]$PfxPassword,  # PFX password to store in Credential Manager as SYSTEM

    [Parameter(Mandatory=$false)]
    [string]$ExportScriptPath,  # Path to the export script, e.g., "C:\Scripts\Export_Cert_CCS_Secure.ps1"

    [Parameter(Mandatory=$false)]
    [string]$TempLogDir = "C:\Logs",  # Directory for temporary task log files (default to C:\Logs)

    [Parameter(Mandatory=$false)]
    [string]$NupkgPath,  # Path to CredentialManager .nupkg file (prompted if not installed in interactive sessions)

    [string]$TaskName = "Certificate Export on Renewal",

    [int]$EventId = 1001,  # Event ID for certificate renewal

    [string]$EventLogName = "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational"
)

# Define logging configuration
$currentDate = Get-Date -Format "yyyyMMdd_HHmmss"
$logPath = Join-Path -Path $TempLogDir -ChildPath "Setup_CCS_and_Task_$currentDate.log"

# Function to write log messages to file and console
function Write-SetupLog {
    param (
        [string]$Message,
        [string]$Level = "INFO",
        [int]$EventId = 1000
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Write to log file with retry logic
    $retryCount = 3
    $retryDelay = 500
    for ($i = 0; $i -lt $retryCount; $i++) {
        try {
            Add-Content -Path $logPath -Value $logMessage -ErrorAction Stop
            break
        } catch {
            if ($i -lt $retryCount - 1) {
                Start-Sleep -Milliseconds $retryDelay
                continue
            }
            Write-Host "[$timestamp] [ERROR] Failed to write to log file ${logPath}: $($_.Exception.Message)"
        }
    }
    
    # Write to console
    Write-Host $logMessage
}

# Function to convert SecureString to plain text (compatible with PowerShell 5.1)
function Convert-SecureStringToPlainText {
    param (
        [securestring]$SecureString
    )
    try {
        if (-not $SecureString) {
            throw "SecureString is null or empty"
        }
        $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
        $plainText = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
        if (-not $plainText) {
            throw "Failed to convert SecureString to plain text: empty result"
        }
        return $plainText
    } finally {
        if ($ptr -ne [IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
        }
    }
}

# Function to check and create required folders and prompt for missing files
function Initialize-FoldersAndFiles {
    $requiredFolders = @(
        "C:\Logs",
        "C:\Scripts",
        "C:\Temp"
    )
    $requiredFiles = @{
        "C:\Scripts\Export_Cert_CCS_Secure.ps1" = "Please copy Export_Cert_CCS_Secure.ps1 to C:\Scripts."
        "C:\Temp\credentialmanager.2.0.0.nupkg" = "Please copy credentialmanager.2.0.0.nupkg to C:\Temp."
    }

    # Check and create folders
    foreach ($folder in $requiredFolders) {
        if (-not (Test-Path $folder)) {
            try {
                New-Item -Path $folder -ItemType Directory -Force | Out-Null
                icacls $folder /grant "NT AUTHORITY\SYSTEM:(OI)(CI)(F)" /grant "Administrators:(OI)(CI)(F)" | Out-Null
                Write-SetupLog -Message "Created directory ${folder} with SYSTEM and Administrators permissions" -EventId 1040
            } catch {
                Write-SetupLog -Message "Failed to create directory ${folder}: $($_.Exception.Message)" -Level "ERROR" -EventId 1041
                throw
            }
        } else {
            Write-SetupLog -Message "Directory ${folder} already exists" -EventId 1042
        }
    }

    # Check for required files and prompt if missing
    foreach ($file in $requiredFiles.Keys) {
        if (-not (Test-Path $file)) {
            Write-SetupLog -Message "File ${file} not found. ${requiredFiles[$file]}" -Level "WARNING" -EventId 1043
            if ($Host.UI.RawUI) {
                Write-SetupLog -Message "Prompting user to copy ${file}" -EventId 1044
                $null = Read-Host -Prompt $requiredFiles[$file]
            } else {
                Write-SetupLog -Message "Non-interactive session: Cannot prompt for file copy. Ensure ${file} is present." -Level "ERROR" -EventId 1045
                throw "Required file ${file} not found in non-interactive session"
            }
        } else {
            Write-SetupLog -Message "File ${file} found" -EventId 1046
        }
    }

    Write-SetupLog -Message "Folder and file initialization completed" -EventId 1047
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
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -Command `"Set-Content -Path '${testFile}' -Value 'Test' -Force`""
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
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -Command `"Set-Content -Path '${testFile}' -Value 'Test' -Force`""
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
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -Command `"for (`$i = 0; `$i -lt 3; `$i++) { try { Set-Content -Path '${testLog}' -Value 'Test' -Force -ErrorAction Stop; break } catch { Start-Sleep -Milliseconds 500; if (`$i -eq 2) { throw `$_.Exception } } }`""
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
        throw
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
    for (`$i = 0; `$i -lt 3; `$i++) {
        try {
            'Test' | Out-File -FilePath '${testLog}' -Append -ErrorAction Stop
            break
        } catch {
            Start-Sleep -Milliseconds 500
            if (`$i -eq 2) { throw `$_.Exception }
        }
    }
} catch {
    for (`$i = 0; `$i -lt 3; `$i++) {
        try {
            "Error: $($_.Exception.Message)" | Out-File -FilePath "${testLog}" -Append -ErrorAction Stop
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
        $testCommand = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"${tempScript}`""
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $testCommand
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
            Remove-Item -Path $testLog -Force -ErrorAction SilentlyContinue
        } else {
            Write-SetupLog -Message "Minimal SYSTEM PowerShell execution test log not found at ${testLog}" -Level "WARNING" -EventId 1026
        }
        Remove-Item -Path $tempScript -Force -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
    } catch {
        Write-SetupLog -Message "Failed to test minimal SYSTEM PowerShell execution: $($_.Exception.Message)" -Level "ERROR" -EventId 1027
        throw
    }
}

# Function to test PowerShell error logging
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
            "Error: $($_.Exception.Message)" | Out-File -FilePath "${testLog}" -Append -ErrorAction Stop
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
        $testCommand = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"${tempScript}`""
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $testCommand
        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $testTaskName = "TestPowerShellError"
        Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $testTaskName -Action $action -Principal $principal -ErrorAction Stop | Out-Null
        Write-SetupLog -Message "Registered test task ${testTaskName} to verify PowerShell error logging" -EventId 1030
        Start-ScheduledTask -TaskName $testTaskName -ErrorAction Stop
        Start-Sleep -Seconds 60
        Log-TaskSchedulerEvents -TaskName $testTaskName
        if (Test-Path $testLog) {
            $taskLog = Get-Content -Path $testLog -Raw
            Write-SetupLog -Message "PowerShell error test log: ${taskLog}" -EventId 1031
            Remove-Item -Path $testLog -Force -ErrorAction SilentlyContinue
        } else {
            Write-SetupLog -Message "PowerShell error test log not found at ${testLog}" -Level "WARNING" -EventId 1032
        }
        Remove-Item -Path $tempScript -Force -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
    } catch {
        Write-SetupLog -Message "Failed to test PowerShell error logging: $($_.Exception.Message)" -Level "ERROR" -EventId 1033
        throw
    }
}

# Function to run IIS Manager and wait for user input or delay in non-interactive mode
function Start-IISManager {
    try {
        $iisManagerPath = "$env:windir\system32\inetsrv\inetmgr.exe"
        if (-not (Test-Path $iisManagerPath)) {
            Write-SetupLog -Message "IIS Manager not found at ${iisManagerPath}" -Level "ERROR" -EventId 1034
            throw "IIS Manager executable missing"
        }
        Write-SetupLog -Message "Starting IIS Manager (${iisManagerPath})" -EventId 1035
        $process = Start-Process -FilePath $iisManagerPath -PassThru -ErrorAction Stop
        if ($Host.UI.RawUI) {
            Write-SetupLog -Message "Waiting for user to configure IIS Manager and press Enter" -EventId 1037
            $null = Read-Host -Prompt "Press Enter to continue after configuring IIS Manager"
        } else {
            Write-SetupLog -Message "Non-interactive session: Waiting 60 seconds for IIS Manager to initialize" -EventId 1037
            Start-Sleep -Seconds 60
        }
        if (-not $process.HasExited) {
            Write-SetupLog -Message "Terminating IIS Manager process (PID: $($process.Id))" -EventId 1038
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
        # Trigger IIS reset to apply changes
        Write-SetupLog -Message "Running iisreset to apply configuration changes" -EventId 1039
        & iisreset | Out-Null
        Write-SetupLog -Message "IIS reset completed" -EventId 1040
    } catch {
        Write-SetupLog -Message "Failed to run IIS Manager or reset IIS: $($_.Exception.Message)" -Level "ERROR" -EventId 1041
        throw
    }
}

# Function to clean up Username and Password registry keys
function Remove-CCSRegistryKeys {
    $registryPath = "HKLM:\SOFTWARE\Microsoft\IIS\CentralCertProvider"
    $keysToRemove = @("Username", "Password")
    try {
        if (-not (Test-Path $registryPath)) {
            Write-SetupLog -Message "CCS registry path ${registryPath} does not exist. No cleanup required." -Level "WARNING" -EventId 1042
            return
        }
        $keysFound = $false
        foreach ($key in $keysToRemove) {
            try {
                $property = Get-ItemProperty -Path $registryPath -Name $key -ErrorAction SilentlyContinue
                if ($property) {
                    $keysFound = $true
                    Write-SetupLog -Message "Found registry key '${key}' in ${registryPath}" -EventId 1043
                    Remove-ItemProperty -Path $registryPath -Name $key -ErrorAction Stop
                    Write-SetupLog -Message "Successfully removed registry key '${key}' from ${registryPath}" -EventId 1044
                } else {
                    Write-SetupLog -Message "Registry key '${key}' not found in ${registryPath}" -Level "WARNING" -EventId 1045
                }
            } catch {
                Write-SetupLog -Message "Failed to remove registry key '${key}' from ${registryPath}: $($_.Exception.Message)" -Level "ERROR" -EventId 1046
                throw
            }
        }
        # Verify removal
        $failedVerification = $false
        foreach ($key in $keysToRemove) {
            try {
                $property = Get-ItemProperty -Path $registryPath -Name $key -ErrorAction SilentlyContinue
                if ($property) {
                    Write-SetupLog -Message "Verification failed: Registry key '${key}' still exists in ${registryPath}" -Level "ERROR" -EventId 1047
                    $failedVerification = $true
                }
            } catch {
                Write-SetupLog -Message "Failed to verify removal of registry key '${key}' from ${registryPath}: $($_.Exception.Message)" -Level "ERROR" -EventId 1048
                throw
            }
        }
        if (-not $keysFound) {
            Write-SetupLog -Message "No specified registry keys (Username, Password) were found in ${registryPath}" -Level "WARNING" -EventId 1049
        } elseif (-not $failedVerification) {
            Write-SetupLog -Message "Verified: Specified registry keys (Username, Password) no longer exist in ${registryPath}" -EventId 1050
        } else {
            throw "Registry key removal verification failed"
        }
    } catch {
        Write-SetupLog -Message "Registry cleanup failed: $($_.Exception.Message)" -Level "ERROR" -EventId 1051
        throw
    }
}

try {
    # Log environment information
    $hostName = $Host.Name
    $psVersion = $PSVersionTable.PSVersion.ToString()
    Write-SetupLog -Message "Running in console host: $hostName, PowerShell version: $psVersion" -EventId 1052
    if ($hostName -eq "Windows PowerShell ISE Host") {
        Write-SetupLog -Message "Warning: Running in PowerShell ISE. For optimal prompt display, run this script in powershell.exe (ConsoleHost)." -Level "WARNING" -EventId 1053
    }

    # Initialize required folders and check for files
    Initialize-FoldersAndFiles

    # Check and install Web-CertProvider feature if not present
    $webCertProviderFeature = Get-WindowsFeature -Name Web-CertProvider -ErrorAction SilentlyContinue
    if ($webCertProviderFeature -and $webCertProviderFeature.Installed) {
        Write-SetupLog -Message "Web-CertProvider feature is already installed." -EventId 1054
    } else {
        Write-SetupLog -Message "Web-CertProvider feature not found or not installed. Attempting to install via Install-WindowsFeature Web-CertProvider." -EventId 1055
        try {
            $installResult = Install-WindowsFeature -Name Web-CertProvider -ErrorAction Stop
            Write-SetupLog -Message "Install-WindowsFeature Web-CertProvider result: Success=$($installResult.Success), RestartNeeded=$($installResult.RestartNeeded), ExitCode=$($installResult.ExitCode)" -EventId 1056
        } catch {
            Write-SetupLog -Message "Failed to install Web-CertProvider feature: $($_.Exception.Message)" -Level "ERROR" -EventId 1057
            Write-SetupLog -Message "In an air-gapped environment, ensure the Windows Server installation media is mounted and run 'Install-WindowsFeature Web-CertProvider -Source <path_to_source>'. Alternatively, ensure the WebAdministration module is available." -Level "ERROR" -EventId 1058
            throw "Web-CertProvider feature installation failed"
        }
    }

    # Check for WebAdministration module and Enable-WebCentralCertProvider cmdlet
    if (-not (Get-Module -ListAvailable -Name WebAdministration)) {
        Write-SetupLog -Message "WebAdministration module not found." -Level "ERROR" -EventId 1059
        Write-SetupLog -Message "The WebAdministration module is required for CCS configuration. Ensure the Web-CertProvider feature is installed and the module is available at C:\Windows\system32\WindowsPowerShell\v1.0\Modules\WebAdministration. In an air-gapped environment, transfer the module from an internet-connected machine." -Level "ERROR" -EventId 1060
        throw "WebAdministration module not installed"
    }
    try {
        Import-Module WebAdministration -Force -ErrorAction Stop
        if (-not (Get-Command -Name Enable-WebCentralCertProvider -ErrorAction SilentlyContinue)) {
            Write-SetupLog -Message "Enable-WebCentralCertProvider cmdlet not found in WebAdministration module." -Level "ERROR" -EventId 1061
            Write-SetupLog -Message "The Enable-WebCentralCertProvider cmdlet is required for CCS configuration. Ensure the Web-CertProvider feature is installed correctly and the WebAdministration module is up to date." -Level "ERROR" -EventId 1062
            throw "Enable-WebCentralCertProvider cmdlet not found"
        }
        Write-SetupLog -Message "WebAdministration module and Enable-WebCentralCertProvider cmdlet verified." -EventId 1063
    } catch {
        Write-SetupLog -Message "Failed to import WebAdministration module: $($_.Exception.Message)" -Level "ERROR" -EventId 1064
        throw
    }

    # Prompt for ExportScriptPath if not provided
    if (-not $ExportScriptPath) {
        Write-SetupLog -Message "Prompting for export script path" -EventId 1065
        $ExportScriptPath = Read-Host -Prompt "Enter the full path to the export script (e.g., C:\Scripts\Export_Cert_CCS_Secure.ps1)"
        if (-not $ExportScriptPath) {
            Write-SetupLog -Message "Export script path is required" -Level "ERROR" -EventId 1066
            throw "Export script path not provided"
        }
        Write-SetupLog -Message "Export script path set to: ${ExportScriptPath}" -EventId 1067
    }

    # Prompt for PfxPassword if not provided
    if (-not $PfxPassword) {
        Write-SetupLog -Message "Prompting for PFX password" -EventId 1068
        $PfxPassword = Read-Host -AsSecureString -Prompt "Enter the PFX password"
        if (-not $PfxPassword) {
            Write-SetupLog -Message "PFX password is required" -Level "ERROR" -EventId 1069
            throw "PFX password not provided"
        }
        Write-SetupLog -Message "Received PFX password" -EventId 1070
    }

    # Prompt for NupkgPath if CredentialManager module is missing
    if (-not (Get-Module -ListAvailable -Name CredentialManager)) {
        Write-SetupLog -Message "Prompting for CredentialManager .nupkg path" -EventId 1071
        $NupkgPath = Read-Host -Prompt "CredentialManager module not found. Enter the path to the CredentialManager .nupkg file (e.g., C:\Temp\credentialmanager.2.0.0.nupkg)"
        if (-not $NupkgPath -or -not (Test-Path $NupkgPath)) {
            Write-SetupLog -Message "CredentialManager .nupkg file not found at ${NupkgPath}" -Level "ERROR" -EventId 1072
            throw "CredentialManager .nupkg file not found"
        }
        Write-SetupLog -Message "Received NupkgPath: ${NupkgPath}" -EventId 1073
        try {
            $modulePath = "C:\Program Files\WindowsPowerShell\Modules\CredentialManager"
            $tempZipPath = [System.IO.Path]::ChangeExtension($NupkgPath, ".zip")
            Write-SetupLog -Message "Copying .nupkg file to temporary .zip file: ${tempZipPath}" -EventId 1074
            Copy-Item -Path $NupkgPath -Destination $tempZipPath -Force -ErrorAction Stop
            New-Item -Path $modulePath -ItemType Directory -Force | Out-Null
            Expand-Archive -Path $tempZipPath -DestinationPath $modulePath -Force -ErrorAction Stop
            Write-SetupLog -Message "Installed CredentialManager module to ${modulePath}" -EventId 1075
            Remove-Item -Path $tempZipPath -Force -ErrorAction SilentlyContinue
            Write-SetupLog -Message "Removed temporary .zip file: ${tempZipPath}" -EventId 1076
        } catch {
            Write-SetupLog -Message "Failed to install CredentialManager module from ${NupkgPath}: $($_.Exception.Message)" -Level "ERROR" -EventId 1077
            throw
        }
    }

    try {
        Import-Module CredentialManager -ErrorAction Stop
        Write-SetupLog -Message "Imported CredentialManager module" -EventId 1078
    } catch {
        Write-SetupLog -Message "Failed to import CredentialManager module: $($_.Exception.Message)" -Level "ERROR" -EventId 1079
        throw
    }

    # Store PFX password in Credential Manager as SYSTEM and verify
    try {
        $plainPassword = Convert-SecureStringToPlainText -SecureString $PfxPassword
        $maskedPassword = if ($plainPassword.Length -le 2) { "*" * $plainPassword.Length } else { $plainPassword[0] + "*" * ($plainPassword.Length - 2) + $plainPassword[-1] }
        # Create temp script to store credential as SYSTEM
        $testDir = "C:\Logs"
        $testFile = "${testDir}\TestStoreCredential_$(Get-Date -Format 'yyyyMMdd_HHmmss_fff').log"
        $testScript = "C:\Temp\TestStoreCredential_$(Get-Date -Format 'yyyyMMdd_HHmmss_fff').ps1"
        $psCommand = @"
Import-Module CredentialManager
try {
    Remove-StoredCredential -Target 'PFXCertPassword' -ErrorAction SilentlyContinue
    New-StoredCredential -Target 'PFXCertPassword' -UserName 'PFXUser' -Password '${plainPassword}' -Persist LocalMachine -ErrorAction Stop
    'Credential stored successfully' | Out-File -FilePath '${testFile}' -Append
} catch {
    "Error: `$($_.Exception.Message)" | Out-File -FilePath '${testFile}' -Append
}
"@
        Set-Content -Path $testScript -Value $psCommand -Force
        icacls $testScript /grant "NT AUTHORITY\SYSTEM:(F)" | Out-Null
        Write-SetupLog -Message "Created test script ${testScript} for SYSTEM credential storage" -EventId 1080
        $taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"${testScript}`""
        $taskPrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $testTaskName = "TestStoreCredential"
        Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $testTaskName -Action $taskAction -Principal $taskPrincipal -ErrorAction Stop | Out-Null
        Write-SetupLog -Message "Registered test task ${testTaskName} to store credential as SYSTEM" -EventId 1081
        Start-ScheduledTask -TaskName $testTaskName -ErrorAction Stop
        Start-Sleep -Seconds 60
        Log-TaskSchedulerEvents -TaskName $testTaskName
        if (Test-Path $testFile) {
            $taskLog = Get-Content -Path $testFile -Raw
            Write-SetupLog -Message "SYSTEM credential storage test log: ${taskLog}" -EventId 1082
            if ($taskLog -match "Credential stored successfully") {
                Write-SetupLog -Message "Successfully stored PFX password in Credential Manager as SYSTEM (masked): ${maskedPassword}" -EventId 1083
            } else {
                Write-SetupLog -Message "Failed to store PFXCertPassword credential as SYSTEM: ${taskLog}" -Level "ERROR" -EventId 1084
                throw "SYSTEM credential storage failed"
            }
            Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
        } else {
            Write-SetupLog -Message "SYSTEM credential storage test log not found at ${testFile}" -Level "ERROR" -EventId 1085
            throw "SYSTEM credential storage test failed"
        }
        Remove-Item -Path $testScript -Force -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
        # Verify credential accessibility as SYSTEM
        try {
            $testFile = "${testDir}\TestCredentialAccess_$(Get-Date -Format 'yyyyMMdd_HHmmss_fff').log"
            $testScript = "C:\Temp\TestCredentialAccess_$(Get-Date -Format 'yyyyMMdd_HHmmss_fff').ps1"
            $psCommand = @"
Import-Module CredentialManager
try {
    `$cred = Get-StoredCredential -Target 'PFXCertPassword' -ErrorAction Stop
    if (`$cred) {
        'Credential found' | Out-File -FilePath '${testFile}' -Append
    } else {
        'Credential not found' | Out-File -FilePath '${testFile}' -Append
    }
} catch {
    "Error: `$($_.Exception.Message)" | Out-File -FilePath '${testFile}' -Append
}
"@
            Set-Content -Path $testScript -Value $psCommand -Force
            icacls $testScript /grant "NT AUTHORITY\SYSTEM:(F)" | Out-Null
            Write-SetupLog -Message "Created test script ${testScript} for SYSTEM credential access verification" -EventId 1086
            $taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"${testScript}`""
            $taskPrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            $testTaskName = "TestCredentialAccess"
            Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
            Register-ScheduledTask -TaskName $testTaskName -Action $taskAction -Principal $taskPrincipal -ErrorAction Stop | Out-Null
            Write-SetupLog -Message "Registered test task ${testTaskName} to verify SYSTEM credential access" -EventId 1087
            Start-ScheduledTask -TaskName $testTaskName -ErrorAction Stop
            Start-Sleep -Seconds 60
            Log-TaskSchedulerEvents -TaskName $testTaskName
            if (Test-Path $testFile) {
                $taskLog = Get-Content -Path $testFile -Raw
                Write-SetupLog -Message "SYSTEM credential access test log: ${taskLog}" -EventId 1088
                if ($taskLog -match "Credential found") {
                    Write-SetupLog -Message "Verified PFXCertPassword credential is accessible to NT AUTHORITY\SYSTEM" -EventId 1089
                } else {
                    Write-SetupLog -Message "SYSTEM cannot access PFXCertPassword credential: ${taskLog}" -Level "ERROR" -EventId 1090
                    Write-SetupLog -Message "Ensure the Credential Manager store is accessible to NT AUTHORITY\SYSTEM. Manually store the credential as SYSTEM." -Level "ERROR" -EventId 1091
                    throw "SYSTEM credential access verification failed"
                }
                Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
            } else {
                Write-SetupLog -Message "SYSTEM credential access test log not found at ${testFile}" -Level "ERROR" -EventId 1092
                throw "SYSTEM credential access test failed"
            }
            Remove-Item -Path $testScript -Force -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
        } catch {
            Write-SetupLog -Message "Failed to verify PFXCertPassword credential accessibility as SYSTEM: $($_.Exception.Message)" -Level "ERROR" -EventId 1093
            throw
        }
    } catch {
        Write-SetupLog -Message "Failed to store or verify PFX password in Credential Manager: $($_.Exception.Message)" -Level "ERROR" -EventId 1094
        throw
    }

    # Verify CCS registry settings and configure if necessary
    $registryPath = "HKLM:\SOFTWARE\Microsoft\IIS\CentralCertProvider"
    try {
        $registryValues = Get-ItemProperty -Path $registryPath -ErrorAction Stop
        Write-SetupLog -Message "CCS registry key found: Enabled=$($registryValues.Enabled), CertStoreLocation=$($registryValues.CertStoreLocation)" -EventId 1095
        if ($registryValues.Enabled -ne 1 -or $registryValues.CertStoreLocation -ne $CcsPhysicalPath) {
            Write-SetupLog -Message "CCS registry key values are incorrect (Enabled=$($registryValues.Enabled), CertStoreLocation=$($registryValues.CertStoreLocation)). Expected Enabled=1 and CertStoreLocation=$CcsPhysicalPath" -Level "ERROR" -EventId 1096
            throw "CCS registry configuration is invalid"
        }
    } catch {
        Write-SetupLog -Message "CCS registry key not found at ${registryPath}. Please create it manually." -Level "ERROR" -EventId 1097
        throw "CCS registry key not found"
    }

    # Run IIS Manager
    Start-IISManager

    # Verify CCS path accessibility
    try {
        if (-not (Test-Path $CcsPhysicalPath)) {
            Write-SetupLog -Message "CCS path ${CcsPhysicalPath} is not accessible" -Level "ERROR" -EventId 1098
            throw "CCS path inaccessible"
        }
        Write-SetupLog -Message "CCS path ${CcsPhysicalPath} is accessible" -EventId 1099
    } catch {
        Write-SetupLog -Message "Error accessing CCS path ${CcsPhysicalPath}: $($_.Exception.Message)" -Level "ERROR" -EventId 1100
        throw
    }

    # Create scheduled task using COM object
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
        # Create event trigger
        $trigger = $taskDefinition.Triggers.Create(0) # 0 = Event trigger
        $trigger.Subscription = $queryXml
        $trigger.Enabled = $true
        # Create startup trigger
        $startupTrigger = $taskDefinition.Triggers.Create(8) # 8 = Startup trigger
        $startupTrigger.Enabled = $true
        $action = $taskDefinition.Actions.Create(0) # 0 = Execute action
        $action.Path = "powershell.exe"
        $action.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$ExportScriptPath`""
        $principal = $taskDefinition.Principal
        $principal.UserId = "NT AUTHORITY\SYSTEM"
        $principal.LogonType = 3 # Service account
        $principal.RunLevel = 1 # Highest privileges
        $folder = $taskService.GetFolder("\")
        try {
            $folder.RegisterTaskDefinition($TaskName, $taskDefinition, 6, $null, $null, 3) | Out-Null
            Write-SetupLog -Message "Registered new scheduled task: ${TaskName}" -EventId 1101
        } catch {
            Write-SetupLog -Message "Updating existing scheduled task: ${TaskName}" -EventId 1102
            $folder.RegisterTaskDefinition($TaskName, $taskDefinition, 4, $null, $null, 3) | Out-Null
        }
    } catch {
        Write-SetupLog -Message "Failed to register or update scheduled task ${TaskName}: $($_.Exception.Message)" -Level "ERROR" -EventId 1103
        throw
    }

    # Verify scheduled task
    try {
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        Write-SetupLog -Message "Verified scheduled task '${TaskName}' exists" -EventId 1104
        Log-TaskSchedulerEvents -TaskName $TaskName
    } catch {
        Write-SetupLog -Message "Failed to verify scheduled task '${TaskName}': $($_.Exception.Message)" -Level "ERROR" -EventId 1105
        throw
    }

    # Test SYSTEM execution environment
    $writableDir = Find-SystemWritableDirectory
    Test-MinimalSystemCmd -LogDir $writableDir
    Test-MinimalSystemPowerShell -LogDir $writableDir
    Test-PowerShellError -LogDir $writableDir
    if (-not (Test-SystemWritePermission -Path $writableDir)) {
        Write-SetupLog -Message "SYSTEM write permission test to ${writableDir} failed" -Level "ERROR" -EventId 1106
        throw "SYSTEM write permission test failed"
    }

    # Clean up Username and Password registry keys
    Remove-CCSRegistryKeys

    Write-SetupLog -Message "Setup completed successfully" -EventId 1107
} catch {
    Write-SetupLog -Message "Setup failed: $($_.Exception.Message)" -Level "ERROR" -EventId 1108
    throw
}
