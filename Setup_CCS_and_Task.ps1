# PowerShell script to enable IIS Centralized Certificate Store (CCS), store PFX password in Credential Manager as SYSTEM,
# and set up a scheduled task to trigger on certificate renewal event (Event ID 1001 in Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational)
# and execute the provided export script (Export_Cert_CCS_Secure.ps1).
#
# This script is designed for an air-gapped environment running Windows PowerShell 5.1 (Windows Server 2019/2022).
# It handles SecureString conversion without the -AsPlainText parameter (not available in PowerShell 5.1).
# The CredentialManager module must be manually installed from a downloaded package.
# Instructions for manual installation:
# 1. On a machine with internet access, download the CredentialManager module:
#    Save-Module -Name CredentialManager -Path "C:\Temp\Modules"
# 2. Transfer the downloaded module (C:\Temp\Modules\CredentialManager) to the air-gapped server, e.g., to C:\Temp\Modules.
# 3. On the air-gapped server, install the module:
#    Copy the CredentialManager folder to C:\Program Files\WindowsPowerShell\Modules
#    Or use: Install-Module -Name CredentialManager -Path "C:\Temp\Modules\CredentialManager" -Scope AllUsers
#
# The CCS file share must be pre-configured to allow access only via computer accounts (SYSTEM context).
# To set up the share securely (run on the file server):
# - Create the local folder: New-Item -Path "C:\IIS_Cert_Store" -ItemType Directory
# - Set NTFS permissions: Disable inheritance, add DOMAIN\IISComputerName$ with Full Control, and local Administrators.
#   Example: icacls "C:\IIS_Cert_Store" /inheritance:r /grant "DOMAIN\IISComputerName$":(OI)(F) /grant Administrators:(OI)(F)
# - Create SMB share: New-SmbShare -Name "IIS_Cert_Store" -Path "C:\IIS_Cert_Store" -FullAccess "DOMAIN\IISComputerName$", "Administrators"
# - Remove other permissions: Revoke-SmbShareAccess -Name "IIS_Cert_Store" -AccountName Everyone

param (
    [Parameter(Mandatory=$true)]
    [string]$CcsPhysicalPath,  # UNC path to the CCS file share, e.g., "\\file-server\IIS_Cert_Store"

    [Parameter(Mandatory=$true)]
    [securestring]$PfxPassword,  # PFX password to store in Credential Manager as SYSTEM

    [Parameter(Mandatory=$false)]
    [string]$ExportScriptPath,  # Path to the export script (prompted if not provided)

    [Parameter(Mandatory=$false)]
    [string]$TempLogDir,  # Directory for temporary task log files (prompted if not provided)

    [string]$TaskName = "Certificate Export on Renewal",

    [int]$EventId = 1001,  # Event ID for certificate renewal

    [string]$EventLogPath = "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational"
)

# Function to write log messages
function Write-SetupLog {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
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

# Function to log Task Scheduler events
function Log-TaskSchedulerEvents {
    param (
        [string]$TaskName
    )
    try {
        $events = Get-WinEvent -LogName "Microsoft-Windows-TaskScheduler/Operational" -MaxEvents 20 -ErrorAction Stop |
            Where-Object { $_.Message -like "*${TaskName}*" }
        if ($events) {
            Write-SetupLog -Message "Task Scheduler events for ${TaskName}:"
            foreach ($event in $events) {
                Write-SetupLog -Message "Event ID: $($event.Id), Time: $($event.TimeCreated), Message: $($event.Message)"
            }
        } else {
            Write-SetupLog -Message "No recent Task Scheduler events found for ${TaskName}"
        }
    } catch {
        Write-SetupLog -Message "Failed to retrieve Task Scheduler events for ${TaskName}: ${$_.Exception.Message}" -Level "WARNING"
    }
}

# Function to test directory write permissions for SYSTEM
function Test-SystemWritePermission {
    param (
        [string]$Path
    )
    try {
        # Sanitize path to avoid invalid characters
        $Path = [System.IO.Path]::GetFullPath($Path)
        $testFile = Join-Path -Path $Path -ChildPath "TestWrite_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        $testLog = Join-Path -Path $Path -ChildPath "TestWriteLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -Command `"try { 'Test' | Out-File '${testFile}' -ErrorAction Stop; 'Success' | Out-File '${testLog}' -Append } catch { 'Error: ' + \$_.Exception.Message | Out-File '${testLog}' -Append }`""
        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $testTaskName = "TestWritePermission"
        Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $testTaskName -Action $action -Principal $principal -ErrorAction Stop | Out-Null
        Write-SetupLog -Message "Registered test task ${testTaskName} to verify write permissions to ${Path}"
        Start-ScheduledTask -TaskName $testTaskName -ErrorAction Stop
        Start-Sleep -Seconds 60
        Log-TaskSchedulerEvents -TaskName $testTaskName
        if (Test-Path $testLog) {
            $taskLog = Get-Content -Path $testLog -Raw
            if ($taskLog -match "Success" -and (Test-Path $testFile)) {
                Write-SetupLog -Message "SYSTEM write permission test to ${Path} succeeded"
                Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
                Remove-Item -Path $testLog -Force -ErrorAction SilentlyContinue
                Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
                return $true
            } else {
                Write-SetupLog -Message "SYSTEM write permission test failed. Log content: ${taskLog}" -Level "ERROR"
                throw "SYSTEM write permission test failed"
            }
        } else {
            Write-SetupLog -Message "Test log file not found at ${testLog}. Falling back to direct write test." -Level "WARNING"
            # Fallback: Try direct write as SYSTEM
            $fallbackFile = Join-Path -Path $Path -ChildPath "FallbackTest_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
            $fallbackAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -Command `' 'Test' | Out-File '${fallbackFile}' -ErrorAction Stop `'"
            Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
            Register-ScheduledTask -TaskName $testTaskName -Action $fallbackAction -Principal $principal -ErrorAction Stop | Out-Null
            Start-ScheduledTask -TaskName $testTaskName -ErrorAction Stop
            Start-Sleep -Seconds 60
            Log-TaskSchedulerEvents -TaskName $testTaskName
            $writeSuccess = Test-Path $fallbackFile
            if ($writeSuccess) {
                Write-SetupLog -Message "Fallback SYSTEM write test to ${Path} succeeded"
                Remove-Item -Path $fallbackFile -Force -ErrorAction SilentlyContinue
            } else {
                Write-SetupLog -Message "Fallback SYSTEM write test to ${Path} failed" -Level "ERROR"
            }
            Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
            return $writeSuccess
        }
    } catch {
        Write-SetupLog -Message "Failed to test SYSTEM write permission to ${Path}: ${$_.Exception.Message}" -Level "ERROR"
        return $false
    }
}

# Function to test SYSTEM execution environment
function Test-SystemExecutionEnvironment {
    param (
        [string]$LogDir
    )
    try {
        $testLog = Join-Path -Path $LogDir -ChildPath "SystemEnvTest_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        $testCommand = "try { 'PSVersion: ' + \$PSVersionTable.PSVersion | Out-File '${testLog}' -Append; 'ModulePath: ' + \$env:PSModulePath | Out-File '${testLog}' -Append; 'Success' | Out-File '${testLog}' -Append } catch { 'Error: ' + \$_.Exception.Message | Out-File '${testLog}' -Append }"
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -Command `"$testCommand`""
        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $testTaskName = "TestSystemEnv"
        Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $testTaskName -Action $action -Principal $principal -ErrorAction Stop | Out-Null
        Write-SetupLog -Message "Registered test task ${testTaskName} to verify SYSTEM execution environment"
        Start-ScheduledTask -TaskName $testTaskName -ErrorAction Stop
        Start-Sleep -Seconds 60
        Log-TaskSchedulerEvents -TaskName $testTaskName
        if (Test-Path $testLog) {
            $taskLog = Get-Content -Path $testLog -Raw
            Write-SetupLog -Message "SYSTEM execution environment test log: ${taskLog}"
            Remove-Item -Path $testLog -Force -ErrorAction SilentlyContinue
        } else {
            Write-SetupLog -Message "SYSTEM execution environment test log not found at ${testLog}" -Level "WARNING"
        }
        Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
    } catch {
        Write-SetupLog -Message "Failed to test SYSTEM execution environment: ${$_.Exception.Message}" -Level "ERROR"
    }
}

try {
    # Check Task Scheduler service status
    $taskService = Get-Service -Name Schedule -ErrorAction Stop
    if ($taskService.Status -ne 'Running') {
        Write-SetupLog -Message "Task Scheduler service is not running. Current status: ${$taskService.Status}" -Level "ERROR"
        throw "Task Scheduler service is not running"
    }
    Write-SetupLog -Message "Task Scheduler service is running"

    # Check PowerShell execution policy
    $executionPolicy = Get-ExecutionPolicy -Scope LocalMachine
    if ($executionPolicy -eq 'Restricted' -or $executionPolicy -eq 'AllSigned') {
        Write-SetupLog -Message "PowerShell execution policy is ${executionPolicy}. This may prevent tasks from running. Consider setting to RemoteSigned or Bypass." -Level "WARNING"
    }
    Write-SetupLog -Message "PowerShell execution policy: ${executionPolicy}"

    # Log module paths for SYSTEM context
    $modulePath = $env:PSModulePath
    Write-SetupLog -Message "PowerShell module path: ${modulePath}"

    # Prompt for ExportScriptPath if not provided
    if (-not $ExportScriptPath) {
        $ExportScriptPath = Read-Host -Prompt "Enter the full path to the export script (e.g., C:\Scripts\Export_Cert_CCS_Secure.ps1)"
        if (-not $ExportScriptPath) {
            Write-SetupLog -Message "No export script path provided. A valid path is required." -Level "ERROR"
            throw "Export script path not provided"
        }
    }

    # Prompt for TempLogDir if not provided
    if (-not $TempLogDir) {
        $TempLogDir = Read-Host -Prompt "Enter the directory for temporary log files (e.g., C:\Logs)"
        if (-not $TempLogDir) {
            Write-SetupLog -Message "No temporary log directory provided. A valid directory is required." -Level "ERROR"
            throw "Temporary log directory not provided"
        }
    }

    # Sanitize TempLogDir path
    $TempLogDir = [System.IO.Path]::GetFullPath($TempLogDir)
    
    # Ensure TempLogDir exists and is writable by SYSTEM
    if (-not (Test-Path $TempLogDir)) {
        try {
            New-Item -Path $TempLogDir -ItemType Directory -Force | Out-Null
            Write-SetupLog -Message "Created temporary log directory: ${TempLogDir}"
        } catch {
            Write-SetupLog -Message "Failed to create temporary log directory ${TempLogDir}: ${$_.Exception.Message}" -Level "ERROR"
            throw
        }
    }
    if (-not (Test-SystemWritePermission -Path $TempLogDir)) {
        Write-SetupLog -Message "SYSTEM account cannot write to ${TempLogDir}. Please ensure SYSTEM has write permissions or choose a different directory." -Level "ERROR"
        Write-SetupLog -Message "To grant permissions, run: icacls '${TempLogDir}' /grant 'NT AUTHORITY\SYSTEM:(OI)(CI)(F)'" -Level "ERROR"
        throw "SYSTEM lacks write permissions to temporary log directory"
    }

    # Test SYSTEM execution environment
    Test-SystemExecutionEnvironment -LogDir $TempLogDir

    # Load WebAdministration module
    Import-Module WebAdministration -ErrorAction Stop
    Write-SetupLog -Message "Successfully loaded WebAdministration module"

    # Check for CredentialManager module
    $credentialManagerModule = Get-Module -ListAvailable -Name CredentialManager
    if (-not $credentialManagerModule) {
        Write-SetupLog -Message "CredentialManager module not found. This script is running in an air-gapped environment." -Level "ERROR"
        Write-SetupLog -Message "Please install the CredentialManager module manually:" -Level "ERROR"
        Write-SetupLog -Message "1. On a machine with internet access, run: Save-Module -Name CredentialManager -Path 'C:\Temp\Modules'" -Level "ERROR"
        Write-SetupLog -Message "2. Transfer the CredentialManager folder to the air-gapped server, e.g., to C:\Temp\Modules" -Level "ERROR"
        Write-SetupLog -Message "3. Install the module by copying to C:\Program Files\WindowsPowerShell\Modules or run: Install-Module -Name CredentialManager -Path 'C:\Temp\Modules\CredentialManager' -Scope AllUsers" -Level "ERROR"
        Write-SetupLog -Message "4. Alternatively, store the PFX password as SYSTEM using: powershell.exe -Command 'Import-Module CredentialManager; New-StoredCredential -Target PFXCertPassword -UserName PFXUser -Password <YourPassword> -Persist LocalMachine -Type Generic' as SYSTEM (e.g., via a temporary scheduled task)." -Level "ERROR"
        throw "CredentialManager module not available"
    }
    Import-Module CredentialManager -ErrorAction Stop
    Write-SetupLog -Message "Successfully loaded CredentialManager module"

    # Verify Windows Server version (2019 or 2022)
    $osVersion = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
    if ($osVersion -notlike "*Windows Server 2019*" -and $osVersion -notlike "*Windows Server 2022*") {
        Write-SetupLog -Message "Unsupported operating system: ${osVersion}. This script is designed for Windows Server 2019 or 2022." -Level "ERROR"
        throw "Unsupported operating system"
    }
    Write-SetupLog -Message "Running on ${osVersion}"

    # Install Web-CertProvider feature if not installed
    $ccsFeature = Get-WindowsFeature -Name Web-CertProvider
    if (-not $ccsFeature.Installed) {
        Write-SetupLog -Message "Installing Web-CertProvider feature"
        Install-WindowsFeature -Name Web-CertProvider -ErrorAction Stop
        Write-SetupLog -Message "Web-CertProvider feature installed"
    } else {
        Write-SetupLog -Message "Web-CertProvider feature is already installed"
    }

    # Check if centralCertProvider section exists, and create it if missing
    $ccsConfig = Get-WebConfiguration -Filter "/system.webServer/centralCertProvider" -ErrorAction SilentlyContinue
    if ($null -eq $ccsConfig) {
        Write-SetupLog -Message "centralCertProvider configuration section not found. Creating section in applicationHost.config" -Level "WARNING"
        try {
            # Add the centralCertProvider section
            Add-WebConfiguration -Filter "/system.webServer" -Value @{ Name = "centralCertProvider"; enabled = $false } -PSPath "MACHINE/WEBROOT/APPHOST" -ErrorAction Stop
            Write-SetupLog -Message "Successfully created centralCertProvider section"
            # Refresh IIS configuration
            Start-Process -FilePath "iisreset" -ArgumentList "/noforce" -Wait -NoNewWindow -ErrorAction Stop
            Write-SetupLog -Message "IIS configuration refreshed"
            $ccsConfig = Get-WebConfiguration -Filter "/system.webServer/centralCertProvider" -ErrorAction Stop
            if ($null -eq $ccsConfig) {
                Write-SetupLog -Message "centralCertProvider section still not found after refresh. Retrying creation." -Level "WARNING"
                Add-WebConfiguration -Filter "/system.webServer" -Value @{ Name = "centralCertProvider"; enabled = $false } -PSPath "MACHINE/WEBROOT/APPHOST" -ErrorAction Stop
                Start-Process -FilePath "iisreset" -ArgumentList "/noforce" -Wait -NoNewWindow -ErrorAction Stop
                $ccsConfig = Get-WebConfiguration -Filter "/system.webServer/centralCertProvider" -ErrorAction Stop
            }
        } catch {
            Write-SetupLog -Message "Failed to create centralCertProvider section or refresh IIS: ${$_.Exception.Message}" -Level "ERROR"
            throw
        }
    } else {
        Write-SetupLog -Message "centralCertProvider configuration section found"
    }

    # Enable CCS if not enabled
    if ($ccsConfig.enabled -ne $true) {
        Write-SetupLog -Message "Enabling Centralized Certificate Store"
        try {
            Set-WebConfigurationProperty -Filter /system.webServer/centralCertProvider -Name enabled -Value $true -PSPath "MACHINE/WEBROOT/APPHOST" -ErrorAction Stop
            Write-SetupLog -Message "Centralized Certificate Store enabled"
        } catch {
            Write-SetupLog -Message "Failed to enable Centralized Certificate Store: ${$_.Exception.Message}" -Level "ERROR"
            throw
        }
    } else {
        Write-SetupLog -Message "Centralized Certificate Store is already enabled"
    }

    # Set CCS physical path (uses computer account for access if no credentials set)
    if ($ccsConfig.physicalPath -ne $CcsPhysicalPath) {
        Write-SetupLog -Message "Setting CCS physical path to ${CcsPhysicalPath}"
        try {
            Set-WebConfigurationProperty -Filter /system.webServer/centralCertProvider -Name physicalPath -Value $CcsPhysicalPath -PSPath "MACHINE/WEBROOT/APPHOST" -ErrorAction Stop
            Write-SetupLog -Message "CCS physical path set to ${CcsPhysicalPath}"
        } catch {
            Write-SetupLog -Message "Failed to set CCS physical path: ${$_.Exception.Message}" -Level "ERROR"
            throw
        }
    } else {
        Write-SetupLog -Message "CCS physical path is already set to ${CcsPhysicalPath}"
    }

    # Verify CCS path accessibility as SYSTEM
    try {
        $testPath = Test-Path $CcsPhysicalPath -ErrorAction Stop
        if (-not $testPath) {
            Write-SetupLog -Message "CCS path ${CcsPhysicalPath} is not accessible. Ensure the share is configured to allow access by the computer account." -Level "ERROR"
            throw "CCS path inaccessible"
        }
        Write-SetupLog -Message "CCS path ${CcsPhysicalPath} is accessible"
    } catch {
        Write-SetupLog -Message "Error accessing CCS path ${CcsPhysicalPath}: ${$_.Exception.Message}" -Level "ERROR"
        throw
    }

    # Store PFX password in Credential Manager as SYSTEM using a temporary scheduled task
    $tempTaskName = "TempStoreCredential"
    $tempLogPath = Join-Path -Path $TempLogDir -ChildPath "TempStoreCredential_$((Get-Date -Format 'yyyyMMdd_HHmmss')).log"
    $tempScriptPath = Join-Path -Path $TempLogDir -ChildPath "TempStoreCredential_$((Get-Date -Format 'yyyyMMdd_HHmmss')).ps1"
    $psPassword = Convert-SecureStringToPlainText -SecureString $PfxPassword
    # Escape single quotes in the password to prevent command injection
    $psPassword = $psPassword -replace "'", "''"
    $modulePath = "C:\Program Files\WindowsPowerShell\Modules"
    $storeCommand = @"
Import-Module CredentialManager -ErrorAction Stop -Force -ModulePath '${modulePath}'
try {
    New-StoredCredential -Target PFXCertPassword -UserName 'PFXUser' -Password '$psPassword' -Persist LocalMachine -Type Generic -ErrorAction Stop
    'Success' | Out-File '$tempLogPath' -Append
} catch {
    'Error: ' + \$_.Exception.Message | Out-File '$tempLogPath' -Append
}
"@
    try {
        # Write the command to a temporary script file
        Set-Content -Path $tempScriptPath -Value $storeCommand -ErrorAction Stop
        Write-SetupLog -Message "Created temporary script file at ${tempScriptPath}"
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -File `"${tempScriptPath}`""
        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Unregister-ScheduledTask -TaskName $tempTaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $tempTaskName -Action $action -Principal $principal -ErrorAction Stop | Out-Null
        Write-SetupLog -Message "Temporary task ${tempTaskName} created to store credential as SYSTEM"
    } catch {
        Write-SetupLog -Message "Failed to register temporary task ${tempTaskName}: ${$_.Exception.Message}" -Level "ERROR"
        throw
    }

    # Run the temp task and verify execution
    try {
        Start-ScheduledTask -TaskName $tempTaskName -ErrorAction Stop
        Write-SetupLog -Message "Started temporary task ${tempTaskName}"
        Start-Sleep -Seconds 60
        Log-TaskSchedulerEvents -TaskName $tempTaskName
        if (Test-Path $tempLogPath) {
            $taskLog = Get-Content -Path $tempLogPath -Raw
            if ($taskLog -match "Success" -or $taskLog -match "TargetName\s*:\s*PFXCertPassword") {
                Write-SetupLog -Message "Temporary task ${tempTaskName} executed successfully. Log content: ${taskLog}"
            } else {
                Write-SetupLog -Message "Temporary task ${tempTaskName} failed. Log content: ${taskLog}" -Level "ERROR"
                throw "Temporary task execution failed"
            }
        } else {
            Write-SetupLog -Message "Temporary task log file not found at ${tempLogPath}. Attempting direct credential storage as fallback." -Level "WARNING"
            # Fallback: Try direct credential storage with log
            $fallbackLog = Join-Path -Path $TempLogDir -ChildPath "FallbackCredential_$((Get-Date -Format 'yyyyMMdd_HHmmss')).log"
            $fallbackScriptPath = Join-Path -Path $TempLogDir -ChildPath "FallbackCredential_$((Get-Date -Format 'yyyyMMdd_HHmmss')).ps1"
            $fallbackCommand = @"
Import-Module CredentialManager -ErrorAction Stop -Force -ModulePath '${modulePath}'
try {
    New-StoredCredential -Target PFXCertPassword -UserName 'PFXUser' -Password '$psPassword' -Persist LocalMachine -Type Generic -ErrorAction Stop
    'Success' | Out-File '$fallbackLog' -Append
} catch {
    'Error: ' + \$_.Exception.Message | Out-File '$fallbackLog' -Append
}
"@
            Set-Content -Path $fallbackScriptPath -Value $fallbackCommand -ErrorAction Stop
            Write-SetupLog -Message "Created fallback script file at ${fallbackScriptPath}"
            $fallbackAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -File `"${fallbackScriptPath}`""
            Unregister-ScheduledTask -TaskName $tempTaskName -Confirm:$false -ErrorAction SilentlyContinue
            Register-ScheduledTask -TaskName $tempTaskName -Action $fallbackAction -Principal $principal -ErrorAction Stop | Out-Null
            Start-ScheduledTask -TaskName $tempTaskName -ErrorAction Stop
            Start-Sleep -Seconds 60
            Log-TaskSchedulerEvents -TaskName $tempTaskName
            if (Test-Path $fallbackLog) {
                $fallbackLogContent = Get-Content -Path $fallbackLog -Raw
                if ($fallbackLogContent -match "Success" -or $fallbackLogContent -match "TargetName\s*:\s*PFXCertPassword") {
                    Write-SetupLog -Message "Fallback credential storage succeeded. Log content: ${fallbackLogContent}"
                } else {
                    Write-SetupLog -Message "Fallback credential storage failed. Log content: ${fallbackLogContent}" -Level "ERROR"
                    throw "Fallback credential storage failed"
                }
            } else {
                Write-SetupLog -Message "Fallback log file not found at ${fallbackLog}. Attempting direct credential storage without log." -Level "WARNING"
                # Final fallback: Store credential directly without log
                $finalScriptPath = Join-Path -Path $TempLogDir -ChildPath "FinalCredential_$((Get-Date -Format 'yyyyMMdd_HHmmss')).ps1"
                $finalCommand = @"
Import-Module CredentialManager -ErrorAction Stop -Force -ModulePath '${modulePath}'
New-StoredCredential -Target PFXCertPassword -UserName 'PFXUser' -Password '$psPassword' -Persist LocalMachine -Type Generic -ErrorAction Stop
"@
                Set-Content -Path $finalScriptPath -Value $finalCommand -ErrorAction Stop
                Write-SetupLog -Message "Created final script file at ${finalScriptPath}"
                $finalAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -File `"${finalScriptPath}`""
                Unregister-ScheduledTask -TaskName $tempTaskName -Confirm:$false -ErrorAction SilentlyContinue
                Register-ScheduledTask -TaskName $tempTaskName -Action $finalAction -Principal $principal -ErrorAction Stop | Out-Null
                Start-ScheduledTask -TaskName $tempTaskName -ErrorAction Stop
                Start-Sleep -Seconds 60
                Log-TaskSchedulerEvents -TaskName $tempTaskName
                # Verify credential storage directly
                try {
                    $credential = Get-StoredCredential -Target PFXCertPassword -ErrorAction Stop
                    if ($credential -and $credential.Password) {
                        Write-SetupLog -Message "Final fallback credential storage succeeded (verified directly)"
                    } else {
                        Write-SetupLog -Message "Final fallback credential storage failed: Credential is null or missing password" -Level "ERROR"
                        throw "Final fallback credential storage failed"
                    }
                } catch {
                    Write-SetupLog -Message "Final fallback credential storage failed: ${$_.Exception.Message}" -Level "ERROR"
                    throw "Final fallback credential storage failed"
                }
            }
        }
    } catch {
        Write-SetupLog -Message "Error running temporary task ${tempTaskName}: ${$_.Exception.Message}" -Level "ERROR"
        throw
    } finally {
        # Clean up temporary files and task
        Remove-Item -Path $tempScriptPath -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $tempLogPath -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $fallbackScriptPath -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $fallbackLog -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $finalScriptPath -Force -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $tempTaskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-SetupLog -Message "Temporary task ${tempTaskName} and files removed"
    }

    # Verify credential storage
    try {
        $credential = Get-StoredCredential -Target PFXCertPassword -ErrorAction Stop
        if ($null -eq $credential -or $null -eq $credential.Password) {
            Write-SetupLog -Message "Failed to verify stored credential for PFXCertPassword. Credential is null or missing password." -Level "ERROR"
            Write-SetupLog -Message "Please manually store the credential as SYSTEM using: powershell.exe -Command 'Import-Module CredentialManager -Force -ModulePath \"C:\Program Files\WindowsPowerShell\Modules\"; New-StoredCredential -Target PFXCertPassword -UserName PFXUser -Password <YourPassword> -Persist LocalMachine -Type Generic'" -Level "ERROR"
            throw "Credential storage failed"
        }
        Write-SetupLog -Message "PFX password successfully stored in Credential Manager"
    } catch {
        Write-SetupLog -Message "Error verifying stored credential: ${$_.Exception.Message}. Please manually store the credential as SYSTEM using: powershell.exe -Command 'Import-Module CredentialManager -Force -ModulePath \"C:\Program Files\WindowsPowerShell\Modules\"; New-StoredCredential -Target PFXCertPassword -UserName PFXUser -Password <YourPassword> -Persist LocalMachine -Type Generic'" -Level "ERROR"
        throw
    }

    # Verify export script exists
    if (-not (Test-Path $ExportScriptPath)) {
        Write-SetupLog -Message "Export script not found at ${ExportScriptPath}" -Level "ERROR"
        throw "Export script missing"
    }

    # Set up the scheduled task for certificate renewal event
    $queryXml = @"
<QueryList>
  <Query Id="0" Path="$EventLogPath">
    <Select Path="$EventLogPath">*[System[(EventID=$EventId)]]</Select>
  </Query>
</QueryList>
"@
    $trigger = New-ScheduledTaskTrigger -TriggerType Event -Subscription $queryXml
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ExportScriptPath`""
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 1) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5)
    $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings

    # Register or update the task
    try {
        if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
            Write-SetupLog -Message "Updating existing scheduled task: ${TaskName}"
            Set-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -ErrorAction Stop
        } else {
            Write-SetupLog -Message "Registering new scheduled task: ${TaskName}"
            Register-ScheduledTask -TaskName $TaskName -InputObject $task -ErrorAction Stop | Out-Null
        }
    } catch {
        Write-SetupLog -Message "Failed to register or update scheduled task ${TaskName}: ${$_.Exception.Message}" -Level "ERROR"
        throw
    }

    Write-SetupLog -Message "Setup completed successfully"
} catch {
    Write-SetupLog -Message "Error during setup: ${$_.Exception.Message}" -Level "ERROR"
    throw
}
