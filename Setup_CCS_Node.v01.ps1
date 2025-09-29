# PowerShell script to configure IIS Centralized Certificate Store (CCS) by verifying registry settings,
# launching IIS Manager, and cleaning up Username and Password registry keys for CCS nodes.
# Logs all setup information to a file under C:\Logs with the format Setup_CCS_Node_<hostname>_<timestamp>.log.
#
# This script is designed for both interactive and non-interactive execution in an air-gapped environment running Windows PowerShell 5.1 (Windows Server 2019/2022).
# In interactive sessions, it prompts for CcsPhysicalPath.
# In non-interactive sessions, it requires CcsPhysicalPath as a parameter.
#
# Prerequisites: The Web-CertProvider feature must be installed (automatically attempted via Install-WindowsFeature Web-CertProvider).
# The WebAdministration module with Enable-WebCentralCertProvider cmdlet is required for CCS configuration.
# Folders C:\Logs and C:\Temp must exist.
# In an air-gapped environment, ensure the Windows Server installation media is available or manually transfer required modules.
#
# Note: For optimal prompt display, run this script in powershell.exe (ConsoleHost) instead of PowerShell ISE (Windows PowerShell ISE Host).

param (
    [Parameter(Mandatory=$true)]
    [string]$CcsPhysicalPath,  # UNC path to the CCS file share, e.g., "\\ocp-lab-srv-1.ocplab.net\IIS_Central_Cert_Store\Cert-IIS01-IIS02"

    [Parameter(Mandatory=$false)]
    [string]$TempLogDir = "C:\Logs"  # Directory for log files (default to C:\Logs)
)

# Define logging configuration
$currentDate = Get-Date -Format "yyyyMMdd_HHmmss"
$hostname = [System.Net.Dns]::GetHostName()
$logPath = Join-Path -Path $TempLogDir -ChildPath "Setup_CCS_Node_${hostname}_${currentDate}.log"

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

# Function to check and create required folders
function Initialize-FoldersAndFiles {
    $requiredFolders = @(
        "C:\Logs",
        "C:\Temp"
    )

    # Check and create folders
    foreach ($folder in $requiredFolders) {
        if (-not (Test-Path $folder)) {
            try {
                New-Item -Path $folder -ItemType Directory -Force | Out-Null
                icacls $folder /grant "NT AUTHORITY\SYSTEM:(OI)(CI)(F)" /grant "Administrators:(OI)(CI)(F)" | Out-Null
                Write-SetupLog -Message "Created directory ${folder} with SYSTEM and Administrators permissions" -EventId 1001
            } catch {
                Write-SetupLog -Message "Failed to create directory ${folder}: $($_.Exception.Message)" -Level "ERROR" -EventId 1002
                throw
            }
        } else {
            Write-SetupLog -Message "Directory ${folder} already exists" -EventId 1003
        }
    }

    Write-SetupLog -Message "Folder initialization completed" -EventId 1004
}

# Function to run IIS Manager and wait for user input or delay in non-interactive mode
function Start-IISManager {
    try {
        $iisManagerPath = "$env:windir\system32\inetsrv\inetmgr.exe"
        if (-not (Test-Path $iisManagerPath)) {
            Write-SetupLog -Message "IIS Manager not found at ${iisManagerPath}" -Level "ERROR" -EventId 1005
            throw "IIS Manager executable missing"
        }
        Write-SetupLog -Message "Starting IIS Manager (${iisManagerPath})" -EventId 1006
        $process = Start-Process -FilePath $iisManagerPath -PassThru -ErrorAction Stop
        if ($Host.UI.RawUI) {
            Write-SetupLog -Message "Waiting for user to configure IIS Manager and press Enter" -EventId 1007
            $null = Read-Host -Prompt "Press Enter to continue after configuring IIS Manager"
        } else {
            Write-SetupLog -Message "Non-interactive session: Waiting 60 seconds for IIS Manager to initialize" -EventId 1008
            Start-Sleep -Seconds 60
        }
        if (-not $process.HasExited) {
            Write-SetupLog -Message "Terminating IIS Manager process (PID: $($process.Id))" -EventId 1009
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
        # Trigger IIS reset to apply changes
        Write-SetupLog -Message "Running iisreset to apply configuration changes" -EventId 1010
        & iisreset | Out-Null
        Write-SetupLog -Message "IIS reset completed" -EventId 1011
    } catch {
        Write-SetupLog -Message "Failed to run IIS Manager or reset IIS: $($_.Exception.Message)" -Level "ERROR" -EventId 1012
        throw
    }
}

# Function to clean up Username and Password registry keys
function Remove-CCSRegistryKeys {
    $registryPath = "HKLM:\SOFTWARE\Microsoft\IIS\CentralCertProvider"
    $keysToRemove = @("Username", "Password")
    try {
        if (-not (Test-Path $registryPath)) {
            Write-SetupLog -Message "CCS registry path ${registryPath} does not exist. No cleanup required." -Level "WARNING" -EventId 1013
            return
        }
        $keysFound = $false
        foreach ($key in $keysToRemove) {
            try {
                $property = Get-ItemProperty -Path $registryPath -Name $key -ErrorAction SilentlyContinue
                if ($property) {
                    $keysFound = $true
                    Write-SetupLog -Message "Found registry key '${key}' in ${registryPath}" -EventId 1014
                    Remove-ItemProperty -Path $registryPath -Name $key -ErrorAction Stop
                    Write-SetupLog -Message "Successfully removed registry key '${key}' from ${registryPath}" -EventId 1015
                } else {
                    Write-SetupLog -Message "Registry key '${key}' not found in ${registryPath}" -Level "WARNING" -EventId 1016
                }
            } catch {
                Write-SetupLog -Message "Failed to remove registry key '${key}' from ${registryPath}: $($_.Exception.Message)" -Level "ERROR" -EventId 1017
                throw
            }
        }
        # Verify removal
        $failedVerification = $false
        foreach ($key in $keysToRemove) {
            try {
                $property = Get-ItemProperty -Path $registryPath -Name $key -ErrorAction SilentlyContinue
                if ($property) {
                    Write-SetupLog -Message "Verification failed: Registry key '${key}' still exists in ${registryPath}" -Level "ERROR" -EventId 1018
                    $failedVerification = $true
                }
            } catch {
                Write-SetupLog -Message "Failed to verify removal of registry key '${key}' from ${registryPath}: $($_.Exception.Message)" -Level "ERROR" -EventId 1019
                throw
            }
        }
        if (-not $keysFound) {
            Write-SetupLog -Message "No specified registry keys (Username, Password) were found in ${registryPath}" -Level "WARNING" -EventId 1020
        } elseif (-not $failedVerification) {
            Write-SetupLog -Message "Verified: Specified registry keys (Username, Password) no longer exist in ${registryPath}" -EventId 1021
        } else {
            throw "Registry key removal verification failed"
        }
    } catch {
        Write-SetupLog -Message "Registry cleanup failed: $($_.Exception.Message)" -Level "ERROR" -EventId 1022
        throw
    }
}

try {
    # Log environment information
    $hostName = $Host.Name
    $psVersion = $PSVersionTable.PSVersion.ToString()
    Write-SetupLog -Message "Running in console host: $hostName, PowerShell version: $psVersion" -EventId 1023
    if ($hostName -eq "Windows PowerShell ISE Host") {
        Write-SetupLog -Message "Warning: Running in PowerShell ISE. For optimal prompt display, run this script in powershell.exe (ConsoleHost)." -Level "WARNING" -EventId 1024
    }

    # Initialize required folders
    Initialize-FoldersAndFiles

    # Check and install Web-CertProvider feature if not present
    $webCertProviderFeature = Get-WindowsFeature -Name Web-CertProvider -ErrorAction SilentlyContinue
    if ($webCertProviderFeature -and $webCertProviderFeature.Installed) {
        Write-SetupLog -Message "Web-CertProvider feature is already installed." -EventId 1025
    } else {
        Write-SetupLog -Message "Web-CertProvider feature not found or not installed. Attempting to install via Install-WindowsFeature Web-CertProvider." -EventId 1026
        try {
            $installResult = Install-WindowsFeature -Name Web-CertProvider -ErrorAction Stop
            Write-SetupLog -Message "Install-WindowsFeature Web-CertProvider result: Success=$($installResult.Success), RestartNeeded=$($installResult.RestartNeeded), ExitCode=$($installResult.ExitCode)" -EventId 1027
        } catch {
            Write-SetupLog -Message "Failed to install Web-CertProvider feature: $($_.Exception.Message)" -Level "ERROR" -EventId 1028
            Write-SetupLog -Message "In an air-gapped environment, ensure the Windows Server installation media is mounted and run 'Install-WindowsFeature Web-CertProvider -Source <path_to_source>'. Alternatively, ensure the WebAdministration module is available." -Level "ERROR" -EventId 1029
            throw "Web-CertProvider feature installation failed"
        }
    }

    # Check for WebAdministration module and Enable-WebCentralCertProvider cmdlet
    if (-not (Get-Module -ListAvailable -Name WebAdministration)) {
        Write-SetupLog -Message "WebAdministration module not found." -Level "ERROR" -EventId 1030
        Write-SetupLog -Message "The WebAdministration module is required for CCS configuration. Ensure the Web-CertProvider feature is installed and the module is available at C:\Windows\system32\WindowsPowerShell\v1.0\Modules\WebAdministration. In an air-gapped environment, transfer the module from an internet-connected machine." -Level "ERROR" -EventId 1031
        throw "WebAdministration module not installed"
    }
    try {
        Import-Module WebAdministration -Force -ErrorAction Stop
        if (-not (Get-Command -Name Enable-WebCentralCertProvider -ErrorAction SilentlyContinue)) {
            Write-SetupLog -Message "Enable-WebCentralCertProvider cmdlet not found in WebAdministration module." -Level "ERROR" -EventId 1032
            Write-SetupLog -Message "The Enable-WebCentralCertProvider cmdlet is required for CCS configuration. Ensure the Web-CertProvider feature is installed correctly and the WebAdministration module is up to date." -Level "ERROR" -EventId 1033
            throw "Enable-WebCentralCertProvider cmdlet not found"
        }
        Write-SetupLog -Message "WebAdministration module and Enable-WebCentralCertProvider cmdlet verified." -EventId 1034
    } catch {
        Write-SetupLog -Message "Failed to import WebAdministration module: $($_.Exception.Message)" -Level "ERROR" -EventId 1035
        throw
    }

    # Verify CCS registry settings
    $registryPath = "HKLM:\SOFTWARE\Microsoft\IIS\CentralCertProvider"
    try {
        $registryValues = Get-ItemProperty -Path $registryPath -ErrorAction Stop
        Write-SetupLog -Message "CCS registry key found: Enabled=$($registryValues.Enabled), CertStoreLocation=$($registryValues.CertStoreLocation)" -EventId 1036
        if ($registryValues.Enabled -ne 1 -or $registryValues.CertStoreLocation -ne $CcsPhysicalPath) {
            Write-SetupLog -Message "CCS registry key values are incorrect (Enabled=$($registryValues.Enabled), CertStoreLocation=$($registryValues.CertStoreLocation)). Expected Enabled=1 and CertStoreLocation=$CcsPhysicalPath" -Level "ERROR" -EventId 1037
            throw "CCS registry configuration is invalid"
        }
    } catch {
        Write-SetupLog -Message "CCS registry key not found at ${registryPath}. Please create it manually." -Level "ERROR" -EventId 1038
        throw "CCS registry key not found"
    }

    # Run IIS Manager
    Start-IISManager

    # Verify CCS path accessibility
    try {
        if (-not (Test-Path $CcsPhysicalPath)) {
            Write-SetupLog -Message "CCS path ${CcsPhysicalPath} is not accessible" -Level "ERROR" -EventId 1039
            throw "CCS path inaccessible"
        }
        Write-SetupLog -Message "CCS path ${CcsPhysicalPath} is accessible" -EventId 1040
    } catch {
        Write-SetupLog -Message "Error accessing CCS path ${CcsPhysicalPath}: $($_.Exception.Message)" -Level "ERROR" -EventId 1041
        throw
    }

    # Clean up Username and Password registry keys
    Remove-CCSRegistryKeys

    Write-SetupLog -Message "Setup completed successfully" -EventId 1042
} catch {
    Write-SetupLog -Message "Setup failed: $($_.Exception.Message)" -Level "ERROR" -EventId 1043
    throw
}
