# Optimized PowerShell script to handle certificate export with date-based logging, event creation, and permission checks
# Triggered by Event ID 1001 (certificate renewal)
# Updated to retrieve PFX password from Credential Manager, get certificate file names from IIS SNI bindings,
# retrieve pfxBasePath from IIS Centralized Certificate Store location, and handle CCS not enabled or inaccessible

# Define logging configuration
$currentDate = Get-Date -Format "yyyy-MM-dd"
$logPath = "C:\Logs\CertificateExport_$currentDate.log"
$eventSource = "CertificateExportScript"
$eventLogName = "Application"

# Define default PFX base path and local fallback
$defaultPfxBasePath = "\\ocp-lab-srv-1.ocplab.net\IIS_Central_Cert_Store\IIS-SRV5-SRV6"
$localFallbackPath = "C:\CertStore"

# Ensure log directory exists
$logDir = Split-Path $logPath -Parent
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

# Create event source if it doesn't exist
if (-not [System.Diagnostics.EventLog]::SourceExists($eventSource)) {
    New-EventLog -LogName $eventLogName -Source $eventSource
}

# Function to write log messages to file and event log
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO",
        [int]$EventId = 1000
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Write to date-based log file
    Add-Content -Path $logPath -Value $logMessage
    
    # Write to event log
    $eventType = switch ($Level) {
        "ERROR" { [System.Diagnostics.EventLogEntryType]::Error }
        "WARNING" { [System.Diagnostics.EventLogEntryType]::Warning }
        default { [System.Diagnostics.EventLogEntryType]::Information }
    }
    
    Write-EventLog -LogName $eventLogName -Source $eventSource -EventId $EventId -EntryType $eventType -Message $Message
}

# Function to check network share or local path access
function Test-NetworkShareAccess {
    param (
        [string]$Path
    )
    try {
        if (Test-Path $Path) {
            Write-Log -Message "Path $Path is accessible" -EventId 1008
            return $true
        } else {
            Write-Log -Message "Path $Path is not accessible" -Level "WARNING" -EventId 1009
            return $false
        }
    } catch {
        Write-Log -Message "Error accessing path $($Path): $($_.Exception.Message)" -Level "WARNING" -EventId 1010
        return $false
    }
}

# Load required modules
try {
    Import-Module -Name WebAdministration -ErrorAction Stop
    Import-Module -Name CredentialManager -ErrorAction Stop
    Write-Log -Message "Successfully loaded WebAdministration and CredentialManager modules" -EventId 1017
} catch {
    Write-Log -Message "Failed to load required modules: $($_.Exception.Message)" -Level "ERROR" -EventId 1018
    throw
}

# Check if CCS feature is installed
try {
    $ccsFeature = Get-WindowsFeature -Name Web-CertProvider -ErrorAction Stop
    if (-not $ccsFeature.Installed) {
        Write-Log -Message "Centralized Certificate Store feature is not installed. Falling back to default path: $defaultPfxBasePath" -Level "WARNING" -EventId 1028
        $pfxBasePath = $defaultPfxBasePath
    } else {
        Write-Log -Message "Centralized Certificate Store feature is installed" -EventId 1029
    }
} catch {
    Write-Log -Message "Failed to check Centralized Certificate Store feature: $($_.Exception.Message). Falling back to default path: $defaultPfxBasePath" -Level "WARNING" -EventId 1030
    $pfxBasePath = $defaultPfxBasePath
}

# Retrieve PFX base path from IIS Centralized Certificate Store if feature is installed
if (-not $pfxBasePath) {
    try {
        $ccsConfig = Get-WebConfiguration -Filter "/system.webServer/centralCertProvider" -ErrorAction Stop
        if ($null -eq $ccsConfig) {
            Write-Log -Message "Centralized Certificate Store configuration not found, possibly due to missing section in applicationHost.config. Please initialize CCS using IIS Manager or PowerShell (Set-WebConfigurationProperty -Filter /system.webServer/centralCertProvider -Name enabled -Value `$true). Falling back to default path: $defaultPfxBasePath" -Level "WARNING" -EventId 1031
            $pfxBasePath = $defaultPfxBasePath
        } elseif ($ccsConfig.enabled -eq $true) {
            $pfxBasePath = $ccsConfig.physicalPath
            if (-not $pfxBasePath) {
                Write-Log -Message "Centralized Certificate Store is enabled but physicalPath is not set. Falling back to default path: $defaultPfxBasePath" -Level "WARNING" -EventId 1024
                $pfxBasePath = $defaultPfxBasePath
            } else {
                Write-Log -Message "Retrieved Centralized Certificate Store path: $pfxBasePath" -EventId 1025
            }
        } else {
            Write-Log -Message "Centralized Certificate Store is installed but not enabled. Please enable CCS in IIS Manager or PowerShell (Set-WebConfigurationProperty -Filter /system.webServer/centralCertProvider -Name enabled -Value `$true). Falling back to default path: $defaultPfxBasePath" -Level "WARNING" -EventId 1026
            $pfxBasePath = $defaultPfxBasePath
        }
    } catch {
        Write-Log -Message "Failed to retrieve Centralized Certificate Store path: $($_.Exception.Message). This may indicate a missing or inaccessible centralCertProvider section. Falling back to default path: $defaultPfxBasePath" -Level "WARNING" -EventId 1027
        $pfxBasePath = $defaultPfxBasePath
    }
}

# Validate and fallback to local path if default path is inaccessible
if (-not (Test-NetworkShareAccess -Path $pfxBasePath)) {
    Write-Log -Message "Default path $pfxBasePath is inaccessible. Attempting to create directory if possible" -Level "WARNING" -EventId 1032
    try {
        New-Item -ItemType Directory -Path $pfxBasePath -Force | Out-Null
        Write-Log -Message "Created default directory: $pfxBasePath" -EventId 1035
    } catch {
        Write-Log -Message "Failed to create default directory $($pfxBasePath): $($_.Exception.Message). Falling back to local path: $localFallbackPath" -Level "WARNING" -EventId 1036
        $pfxBasePath = $localFallbackPath
        # Ensure local fallback directory exists
        if (-not (Test-Path $localFallbackPath)) {
            try {
                New-Item -ItemType Directory -Path $localFallbackPath -Force | Out-Null
                Write-Log -Message "Created local fallback directory: $localFallbackPath" -EventId 1033
            } catch {
                Write-Log -Message "Failed to create local fallback directory $($localFallbackPath): $($_.Exception.Message)" -Level "ERROR" -EventId 1034
                throw "No accessible path for certificate export"
            }
        }
    }
}

# Retrieve PFX password from Credential Manager
try {
    Write-Log -Message "Attempting to retrieve PFX password from Credential Manager" -EventId 1037
    $credential = Get-StoredCredential -Target PFXCertPassword -ErrorAction Stop
    if ($null -eq $credential -or $null -eq $credential.Password) {
        Write-Log -Message "Credential Manager returned null or invalid credential for PFXCertPassword. Please store the credential using New-StoredCredential as SYSTEM" -Level "ERROR" -EventId 1039
        throw "Invalid or missing credential in Credential Manager"
    }
    $pfxPassword = $credential.Password  # SecureString
    Write-Log -Message "Successfully retrieved PFX password from Credential Manager" -EventId 1019
} catch {
    Write-Log -Message "Failed to retrieve PFX password from Credential Manager: $($_.Exception.Message). Please ensure the credential is stored for SYSTEM using New-StoredCredential -Target PFXCertPassword" -Level "ERROR" -EventId 1020
    # Optional: Fallback to hardcoded password for testing (uncomment with caution)
    # $pfxPassword = ConvertTo-SecureString "LAB$upp0rt" -AsPlainText -Force
    # Write-Log -Message "Using fallback hardcoded password due to Credential Manager failure" -Level "WARNING" -EventId 1041
    throw
}

# Get certificate configurations from IIS SNI bindings
try {
    Write-Log -Message "Attempting to retrieve IIS SNI bindings" -EventId 1038
    $certConfigs = Get-WebBinding -Protocol https | 
        Where-Object { $_.bindingInformation -match ":443:" } | 
        ForEach-Object {
            $hostName = $_.bindingInformation.Split(":")[-1]
            if ($hostName) {
                @{
                    Subject = "*$hostName*"
                    PfxFile = "$hostName.pfx"
                }
            }
        } | Where-Object { $_ }  # Filter out null entries

    if (-not $certConfigs) {
        Write-Log -Message "No HTTPS bindings with SNI found in IIS. Exiting as no certificates to export" -Level "WARNING" -EventId 1021
        exit
    }
    
    Write-Log -Message "Found $($certConfigs.Count) HTTPS bindings with SNI" -EventId 1022
} catch {
    Write-Log -Message "Failed to retrieve IIS bindings: $($_.Exception.Message)" -Level "ERROR" -EventId 1023
    throw
}

try {
    Write-Log -Message "Starting certificate export process" -EventId 1001
    
    # Check certificate store access
    try {
        $certStore = Get-ChildItem -Path "Cert:\LocalMachine\My" -ErrorAction Stop
        Write-Log -Message "Successfully accessed certificate store Cert:\LocalMachine\My" -EventId 1011
    } catch {
        Write-Log -Message "Failed to access certificate store Cert:\LocalMachine\My: $($_.Exception.Message)" -Level "ERROR" -EventId 1012
        throw
    }

    # Process each certificate
    foreach ($config in $certConfigs) {
        $subject = $config.Subject
        $pfxPath = Join-Path -Path $pfxBasePath -ChildPath $config.PfxFile
        
        try {
            # Get the most recent certificate
            $cert = Get-ChildItem -Path "Cert:\LocalMachine\My" |
                    Where-Object { $_.Subject -like $subject } |
                    Sort-Object NotAfter -Descending |
                    Select-Object -First 1
            
            if ($null -eq $cert) {
                Write-Log -Message "No certificate found for subject: $subject" -Level "ERROR" -EventId 1002
                continue
            }
            
            # Check private key export permissions
            if (-not $cert.HasPrivateKey) {
                Write-Log -Message "Certificate for subject $subject does not have a private key" -Level "ERROR" -EventId 1014
                continue
            }

            # Attempt to access private key to verify permissions
            try {
                $privateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
                if ($null -eq $privateKey) {
                    Write-Log -Message "Unable to access private key for subject $subject. Permission denied or key not exportable" -Level "ERROR" -EventId 1015
                    continue
                }
            } catch {
                Write-Log -Message "Failed to access private key for subject $($subject): $($_.Exception.Message)" -Level "ERROR" -EventId 1016
                continue
            }

            # Export certificate
            Write-Log -Message "Exporting certificate for subject: $subject to $pfxPath" -EventId 1003
            if ($null -eq $pfxPassword) {
                Write-Log -Message "PFX password is null before export for subject: $subject" -Level "ERROR" -EventId 1040
                throw "PFX password is null"
            }
            Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $pfxPassword -Force -ErrorAction Stop
            
            Write-Log -Message "Successfully exported certificate for subject: $subject" -EventId 1004
        }
        catch {
            Write-Log -Message "Failed to export certificate for subject: $subject. Error: $($_.Exception.Message)" -Level "ERROR" -EventId 1005
            continue
        }
    }
    
    Write-Log -Message "Certificate export process completed" -EventId 1006
}
catch {
    Write-Log -Message "Unexpected error in certificate export process: $($_.Exception.Message)" -Level "ERROR" -EventId 1007
}