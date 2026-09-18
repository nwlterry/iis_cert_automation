# Optimized PowerShell script to handle certificate export with date-based logging, event creation, and permission checks
# Triggered by Event ID 1001 (certificate renewal)
# Updated to use registry for verifying Centralized Certificate Store and retrieving path,
# get certificate file names from IIS HTTPS bindings via appcmd.exe, handle access denied errors,
# and use a manually configured password for production

# Define logging configuration
$currentDate = Get-Date -Format "yyyy-MM-dd"
$logPath = "C:\Logs\CertificateExport_$currentDate.log"
$eventSource = "CertificateExportScript"
$eventLogName = "Application"

# Define default PFX base path and local fallback
$defaultPfxBasePath = "\\ocp-lab-srv-1.ocplab.net\IIS_Central_Cert_Store\Cert-IIS01-IIS02"
$localFallbackPath = "C:\CertStore"

# Define PFX password (set manually for production)
$pfxPassword = $null
# For production, uncomment and set the correct password:
# $pfxPassword = ConvertTo-SecureString "<YourProductionPassword>" -AsPlainText -Force
# For testing, use fallback password:
if ($null -eq $pfxPassword) {
    $pfxPassword = ConvertTo-SecureString "P@ssw0rdP@ssw0rd" -AsPlainText -Force
    Write-Warning "Using fallback PFX password for testing. For production, manually set the correct password in the script."
}

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

# Function to test write permissions to a path
function Test-WritePermission {
    param (
        [string]$Path
    )
    try {
        # Log current permissions
        $ntfsPermissions = icacls $Path
        Write-Log -Message "NTFS permissions for $Path`: $($ntfsPermissions -join ', ')" -EventId 1052
        if ($Path -like "\\*") {
            Write-Log -Message "Skipping SMB share permissions check for UNC path $Path on client server. Verify permissions on the file server." -EventId 1053
        } else {
            $shareName = ($Path -split "\\")[3]
            try {
                $smbPermissions = Get-SmbShareAccess -Name $shareName -ErrorAction Stop
                Write-Log -Message "SMB share permissions for $shareName`: $($smbPermissions | ForEach-Object { "$($_.AccountName): $($_.AccessRight)" } -join ', ')" -EventId 1053
            } catch {
                Write-Log -Message "Failed to retrieve SMB share permissions for $shareName`: $($_.Exception.Message)" -Level "WARNING" -EventId 1054
            }
        }
        $testFile = Join-Path -Path $Path -ChildPath "TestWrite_$(Get-Date -Format 'yyyyMMdd_HHmmss_fff').txt"
        [System.IO.File]::WriteAllText($testFile, "Test")
        Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Write permission test to $Path succeeded" -EventId 1046
        return $true
    } catch {
        Write-Log -Message "Write permission test to $Path failed: $($_.Exception.Message)" -Level "ERROR" -EventId 1047
        return $false
    }
}

# Check CCS via registry
$registryPath = "HKLM:\SOFTWARE\Microsoft\IIS\CentralCertProvider"
try {
    $registryValues = Get-ItemProperty -Path $registryPath -ErrorAction Stop
    if ($registryValues.Enabled -eq 1) {
        Write-Log -Message "Centralized Certificate Store is enabled in registry" -EventId 1029
        $pfxBasePath = $registryValues.CertStoreLocation
        if (-not $pfxBasePath) {
            Write-Log -Message "CertStoreLocation not set in registry. Falling back to default path: $defaultPfxBasePath" -Level "WARNING" -EventId 1024
            $pfxBasePath = $defaultPfxBasePath
        } else {
            Write-Log -Message "Retrieved Centralized Certificate Store path from registry: $pfxBasePath" -EventId 1025
        }
    } else {
        Write-Log -Message "Centralized Certificate Store is not enabled in registry. Falling back to default path: $defaultPfxBasePath" -Level "WARNING" -EventId 1026
        $pfxBasePath = $defaultPfxBasePath
    }
} catch {
    Write-Log -Message "Failed to retrieve Centralized Certificate Store registry: $($_.Exception.Message). Falling back to default path: $defaultPfxBasePath" -Level "WARNING" -EventId 1030
    $pfxBasePath = $defaultPfxBasePath
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

# Verify write permissions to CCS path
if (-not (Test-WritePermission -Path $pfxBasePath)) {
    Write-Log -Message "SYSTEM account lacks write permissions to $pfxBasePath. Please grant write permissions to NT AUTHORITY\SYSTEM." -Level "ERROR" -EventId 1048
    throw "No write permissions to CCS path"
}

# Log PFX password configuration
if ($pfxPassword -eq (ConvertTo-SecureString "P@ssw0rdP@ssw0rd" -AsPlainText -Force)) {
    Write-Log -Message "Using fallback PFX password for testing. For production, manually set the correct password in the script." -Level "WARNING" -EventId 1041
} else {
    Write-Log -Message "Using configured PFX password for certificate export" -EventId 1019
}

# Get certificate configurations from IIS HTTPS bindings using appcmd.exe
try {
    Write-Log -Message "Attempting to retrieve IIS HTTPS bindings using appcmd.exe" -EventId 1038
    $appcmdOutput = & "C:\Windows\System32\inetsrv\appcmd.exe" list sites
    Write-Log -Message "Raw appcmd.exe output: $($appcmdOutput -join ', ')" -EventId 1042
    $certConfigs = $appcmdOutput | ForEach-Object {
        # Match HTTPS bindings in site bindings
        if ($_ -match "bindings:.*https/[^:]+:(\d+):([^ ,]*)") {
            $port = $matches[1]
            $hostName = $matches[2]
            # Use hostname if present, otherwise use a generic identifier
            $subject = if ($hostName) { "*$hostName*" } else { "*default*" }
            $pfxFile = if ($hostName) { "$hostName.pfx" } else { "default.pfx" }
            @{
                Subject = $subject
                PfxFile = $pfxFile
            }
        }
    } | Where-Object { $_ }  # Filter out null entries

    if (-not $certConfigs) {
        Write-Log -Message "No HTTPS bindings found in IIS. Checking CCS path for .pfx files as fallback." -Level "WARNING" -EventId 1021
        # Fallback: Check CCS path for .pfx files
        try {
            $pfxFiles = Get-ChildItem -Path $pfxBasePath -Filter "*.pfx" -ErrorAction Stop
            if ($pfxFiles) {
                $certConfigs = $pfxFiles | ForEach-Object {
                    $hostName = [System.IO.Path]::GetFileNameWithoutExtension($_.Name)
                    @{
                        Subject = "*$hostName*"
                        PfxFile = $_.Name
                    }
                }
                Write-Log -Message "Found $($certConfigs.Count) .pfx files in CCS path: $($certConfigs.PfxFile -join ', ')" -EventId 1043
            } else {
                Write-Log -Message "No .pfx files found in CCS path $pfxBasePath. Ensure certificates are present in the CCS store or Cert:\LocalMachine\My and IIS bindings are configured. Exiting." -Level "WARNING" -EventId 1044
                exit
            }
        } catch {
            Write-Log -Message "Failed to access CCS path $pfxBasePath for .pfx files: $($_.Exception.Message). Ensure certificates are present in the CCS store or Cert:\LocalMachine\My and IIS bindings are configured. Exiting." -Level "ERROR" -EventId 1045
            exit
        }
    } else {
        Write-Log -Message "Found $($certConfigs.Count) HTTPS bindings: $($certConfigs.PfxFile -join ', ')" -EventId 1022
    }
} catch {
    Write-Log -Message "Failed to retrieve IIS bindings using appcmd.exe: $($_.Exception.Message)" -Level "ERROR" -EventId 1023
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
            
            # Log certificate details
            Write-Log -Message "Certificate details for $subject - Thumbprint: $($cert.Thumbprint), NotAfter: $($cert.NotAfter), HasPrivateKey: $($cert.HasPrivateKey)" -EventId 1049
            
            # Check private key exportability
            if ($cert.HasPrivateKey) {
                try {
                    $privateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
                    if ($null -eq $privateKey) {
                        Write-Log -Message "Unable to access private key for subject $subject. Permission denied or key not exportable" -Level "ERROR" -EventId 1015
                        continue
                    }
                    # Check exportability
                    $key = $cert.PrivateKey
                    if ($null -ne $key -and $key.CspKeyContainerInfo.Exportable) {
                        Write-Log -Message "Private key for subject $subject is exportable" -EventId 1050
                    } else {
                        Write-Log -Message "Private key for subject $subject is not exportable. Cannot export certificate." -Level "ERROR" -EventId 1051
                        continue
                    }
                } catch {
                    Write-Log -Message "Failed to access private key for subject $subject. Error: $($_.Exception.Message)" -Level "ERROR" -EventId 1016
                    continue
                }
            } else {
                Write-Log -Message "Certificate for subject $subject does not have a private key" -Level "ERROR" -EventId 1014
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
