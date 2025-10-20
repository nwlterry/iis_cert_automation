# PowerShell script to export certificates from the local computer certificate store (Cert:\LocalMachine\My)
# to PFX files in the IIS Centralized Certificate Store (CCS) path using a password stored in the Credential Manager.
# Certificates are exported only if their Common Name (CN) matches one of the manually defined SNI hostnames.
# Exports separate PFX files for each SNI hostname (e.g., example.com.pfx) and each node hostname (e.g., node1.pfx).
# Existing PFX files in the CCS path are backed up with a timestamp before overwriting, keeping only the 3 most recent backups per CN.
# The exported PFX file is verified to ensure validity.
# The retrieved PFX password is logged in a masked format for troubleshooting.
# Logs all actions to a file under C:\Logs with full timestamp and to the Windows Event Log (Application log, source: CertificateExport).
# Includes enhanced error handling for export, file write, and event log operations, increased retries, and robust fallback logic.
# Designed for an air-gapped environment running Windows PowerShell 5.1 (Windows Server 2019/2022).
# Assumes the CCS share has appropriate permissions for NT AUTHORITY\SYSTEM, Administrators, and OCPLAB\ISMWIN2019IIS01$.

# Manually define SNI and node hostnames
$sniHostNames = @("lab-iis-test-01.ocplab.net")  # Define your SNI hostnames here
$nodeHostNames = @("ismwin2019iis01.ocplab.net", "ismwin2019iis02.ocplab.net")  # Define your node hostnames here, defaulting to local computer name
$maxLogFiles = 5  # User-defined number of log files to keep

$currentDate = Get-Date -Format "yyyyMMdd_HHmmss"
$logPath = "C:\Logs\CertificateExport_$currentDate.log"
$successCount = 0  # Track successful exports
$tempPath = "C:\Temp"  # Fallback local path for failed network writes
$eventLogSource = "CertificateExport"
$eventLogName = "Application"

# Function to create event log source if it doesn't exist
function Initialize-EventLogSource {
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($eventLogSource)) {
            Write-Output "Creating event log source: $eventLogSource"
            New-EventLog -LogName $eventLogName -Source $eventLogSource -ErrorAction Stop
            Write-Output "Event log source $eventLogSource created successfully"
        }
    } catch {
        Write-Output "Failed to create event log source $($eventLogSource): $($_.Exception.Message)"
        # Fallback to logging only to file if event source creation fails
    }
}

# Function to write to Windows Event Log
function Write-EventLogMessage {
    param (
        [string]$Message,
        [string]$Level = "INFO",
        [int]$EventId
    )
    try {
        $eventType = switch ($Level) {
            "ERROR" { [System.Diagnostics.EventLogEntryType]::Error }
            "WARNING" { [System.Diagnostics.EventLogEntryType]::Warning }
            default { [System.Diagnostics.EventLogEntryType]::Information }
        }
        Write-EventLog -LogName $eventLogName -Source $eventLogSource -EventId $EventId -EntryType $eventType -Message $Message -ErrorAction Stop
    } catch {
        Write-Output "Failed to write to Event Log: $($_.Exception.Message)"
    }
}

# Function to write log messages to file and Windows Event Log
function Write-ExportLog {
    param (
        [string]$Message,
        [string]$Level = "INFO",
        [int]$EventId
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
            Write-Output "[$timestamp] [ERROR] Failed to write to log file ${logPath}: $($_.Exception.Message)"
        }
    }
    
    # Write to Windows Event Log
    Write-EventLogMessage -Message $logMessage -Level $Level -EventId $EventId
    
    # Write to console
    Write-Output $logMessage
}

# Function to manage log file retention
function Manage-LogFiles {
    param (
        [string]$LogDir,
        [int]$MaxFiles
    )
    try {
        $logFiles = Get-ChildItem -Path $LogDir -Filter "CertificateExport_*.log" | Sort-Object CreationTime -Descending
        if ($logFiles.Count -gt $MaxFiles) {
            $filesToDelete = $logFiles | Select-Object -Skip $MaxFiles
            foreach ($file in $filesToDelete) {
                try {
                    Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                    Write-ExportLog -Message "Deleted older log file: $($file.FullName)" -Level "INFO" -EventId 1067
                } catch {
                    Write-ExportLog -Message "Failed to delete older log file $($file.FullName): $($_.Exception.Message)" -Level "WARNING" -EventId 1068
                }
            }
        }
    } catch {
        Write-ExportLog -Message "Failed to manage log files in ${LogDir}: $($_.Exception.Message)" -Level "ERROR" -EventId 1069
    }
}

# Function to mask sensitive data (e.g., password) for logging
function Mask-SensitiveData {
    param (
        [string]$Data
    )
    if (-not $Data) {
        return "Empty"
    }
    if ($Data.Length -le 2) {
        return "*" * $Data.Length
    }
    $firstChar = $Data.Substring(0, 1)
    $lastChar = $Data.Substring($Data.Length - 1, 1)
    $maskedMiddle = "*" * ($Data.Length - 2)
    return "${firstChar}${maskedMiddle}${lastChar}"
}

# Function to extract Common Name (CN) from certificate subject
function Get-CertificateCommonName {
    param (
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    try {
        $subject = $Certificate.Subject
        $cnMatch = [regex]::Match($subject, "CN=([^,]+)")
        if ($cnMatch.Success) {
            $cn = $cnMatch.Groups[1].Value
            # Replace invalid file name characters with underscores
            $invalidChars = [System.IO.Path]::GetInvalidFileNameChars()
            foreach ($char in $invalidChars) {
                $cn = $cn.Replace($char, "_")
            }
            return $cn
        } else {
            throw "Common Name (CN) not found in certificate subject: $subject"
        }
    } catch {
        throw "Failed to extract Common Name from certificate: $($_.Exception.Message)"
    }
}

# Function to sanitize filename
function Sanitize-Filename {
    param (
        [string]$Filename
    )
    try {
        # Replace invalid file name characters with underscores
        $invalidChars = [System.IO.Path]::GetInvalidFileNameChars()
        foreach ($char in $invalidChars) {
            $Filename = $Filename.Replace($char, "_")
        }
        # Ensure .pfx extension
        if (-not $Filename.EndsWith(".pfx")) {
            $Filename = $Filename + ".pfx"
        }
        return $Filename
    } catch {
        Write-ExportLog -Message "Failed to sanitize filename ${Filename}: $($_.Exception.Message)" -Level "ERROR" -EventId 1008
        throw
    }
}

# Function to manage backups (keep only 3 most recent per CN)
function Manage-CertificateBackups {
    param (
        [string]$OutputDir,
        [string]$CN
    )
    try {
        $backupFiles = Get-ChildItem -Path $OutputDir -Filter "${CN}*.pfx.bak" | Sort-Object CreationTime -Descending
        if ($backupFiles.Count -gt 3) {
            $filesToDelete = $backupFiles | Select-Object -Skip 3
            foreach ($file in $filesToDelete) {
                try {
                    Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                    Write-ExportLog -Message "Deleted older backup file: $($file.FullName)" -Level "INFO" -EventId 1005
                } catch {
                    Write-ExportLog -Message "Failed to delete older backup file $($file.FullName): $($_.Exception.Message)" -Level "WARNING" -EventId 1006
                }
            }
        }
    } catch {
        Write-ExportLog -Message "Failed to manage backups for CN ${CN}: $($_.Exception.Message)" -Level "ERROR" -EventId 1007
    }
}

# Function to test write access to the CCS path with a binary file
function Test-WriteAccess {
    param (
        [string]$Path
    )
    try {
        $testFile = Join-Path -Path $Path -ChildPath "test_$(Get-Date -Format 'yyyyMMdd_HHmmss_fff').bin"
        # Generate a 5 KB binary file to mimic PFX file write
        $testBytes = New-Object byte[] 5120
        $random = New-Object System.Random
        $random.NextBytes($testBytes)
        [System.IO.File]::WriteAllBytes($testFile, $testBytes)
        if (Test-Path $testFile) {
            Remove-Item -Path $testFile -Force -ErrorAction Stop
            Write-ExportLog -Message "Write access test to ${Path} succeeded with binary file" -Level "INFO" -EventId 1001
            return $true
        } else {
            Write-ExportLog -Message "Write access test to ${Path} failed: Binary file not created" -Level "ERROR" -EventId 1002
            return $false
        }
    } catch {
        Write-ExportLog -Message "Failed to test write access to ${Path}: $($_.Exception.Message)" -Level "ERROR" -EventId 1003
        return $false
    }
}

# Function to test network connectivity to the file server
function Test-NetworkConnectivity {
    param (
        [string]$Server
    )
    try {
        $ping = Test-Connection -ComputerName $Server -Count 1 -Quiet -ErrorAction Stop
        if ($ping) {
            Write-ExportLog -Message "Network connectivity test to ${Server} succeeded" -Level "INFO" -EventId 1004
            return $true
        } else {
            Write-ExportLog -Message "Network connectivity test to ${Server} failed" -Level "WARNING" -EventId 1005
            return $false
        }
    } catch {
        Write-ExportLog -Message "Failed to test network connectivity to ${Server}: $($_.Exception.Message)" -Level "ERROR" -EventId 1006
        return $false
    }
}

try {
    # Initialize event log source
    Initialize-EventLogSource

    # Ensure log directory exists
    $logDir = Split-Path -Path $logPath -Parent
    if (-not (Test-Path $logDir)) {
        try {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
            Write-ExportLog -Message "Created log directory: ${logDir}" -Level "INFO" -EventId 1007
        } catch {
            Write-ExportLog -Message "Failed to create log directory ${logDir}: $($_.Exception.Message)" -Level "ERROR" -EventId 1008
            throw
        }
    }

    # Perform log file housekeeping
    Manage-LogFiles -LogDir $logDir -MaxFiles $maxLogFiles

    # Ensure temp directory exists
    if (-not (Test-Path $tempPath)) {
        try {
            New-Item -Path $tempPath -ItemType Directory -Force | Out-Null
            Write-ExportLog -Message "Created temp directory: ${tempPath}" -Level "INFO" -EventId 1009
        } catch {
            Write-ExportLog -Message "Failed to create temp directory ${tempPath}: $($_.Exception.Message)" -Level "ERROR" -EventId 1010
            throw
        }
    }

    # Verify CredentialManager module
    if (-not (Get-Module -ListAvailable -Name CredentialManager)) {
        Write-ExportLog -Message "CredentialManager module not found. Ensure it is installed in C:\Program Files\WindowsPowerShell\Modules\CredentialManager." -Level "ERROR" -EventId 1011
        throw "CredentialManager module not installed"
    }
    try {
        Import-Module CredentialManager -ErrorAction Stop
        Write-ExportLog -Message "Imported CredentialManager module" -Level "INFO" -EventId 1012
    } catch {
        Write-ExportLog -Message "Failed to import CredentialManager module: $($_.Exception.Message)" -Level "ERROR" -EventId 1013
        throw
    }

    # Retrieve PFX password from Credential Manager
    try {
        $credential = Get-StoredCredential -Target 'PFXCertPassword' -ErrorAction Stop
        if (-not $credential) {
            Write-ExportLog -Message "No credential found for PFXCertPassword in Credential Manager" -Level "ERROR" -EventId 1014
            throw "Credential not found"
        }
        $pfxPassword = $credential.GetNetworkCredential().Password
        if (-not $pfxPassword) {
            Write-ExportLog -Message "Retrieved password is empty or null" -Level "ERROR" -EventId 1015
            throw "Invalid password retrieved from Credential Manager"
        }
        $maskedPassword = Mask-SensitiveData -Data $pfxPassword
        Write-ExportLog -Message "Successfully retrieved PFX password from Credential Manager (masked): ${maskedPassword}" -Level "INFO" -EventId 1016
    } catch {
        Write-ExportLog -Message "Failed to retrieve PFX password from Credential Manager: $($_.Exception.Message)" -Level "ERROR" -EventId 1017
        throw
    }

    # Verify CCS registry settings and get export location
    $registryPath = "HKLM:\SOFTWARE\Microsoft\IIS\CentralCertProvider"
    try {
        $registryValues = Get-ItemProperty -Path $registryPath -ErrorAction Stop
        if ($registryValues.Enabled -ne 1) {
            Write-ExportLog -Message "CCS is not enabled in registry (Enabled=$($registryValues.Enabled))." -Level "ERROR" -EventId 1018
            throw "CCS not enabled"
        }
        $ccsPath = $registryValues.CertStoreLocation
        $outputDir = $ccsPath  # Export directly to CCS path
        Write-ExportLog -Message "CCS registry key found: PhysicalPath=$ccsPath, ExportPath=$outputDir" -Level "INFO" -EventId 1019
    } catch {
        Write-ExportLog -Message "CCS registry key not found at ${registryPath}: $($_.Exception.Message)" -Level "ERROR" -EventId 1020
        throw
    }

    # Ensure output directory exists
    if (-not (Test-Path $outputDir)) {
        try {
            New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
            Write-ExportLog -Message "Created output directory: ${outputDir}" -Level "INFO" -EventId 1021
        } catch {
            Write-ExportLog -Message "Failed to create output directory ${outputDir}: $($_.Exception.Message)" -Level "ERROR" -EventId 1022
            throw
        }
    }

    # Verify CCS path accessibility
    try {
        if (-not (Test-Path $ccsPath)) {
            Write-ExportLog -Message "CCS path ${ccsPath} is not accessible" -Level "ERROR" -EventId 1023
            throw "CCS path inaccessible"
        }
        Write-ExportLog -Message "CCS path ${ccsPath} is accessible" -Level "INFO" -EventId 1024
    } catch {
        Write-ExportLog -Message "Error accessing CCS path ${ccsPath}: $($_.Exception.Message)" -Level "ERROR" -EventId 1025
        throw
    }

    # Verify output directory accessibility and write access
    try {
        if (-not (Test-Path $outputDir)) {
            Write-ExportLog -Message "Output directory ${outputDir} is not accessible" -Level "ERROR" -EventId 1026
            throw "Output directory inaccessible"
        }
        Write-ExportLog -Message "Output directory ${outputDir} is accessible" -Level "INFO" -EventId 1027
        if (-not (Test-WriteAccess -Path $outputDir)) {
            Write-ExportLog -Message "Write access to ${outputDir} is not sufficient" -Level "ERROR" -EventId 1028
            throw "Insufficient write access to output directory"
        }
        # Test network connectivity to the file server
        $fileServer = "ocp-lab-srv-1.ocplab.net"
        if (-not (Test-NetworkConnectivity -Server $fileServer)) {
            Write-ExportLog -Message "Network connectivity to ${fileServer} is unreliable, proceeding with caution" -Level "WARNING" -EventId 1029
        }
    } catch {
        Write-ExportLog -Message "Error accessing output directory ${outputDir}: $($_.Exception.Message)" -Level "ERROR" -EventId 1030
        throw
    }

    # Log defined SNI and node hostnames
    Write-ExportLog -Message "Using defined SNI hostname(s): $($sniHostNames -join ', ')" -Level "INFO" -EventId 1031
    Write-ExportLog -Message "Using defined node hostname(s): $($nodeHostNames -join ', ')" -Level "INFO" -EventId 1032

    # Get certificates from local computer store
    try {
        $certStore = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction Stop
        if (-not $certStore) {
            Write-ExportLog -Message "No certificates found in local computer store (Cert:\LocalMachine\My)" -Level "WARNING" -EventId 1033
            return
        }
        Write-ExportLog -Message "Found $($certStore.Count) certificates in local computer store: $($certStore.Subject -join ', ')" -Level "INFO" -EventId 1034
    } catch {
        Write-ExportLog -Message "Failed to retrieve certificates from local computer store: $($_.Exception.Message)" -Level "ERROR" -EventId 1035
        throw
    }

    # Filter certificates by defined SNI hostname(s)
    $certificatesToExport = @()
    foreach ($cert in $certStore) {
        try {
            $cn = Get-CertificateCommonName -Certificate $cert
            if ($sniHostNames -contains $cn) {
                $certificatesToExport += $cert
            } else {
                Write-ExportLog -Message "Certificate with subject $($cert.Subject) (CN=$cn) does not match any defined SNI hostname, skipping" -Level "INFO" -EventId 1036
            }
        } catch {
            Write-ExportLog -Message "Failed to extract Common Name for certificate with subject $($cert.Subject): $($_.Exception.Message). Skipping certificate." -Level "WARNING" -EventId 1037
            continue
        }
    }

    if (-not $certificatesToExport) {
        Write-ExportLog -Message "No certificates in local store match defined SNI hostname(s): $($sniHostNames -join ', ')" -Level "WARNING" -EventId 1038
        return
    }
    Write-ExportLog -Message "Certificates to export (matching SNI): $($certificatesToExport.Subject -join ', ')" -Level "INFO" -EventId 1039

    # Process each certificate for SNI and node hostname files
    foreach ($cert in $certificatesToExport) {
        try {
            # Verify private key exportability
            if (-not $cert.HasPrivateKey) {
                Write-ExportLog -Message "Certificate with subject $($cert.Subject) does not have a private key" -Level "WARNING" -EventId 1040
                continue
            }
            if (-not $cert.PrivateKey) {
                Write-ExportLog -Message "Certificate with subject $($cert.Subject) private key is not exportable" -Level "WARNING" -EventId 1041
                continue
            }

            # Get Common Name (CN)
            try {
                $cn = Get-CertificateCommonName -Certificate $cert
            } catch {
                Write-ExportLog -Message "Failed to extract Common Name for certificate with subject $($cert.Subject): $($_.Exception.Message). Skipping certificate." -Level "WARNING" -EventId 1042
                continue
            }

            # Export certificate for each SNI hostname
            foreach ($sni in $sniHostNames) {
                if ($sni -ne $cn) {
                    continue  # Skip if SNI doesn't match certificate CN
                }
                try {
                    $outputFileName = Sanitize-Filename -Filename $sni
                    $outputPath = Join-Path -Path $outputDir -ChildPath $outputFileName
                    $tempOutputPath = Join-Path -Path $tempPath -ChildPath $outputFileName

                    # Back up existing file if it exists with timestamp
                    if (Test-Path $outputPath) {
                        $backupTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                        $backupPath = Join-Path -Path $outputDir -ChildPath "${cn}_${backupTimestamp}.pfx.bak"
                        try {
                            Copy-Item -Path $outputPath -Destination $backupPath -Force -ErrorAction Stop
                            Write-ExportLog -Message "Backed up existing certificate $($outputFileName) to $($backupPath)" -Level "INFO" -EventId 1043
                        } catch {
                            Write-ExportLog -Message "Failed to back up existing certificate $($outputFileName) to $($backupPath): $($_.Exception.Message)" -Level "ERROR" -EventId 1044
                            throw
                        }
                        # Manage backups to keep only 3 most recent
                        Manage-CertificateBackups -OutputDir $outputDir -CN $cn
                    }

                    # Export certificate to PFX
                    try {
                        Write-ExportLog -Message "Attempting to export certificate with subject $($cert.Subject) to PFX for SNI: $sni" -Level "INFO" -EventId 1045
                        $securePassword = ConvertTo-SecureString $pfxPassword -AsPlainText -Force
                        try {
                            $pfxBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $pfxPassword)
                            Write-ExportLog -Message "Successfully generated PFX bytes for certificate with subject $($cert.Subject) (Size: $($pfxBytes.Length) bytes)" -Level "INFO" -EventId 1046
                        } catch {
                            $errorDetails = "Failed to export certificate with subject $($cert.Subject) to PFX: $($_.Exception.Message)"
                            if ($_.Exception -is [System.Security.Cryptography.CryptographicException]) {
                                $errorDetails += " (Possible private key issue or certificate corruption)"
                            }
                            Write-ExportLog -Message $errorDetails -Level "ERROR" -EventId 1047
                            throw
                        }
                        $writeSuccess = $false
                        for ($i = 0; $i -lt 5; $i++) {
                            try {
                                Write-ExportLog -Message "Attempting to write PFX file to ${outputPath} (Attempt $($i + 1)/5)" -Level "INFO" -EventId 1048
                                [System.IO.File]::WriteAllBytes($outputPath, $pfxBytes)
                                Write-ExportLog -Message "Exported certificate with subject $($cert.Subject) to $($outputPath)" -Level "INFO" -EventId 1049
                                $writeSuccess = $true
                                $successCount++
                                break
                            } catch {
                                $hresult = [System.Runtime.InteropServices.Marshal]::GetHRForException($_.Exception)
                                $errorDetails = "Failed to write PFX file to ${outputPath}: $($_.Exception.Message) (HRESULT: 0x$([System.Convert]::ToString($hresult, 16)))"
                                if ($_.Exception -is [System.UnauthorizedAccessException]) {
                                    $errorDetails += " (Permission issue)"
                                } elseif ($_.Exception -is [System.IO.IOException]) {
                                    $errorDetails += " (Network or file lock issue)"
                                }
                                Write-ExportLog -Message $errorDetails -Level "WARNING" -EventId 1050
                                Start-Sleep -Milliseconds 1000
                                if ($i -eq 4) {
                                    Write-ExportLog -Message "All attempts to write PFX file to ${outputPath} failed" -Level "ERROR" -EventId 1051
                                    # Fallback to local write
                                    try {
                                        Write-ExportLog -Message "Attempting fallback write to ${tempOutputPath}" -Level "INFO" -EventId 1052
                                        [System.IO.File]::WriteAllBytes($tempOutputPath, $pfxBytes)
                                        Write-ExportLog -Message "Fallback: Successfully wrote PFX file to ${tempOutputPath}" -Level "INFO" -EventId 1053
                                        # Verify fallback file
                                        try {
                                            $testCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                                            $testCert.Import($tempOutputPath, $securePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet)
                                            Write-ExportLog -Message "Verified fallback PFX file ${tempOutputPath}" -Level "INFO" -EventId 1054
                                            # Attempt manual copy to CCS path
                                            try {
                                                Copy-Item -Path $tempOutputPath -Destination $outputPath -Force -ErrorAction Stop
                                                Write-ExportLog -Message "Successfully copied fallback PFX file to ${outputPath}" -Level "INFO" -EventId 1055
                                                $writeSuccess = $true
                                                $successCount++
                                            } catch {
                                                Write-ExportLog -Message "Failed to copy fallback PFX file to ${outputPath}: $($_.Exception.Message)" -Level "ERROR" -EventId 1056
                                            }
                                        } catch {
                                            Write-ExportLog -Message "Failed to verify fallback PFX file ${tempOutputPath}: $($_.Exception.Message)" -Level "ERROR" -EventId 1057
                                        }
                                    } catch {
                                        Write-ExportLog -Message "Fallback write to ${tempOutputPath} failed: $($_.Exception.Message)" -Level "ERROR" -EventId 1058
                                    }
                                    throw
                                }
                            }
                        }
                        if (-not $writeSuccess) {
                            continue
                        }
                    } catch {
                        Write-ExportLog -Message "Failed to process export for certificate with subject $($cert.Subject) for SNI: $($sni): $($_.Exception.Message)" -Level "ERROR" -EventId 1059
                        continue
                    }

                    # Verify exported PFX file
                    try {
                        $testCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                        $testCert.Import($outputPath, $securePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet)
                        Write-ExportLog -Message "Verified exported PFX file ${outputPath}" -Level "INFO" -EventId 1060
                    } catch {
                        Write-ExportLog -Message "Failed to verify exported PFX file ${outputPath}: $($_.Exception.Message)" -Level "ERROR" -EventId 1061
                        throw
                    }
                } catch {
                    Write-ExportLog -Message "Failed to process certificate with subject $($cert.Subject) for SNI: $($sni): $($_.Exception.Message)" -Level "ERROR" -EventId 1062
                    continue
                }
            }

            # Export certificate for each node hostname
            foreach ($node in $nodeHostNames) {
                try {
                    $outputFileName = Sanitize-Filename -Filename $node
                    $outputPath = Join-Path -Path $outputDir -ChildPath $outputFileName
                    $tempOutputPath = Join-Path -Path $tempPath -ChildPath $outputFileName

                    # Back up existing file if it exists with timestamp
                    if (Test-Path $outputPath) {
                        $backupTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                        $backupPath = Join-Path -Path $outputDir -ChildPath "${cn}_${backupTimestamp}.pfx.bak"
                        try {
                            Copy-Item -Path $outputPath -Destination $backupPath -Force -ErrorAction Stop
                            Write-ExportLog -Message "Backed up existing certificate $($outputFileName) to $($backupPath)" -Level "INFO" -EventId 1043
                        } catch {
                            Write-ExportLog -Message "Failed to back up existing certificate $($outputFileName) to $($backupPath): $($_.Exception.Message)" -Level "ERROR" -EventId 1044
                            throw
                        }
                        # Manage backups to keep only 3 most recent
                        Manage-CertificateBackups -OutputDir $outputDir -CN $cn
                    }

                    # Export certificate to PFX
                    try {
                        Write-ExportLog -Message "Attempting to export certificate with subject $($cert.Subject) to PFX for Node: $node" -Level "INFO" -EventId 1045
                        $securePassword = ConvertTo-SecureString $pfxPassword -AsPlainText -Force
                        try {
                            $pfxBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $pfxPassword)
                            Write-ExportLog -Message "Successfully generated PFX bytes for certificate with subject $($cert.Subject) (Size: $($pfxBytes.Length) bytes)" -Level "INFO" -EventId 1046
                        } catch {
                            $errorDetails = "Failed to export certificate with subject $($cert.Subject) to PFX: $($_.Exception.Message)"
                            if ($_.Exception -is [System.Security.Cryptography.CryptographicException]) {
                                $errorDetails += " (Possible private key issue or certificate corruption)"
                            }
                            Write-ExportLog -Message $errorDetails -Level "ERROR" -EventId 1047
                            throw
                        }
                        $writeSuccess = $false
                        for ($i = 0; $i -lt 5; $i++) {
                            try {
                                Write-ExportLog -Message "Attempting to write PFX file to ${outputPath} (Attempt $($i + 1)/5)" -Level "INFO" -EventId 1048
                                [System.IO.File]::WriteAllBytes($outputPath, $pfxBytes)
                                Write-ExportLog -Message "Exported certificate with subject $($cert.Subject) to $($outputPath)" -Level "INFO" -EventId 1049
                                $writeSuccess = $true
                                $successCount++
                                break
                            } catch {
                                $hresult = [System.Runtime.InteropServices.Marshal]::GetHRForException($_.Exception)
                                $errorDetails = "Failed to write PFX file to ${outputPath}: $($_.Exception.Message) (HRESULT: 0x$([System.Convert]::ToString($hresult, 16)))"
                                if ($_.Exception -is [System.UnauthorizedAccessException]) {
                                    $errorDetails += " (Permission issue)"
                                } elseif ($_.Exception -is [System.IO.IOException]) {
                                    $errorDetails += " (Network or file lock issue)"
                                }
                                Write-ExportLog -Message $errorDetails -Level "WARNING" -EventId 1050
                                Start-Sleep -Milliseconds 1000
                                if ($i -eq 4) {
                                    Write-ExportLog -Message "All attempts to write PFX file to ${outputPath} failed" -Level "ERROR" -EventId 1051
                                    # Fallback to local write
                                    try {
                                        Write-ExportLog -Message "Attempting fallback write to ${tempOutputPath}" -Level "INFO" -EventId 1052
                                        [System.IO.File]::WriteAllBytes($tempOutputPath, $pfxBytes)
                                        Write-ExportLog -Message "Fallback: Successfully wrote PFX file to ${tempOutputPath}" -Level "INFO" -EventId 1053
                                        # Verify fallback file
                                        try {
                                            $testCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                                            $testCert.Import($tempOutputPath, $securePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet)
                                            Write-ExportLog -Message "Verified fallback PFX file ${tempOutputPath}" -Level "INFO" -EventId 1054
                                            # Attempt manual copy to CCS path
                                            try {
                                                Copy-Item -Path $tempOutputPath -Destination $outputPath -Force -ErrorAction Stop
                                                Write-ExportLog -Message "Successfully copied fallback PFX file to ${outputPath}" -Level "INFO" -EventId 1055
                                                $writeSuccess = $true
                                                $successCount++
                                            } catch {
                                                Write-ExportLog -Message "Failed to copy fallback PFX file to ${outputPath}: $($_.Exception.Message)" -Level "ERROR" -EventId 1056
                                            }
                                        } catch {
                                            Write-ExportLog -Message "Failed to verify fallback PFX file ${tempOutputPath}: $($_.Exception.Message)" -Level "ERROR" -EventId 1057
                                        }
                                    } catch {
                                        Write-ExportLog -Message "Fallback write to ${tempOutputPath} failed: $($_.Exception.Message)" -Level "ERROR" -EventId 1058
                                    }
                                    throw
                                }
                            }
                        }
                        if (-not $writeSuccess) {
                            continue
                        }
                    } catch {
                        Write-ExportLog -Message "Failed to process export for certificate with subject $($cert.Subject) for Node: $($node): $($_.Exception.Message)" -Level "ERROR" -EventId 1059
                        continue
                    }

                    # Verify exported PFX file
                    try {
                        $testCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                        $testCert.Import($outputPath, $securePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet)
                        Write-ExportLog -Message "Verified exported PFX file ${outputPath}" -Level "INFO" -EventId 1060
                    } catch {
                        Write-ExportLog -Message "Failed to verify exported PFX file ${outputPath}: $($_.Exception.Message)" -Level "ERROR" -EventId 1061
                        throw
                    }
                } catch {
                    Write-ExportLog -Message "Failed to process certificate with subject $($cert.Subject) for Node: $($node): $($_.Exception.Message)" -Level "ERROR" -EventId 1062
                    continue
                }
            }
        } catch {
            Write-ExportLog -Message "Failed to process certificate with subject $($cert.Subject): $($_.Exception.Message)" -Level "ERROR" -EventId 1063
            continue
        }
    }

    if ($successCount -eq 0) {
        Write-ExportLog -Message "No certificates were successfully exported" -Level "WARNING" -EventId 1064
    } else {
        Write-ExportLog -Message "Certificate export completed successfully with $successCount certificate(s) exported" -Level "INFO" -EventId 1065
    }
} catch {
    Write-ExportLog -Message "Error during certificate export: $($_.Exception.Message)" -Level "ERROR" -EventId 1066
    throw
}
