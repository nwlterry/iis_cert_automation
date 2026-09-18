# PowerShell script to export certificates from the local computer certificate store (Cert:\LocalMachine\My)
# to PFX files in the IIS Centralized Certificate Store (CCS) path using a password stored in the Credential Manager.
# Only certificates with a Common Name (CN) matching the SNI host names in IIS HTTPS bindings are exported.
# Existing PFX files in the CCS path are backed up with a timestamp before overwriting, keeping only the 3 most recent backups per CN.
# The exported PFX file is verified to ensure validity.
# The retrieved PFX password is logged in a masked format for troubleshooting.
# HTTPS bindings are logged for reference and used to filter certificates.
# Includes enhanced error handling for export and file write operations, increased retries, and robust fallback logic.
# Designed for an air-gapped environment running Windows PowerShell 5.1 (Windows Server 2019/2022).
# Logs all actions to a file under C:\Logs with full timestamp.
# Assumes the CCS share has appropriate permissions for NT AUTHORITY\SYSTEM, Administrators, and OCPLAB\ISMWIN2019IIS01$.

$currentDate = Get-Date -Format "yyyyMMdd_HHmmss"
$logPath = "C:\Logs\CertificateExport_$currentDate.log"
$successCount = 0  # Track successful exports
$tempPath = "C:\Temp"  # Fallback local path for failed network writes

# Function to write log messages to file and console
function Write-ExportLog {
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
            Write-Output "[$timestamp] [ERROR] Failed to write to log file ${logPath}: $($_.Exception.Message)"
        }
    }
    
    # Write to console
    Write-Output $logMessage
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
                    Write-ExportLog -Message "Deleted older backup file: $($file.FullName)" -EventId 1080
                } catch {
                    Write-ExportLog -Message "Failed to delete older backup file $($file.FullName): $($_.Exception.Message)" -Level "WARNING" -EventId 1081
                }
            }
        }
    } catch {
        Write-ExportLog -Message "Failed to manage backups for CN ${CN}: $($_.Exception.Message)" -Level "ERROR" -EventId 1082
    }
}

# Function to extract SNI host names from HTTPS bindings
function Get-SNIHostNames {
    param (
        [string[]]$Bindings
    )
    $sniHostNames = @()
    foreach ($binding in $Bindings) {
        if ($binding -match "https/[^:]+:\d+:([^/]+)") {
            $sniHostNames += $Matches[1]
        }
    }
    return $sniHostNames
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
            Write-ExportLog -Message "Write access test to ${Path} succeeded with binary file" -EventId 1069
            return $true
        } else {
            Write-ExportLog -Message "Write access test to ${Path} failed: Binary file not created" -Level "ERROR" -EventId 1070
            return $false
        }
    } catch {
        Write-ExportLog -Message "Failed to test write access to ${Path}: $($_.Exception.Message)" -Level "ERROR" -EventId 1071
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
            Write-ExportLog -Message "Network connectivity test to ${Server} succeeded" -EventId 1072
            return $true
        } else {
            Write-ExportLog -Message "Network connectivity test to ${Server} failed" -Level "WARNING" -EventId 1073
            return $false
        }
    } catch {
        Write-ExportLog -Message "Failed to test network connectivity to ${Server}: $($_.Exception.Message)" -Level "ERROR" -EventId 1074
        return $false
    }
}

try {
    # Ensure log directory exists
    $logDir = Split-Path -Path $logPath -Parent
    if (-not (Test-Path $logDir)) {
        try {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
            Write-ExportLog -Message "Created log directory: ${logDir}" -EventId 1050
        } catch {
            Write-ExportLog -Message "Failed to create log directory ${logDir}: $($_.Exception.Message)" -Level "ERROR" -EventId 1051
            throw
        }
    }

    # Ensure temp directory exists
    if (-not (Test-Path $tempPath)) {
        try {
            New-Item -Path $tempPath -ItemType Directory -Force | Out-Null
            Write-ExportLog -Message "Created temp directory: ${tempPath}" -EventId 1052
        } catch {
            Write-ExportLog -Message "Failed to create temp directory ${tempPath}: $($_.Exception.Message)" -Level "ERROR" -EventId 1053
            throw
        }
    }

    # Verify CredentialManager module
    if (-not (Get-Module -ListAvailable -Name CredentialManager)) {
        Write-ExportLog -Message "CredentialManager module not found. Ensure it is installed in C:\Program Files\WindowsPowerShell\Modules\CredentialManager." -Level "ERROR" -EventId 1054
        throw "CredentialManager module not installed"
    }
    try {
        Import-Module CredentialManager -ErrorAction Stop
        Write-ExportLog -Message "Imported CredentialManager module" -EventId 1055
    } catch {
        Write-ExportLog -Message "Failed to import CredentialManager module: $($_.Exception.Message)" -Level "ERROR" -EventId 1056
        throw
    }

    # Retrieve PFX password from Credential Manager
    try {
        $credential = Get-StoredCredential -Target 'PFXCertPassword' -ErrorAction Stop
        if (-not $credential) {
            Write-ExportLog -Message "No credential found for PFXCertPassword in Credential Manager" -Level "ERROR" -EventId 1057
            throw "Credential not found"
        }
        $pfxPassword = $credential.GetNetworkCredential().Password
        if (-not $pfxPassword) {
            Write-ExportLog -Message "Retrieved password is empty or null" -Level "ERROR" -EventId 1058
            throw "Invalid password retrieved from Credential Manager"
        }
        $maskedPassword = Mask-SensitiveData -Data $pfxPassword
        Write-ExportLog -Message "Successfully retrieved PFX password from Credential Manager (masked): ${maskedPassword}" -EventId 1059
    } catch {
        Write-ExportLog -Message "Failed to retrieve PFX password from Credential Manager: $($_.Exception.Message)" -Level "ERROR" -EventId 1060
        throw
    }

    # Verify CCS registry settings and get export location
    $registryPath = "HKLM:\SOFTWARE\Microsoft\IIS\CentralCertProvider"
    try {
        $registryValues = Get-ItemProperty -Path $registryPath -ErrorAction Stop
        if ($registryValues.Enabled -ne 1) {
            Write-ExportLog -Message "CCS is not enabled in registry (Enabled=$($registryValues.Enabled))." -Level "ERROR" -EventId 1061
            throw "CCS not enabled"
        }
        $ccsPath = $registryValues.CertStoreLocation
        $outputDir = $ccsPath  # Export directly to CCS path
        Write-ExportLog -Message "CCS registry key found: PhysicalPath=$ccsPath, ExportPath=$outputDir" -EventId 1062
    } catch {
        Write-ExportLog -Message "CCS registry key not found at ${registryPath}: $($_.Exception.Message)" -Level "ERROR" -EventId 1063
        throw
    }

    # Ensure output directory exists
    if (-not (Test-Path $outputDir)) {
        try {
            New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
            Write-ExportLog -Message "Created output directory: ${outputDir}" -EventId 1064
        } catch {
            Write-ExportLog -Message "Failed to create output directory ${outputDir}: $($_.Exception.Message)" -Level "ERROR" -EventId 1065
            throw
        }
    }

    # Verify CCS path accessibility
    try {
        if (-not (Test-Path $ccsPath)) {
            Write-ExportLog -Message "CCS path ${ccsPath} is not accessible" -Level "ERROR" -EventId 1066
            throw "CCS path inaccessible"
        }
        Write-ExportLog -Message "CCS path ${ccsPath} is accessible" -EventId 1067
    } catch {
        Write-ExportLog -Message "Error accessing CCS path ${ccsPath}: $($_.Exception.Message)" -Level "ERROR" -EventId 1068
        throw
    }

    # Verify output directory accessibility and write access
    try {
        if (-not (Test-Path $outputDir)) {
            Write-ExportLog -Message "Output directory ${outputDir} is not accessible" -Level "ERROR" -EventId 1069
            throw "Output directory inaccessible"
        }
        Write-ExportLog -Message "Output directory ${outputDir} is accessible" -EventId 1070
        if (-not (Test-WriteAccess -Path $outputDir)) {
            Write-ExportLog -Message "Write access to ${outputDir} is not sufficient" -Level "ERROR" -EventId 1071
            throw "Insufficient write access to output directory"
        }
        # Test network connectivity to the file server
        $fileServer = "ocp-lab-srv-1.ocplab.net"
        if (-not (Test-NetworkConnectivity -Server $fileServer)) {
            Write-ExportLog -Message "Network connectivity to ${fileServer} is unreliable, proceeding with caution" -Level "WARNING" -EventId 1072
        }
    } catch {
        Write-ExportLog -Message "Error accessing output directory ${outputDir}: $($_.Exception.Message)" -Level "ERROR" -EventId 1073
        throw
    }

    # Get HTTPS bindings from IIS for SNI filtering and logging
    $appCmdPath = "$env:windir\system32\inetsrv\appcmd.exe"
    if (-not (Test-Path $appCmdPath)) {
        Write-ExportLog -Message "appcmd.exe not found at ${appCmdPath}" -Level "ERROR" -EventId 1074
        throw "appcmd.exe missing"
    }
    try {
        $bindings = & $appCmdPath list site /text:bindings
        $httpsBindings = $bindings | Where-Object { $_ -like "https/*" }
        if (-not $httpsBindings) {
            Write-ExportLog -Message "No HTTPS bindings found in IIS configuration" -Level "WARNING" -EventId 1075
            return
        }
        Write-ExportLog -Message "Retrieved HTTPS bindings for reference: $($httpsBindings -join ', ')" -EventId 1076
        $sniHostNames = Get-SNIHostNames -Bindings $httpsBindings
        Write-ExportLog -Message "SNI host names extracted: $($sniHostNames -join ', ')" -EventId 1077
    } catch {
        Write-ExportLog -Message "Failed to retrieve HTTPS bindings: $($_.Exception.Message)" -Level "ERROR" -EventId 1078
        throw
    }

    # Get certificates from local computer store
    try {
        $certStore = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction Stop
        if (-not $certStore) {
            Write-ExportLog -Message "No certificates found in local computer store (Cert:\LocalMachine\My)" -Level "WARNING" -EventId 1079
            return
        }
        Write-ExportLog -Message "Found $($certStore.Count) certificates in local computer store: $($certStore.Subject -join ', ')" -EventId 1080
    } catch {
        Write-ExportLog -Message "Failed to retrieve certificates from local computer store: $($_.Exception.Message)" -Level "ERROR" -EventId 1081
        throw
    }

    # Filter certificates by SNI host names
    $certificatesToExport = @()
    foreach ($cert in $certStore) {
        try {
            $cn = Get-CertificateCommonName -Certificate $cert
            if ($sniHostNames -contains $cn) {
                $certificatesToExport += $cert
            } else {
                Write-ExportLog -Message "Certificate with subject $($cert.Subject) (CN=$cn) does not match any SNI host name, skipping" -Level "INFO" -EventId 1082
            }
        } catch {
            Write-ExportLog -Message "Failed to extract Common Name for certificate with subject $($cert.Subject): $($_.Exception.Message). Skipping certificate." -Level "WARNING" -EventId 1083
            continue
        }
    }

    if (-not $certificatesToExport) {
        Write-ExportLog -Message "No certificates in local store match SNI host names: $($sniHostNames -join ', ')" -Level "WARNING" -EventId 1084
        return
    }
    Write-ExportLog -Message "Certificates to export (matching SNI): $($certificatesToExport.Subject -join ', ')" -EventId 1085

    # Process each certificate
    foreach ($cert in $certificatesToExport) {
        try {
            # Verify private key exportability
            if (-not $cert.HasPrivateKey) {
                Write-ExportLog -Message "Certificate with subject $($cert.Subject) does not have a private key" -Level "WARNING" -EventId 1086
                continue
            }
            if (-not $cert.PrivateKey) {
                Write-ExportLog -Message "Certificate with subject $($cert.Subject) private key is not exportable" -Level "WARNING" -EventId 1087
                continue
            }

            # Get Common Name (CN) for output file name
            try {
                $cn = Get-CertificateCommonName -Certificate $cert
                $outputFileName = "${cn}.pfx"
            } catch {
                Write-ExportLog -Message "Failed to extract Common Name for certificate with subject $($cert.Subject): $($_.Exception.Message). Skipping certificate." -Level "WARNING" -EventId 1088
                continue
            }
            $outputPath = Join-Path -Path $outputDir -ChildPath $outputFileName
            $tempOutputPath = Join-Path -Path $tempPath -ChildPath $outputFileName

            # Back up existing file if it exists with timestamp
            if (Test-Path $outputPath) {
                $backupTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                $backupPath = Join-Path -Path $outputDir -ChildPath "${cn}_${backupTimestamp}.pfx.bak"
                try {
                    Copy-Item -Path $outputPath -Destination $backupPath -Force -ErrorAction Stop
                    Write-ExportLog -Message "Backed up existing certificate $($outputFileName) to $($backupPath)" -EventId 1089
                } catch {
                    Write-ExportLog -Message "Failed to back up existing certificate $($outputFileName) to $($backupPath): $($_.Exception.Message)" -Level "ERROR" -EventId 1090
                    throw
                }
                # Manage backups to keep only 3 most recent
                Manage-CertificateBackups -OutputDir $outputDir -CN $cn
            }

            # Export certificate to PFX
            try {
                Write-ExportLog -Message "Attempting to export certificate with subject $($cert.Subject) to PFX" -EventId 1091
                $securePassword = ConvertTo-SecureString $pfxPassword -AsPlainText -Force
                try {
                    $pfxBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $pfxPassword)
                    Write-ExportLog -Message "Successfully generated PFX bytes for certificate with subject $($cert.Subject) (Size: $($pfxBytes.Length) bytes)" -EventId 1092
                } catch {
                    $errorDetails = "Failed to export certificate with subject $($cert.Subject) to PFX: $($_.Exception.Message)"
                    if ($_.Exception -is [System.Security.Cryptography.CryptographicException]) {
                        $errorDetails += " (Possible private key issue or certificate corruption)"
                    }
                    Write-ExportLog -Message $errorDetails -Level "ERROR" -EventId 1093
                    throw
                }
                $writeSuccess = $false
                for ($i = 0; $i -lt 5; $i++) {
                    try {
                        Write-ExportLog -Message "Attempting to write PFX file to ${outputPath} (Attempt $($i + 1)/5)" -EventId 1094
                        [System.IO.File]::WriteAllBytes($outputPath, $pfxBytes)
                        Write-ExportLog -Message "Exported certificate with subject $($cert.Subject) to $($outputPath)" -EventId 1095
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
                        Write-ExportLog -Message $errorDetails -Level "WARNING" -EventId 1096
                        Start-Sleep -Milliseconds 1000
                        if ($i -eq 4) {
                            Write-ExportLog -Message "All attempts to write PFX file to ${outputPath} failed" -Level "ERROR" -EventId 1097
                            # Fallback to local write
                            try {
                                Write-ExportLog -Message "Attempting fallback write to ${tempOutputPath}" -EventId 1098
                                [System.IO.File]::WriteAllBytes($tempOutputPath, $pfxBytes)
                                Write-ExportLog -Message "Fallback: Successfully wrote PFX file to ${tempOutputPath}" -EventId 1099
                                # Verify fallback file
                                try {
                                    $testCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                                    $testCert.Import($tempOutputPath, $securePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet)
                                    Write-ExportLog -Message "Verified fallback PFX file ${tempOutputPath}" -EventId 1100
                                    # Attempt manual copy to CCS path
                                    try {
                                        Copy-Item -Path $tempOutputPath -Destination $outputPath -Force -ErrorAction Stop
                                        Write-ExportLog -Message "Successfully copied fallback PFX file to ${outputPath}" -EventId 1101
                                        $writeSuccess = $true
                                        $successCount++
                                    } catch {
                                        Write-ExportLog -Message "Failed to copy fallback PFX file to ${outputPath}: $($_.Exception.Message)" -Level "ERROR" -EventId 1102
                                    }
                                } catch {
                                    Write-ExportLog -Message "Failed to verify fallback PFX file ${tempOutputPath}: $($_.Exception.Message)" -Level "ERROR" -EventId 1103
                                }
                            } catch {
                                Write-ExportLog -Message "Fallback write to ${tempOutputPath} failed: $($_.Exception.Message)" -Level "ERROR" -EventId 1104
                            }
                            throw
                        }
                    }
                }
                if (-not $writeSuccess) {
                    continue
                }
            } catch {
                Write-ExportLog -Message "Failed to process export for certificate with subject $($cert.Subject): $($_.Exception.Message)" -Level "ERROR" -EventId 1105
                throw
            }

            # Verify exported PFX file
            try {
                $testCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                $testCert.Import($outputPath, $securePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet)
                Write-ExportLog -Message "Verified exported PFX file ${outputPath}" -EventId 1106
            } catch {
                Write-ExportLog -Message "Failed to verify exported PFX file ${outputPath}: $($_.Exception.Message)" -Level "ERROR" -EventId 1107
                throw
            }
        } catch {
            Write-ExportLog -Message "Failed to process certificate with subject $($cert.Subject): $($_.Exception.Message)" -Level "ERROR" -EventId 1108
            continue
        }
    }

    if ($successCount -eq 0) {
        Write-ExportLog -Message "No certificates were successfully exported" -Level "WARNING" -EventId 1109
    } else {
        Write-ExportLog -Message "Certificate export completed successfully with $successCount certificate(s) exported" -EventId 1110
    }
} catch {
    Write-ExportLog -Message "Error during certificate export: $($_.Exception.Message)" -Level "ERROR" -EventId 1111
    throw
}
