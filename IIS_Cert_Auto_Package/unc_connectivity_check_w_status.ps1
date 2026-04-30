# =====================================================
# UNC Connectivity Checker + IIS Reset + Health Check
# Updated per your request
# =====================================================

# ── Configuration ─────────────────────────────────────
$uncPath     = "\\labwinadm01.devops.local\ACME_Share"   # Replace with your UNC path
$testPath    = "E:\ACME-ADCS"                            # Mapped drive path
$driveLetter = "E"                                       # Drive letter used

$server      = ($uncPath -split '\\')[2]

# IIS Health Check
$healthUrl   = "https://localhost/"                      # Change to your actual site URL / health endpoint
$maxRetries  = 10                                        # Max IISreset + curl attempts
$retryDelay  = 5                                         # Seconds between retries

# Logging
$source      = "UNC-Connectivity-Checker"
$logName     = "Application"
$logFolder   = "C:\Logs"
$daysToKeep  = 14

$today       = Get-Date -Format "yyyy-MM-dd"
$logFile     = Join-Path $logFolder "UNC_Check_$today.log"

# ── Log Rotation ─────────────────────────────────────
$cutoffDate = (Get-Date).AddDays(-$daysToKeep)

if (Test-Path $logFolder) {
    Get-ChildItem -Path $logFolder -File -Filter "*.log" -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt $cutoffDate } |
        ForEach-Object {
            try {
                Remove-Item $_.FullName -Force
                Write-LogEvent "Deleted old log: $($_.Name)" "Information" 1005
            } catch { }
        }
} else {
    New-Item -Path $logFolder -ItemType Directory -Force | Out-Null
}

# ── Logging Functions ────────────────────────────────
function Write-LogEvent {
    param([string]$Message, [string]$EntryType = "Information", [int]$EventId = 1000)
    
    if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
        try { [System.Diagnostics.EventLog]::CreateEventSource($source, $logName) } catch { }
    }
    try {
        [System.Diagnostics.EventLog]::WriteEntry($source, $Message, $EntryType, $EventId)
    } catch { }
}

function Write-LogFile {
    param([string]$msg)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $msg" | Out-File -FilePath $logFile -Append -Encoding UTF8
}

# ── Main Logic ───────────────────────────────────────
$status = Test-Path -Path $testPath -ErrorAction SilentlyContinue

if ($status) {
    $msg = "UNC path $testPath ($uncPath) is accessible."
    Write-LogEvent $msg "Information" 1000
    Write-LogFile $msg
} 
else {
    $msg = "UNC path $testPath ($uncPath) is NOT accessible. Attempting reconnect..."
    Write-LogEvent $msg "Warning" 1001
    Write-LogFile $msg

    # Disconnect existing mapping
    try {
        Remove-PSDrive -Name $driveLetter -PSProvider FileSystem -ErrorAction SilentlyContinue
        Write-LogEvent "Disconnected existing drive $driveLetter`:" "Information" 1002
        Write-LogFile "Disconnected existing drive $driveLetter`:"
    } catch { }

    # Re-map the drive
    try {
        New-PSDrive -Name $driveLetter -PSProvider FileSystem -Root $uncPath -Persist -ErrorAction Stop
        Write-LogEvent "Reconnected to $uncPath" "Information" 1003
        Write-LogFile "Reconnected to $uncPath"
    } catch {
        $err = "Reconnect FAILED: $($_.Exception.Message)"
        Write-LogEvent $err "Error" 2003
        Write-LogFile $err
        exit 1
    }

    # Verify after remap
    if (-not (Test-Path $testPath)) {
        $msg = "Reconnect verification FAILED."
        Write-LogEvent $msg "Error" 2002
        Write-LogFile $msg
        exit 1
    }
}

# ── IIS Reset + Health Check after successful remap ──
Write-LogEvent "Starting IISreset + health check after drive remap" "Information" 3000
Write-LogFile "=== Starting IISreset + health check ==="

$attempt = 0
$success = $false

while (-not $success -and $attempt -lt $maxRetries) {
    $attempt++
    
    try {
        Write-LogFile "Attempt $attempt/$maxRetries - Running iisreset..."
        $iisResult = iisreset.exe /restart 2>&1
        Write-LogFile "iisreset output: $($iisResult -join ' | ')"

        Start-Sleep -Seconds 3   # Give IIS a moment to start responding

        # Perform curl test
        $curlOutput = curl.exe -s -o NUL -w "%{http_code}" -k $healthUrl 2>&1
        $httpCode = $curlOutput.Trim()

        Write-LogFile "Curl health check returned HTTP code: $httpCode"

        if ($httpCode -match '^(2|3)\d{2}$') {   # 2xx or 3xx = success
            $msg = "IIS health check PASSED (HTTP $httpCode) on attempt $attempt"
            Write-LogEvent $msg "Information" 3001
            Write-LogFile $msg
            $success = $true
        } 
        else {
            throw "Health check failed with code $httpCode"
        }
    }
    catch {
        $err = "Attempt $attempt failed: $($_.Exception.Message)"
        Write-LogEvent $err "Warning" 3002
        Write-LogFile $err

        if ($attempt -lt $maxRetries) {
            Start-Sleep -Seconds $retryDelay
        }
    }
}

if (-not $success) {
    $finalMsg = "IIS health check FAILED after $maxRetries attempts. Manual intervention required."
    Write-LogEvent $finalMsg "Error" 3999
    Write-LogFile $finalMsg
    exit 1
} else {
    $finalMsg = "Drive remap + IISreset + health check completed successfully."
    Write-LogEvent $finalMsg "Information" 3003
    Write-LogFile $finalMsg
}
