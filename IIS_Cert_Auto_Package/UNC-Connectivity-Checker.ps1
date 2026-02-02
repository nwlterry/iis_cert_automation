# Define variables
$uncPath = "\\labwinadm01.devops.local\ACME_Share"                  # ? Replace with your UNC path
$server  = ($uncPath -split '\\')[2]         # Extracts server name
$source  = "UNC-Connectivity-Checker"        # Custom event source name
$logName = "Application"                     # Standard log
$logFolder  = "C:\Logs"                      # Folder for logs
$daysToKeep = 14                             # Keep logs for 14 days

# Build today's log file name (date only: 2026-01-27.log)
$today      = Get-Date -Format "yyyy-MM-dd"
$logFile    = Join-Path $logFolder "UNC_Check_$today.log"

# ────────────────────────────────────────────────────────────────
# Log rotation: Delete old log files (keep last 14 days)
$cutoffDate = (Get-Date).AddDays(-$daysToKeep)

if (Test-Path $logFolder) {
    Get-ChildItem -Path $logFolder `
                  -File `
                  -Filter "*.log" `
                  -ErrorAction SilentlyContinue `
    | Where-Object { $_.LastWriteTime -lt $cutoffDate } `
    | ForEach-Object {
        try {
            Remove-Item $_.FullName -Force -ErrorAction Stop
            # Optional: notify in Event Log
            if ([System.Diagnostics.EventLog]::SourceExists($source)) {
                [System.Diagnostics.EventLog]::WriteEntry(
                    $source,
                    "Deleted old log: $($_.Name) (older than $daysToKeep days)",
                    "Information",
                    1005
                )
            }
        }
        catch {
            if ([System.Diagnostics.EventLog]::SourceExists($source)) {
                [System.Diagnostics.EventLog]::WriteEntry(
                    $source,
                    "Failed to delete old log $($_.Name): $($_.Exception.Message)",
                    "Warning",
                    2004
                )
            }
        }
    }
} else {
    # Create folder if missing
    New-Item -Path $logFolder -ItemType Directory -Force | Out-Null
}

# ────────────────────────────────────────────────────────────────
# Function to write to Event Log (.NET method – works in PS 5.1 and 7+)
function Write-LogEvent {
    param (
        [string]$Message,
        [string]$EntryType = "Information",
        [int]$EventId = 1000
    )
    
    if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
        try {
            [System.Diagnostics.EventLog]::CreateEventSource($source, $logName)
            Start-Sleep -Seconds 2
        }
        catch { }  # best effort
    }
    
    try {
        [System.Diagnostics.EventLog]::WriteEntry($source, $Message, $EntryType, $EventId)
    }
    catch { }
}

# Function to write to today's log file
function Write-LogFile {
    param([string]$msg)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $msg" | Out-File -FilePath $logFile -Append -Encoding UTF8
}

# ────────────────────────────────────────────────────────────────
# Main logic
$status = Test-Path -Path $uncPath -ErrorAction SilentlyContinue

if ($status) {
    $msg = "UNC path $uncPath is accessible."
    Write-LogEvent -Message $msg -EntryType Information -EventId 1000
    Write-LogFile $msg
}
else {
    $msg = "UNC path $uncPath is NOT accessible. Attempting reconnect..."
    Write-LogEvent -Message $msg -EntryType Warning -EventId 1001
    Write-LogFile $msg
    
    # Disconnect stale sessions
    try {
        net use \\$server /delete /y 2>$null
        $msg = "Disconnected existing sessions to \\$server."
        Write-LogEvent -Message $msg -EntryType Information -EventId 1002
        Write-LogFile $msg
    }
    catch {
        $err = "Error disconnecting: $($_.Exception.Message)"
        Write-LogEvent -Message $err -EntryType Error -EventId 2001
        Write-LogFile $err
    }
    
    # Attempt reconnect (using computer account)
    try {
        net use F: $uncPath 2>$null
        $msg = "Reconnected to $uncPath."
        Write-LogEvent -Message $msg -EntryType Information -EventId 1003
        Write-LogFile $msg
        
        # Verify
        if (Test-Path -Path $uncPath -ErrorAction SilentlyContinue) {
            $msg = "Reconnect SUCCESS: $uncPath is now accessible."
            Write-LogEvent -Message $msg -EntryType Information -EventId 1004
            Write-LogFile $msg
        }
        else {
            $msg = "Reconnect FAILED: $uncPath still inaccessible."
            Write-LogEvent -Message $msg -EntryType Error -EventId 2002
            Write-LogFile $msg
        }
    }
    catch {
        $err = "Error reconnecting: $($_.Exception.Message)"
        Write-LogEvent -Message $err -EntryType Error -EventId 2003
        Write-LogFile $err
    }
}