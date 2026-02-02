<#
.SYNOPSIS
  Runtime QA helper for iis_cert_automation.

.DESCRIPTION
  Performs non-destructive checks useful for QA runs:
  - Verifies CCS registry key and configured CertStoreLocation
  - Tests UNC/CCS path accessibility
  - Verifies SYSTEM account can write to a path using a temporary scheduled task
  - Checks that the export script exists

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\IIS_Cert_Auto_Package\Runtime_QA_Check.ps1 \
    -CcsPath "\\\\file-server\\IIS_Cert_Store" -ExportScriptPath "C:\\Scripts\\Export_Cert_CCS_Secure.ps1" -TempLogDir "C:\\Logs"
#>

param(
    [string]$CcsPath,
    [string]$ExportScriptPath,
    [string]$TempLogDir = "C:\Logs",
    [int]$SleepSeconds = 20,
    [string[]]$EventSources = @('CertificateExportScript','UNC-Connectivity-Checker'),
    [switch]$CheckIISBindings
)

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$ts [$Level] $Message" | Out-Host
}

function Test-RegistryCCS {
    $reg = 'HKLM:\\SOFTWARE\\Microsoft\\IIS\\CentralCertProvider'
    try {
        $vals = Get-ItemProperty -Path $reg -ErrorAction Stop
        Write-Log "Found CCS registry key: Enabled=$($vals.Enabled), CertStoreLocation=$($vals.CertStoreLocation)"
        return @{ Found = $true; Enabled = $vals.Enabled; Path = $vals.CertStoreLocation }
    } catch {
        Write-Log "CCS registry key not found at $reg" 'WARNING'
        return @{ Found = $false }
    }
}

function Test-PathAccess {
    param([string]$Path)
    try {
        if (Test-Path -Path $Path) {
            Write-Log "Path $Path is accessible"
            return $true
        } else {
            Write-Log "Path $Path is not accessible" 'WARNING'
            return $false
        }
    } catch {
        Write-Log "Error accessing $Path: $($_.Exception.Message)" 'ERROR'
        return $false
    }
}

function Test-EventLogWrite {
    param(
        [string]$Source,
        [string]$LogName = 'Application'
    )
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
            Write-Log "Event source '$Source' does not exist. Skipping write test." 'WARNING'
            return $false
        }
        $unique = "RuntimeQA-$(New-Guid)"
        # Write a temporary event entry
        [System.Diagnostics.EventLog]::WriteEntry($Source, "$unique - EventLog write test", [System.Diagnostics.EventLogEntryType]::Information, 9999)
        Start-Sleep -Seconds 3
        # Query recent events for the unique marker
        $found = Get-WinEvent -LogName $LogName -MaxEvents 50 -ErrorAction SilentlyContinue |
                 Where-Object { $_.ProviderName -eq $Source -and $_.Message -like "*$unique*" }
        if ($found) {
            Write-Log "Event write/read test succeeded for source '$Source'" 'INFO'
            return $true
        } else {
            Write-Log "Event write/read test did not find the test entry for source '$Source'" 'ERROR'
            return $false
        }
    } catch {
        Write-Log "Error testing event log source $Source: $($_.Exception.Message)" 'ERROR'
        return $false
    }
}

function Get-IISHttpsBindings {
    try {
        $appcmd = Join-Path $env:SystemRoot 'System32\inetsrv\appcmd.exe'
        if (-not (Test-Path $appcmd)) {
            Write-Log "appcmd.exe not found at $appcmd; skipping IIS binding discovery" 'WARNING'
            return @()
        }
        $output = & $appcmd list sites 2>$null
        $bindings = @()
        foreach ($line in $output) {
            if ($line -match 'bindings:.*https/[^:]+:(\d+):([^ ,]*)') {
                $port = $matches[1]
                $host = $matches[2]
                $pfx = if ($host) { "$host.pfx" } else { 'default.pfx' }
                $bindings += @{ Host = $host; Port = $port; PfxFile = $pfx }
            }
        }
        if ($bindings.Count -gt 0) {
            Write-Log "Discovered $($bindings.Count) HTTPS binding(s) via appcmd.exe"
        } else {
            Write-Log "No HTTPS bindings discovered via appcmd.exe" 'WARNING'
        }
        return $bindings
    } catch {
        Write-Log "Error discovering IIS bindings: $($_.Exception.Message)" 'ERROR'
        return @()
    }
}

function Test-SystemWrite {
    param([string]$Path)
    # Create a unique test file under the target path and use a temporary scheduled task running as SYSTEM
    try {
        if (-not (Test-Path -Path $Path)) {
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
            Write-Log "Created directory $Path"
        }
        $testFile = Join-Path -Path $Path -ChildPath "SysWriteTest_$(Get-Date -Format 'yyyyMMdd_HHmmss_fff').txt"
        $taskName = "RuntimeQASysWrite_$(Get-Random)"
        $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c echo OK > \"$testFile\""
        $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -ErrorAction Stop | Out-Null
        Write-Log "Registered temporary task $taskName to write as SYSTEM"
        Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
        Start-Sleep -Seconds $SleepSeconds
        if (Test-Path -Path $testFile) {
            Write-Log "SYSTEM write test succeeded: $testFile"
            Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
            return $true
        } else {
            Write-Log "SYSTEM write test failed: $testFile" 'ERROR'
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
            return $false
        }
    } catch {
        Write-Log "Error during SYSTEM write test: $($_.Exception.Message)" 'ERROR'
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        return $false
    }
}

# --- Main ---
Write-Log "Starting Runtime QA checks"

# 1) Registry
$regResult = Test-RegistryCCS

# 1b) Event Log write checks for known sources
foreach ($src in $EventSources) {
    Test-EventLogWrite -Source $src | Out-Null
}

# 2) Determine CCS path to test
if ($CcsPath) {
    $testPath = $CcsPath
} elseif ($regResult.Found -and $regResult.Path) {
    $testPath = $regResult.Path
} else {
    Write-Log "No CCS path provided and registry did not provide one" 'WARNING'
    $testPath = $null
}

if ($testPath) {
    Test-PathAccess -Path $testPath | Out-Null
} else {
    Write-Log "Skipping CCS path access test" 'WARNING'
}

# 3) SYSTEM write test (only if we have a path to test)
if ($testPath) {
    $canWrite = Test-SystemWrite -Path $testPath
    if (-not $canWrite) {
        Write-Log "SYSTEM cannot write to $testPath. Consider verifying NT AUTHORITY\\SYSTEM permissions on the share." 'ERROR'
    }
}

# 4) Export script exists
if ($ExportScriptPath) {
    if (Test-Path -Path $ExportScriptPath) {
        Write-Log "Export script found: $ExportScriptPath"
    } else {
        Write-Log "Export script not found at $ExportScriptPath" 'ERROR'
    }
} else {
    Write-Log "No ExportScriptPath provided; skipping export script check" 'WARNING'
}

# 5) Optional: IIS HTTPS binding discovery
if ($CheckIISBindings.IsPresent) {
    $bindings = Get-IISHttpsBindings
    foreach ($b in $bindings) {
        Write-Log "Binding: Host='$($b.Host)' Port=$($b.Port) PfxFile=$($b.PfxFile)"
    }
}

Write-Log "Runtime QA checks completed"
