# PowerShell script to enable IIS Centralized Certificate Store (CCS) via registry, store PFX password in Credential Manager as SYSTEM,
# and set up a scheduled task to trigger on certificate renewal event (Event ID 1001 in Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational)
# and execute the provided export script (Export_Cert_CCS_Secure.ps1).
#
# This script is designed for an air-gapped environment running Windows PowerShell 5.1 (Windows Server 2019/2022).
# It handles SecureString conversion without the -AsPlainText parameter (not available in PowerShell 5.1).
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
        $events = Get-WinEvent -LogName "Microsoft-Windows-TaskScheduler/Operational" -MaxEvents 50 -ErrorAction Stop |
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
        Write-SetupLog -Message "Failed to retrieve Task Scheduler events for ${TaskName}: $($_.Exception.Message)" -Level "WARNING"
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
                Write-SetupLog -Message "Created directory ${dir} with SYSTEM and Administrators permissions"
            }
            $acl = icacls $dir
            Write-SetupLog -Message "Permissions for ${dir}: $($acl -join ', ')"
            $testFile = Join-Path -Path $dir -ChildPath "TestWrite_$(Get-Date -Format 'yyyyMMdd_HHmmss_fff').txt"
            $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c echo Test > ${testFile}"
            $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            $testTaskName = "TestWriteDir"
            Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
            Register-ScheduledTask -TaskName $testTaskName -Action $action -Principal $principal -ErrorAction Stop | Out-Null
            Start-ScheduledTask -TaskName $testTaskName -ErrorAction Stop
            Start-Sleep -Seconds 60
            Log-TaskSchedulerEvents -TaskName $testTaskName
            Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
            if (Test-Path $testFile) {
                Write-SetupLog -Message "SYSTEM can write to ${dir}"
                Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
                return $dir
            } else {
                Write-SetupLog -Message "SYSTEM write test to ${dir} failed: No log file created" -Level "WARNING"
            }
        } catch {
            Write-SetupLog -Message "Failed to test SYSTEM write permission to ${dir}: $($_.Exception.Message)" -Level "WARNING"
        }
    }
    Write-SetupLog -Message "No SYSTEM-writable directory found. Falling back to C:\Windows\Temp." -Level "WARNING"
    return "C:\Windows\Temp"
}

# Function to test directory write permissions for SYSTEM
function Test-SystemWritePermission {
    param (
        [string]$Path
    )
    try {
        if (-not $Path -or $Path -match "^\[.*") {
            Write-SetupLog -Message "Invalid path provided to Test-SystemWritePermission: ${Path}" -Level "ERROR"
            return $false
        }
        # Sanitize path to avoid invalid characters
        $Path = [System.IO.Path]::GetFullPath($Path)
        $testFile = Join-Path -Path $Path -ChildPath "TestWrite_$(Get-Date -Format 'yyyyMMdd_HHmmss_fff').txt"
        $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c echo Test > ${testFile}"
        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $testTaskName = "TestWritePermission"
        Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $testTaskName -Action $action -Principal $principal -ErrorAction Stop | Out-Null
        Write-SetupLog -Message "Registered test task ${testTaskName} to verify write permissions to ${Path}"
        Start-ScheduledTask -TaskName $testTaskName -ErrorAction Stop
        Start-Sleep -Seconds 60
        Log-TaskSchedulerEvents -TaskName $testTaskName
        if (Test-Path $testFile) {
            Write-SetupLog -Message "SYSTEM write permission test to ${Path} succeeded"
            Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
            return $true
        } else {
            Write-SetupLog -Message "SYSTEM write permission test to ${Path} failed" -Level "WARNING"
            return $false
        }
    } catch {
        Write-SetupLog -Message "Failed to test SYSTEM write permission to ${Path}: $($_.Exception.Message)" -Level "ERROR"
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
            Write-SetupLog -Message "Invalid log directory provided to Test-MinimalSystemCmd: ${LogDir}" -Level "ERROR"
            return
        }
        $testLog = Join-Path -Path $LogDir -ChildPath "MinimalSystemCmdTest_$(Get-Date -Format 'yyyyMMdd_HHmmss_fff').log"
        $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c echo Test > ${testLog}"
        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $testTaskName = "TestMinimalSystemCmd"
        Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $testTaskName -Action $action -Principal $principal -ErrorAction Stop | Out-Null
        Write-SetupLog -Message "Registered minimal cmd test task ${testTaskName} to verify SYSTEM execution"
        Start-ScheduledTask -TaskName $testTaskName -ErrorAction Stop
        Start-Sleep -Seconds 60
        Log-TaskSchedulerEvents -TaskName $testTaskName
        if (Test-Path $testLog) {
            $taskLog = Get-Content -Path $testLog -Raw
            Write-SetupLog -Message "Minimal SYSTEM cmd execution test log: ${taskLog}"
            Remove-Item -Path $testLog -Force -ErrorAction SilentlyContinue
        } else {
            Write-SetupLog -Message "Minimal SYSTEM cmd execution test log not found at ${testLog}" -Level "WARNING"
        }
        Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
    } catch {
        Write-SetupLog -Message "Failed to test minimal SYSTEM cmd execution: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Function to test minimal SYSTEM execution with PowerShell
function Test-MinimalSystemPowerShell {
    param (
        [string]$LogDir
    )
    try {
        if (-not $LogDir -or $LogDir -match "^\[.*") {
            Write-SetupLog -Message "Invalid log directory provided to Test-MinimalSystemPowerShell: ${LogDir}" -Level "ERROR"
            return
        }
        $testLog = Join-Path -Path $LogDir -ChildPath "MinimalSystemTest_$(Get-Date -Format 'yyyyMMdd_HHmmss_fff').log"
        $tempScript = Join-Path -Path "C:\Windows\Temp" -ChildPath "MinimalSystemTest_$(Get-Date -Format 'yyyyMMdd_HHmmss_fff').ps1"
        $psCommand = @"
try {
    'Test' | Out-File -FilePath '${testLog}' -Append -ErrorAction Stop
} catch {
    for (`$i = 0; `$i -lt 3; `$i++) {
        try {
            "Error: `$($_.Exception.Message)" | Out-File -FilePath "${testLog}" -Append -ErrorAction Stop
            break
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }
}
"@
        Set-Content -Path $tempScript -Value $psCommand -Force
        icacls $tempScript /grant "NT AUTHORITY\SYSTEM:(F)" | Out-Null
        Write-SetupLog -Message "Set SYSTEM permissions on ${tempScript}"
        $testCommand = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"${tempScript}`" > ${testLog} 2>&1"
        $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c ${testCommand}"
        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $testTaskName = "TestMinimalSystem"
        Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $testTaskName -Action $action -Principal $principal -ErrorAction Stop | Out-Null
        Write-SetupLog -Message "Registered minimal test task ${testTaskName} to verify SYSTEM execution"
        Start-ScheduledTask -TaskName $testTaskName -ErrorAction Stop
        Start-Sleep -Seconds 60
        Log-TaskSchedulerEvents -TaskName $testTaskName
        if (Test-Path $testLog) {
            $taskLog = Get-Content -Path $testLog -Raw
            Write-SetupLog -Message "Minimal SYSTEM PowerShell execution test log: ${taskLog}"
            Remove-Item -Path $testLog -Force -ErrorAction SilentlyContinue
        } else {
            Write-SetupLog -Message "Minimal SYSTEM PowerShell execution test log not found at ${testLog}" -Level "WARNING"
        }
        Remove-Item -Path $tempScript -Force -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
    } catch {
        Write-SetupLog -Message "Failed to test minimal SYSTEM PowerShell execution: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Function to test PowerShell error logging via cmd.exe
function Test-PowerShellError {
    param (
        [string]$LogDir
    )
    try {
        if (-not $LogDir -or $LogDir -match "^\[.*") {
            Write-SetupLog -Message "Invalid log directory provided to Test-PowerShellError: ${LogDir}" -Level "ERROR"
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
            "Error: `$($_.Exception.Message)" | Out-File -FilePath "${testLog}" -Append -ErrorAction Stop
            break
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }
}
"@
        Set-Content -Path $tempScript -Value $psCommand -Force
        icacls $tempScript /grant "NT AUTHORITY\SYSTEM:(F)" | Out-Null
        Write-SetupLog -Message "Set SYSTEM permissions on ${tempScript}"
        $testCommand = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"${tempScript}`" > ${testLog} 2>&1"
        $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c ${testCommand}"
        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $testTaskName = "TestPowerShellError"
        Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $testTaskName -Action $action -Principal $principal -ErrorAction Stop | Out-Null
        Write-SetupLog -Message "Registered test task ${testTaskName} to verify PowerShell error logging via cmd.exe"
        Start-ScheduledTask -TaskName $testTaskName -ErrorAction Stop
        Start-Sleep -Seconds 60
        Log-TaskSchedulerEvents -TaskName $testTaskName
        if (Test-Path $testLog) {
            $taskLog = Get-Content -Path $testLog -Raw
            Write-SetupLog -Message "PowerShell error test log via cmd.exe: ${taskLog}"
            Remove-Item -Path $testLog -Force -ErrorAction SilentlyContinue
        } else {
            Write-SetupLog -Message "PowerShell error test log not found at ${testLog}" -Level "WARNING"
        }
        Remove-Item -Path $tempScript -Force -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
    } catch {
        Write-SetupLog -Message "Failed to test PowerShell error logging via cmd.exe: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Function to test PowerShell environment in SYSTEM context
function Test-PowerShellEnvironment {
    param (
        [string]$LogDir
    )
    try {
        if (-not $LogDir -or $LogDir -match "^\[.*") {
            Write-SetupLog -Message "Invalid log directory provided to Test-PowerShellEnvironment: ${LogDir}" -Level "ERROR"
            return
        }
        $testLog = Join-Path -Path $LogDir -ChildPath "PowerShellEnvTest_$(Get-Date -Format 'yyyyMMdd_HHmmss_fff').log"
        $tempScript = Join-Path -Path "C:\Windows\Temp" -ChildPath "PowerShellEnvTest_$(Get-Date -Format 'yyyyMMdd_HHmmss_fff').ps1"
        $psCommand = @"
try {
    `$envInfo = "PSVersion: `$($PSVersionTable.PSVersion)"
    `$envInfo += "`nExecutionPolicy: `$(Get-ExecutionPolicy -Scope CurrentUser)"
    `$envInfo += "`nUser: `$($env:USERNAME)"
    `$envInfo += "`nPath: `$($env:PSModulePath)"
    `$envInfo += "`nSecurityPolicy: `$(Get-ExecutionPolicy -List | Out-String)"
    `$envInfo += "`nWhoAmI: `$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
    `$envInfo += "`nErrorActionPreference: `$($ErrorActionPreference)"
    `$envInfo += "`nAppLockerPolicy: `$(try { Get-AppLockerPolicy -Effective -Local | Out-String } catch { 'Error: ' + `$_.Exception.Message })"
    `$envInfo += "`nProcessToken: `$(try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Groups | ForEach-Object { `$_.Translate([System.Security.Principal.NTAccount]) } | Out-String } catch { 'Error: ' + `$_.Exception.Message })"
    `$envInfo | Out-File -FilePath "${testLog}" -Append -ErrorAction Stop
} catch {
    for (`$i = 0; `$i -lt 3; `$i++) {
        try {
            "Error: `$($_.Exception.Message)" | Out-File -FilePath "${testLog}" -Append -ErrorAction Stop
            break
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }
}
"@
        Set-Content -Path $tempScript -Value $psCommand -Force
        icacls $tempScript /grant "NT AUTHORITY\SYSTEM:(F)" | Out-Null
        Write-SetupLog -Message "Set SYSTEM permissions on ${tempScript}"
        $testCommand = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"${tempScript}`" > ${testLog} 2>&1"
        $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c ${testCommand}"
        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $testTaskName = "TestPowerShellEnv"
        Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $testTaskName -Action $action -Principal $principal -ErrorAction Stop | Out-Null
        Write-SetupLog -Message "Registered test task ${testTaskName} to verify PowerShell environment in SYSTEM context"
        Start-ScheduledTask -TaskName $testTaskName -ErrorAction Stop
        Start-Sleep -Seconds 60
        Log-TaskSchedulerEvents -TaskName $testTaskName
        if (Test-Path $testLog) {
            $taskLog = Get-Content -Path $testLog -Raw
            Write-SetupLog -Message "PowerShell environment test log: ${taskLog}"
            Remove-Item -Path $testLog -Force -ErrorAction SilentlyContinue
        } else {
            Write-SetupLog -Message "PowerShell environment test log not found at ${testLog}" -Level "WARNING"
        }
        Remove-Item -Path $tempScript -Force -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
    } catch {
        Write-SetupLog -Message "Failed to test PowerShell environment in SYSTEM context: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Function to verify credential storage in SYSTEM context
function Verify-CredentialStorage {
    param (
        [string]$LogDir
    )
    try {
        $testLog = Join-Path -Path $LogDir -ChildPath "CmdkeyVerify_$(Get-Date -Format 'yyyyMMdd_HHmmss_fff').log"
        $verifyCommand = "cmdkey /list | findstr PFXCertPassword > ${testLog}"
        $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c ${verifyCommand}"
        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $testTaskName = "TestCmdkeyVerify"
        Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $testTaskName -Action $action -Principal $principal -ErrorAction Stop | Out-Null
        Write-SetupLog -Message "Registered test task ${testTaskName} to verify credential storage in SYSTEM context"
        Start-ScheduledTask -TaskName $testTaskName -ErrorAction Stop
        Start-Sleep -Seconds 60
        Log-TaskSchedulerEvents -TaskName $testTaskName
        if (Test-Path $testLog) {
            $taskLog = Get-Content -Path $testLog -Raw
            Write-SetupLog -Message "Credential verification log: ${taskLog}"
            Remove-Item -Path $testLog -Force -ErrorAction SilentlyContinue
            if ($taskLog -match "PFXCertPassword") {
                Write-SetupLog -Message "Cmdkey credential verified in SYSTEM context: ${taskLog}"
                return $true
            } else {
                Write-SetupLog -Message "Cmdkey credential not found in SYSTEM context. Log content: ${taskLog}" -Level "ERROR"
                return $false
            }
        } else {
            Write-SetupLog -Message "Credential verification log not found at ${testLog}" -Level "ERROR"
            return $false
        }
    } catch {
        Write-SetupLog -Message "Failed to verify credential storage in SYSTEM context: $($_.Exception.Message)" -Level "ERROR"
        return $false
    } finally {
        Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
    }
}

try {
    # Check Task Scheduler service status
    $taskService = Get-Service -Name Schedule -ErrorAction Stop
    if ($taskService.Status -ne 'Running') {
        Write-SetupLog -Message "Task Scheduler service is not running. Current status: $($taskService.Status)" -Level "ERROR"
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

    # Log security policy information
    try {
        $appLockerPolicy = Get-AppLockerPolicy -Effective -Local -ErrorAction Stop
        Write-SetupLog -Message "AppLocker policy: $($appLockerPolicy | Out-String)"
    } catch {
        Write-SetupLog -Message "Failed to retrieve AppLocker policy: $($_.Exception.Message)" -Level "WARNING"
    }
    try {
        $groupPolicy = gpresult /R /SCOPE COMPUTER
        Write-SetupLog -Message "Group Policy (Computer scope): $($groupPolicy -join ', ')"
    } catch {
        Write-SetupLog -Message "Failed to retrieve Group Policy: $($_.Exception.Message)" -Level "WARNING"
    }

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
            icacls $TempLogDir /grant "NT AUTHORITY\SYSTEM:(OI)(CI)(F)" /grant "Administrators:(OI)(CI)(F)" | Out-Null
            Write-SetupLog -Message "Created temporary log directory: ${TempLogDir} with SYSTEM and Administrators permissions"
        } catch {
            Write-SetupLog -Message "Failed to create temporary log directory ${TempLogDir}: $($_.Exception.Message)" -Level "ERROR"
            throw
        }
    }
    if (-not (Test-SystemWritePermission -Path $TempLogDir)) {
        Write-SetupLog -Message "SYSTEM account cannot write to ${TempLogDir}. Attempting to find a SYSTEM-writable directory." -Level "WARNING"
        $TempLogDir = Find-SystemWritableDirectory
        Write-SetupLog -Message "Using SYSTEM-writable directory: ${TempLogDir}"
    }
    $acl = icacls $TempLogDir
    Write-SetupLog -Message "Permissions for ${TempLogDir}: $($acl -join ', ')"

    # Test minimal SYSTEM execution with cmd.exe
    Test-MinimalSystemCmd -LogDir $TempLogDir

    # Test minimal SYSTEM execution with PowerShell
    Test-MinimalSystemPowerShell -LogDir $TempLogDir

    # Test PowerShell error logging via cmd.exe
    Test-PowerShellError -LogDir $TempLogDir

    # Test PowerShell environment in SYSTEM context
    Test-PowerShellEnvironment -LogDir $TempLogDir

    # Verify Windows Server version (2019 or 2022)
    $osVersion = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
    if ($osVersion -notlike "*Windows Server 2019*" -and $osVersion -notlike "*Windows Server 2022*") {
        Write-SetupLog -Message "Unsupported operating system: ${osVersion}. This script is designed for Windows Server 2019 or 2022." -Level "ERROR"
        throw "Unsupported operating system"
    }
    Write-SetupLog -Message "Running on ${osVersion}"

    # Install Web-Scripting-Tools and Web-CertProvider features if not already installed
    $scriptingFeature = Get-WindowsFeature -Name Web-Scripting-Tools
    if (-not $scriptingFeature.Installed) {
        Write-SetupLog -Message "Installing Web-Scripting-Tools feature"
        Install-WindowsFeature -Name Web-Scripting-Tools -ErrorAction Stop
        Write-SetupLog -Message "Web-Scripting-Tools feature installed"
    } else {
        Write-SetupLog -Message "Web-Scripting-Tools feature is already installed"
    }
    $ccsFeature = Get-WindowsFeature -Name Web-CertProvider
    if (-not $ccsFeature.Installed) {
        Write-SetupLog -Message "Installing Web-CertProvider feature"
        Install-WindowsFeature -Name Web-CertProvider -ErrorAction Stop
        Write-SetupLog -Message "Web-CertProvider feature installed"
    } else {
        Write-SetupLog -Message "Web-CertProvider feature is already installed"
    }

    # Verify and configure CCS via registry
    $registryPath = "HKLM:\SOFTWARE\Microsoft\IIS\CentralCertProvider"
    try {
        $registryValues = Get-ItemProperty -Path $registryPath -ErrorAction Stop
        Write-SetupLog -Message "CCS registry key found: Enabled=$($registryValues.Enabled), PhysicalPath=$($registryValues.CertStoreLocation)"
        if ($registryValues.Enabled -ne 1 -or $registryValues.CertStoreLocation -ne $CcsPhysicalPath) {
            Write-SetupLog -Message "CCS registry key values incorrect. Updating registry." -Level "WARNING"
            Set-ItemProperty -Path $registryPath -Name Enabled -Value 1 -ErrorAction Stop
            Set-ItemProperty -Path $registryPath -Name CertStoreLocation -Value $CcsPhysicalPath -ErrorAction Stop
            Write-SetupLog -Message "Updated CCS registry key: Enabled=1, PhysicalPath=$CcsPhysicalPath"
        }
    } catch {
        Write-SetupLog -Message "CCS registry key not found at ${registryPath}. Creating key." -Level "WARNING"
        New-Item -Path $registryPath -Force | Out-Null
        New-ItemProperty -Path $registryPath -Name Enabled -Value 1 -PropertyType DWord -ErrorAction Stop | Out-Null
        New-ItemProperty -Path $registryPath -Name CertStoreLocation -Value $CcsPhysicalPath -PropertyType String -ErrorAction Stop | Out-Null
        Write-SetupLog -Message "Created CCS registry key: Enabled=1, PhysicalPath=$CcsPhysicalPath"
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
        Write-SetupLog -Message "Error accessing CCS path ${CcsPhysicalPath}: $($_.Exception.Message)" -Level "ERROR"
        throw
    }

    # Store PFX password in Credential Manager as SYSTEM using cmd.exe
    $tempTaskName = "TempStoreCredential"
    $tempLogPath = Join-Path -Path $TempLogDir -ChildPath "TempStoreCredential_$((Get-Date -Format 'yyyyMMdd_HHmmss_fff')).log"
    $psPassword = Convert-SecureStringToPlainText -SecureString $PfxPassword
    # Escape single quotes in the password to prevent command injection
    $psPassword = $psPassword -replace "'", "''"
    $storeCommand = "cmdkey /generic:PFXCertPassword /user:PFXUser /pass:$psPassword > $tempLogPath 2>&1"
    try {
        $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c $storeCommand"
        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Unregister-ScheduledTask -TaskName $tempTaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $tempTaskName -Action $action -Principal $principal -ErrorAction Stop | Out-Null
        Write-SetupLog -Message "Temporary task ${tempTaskName} created to store credential as SYSTEM"
    } catch {
        Write-SetupLog -Message "Failed to register temporary task ${tempTaskName}: $($_.Exception.Message)" -Level "ERROR"
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
            if ($taskLog -match "Credential added successfully") {
                Write-SetupLog -Message "Temporary task ${tempTaskName} executed successfully. Log content: ${taskLog}"
            } else {
                Write-SetupLog -Message "Temporary task ${tempTaskName} failed. Log content: ${taskLog}" -Level "ERROR"
                throw "Temporary task execution failed"
            }
        } else {
            Write-SetupLog -Message "Temporary task log file not found at ${tempLogPath}. Credential storage failed." -Level "ERROR"
            throw "Credential storage failed"
        }
    } catch {
        Write-SetupLog -Message "Error running temporary task ${tempTaskName}: $($_.Exception.Message)" -Level "ERROR"
        throw
    } finally {
        # Clean up temporary files and task
        Remove-Item -Path $tempLogPath -Force -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $tempTaskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-SetupLog -Message "Temporary task ${tempTaskName} and files removed"
    }

    # Verify credential storage in SYSTEM context with retries
    $retryCount = 3
    $retryDelay = 5
    $credentialVerified = $false
    for ($i = 0; $i -lt $retryCount; $i++) {
        try {
            $credentialVerified = Verify-CredentialStorage -LogDir $TempLogDir
            if ($credentialVerified) {
                break
            } else {
                Write-SetupLog -Message "Attempt $($i + 1) to verify credential failed. Retrying after ${retryDelay} seconds." -Level "WARNING"
                if ($i -lt $retryCount - 1) {
                    Start-Sleep -Seconds $retryDelay
                    continue
                }
            }
        } catch {
            Write-SetupLog -Message "Attempt $($i + 1) to verify credential failed: $($_.Exception.Message)" -Level "WARNING"
            if ($i -lt $retryCount - 1) {
                Start-Sleep -Seconds $retryDelay
                continue
            }
        }
    }
    if (-not $credentialVerified) {
        Write-SetupLog -Message "Failed to verify stored credential for PFXCertPassword after $retryCount attempts. Credential is not found." -Level "ERROR"
        Write-SetupLog -Message "Please manually store the credential as SYSTEM using: cmdkey /generic:PFXCertPassword /user:PFXUser /pass:<YourPassword>" -Level "ERROR"
        throw "Credential storage failed"
    }

    # Verify export script exists
    if (-not (Test-Path $ExportScriptPath)) {
        Write-SetupLog -Message "Export script not found at ${ExportScriptPath}" -Level "ERROR"
        throw "Export script missing"
    }

    # Set up the scheduled task for certificate renewal event using COM object
    try {
        $queryXml = @"
<QueryList>
  <Query Id="0" Path="$EventLogPath">
    <Select Path="$EventLogPath">*[System[(EventID=$EventId)]]</Select>
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
        $trigger = $taskDefinition.Triggers.Create(0) # 0 = Event trigger
        $trigger.Subscription = $queryXml
        $trigger.Enabled = $true
        $action = $taskDefinition.Actions.Create(0) # 0 = Execute action
        $action.Path = "cmd.exe"
        $action.Arguments = "/c powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$ExportScriptPath`""
        $principal = $taskDefinition.Principal
        $principal.UserId = "NT AUTHORITY\SYSTEM"
        $principal.LogonType = 3 # Service account
        $principal.RunLevel = 1 # Highest privileges
        $folder = $taskService.GetFolder("\")
        try {
            $folder.RegisterTaskDefinition($TaskName, $taskDefinition, 6, $null, $null, 3) | Out-Null
            Write-SetupLog -Message "Registered new scheduled task: ${TaskName}"
        } catch {
            Write-SetupLog -Message "Updating existing scheduled task: ${TaskName}"
            $folder.RegisterTaskDefinition($TaskName, $taskDefinition, 4, $null, $null, 3) | Out-Null
        }
    } catch {
        Write-SetupLog -Message "Failed to register or update scheduled task ${TaskName}: $($_.Exception.Message)" -Level "ERROR"
        throw
    }

    Write-SetupLog -Message "Setup completed successfully"
} catch {
    Write-SetupLog -Message "Error during setup: $($_.Exception.Message)" -Level "ERROR"
    throw
}
