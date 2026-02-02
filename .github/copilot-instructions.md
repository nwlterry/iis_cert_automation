<!-- Copilot / AI agent instructions for the iis_cert_automation repo -->
# Quick orientation for AI coding agents

This repository contains PowerShell automation for exporting IIS certificates into a Centralized Certificate Store (CCS), configuring CCS and a SYSTEM-scheduled task, and helper utilities.

Key constraints
- PowerShell scripts target Windows Server (2019/2022) and Windows PowerShell 5.1 behavior.
- Scripts run as `NT AUTHORITY\\SYSTEM` via Task Scheduler; many checks test SYSTEM write/access.
- Primary CCS registry key: `HKLM:\\SOFTWARE\\Microsoft\\IIS\\CentralCertProvider` (fields: `Enabled`, `CertStoreLocation`).

Big-picture architecture
- Setup: [Setup_CCS_and_Task.ps1](Setup_CCS_and_Task.ps1) configures CCS (registry), stores the PFX password for SYSTEM, installs IIS features, and registers a scheduled task triggered by a certificate-renewal event.
- Export: [Export_Cert_CCS_Secure.ps1](Export_Cert_CCS_Secure.ps1) (and variants) runs under SYSTEM to export certificates from `Cert:\\LocalMachine\\My` to the CCS share as PFX files.
- Utilities: [IIS_Cert_Auto_Package/UNC-Connectivity-Checker.ps1](IIS_Cert_Auto_Package/UNC-Connectivity-Checker.ps1) verifies UNC connectivity, rotates logs, and attempts reconnects.

Project-specific patterns and conventions
- Date-based logs: scripts use `C:\\Logs` with filenames like `CertificateExport_yyyy-MM-dd.log` or `UNC_Check_yyyy-MM-dd.log`.
- Event logging: scripts write structured Event Log entries. Common event IDs:
  - `1001` start export; `1004` export success; `1005` export failure. Check scripts for exact mappings.
- Fallback behavior: scripts prefer registry-provided CCS path; if inaccessible they attempt to create the path or fall back to a local `C:\\CertStore`.
- AppCmd usage: `appcmd.exe list sites` is parsed to infer HTTPS bindings and expected .pfx filenames when IIS bindings exist.
- Password handling: production expects a `SecureString` password stored for SYSTEM (scripts sometimes include a test fallback password—do not use in production).
- Permission checks: `icacls`, `Get-SmbShareAccess`, and scheduled-task-based write tests are used to validate SYSTEM permissions.

How to run and test locally (developer workflow)
- Prereqs: run as Administrator on a Windows Server 2019/2022 VM, PowerShell 5.1. Ensure Task Scheduler service is running.
- Quick setup example (interactive PFX password):
```
powershell -NoProfile -ExecutionPolicy Bypass -File Setup_CCS_and_Task.ps1 \
  -CcsPhysicalPath "\\\\file-server\\IIS_Cert_Store" \
  -PfxPassword (Read-Host -AsSecureString "Enter PFX password for CCS") \
  -ExportScriptPath "C:\\Scripts\\Export_Cert_CCS_Secure.ps1" \
  -TempLogDir "C:\\Logs"
```
- To test exports without modifying server registry/share: run `Export_Cert_CCS_Secure.v03.ps1` variants or run `Export_Cert_CCS_Secure.ps1` interactively and point `-pfxBasePath` to a local folder.
- To verify behavior: check log files in `C:\\Logs` and the Windows Event Log under `Application` (event source names appear inside scripts).

Integration points & external dependencies
- SMB/UNC CCS share: scripts assume a pre-created share with NTFS and SMB permissions allowing the computer account (SYSTEM) to write.
- IIS & appcmd.exe: scripts call `C:\\Windows\\System32\\inetsrv\\appcmd.exe` to list bindings.
- Windows features: `Web-Scripting-Tools` and `Web-CertProvider` may be installed by setup script.
- Credential storage: scripts use `cmdkey` via a temporary scheduled task to store a PFX password for the SYSTEM account.

What an agent should avoid changing
- Do not replace or surface real passwords—scripts intentionally require manual password input for production.
- Do not alter SYSTEM-permission checks or the scheduled-task execution context without explicit rationale (these are central to design).

Examples of small, safe tasks an agent may perform
- Extract and list all event IDs used by scripts (helpful when writing monitoring docs).
- Add clarifying comments or short README excerpts near complex functions (e.g., the scheduled-task registration block in `Setup_CCS_and_Task.ps1`).
- Produce a testing checklist that reproduces the manual steps in `Setup_CCS_and_Task.ps1` (create share, set icacls, verify Task Scheduler). 

If you need more context
- Inspect these files first: [Setup_CCS_and_Task.ps1](Setup_CCS_and_Task.ps1), [Export_Cert_CCS_Secure.ps1](Export_Cert_CCS_Secure.ps1), and [IIS_Cert_Auto_Package/UNC-Connectivity-Checker.ps1](IIS_Cert_Auto_Package/UNC-Connectivity-Checker.ps1).
- Ask the repo owner for the canonical CCS UNC path and production PFX handling guidelines before making changes that touch credential storage or share permissions.

Request feedback: is any operational detail missing or should I include a short runtime checklist for QA runs?

**Event ID mappings (quick reference)**

- **Certificate export (detailed):** see [Export_Cert_EventIDs.md](Export_Cert_EventIDs.md) — comprehensive list of Event IDs used by the export logic (1001–1076). Note: the export scripts in the repo register the event source `CertificateExportScript` and write to the `Application` log.
- **UNC connectivity helper (`IIS_Cert_Auto_Package/UNC-Connectivity-Checker.ps1`):**
  - `1000` : UNC path is accessible (Information).
  - `1001` : UNC path not accessible — attempting reconnect (Warning).
  - `1002` : Disconnected existing sessions to the server (Information).
  - `1003` : Reconnected (Information).
  - `1004` : Reconnect verified success (Information).
  - `1005` : Deleted old log during rotation (Information).
  - `2001` : Error disconnecting existing sessions (Error).
  - `2002` : Reconnect failed (Error).
  - `2003` : Error reconnecting (Error).

- **Setup script (`Setup_CCS_and_Task.ps1` and variants):** listens/uses Event ID `1001` as the certificate-renewal trigger when registering the scheduled task (Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational context).

When writing monitoring or alerts, prefer referencing the detailed mapping in [Export_Cert_EventIDs.md](Export_Cert_EventIDs.md) for export-related events, and use the UNC helper mappings above for connectivity alerts.

**Runtime QA Checklist**

- **Prerequisites:** Windows Server 2019/2022 VM, Administrator account, Task Scheduler running.
- **Create and secure CCS share (on file server):** create folder, set NTFS and SMB permissions for computer accounts. Example commands (run on file server):
```
New-Item -Path "C:\IIS_Cert_Store" -ItemType Directory
icacls "C:\IIS_Cert_Store" /inheritance:r /grant "DOMAIN\IISComputerName$":(OI)(CI)(F) /grant Administrators:(OI)(CI)(F)
New-SmbShare -Name "IIS_Cert_Store" -Path "C:\IIS_Cert_Store" -FullAccess "DOMAIN\IISComputerName$","Administrators"
```
- **Verify CCS registry and accessibility:** on web server, confirm `HKLM:\SOFTWARE\Microsoft\IIS\CentralCertProvider` (`Enabled=1`, `CertStoreLocation` set to UNC). Then test path access:
```
Test-Path "\\file-server\IIS_Cert_Store"
Test-Path "HKLM:\SOFTWARE\Microsoft\IIS\CentralCertProvider"
```
- **Store PFX password for SYSTEM (test only):** the setup script uses `cmdkey` via a temporary scheduled task. To verify storage as SYSTEM, run `Setup_CCS_and_Task.ps1` with `-PfxPassword` and then verify via a scheduled task run that calls `cmdkey /list` in SYSTEM context (see `Verify-CredentialStorage` function).
- **Verify SYSTEM write permissions to CCS:** use the scheduled-task based checks in `Setup_CCS_and_Task.ps1` (`Test-SystemWritePermission`, `Find-SystemWritableDirectory`). To run a manual quick check create a scheduled task that runs as `NT AUTHORITY\SYSTEM` to `cmd.exe /c echo ok > C:\IIS_Cert_Store\test.txt` and verify file creation.
- **Test scheduled task trigger:** register the task via `Setup_CCS_and_Task.ps1` then simulate the event or run the task manually and verify the task writes expected logs to `C:\Logs` and Event Log entries (source names in scripts). Use `Get-ScheduledTask` and `Get-ScheduledTaskInfo` to inspect.
- **Run export script manually (dry run):** run `Export_Cert_CCS_Secure.ps1` interactively, set `-pfxBasePath` to a local folder and provide a test `SecureString` password to verify export logic and logging.
```
powershell -NoProfile -ExecutionPolicy Bypass -File Export_Cert_CCS_Secure.ps1 -pfxBasePath "C:\Temp\Certs" -PfxPassword (ConvertTo-SecureString "TestPass" -AsPlainText -Force)
```
- **Check IIS binding discovery:** verify `appcmd.exe list sites` returns HTTPS bindings and that the script extracts hostnames. If IIS has no HTTPS bindings, ensure `.pfx` files exist in CCS path as fallback.
- **UNC connectivity helper:** run `IIS_Cert_Auto_Package\UNC-Connectivity-Checker.ps1` to exercise reconnect logic, log rotation, and Event Log messages.
- **Event Log verification:** Inspect `Application` log for script event IDs (start/success/failure). Example IDs used: `1001` (start), `1004` (export success), `1005` (export failure) — confirm exact mapping inside scripts before alerting/monitoring.
- **Cleanup and safety:** remove any temporary test credentials (`cmdkey /delete:PFXCertPassword`), unregister test scheduled tasks, and delete test files created by SYSTEM checks.

If you'd like, I can expand any checklist step into a runnable step-by-step script for QA runs.
