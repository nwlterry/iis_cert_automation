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
