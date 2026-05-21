# IIS Certificate Automation (CCS)

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue)](https://github.com/nwlterry/iis_cert_automation)
[![Windows Server](https://img.shields.io/badge/Windows_Server-2019%2F2022-green)]()
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Automate export of IIS certificates to a Centralized Certificate Store (CCS) + configure IIS + SYSTEM scheduled task.**

## Features

- Export certificates from `Cert:\LocalMachine\My` → UNC CCS share as `.pfx` files.
- Configure IIS CentralCertProvider registry + install required features.
- Register scheduled task triggered by certificate renewal events (runs as `NT AUTHORITY\SYSTEM`).
- Secure credential handling (PFX password stored for SYSTEM via `cmdkey`).
- UNC connectivity monitoring with auto-reconnect & log rotation.
- Runtime QA checks for registry, permissions, and SYSTEM write access.

## Quick Start – Runtime QA

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/Runtime-QA-Check.ps1 `
  -CcsPath "\\file-server\IIS_Cert_Store" `
  -ExportScriptPath "C:\Scripts\Export-Cert-CCS-Secure.ps1" `
  -TempLogDir "C:\Logs" -CheckIISBindings
