# IIS Certificate Automation (CCS)

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue)](https://github.com/nwlterry/iis_cert_automation)
[![Windows Server](https://img.shields.io/badge/Windows%20Server-2019%2F2022-green)]()
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Automate export of IIS certificates to a Centralized Certificate Store (CCS) + configure IIS + SYSTEM scheduled task.**

## Features

- Secure certificate export from `Cert:\LocalMachine\My` → UNC CCS share (`.pfx`)
- IIS Central Certificate Provider registry configuration
- Scheduled task triggered by certificate renewal events (runs as `NT AUTHORITY\SYSTEM`)
- UNC connectivity monitoring with auto-reconnect
- Runtime QA validation tools

## Quick Start – Runtime QA

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/Runtime-QA-Check.ps1 `
  -CcsPath "\\file-server\\IIS_Cert_Store" `
  -ExportScriptPath "C:\\Scripts\\Export-Cert-CCS-Secure.ps1" `
  -TempLogDir "C:\\Logs" -CheckIISBindings
```

See full documentation in `docs/`.

## Installation

1. Prepare the CCS share on the file server (Full Control for computer accounts).
2. Run setup on each web server (as Administrator):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File src/Setup-CCS-and-Task.ps1 `
  -CcsPhysicalPath "\\file-server\\IIS_Cert_Store" `
  -PfxPassword (Read-Host -AsSecureString "PFX Password")
```

## Project Structure

- `src/`          → Core production scripts
- `tools/`        → QA, monitoring & helper scripts
- `docs/`         → Documentation & implementation plan
- `examples/`     → Configuration templates
- `archive/`      → Old versioned files

## Requirements

- Windows Server 2019 / 2022
- PowerShell 5.1+
- IIS with CentralCertProvider feature
- Computer account (`DOMAIN\SERVER$`) needs Full Control on CCS share

## License

MIT License – see [LICENSE](LICENSE) file.

## Author

[nwlterry](https://github.com/nwlterry)