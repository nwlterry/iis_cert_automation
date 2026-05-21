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
```

**What it verifies:**
- CCS registry key (`HKLM:\SOFTWARE\Microsoft\IIS\CentralCertProvider`)
- UNC path accessibility
- SYSTEM account write permission (via temp scheduled task)
- Export script presence + optional IIS HTTPS binding discovery

## Installation & Setup

1. **Prepare CCS Share** (on file server – see [docs/implementation-plan.md](docs/implementation-plan.md)).
2. Run setup (as Administrator):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File src/Setup-CCS-and-Task.ps1 `
  -CcsPhysicalPath "\\file-server\IIS_Cert_Store" `
  -PfxPassword (Read-Host -AsSecureString "Enter PFX password") `
  -ExportScriptPath "C:\Scripts\Export-Cert-CCS-Secure.ps1"
```

3. Deploy `Export-Cert-CCS-Secure.ps1` to web servers.
4. (Optional) Deploy UNC checker as additional scheduled task.

See full [docs/runtime-qa-checklist.md](docs/runtime-qa-checklist.md) for detailed steps and troubleshooting.

## Project Structure

- `src/` – Core scripts (production use)
- `tools/` – Helpers & QA utilities
- `docs/` – Documentation & event ID mappings
- `.github/copilot-instructions.md` – Guidance for AI coding agents

## Requirements

- **OS**: Windows Server 2019 / 2022
- **PowerShell**: 5.1 (Windows PowerShell)
- **IIS Features**: Web-Scripting-Tools, Web-CertProvider (installed by setup)
- **Permissions**: Computer account (`DOMAIN\WEB01$`) needs Full Control on CCS share (NTFS + SMB)

## Event Logging

Scripts write to the **Application** log with source `CertificateExportScript` (and others). Full mappings in [docs/Export_Cert_EventIDs.md](docs/Export_Cert_EventIDs.md).

## License

[MIT License](LICENSE) – see file for details.

## Contributing

Contributions welcome! Please open an issue or PR. See [copilot-instructions.md](.github/copilot-instructions.md) for architecture notes.

## Author

Created by [nwlterry](https://github.com/nwlterry).
```

### 3. Other Repository Settings & Requirements

- **Repository "About" section** (GitHub repo settings):
  - **Description**: "PowerShell tools to export IIS certificates to Centralized Certificate Store (CCS), configure IIS, and run renewal tasks as SYSTEM."
  - **Topics/tags**: `iis`, `powershell`, `certificate`, `ccs`, `automation`, `windows-server`, `pki`
  - **Website** (optional): Link to a docs page if you add one.
  - **Template**: Add a short repo description.

- **LICENSE file**: Add a standard `MIT` or `GPL-3.0` license via GitHub (Settings → Manage access or create `LICENSE` file). MIT is common for scripts.

- **CHANGELOG.md**: Add one tracking major versions (e.g., v1.0 – Initial CCS export).

- **Releases**: Create a v1.0 release with a ZIP of `src/` + `tools/` (exclude old versions).

- **.gitignore** example:
  ```
  *.log
  *.pfx
  *.tmp
  archive/
  *.xlsx
  ```

- **Make it a PowerShell Module** (future enhancement): Wrap in a `.psm1` + manifest for easier installation (`Install-Module`).

### Next Steps Summary
1. Refactor file structure as proposed (use Git moves to preserve history).
2. Update README.md with the version above.
3. Add LICENSE + CHANGELOG.
4. Archive old versioned scripts.
5. Update links in `copilot-instructions.md` and other docs to match new paths.
6. Test everything after changes.

This will make the repo much more professional, discoverable, and maintainable. Let me know if you want me to generate specific files (e.g., full LICENSE, updated script headers, or a module manifest)!
