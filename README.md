# iis_cert_autonmation

Quick start — runtime QA

This repository provides PowerShell tooling to export IIS certificates into a Centralized Certificate Store (CCS), configure IIS CCS and a SYSTEM scheduled task, and helper utilities.

Quick runnable check: use the runtime QA helper to validate registry, UNC access, SYSTEM write, and export-script presence:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File IIS_Cert_Auto_Package\Runtime_QA_Check.ps1 \
	-CcsPath "\\file-server\IIS_Cert_Store" \
	-ExportScriptPath "C:\Scripts\Export_Cert_CCS_Secure.ps1" \
	-TempLogDir "C:\Logs"
```

What it verifies:
- CCS registry key and configured `CertStoreLocation`
- UNC/CCS path accessibility
- SYSTEM account write capability (via temporary scheduled task)
- Presence of the export script

See `.github/copilot-instructions.md` for AI agent guidance and the `IIS_Cert_Auto_Package` folder for helpers.