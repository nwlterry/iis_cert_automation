# IIS Certificate Automation (CCS)

Export IIS certificates to a Centralized Certificate Store, configure the CCS registry, and register a SYSTEM scheduled task on renewal events.

Site names and UNC paths come from `IIS_Cert_Auto_Package/iis-cert-automation.config.json` (see `config.example.json`). Do not put the PFX password in that file or on a command line. Setup prompts for it and stores it for SYSTEM through a DPAPI blob.

```powershell
powershell -NoProfile -ExecutionPolicy RemoteSigned -File IIS_Cert_Auto_Package\Setup_CCS_and_Task.ps1 `
  -CcsPhysicalPath "\\fileserver.example\IIS_Cert_Store"
```

Copy `Security.Common.ps1` next to every script you schedule. `archive/` is historical and refuses to run (`#requires -Version 99.0`).

Legacy CMD cannot replace these scripts. The comparison is in [docs/POWERSHELL-VS-CMD.md](docs/POWERSHELL-VS-CMD.md). The .NET 8 and .NET 10 port is [iis_cert_automation-dotnet](https://github.com/nwlterry/iis_cert_automation-dotnet).

Security review: [docs/SECURITY_SCAN.md](docs/SECURITY_SCAN.md).

Architecture diagrams: [eraser_project](https://github.com/nwlterry/eraser_project).

See [GROUP.md](GROUP.md) for sibling repositories. Catalog: https://github.com/nwlterry/nwlterry
