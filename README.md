# IIS Certificate Automation (CCS)

Two packages that are actually deployed. Everything else in this repository is a helper or history.

Site names and UNC paths come from `IIS_Cert_Auto_Package/iis-cert-automation.config.json` (copy `config.example.json`). Do not put the PFX password in that file or on a command line.

## 1. IIS CCS setup

| File | Role |
|---|---|
| `Export_Cert_CCS_Secure.ps1` | Export matching LocalMachine certificates to the CCS share as PFX. Password comes from Credential Manager target `PFXCertPassword`. |
| `Setup_CCS_and_Task.ps1` | Enable the CCS registry key, store the PFX password for SYSTEM, register the renewal task. |
| `Setup_CCS_Node.ps1` | On an extra IIS node: confirm the CCS path, open IIS Manager, remove the Username and Password registry values. No password is stored here. |
| `credentialmanager.2.0.0.nupkg` | Air-gapped CredentialManager 2.0 module. SHA256 `f520ddc58ab12e888bd9fb50d56ead511aa2b416df07ccef01800775f4501299`. |

```powershell
powershell -NoProfile -ExecutionPolicy RemoteSigned -File IIS_Cert_Auto_Package\Setup_CCS_and_Task.ps1 `
  -CcsPhysicalPath "\\fileserver.example\IIS_Cert_Store"
```

`Security.Common.ps1` must sit next to the scripts. It is not optional: the scripts above refuse to run without it.

## 2. File share for multi-node ACME-ADCS IIS

| File | Role |
|---|---|
| `drive_mapping.ps1` | If the mapped test path is down, drop the drive and map the configured UNC as the computer account. |
| `drive_mapping_schedule_task.ps1` | SYSTEM task, at startup. |
| `unc_connectivity_checker_w_status.ps1` | Remap if needed, then `iisreset` with an HTTPS health check. |
| `unc_checker_schedule_task.ps1` | SYSTEM task, at startup and hourly. It runs `unc_connectivity_checker_w_status.ps1`. |

Copy those scripts, `Security.Common.ps1`, and the config file to `C:\Scripts` before registering the tasks.

## Not part of the deployed set

`Runtime_QA_Check.ps1` is an optional probe. `drive_mapping.bat` is the only pure CMD helper and does not replace the scripts. `archive/` is historical and refuses to run (`#requires -Version 99.0`).

Legacy CMD cannot replace the deployed scripts. The full comparison is in [docs/POWERSHELL-VS-CMD.md](docs/POWERSHELL-VS-CMD.md).

The .NET 8 and .NET 10 port is [iis_cert_automation-dotnet](https://github.com/nwlterry/iis_cert_automation-dotnet). Prefer `net10.0`.

Security review: [docs/SECURITY_SCAN.md](docs/SECURITY_SCAN.md).

Architecture diagrams: [eraser_project](https://github.com/nwlterry/eraser_project).

See [GROUP.md](GROUP.md) for sibling repositories. Catalog: https://github.com/nwlterry/nwlterry
