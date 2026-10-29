# PowerShell 5.1 vs legacy CMD

Legacy `cmd.exe` does not run these scripts. Calling `powershell.exe -File` from a batch file is still PowerShell.

The full table is the same one published with the .NET port: [nwlterry/iis_cert_automation-dotnet](https://github.com/nwlterry/iis_cert_automation-dotnet/blob/main/docs/POWERSHELL-VS-CMD.md).

| Script | Pure CMD? | Notes |
|---|---|---|
| `Export_Cert_CCS_Secure.ps1` | No | Needs the certificate store, Credential Manager, and the event log |
| `Setup_CCS_and_Task.ps1` | No | Needs the CCS registry, an event-triggered SYSTEM task, and DPAPI |
| `Runtime_QA_Check.ps1` | Partial | `reg.exe` and `appcmd.exe` cover checks, not the SYSTEM probe |
| `unc_connectivity_checker.ps1` | Partial | `net use` works; event IDs and log rotation do not |
| `unc_connectivity_check_w_status.ps1` | Partial | `iisreset.exe` and `curl.exe` are callable; orchestration is not a safe `.bat` |
| `drive_mapping.ps1` | Mostly | Use `drive_mapping.bat DRIVE UNC` |
| `drive_mapping.bat` | Yes | Only script that is already CMD. No password argument |
| `*_schedule_task.ps1` | Partial | `schtasks.exe` can register SYSTEM tasks with a fixed `/TR` |

Do not pass the PFX password on a CMD command line.
