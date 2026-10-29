# PowerShell 5.1 vs legacy CMD vs .NET

Legacy `cmd.exe` does not run these scripts. A batch file that calls `powershell.exe -File` is still PowerShell. Do not pass the PFX password on a CMD command line.

The same table is published with the .NET port.

| Script | What it does | Pure `cmd.exe` | Why CMD is not enough | .NET 8 / .NET 10 command |
|---|---|---|---|---|
| `Export_Cert_CCS_Secure.ps1` | Export LocalMachine certs whose CN is in the config to CCS PFX files. Password from Credential Manager. Ephemeral verify. Keep 3 backups. | No | No certificate store, no `Get-StoredCredential`, no `X509Certificate2`, no Application event source | `export --config <file>` |
| `Setup_CCS_and_Task.ps1` | CCS registry, DPAPI blob, SYSTEM credential task, event ID 1001 plus startup task, hash-pinned nupkg | No | No DPAPI, no Credential Manager module, no event-trigger XML, no `Install-WindowsFeature` | `setup --ccs <unc> --config <file>` |
| `Setup_CCS_Node.ps1` | Confirm CCS registry on another node, IIS Manager, delete Username and Password values | No | `reg.exe` can delete values, but the script also checks Web-CertProvider and the WebAdministration cmdlet | `setup-node --ccs <unc>` |
| `credentialmanager.2.0.0.nupkg` | PowerShell module, SHA256 pinned | No | CMD cannot import a PowerShell module. The .NET port calls CredWrite and does not install this package | not used |
| `drive_mapping.ps1` | Test the mapped path, reconnect the UNC with the computer account, 14-day log rotation, event log | Mostly | `net use` maps a drive. It does not write event IDs or rotate `UNC_Check_*.log` | `map-drive --config <file>` |
| `drive_mapping_schedule_task.ps1` | SYSTEM task at startup | Partial | `schtasks /Create /RU SYSTEM /SC ONSTART` can register a fixed command. It cannot build the repetition object the checker uses | `register-share-tasks --config <file>` |
| `unc_connectivity_checker_w_status.ps1` | Remap, then up to 10 `iisreset` attempts and an HTTPS health check. TLS verify stays on unless the config flag is set | Partial | `iisreset.exe` and `curl.exe` exist. The retry, event IDs, and config guard are not a safe `.bat` | `unc-check --config <file>` |
| `unc_checker_schedule_task.ps1` | SYSTEM task at startup and every hour. Runs the status checker, not the removed checker | Partial | `schtasks` can do `/SC HOURLY`, but not the startup-plus-hourly trigger this script registers | `register-share-tasks --config <file>` |
| `Security.Common.ps1` | Path allow-list, config password rejection, nupkg pin, ephemeral key flag, tight ACL | No | CMD has no equivalent guard used by every script above | `PathGuard`, `AppConfig` |
| `drive_mapping.bat` | Optional one-shot `net use` | Yes | This is the only file that is already CMD. It takes a drive letter and a UNC path. No password argument | `map-drive` |

`Runtime_QA_Check.ps1` is not part of the deployed set. `reg query` covers the registry line only.
