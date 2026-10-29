# Security scan — 2026-10-29 (in-use scripts)

Scope is the deployed set only:

- CCS: `Export_Cert_CCS_Secure.ps1`, `Setup_CCS_Node.ps1`, `Setup_CCS_and_Task.ps1`, `credentialmanager.2.0.0.nupkg`
- File share: `drive_mapping.ps1`, `drive_mapping_schedule_task.ps1`, `unc_checker_schedule_task.ps1`, `unc_connectivity_checker_w_status.ps1`
- Companion required by those scripts: `Security.Common.ps1`, `config.example.json`

Scanner: `tools/static_scan.py` (iis-cert-static-scan 1.0.0).
Post-fix SARIF: [security-scan.sarif.json](security-scan.sarif.json).
`archive/` is skipped by the scanner and is not deployed.

Open regression hits after the fixes: **0**.

## Findings

| ID | Severity | CWE | Where | What was wrong | Status |
|---|---|---|---|---|---|
| PS-001 | High | CWE-312 / CWE-77 | `Setup_CCS_and_Task.ps1` credential here-string | The PFX password was expanded into a script under `C:\Temp`. A quote in the password broke out of the string. | Fixed. DPAPI LocalMachine blob, ACL limited to SYSTEM and Administrators, script contains no password, blob deleted by the SYSTEM task. |
| PS-002 | Medium | CWE-532 | Export log | First and last password characters were written to the log and the Application event log. | Fixed. Password values are not logged. |
| PS-003 | Medium | CWE-78 | Scheduled task `-Command` strings | Paths were interpolated into PowerShell command lines. | Fixed. Paths with quotes or shell metacharacters are rejected before use. |
| PS-004 | Medium | CWE-200 | Package scripts | Lab host names and UNC paths were hard-coded. | Fixed. Values come from a gitignored config file. |
| PS-005 | Medium | CWE-295 | UNC status checker | `curl.exe -k` disabled TLS verification for the health check. | Fixed. `-k` is used only when `allowInsecureHealthCheck` is true. |
| PS-006 | Medium | CWE-829 | CredentialManager nupkg install | The air-gapped module was expanded with no integrity check. | Fixed. SHA256 `f520ddc58ab12e888bd9fb50d56ead511aa2b416df07ccef01800775f4501299` is required before install. The .NET port does not use this module. |
| PS-007 | Low | CWE-732 | Temp credential script ACL | `icacls /grant` added SYSTEM without removing inherited Users read. | Fixed. Inheritance is removed on the blob and on both generated scripts. |
| PS-008 | Medium | CWE-522 | PFX verify | `X509KeyStorageFlags.DefaultKeySet` could persist the private key. | Fixed. `EphemeralKeySet`. The .NET 10 build uses `X509CertificateLoader`. |
| PS-009 | Low | CWE-693 | Scheduled tasks | `ExecutionPolicy Bypass` was used for production tasks. | Fixed. Production tasks use `RemoteSigned`. |
| PS-012 | Medium | CWE-200 | `Setup_CCS_Node.ps1` comment | A lab FQDN and share name were committed after the earlier redaction. | Fixed. The comment uses `fileserver.example`. |
| PS-013 | Medium | CWE-693 | `unc_checker_schedule_task.ps1` | The task still started the removed `unc_connectivity_checker.ps1`, and SYSTEM was passed as `-GroupId`. | Fixed. It starts `unc_connectivity_checker_w_status.ps1` as `-UserId` SYSTEM with `ServiceAccount`. |
| PS-014 | Low | CWE-778 | `unc_connectivity_checker_w_status.ps1` | `$logFile` was never set, so the health-check file log could not be written. | Fixed. |
| PS-015 | Low | CWE-778 | Drive map and UNC checker | Rotation deleted every `*.log` under the log folder, including certificate-export audit logs. | Fixed. Only `UNC_Check_*.log` is removed. |
| PS-016 | Low | CWE-20 | `Setup_CCS_Node.ps1` | `CcsPhysicalPath` was not checked by `Assert-SafeTaskPath`. | Fixed. |
| PS-011 | Info | — | `archive/` | Historical copies contained the old patterns. | Disabled with `#requires -Version 99.0`. Do not deploy. |

## Accepted

- LocalMachine DPAPI and a LocalMachine credential are readable by local administrators. That is the same trust boundary IIS already requires so SYSTEM can open the PFX.
- `C:\Logs` grants SYSTEM full control on purpose. The scheduled tasks run as SYSTEM.
- The health check can disable TLS validation only when the config flag is explicitly true, and it logs a warning.

## Not a secret

No live passwords, tokens, or private keys were in the tree. The vendored `credentialmanager.2.0.0.nupkg` is the public 2016 CredentialManager 2.0 module, pinned by hash.
