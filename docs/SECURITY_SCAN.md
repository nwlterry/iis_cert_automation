# Security scan — 2026-10-29

Scanner: `tools/static_scan.py` (iis-cert-static-scan 1.0.0).
Post-fix SARIF: [security-scan.sarif.json](security-scan.sarif.json).
Open regression hits after the fixes: **0**.

Tests for the .NET port: 13 passed on `net8.0`, 13 passed on `net10.0`.

## Findings

| ID | Severity | CWE | Where | What was wrong | Status |
|---|---|---|---|---|---|
| PS-001 | High | CWE-312 / CWE-77 | `Setup_CCS_and_Task.ps1` credential here-string | The PFX password was expanded into a script under `C:\Temp`. A quote in the password broke out of the string. | Fixed. DPAPI LocalMachine blob, ACL limited to SYSTEM and Administrators, script contains no password, blob deleted by the SYSTEM task. |
| PS-002 | Medium | CWE-532 | `Mask-SensitiveData` and setup log | First and last password characters were written to the log and the Application event log. | Fixed. Password values are not logged. |
| PS-003 | Medium | CWE-78 | Scheduled task `-Command` strings | Paths were interpolated into PowerShell and `cmd` command lines. | Fixed. Paths with quotes or shell metacharacters are rejected before use. |
| PS-004 | Medium | CWE-200 | Package scripts | Lab host names and UNC paths were hard-coded in a public repository. | Fixed. Values come from `config.example.json` / a local config file that is gitignored. |
| PS-005 | Medium | CWE-295 | `unc_connectivity_check_w_status.ps1` | `curl.exe -k` disabled TLS verification for the health check. | Fixed. `-k` is used only when `allowInsecureHealthCheck` is true. |
| PS-006 | Medium | CWE-829 | CredentialManager nupkg install | The air-gapped module was expanded with no integrity check. | Fixed. SHA256 `f520ddc58ab12e888bd9fb50d56ead511aa2b416df07ccef01800775f4501299` is required before install. The .NET port does not use this module. |
| PS-007 | Low | CWE-732 | Temp credential script ACL | `icacls /grant` added SYSTEM without removing inherited Users read. | Fixed. Inheritance is removed on the blob and the script. |
| PS-008 | Medium | CWE-522 | PFX verify | `X509KeyStorageFlags.DefaultKeySet` could persist the private key into a certificate store. | Fixed. `EphemeralKeySet`, and the .NET 10 build uses `X509CertificateLoader`. |
| PS-009 | Low | CWE-693 | Scheduled tasks | `ExecutionPolicy Bypass` was used for production tasks. | Fixed. Production tasks use `RemoteSigned`. |
| PS-010 | Low | — | `Runtime_QA_Check.ps1` | The registry probe used a doubled backslash, so it never read the CCS key. The SYSTEM probe also built a `cmd /c` command. | Fixed. |
| PS-011 | Info | — | `archive/` | Historical copies contained the old patterns and host names. | Disabled with `#requires -Version 99.0`. Host names redacted. Do not deploy. |

## Accepted

- LocalMachine DPAPI and a LocalMachine credential are readable by local administrators. That is the same trust boundary IIS already requires so SYSTEM can open the PFX.
- `C:\Logs` grants SYSTEM full control on purpose. The scheduled task runs as SYSTEM.
- The .NET health check can disable TLS validation only when the config flag is explicitly true, and it logs a warning.

## Not a secret

No live passwords, tokens, or private keys were in the tree. The vendored `credentialmanager.2.0.0.nupkg` is the public 2016 CredentialManager 2.0 module, pinned by hash.
