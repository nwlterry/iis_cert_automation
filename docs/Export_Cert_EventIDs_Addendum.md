## Additional Event Sources (addendum)

This addendum lists additional Event Log sources and quick mappings discovered in the codebase that complement `Export_Cert_EventIDs.md`.

- `CertificateExportScript` — observed in `Export_Cert_CCS.ps1` and some script variants. It overlaps functionally with `CertificateExport` in several scripts. Monitor both names or consider unifying to a single canonical source.

- `UNC-Connectivity-Checker` — source used by `IIS_Cert_Auto_Package/UNC-Connectivity-Checker.ps1`. Key event IDs:
  - `1000` : UNC path accessible (Information)
  - `1001` : UNC path not accessible — attempting reconnect (Warning)
  - `1002` : Disconnected existing sessions to the server (Information)
  - `1003` : Reconnected (Information)
  - `1004` : Reconnect verified success (Information)
  - `1005` : Deleted old log during rotation (Information)
  - `2001` : Error disconnecting existing sessions (Error)
  - `2002` : Reconnect failed (Error)
  - `2003` : Error reconnecting (Error)

- `Runtime QA` — `IIS_Cert_Auto_Package/Runtime_QA_Check.ps1` performs temporary event-write tests. It writes a unique marker to validate that an event source is writable and that events are readable from the `Application` log.

Files that create or register event sources:
- `IIS_Cert_Auto_Package/Export_Cert_CCS_Secure.ps1` and `Export_Cert_CCS.ps1` call `New-EventLog` to register `CertificateExport` / `CertificateExportScript` sources.
- `IIS_Cert_Auto_Package/UNC-Connectivity-Checker.ps1` writes using `[System.Diagnostics.EventLog]::WriteEntry` under `UNC-Connectivity-Checker`.

Recommendation
- Use `Export_Cert_EventIDs.md` as the canonical mapping for certificate-export events. Add this addendum's `UNC-Connectivity-Checker` mappings into monitoring dashboards.
- Optionally consolidate `CertificateExport` and `CertificateExportScript` into one event source to simplify alerts and dashboards.
