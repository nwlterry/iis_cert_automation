# Certificate Export Script Event ID Information

This document lists all Event IDs defined in the `Export_Cert_CCS_Secure_Define.ps1` script, along with their associated log levels and event information. These events are logged to both a file (`C:\Logs\CertificateExport_<timestamp>.log`) and the Windows Event Log (Application log, source: `CertificateExport`). The Event IDs are aligned with the `Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational` log, starting from 1001.

| Event ID | Log Level | Event Information |
|----------|-----------|-------------------|
| 1001     | INFO      | Write access test to the CCS path succeeded with a binary file. |
| 1002     | ERROR     | Write access test to the CCS path failed: Binary file not created. |
| 1003     | ERROR     | Failed to test write access to the CCS path with a binary file. |
| 1004     | INFO      | Network connectivity test to the file server succeeded. |
| 1005     | WARNING   | Network connectivity test to the file server failed. |
| 1005     | INFO      | Deleted older backup file during PFX backup management. |
| 1006     | WARNING   | Failed to delete older backup file during PFX backup management. |
| 1006     | ERROR     | Failed to test network connectivity to the file server. |
| 1007     | INFO      | Created log directory for file-based logging. |
| 1007     | ERROR     | Failed to manage backups for a certificate's CN during PFX backup management. |
| 1008     | ERROR     | Failed to create log directory for file-based logging. |
| 1008     | ERROR     | Failed to sanitize filename during PFX file naming. |
| 1009     | INFO      | Created temporary directory for fallback PFX writes. |
| 1010     | ERROR     | Failed to create temporary directory for fallback PFX writes. |
| 1011     | ERROR     | CredentialManager module not found. |
| 1012     | INFO      | Successfully imported CredentialManager module. |
| 1013     | ERROR     | Failed to import CredentialManager module. |
| 1014     | ERROR     | No credential found for PFXCertPassword in Credential Manager. |
| 1015     | ERROR     | Retrieved PFX password is empty or null. |
| 1016     | INFO      | Successfully retrieved PFX password from Credential Manager (masked). |
| 1017     | ERROR     | Failed to retrieve PFX password from Credential Manager. |
| 1018     | ERROR     | CCS is not enabled in the registry. |
| 1019     | INFO      | CCS registry key found with physical path and export path details. |
| 1020     | ERROR     | CCS registry key not found. |
| 1021     | INFO      | Created output directory for PFX files. |
| 1022     | ERROR     | Failed to create output directory for PFX files. |
| 1023     | ERROR     | CCS path is not accessible. |
| 1024     | INFO      | CCS path is accessible. |
| 1025     | ERROR     | Error accessing CCS path. |
| 1026     | ERROR     | Output directory is not accessible. |
| 1027     | INFO      | Output directory is accessible. |
| 1028     | ERROR     | Insufficient write access to the output directory. |
| 1029     | WARNING   | Network connectivity to the file server is unreliable, proceeding with caution. |
| 1030     | ERROR     | Error accessing output directory. |
| 1031     | INFO      | Using defined SNI hostname(s). |
| 1032     | INFO      | Using defined node hostname(s). |
| 1033     | WARNING   | No certificates found in local computer store (Cert:\LocalMachine\My). |
| 1034     | INFO      | Found certificates in local computer store with their subjects. |
| 1035     | ERROR     | Failed to retrieve certificates from local computer store. |
| 1036     | INFO      | Certificate does not match any defined SNI hostname, skipping. |
| 1037     | WARNING   | Failed to extract Common Name for a certificate, skipping. |
| 1038     | WARNING   | No certificates in local store match defined SNI hostname(s). |
| 1039     | INFO      | Certificates to export (matching SNI) with their subjects. |
| 1040     | WARNING   | Certificate does not have a private key. |
| 1041     | WARNING   | Certificate private key is not exportable. |
| 1042     | WARNING   | Failed to extract Common Name for a certificate, skipping export. |
| 1043     | INFO      | Backed up existing certificate to a backup file. |
| 1044     | ERROR     | Failed to back up existing certificate to a backup file. |
| 1045     | INFO      | Attempting to export certificate to PFX for SNI or node hostname. |
| 1046     | INFO      | Successfully generated PFX bytes for a certificate. |
| 1047     | ERROR     | Failed to export certificate to PFX (possible private key issue or corruption). |
| 1048     | INFO      | Attempting to write PFX file to the output path. |
| 1049     | INFO      | Successfully exported certificate to PFX file. |
| 1050     | WARNING   | Failed to write PFX file to the output path with HRESULT details. |
| 1051     | ERROR     | All attempts to write PFX file to the output path failed. |
| 1052     | INFO      | Attempting fallback write to the temporary path. |
| 1053     | INFO      | Successfully wrote PFX file to the temporary path (fallback). |
| 1054     | INFO      | Verified fallback PFX file. |
| 1055     | INFO      | Successfully copied fallback PFX file to the output path. |
| 1056     | ERROR     | Failed to copy fallback PFX file to the output path. |
| 1057     | ERROR     | Failed to verify fallback PFX file. |
| 1058     | ERROR     | Fallback write to the temporary path failed. |
| 1059     | ERROR     | Failed to process export for a certificate for SNI or node hostname. |
| 1060     | INFO      | Verified exported PFX file. |
| 1061     | ERROR     | Failed to verify exported PFX file. |
| 1062     | ERROR     | Failed to process certificate for SNI hostname. |
| 1063     | ERROR     | Failed to process certificate. |
| 1064     | WARNING   | No certificates were successfully exported. |
| 1065     | INFO      | Certificate export completed successfully with the number of certificates exported. |
| 1066     | ERROR     | Error during certificate export (overall script failure). |
| 1067     | INFO      | Deleted older log file during log file housekeeping. |
| 1068     | WARNING   | Failed to delete older log file during log file housekeeping. |
| 1069     | ERROR     | Failed to manage log files during housekeeping. |
| 1070     | ERROR     | Certificate has expired. |
| 1071     | WARNING   | Certificate is nearing expiration within the warning period. |
| 1072     | INFO      | Certificate is valid with expiration date. |
| 1073     | WARNING   | Certificate has chain status issues. |
| 1074     | INFO      | Certificate has a valid chain. |
| 1075     | ERROR     | Failed to verify certificate chain. |
| 1076     | ERROR     | Failed to monitor certificate. |

## Notes
- **Event ID Range**: The Event IDs range from 1001 to 1076, aligned with the `Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational` log's context, starting from 1001 to reflect certificate lifecycle events.
- **Log Levels**: Events are categorized as `INFO`, `WARNING`, or `ERROR`, indicating the severity of the action or issue.
- **Event Information**: Each event describes specific actions or issues, such as directory creation, certificate monitoring, export processes, backup management, log file housekeeping, and error conditions.
- **Logging Destinations**: All events are logged to both the file at `C:\Logs\CertificateExport_<timestamp>.log` and the Windows Event Log (Application log, source: `CertificateExport`).
- **Housekeeping**: Events 1067–1069 manage the retention of `CertificateExport_*.log` files, keeping only the latest 5 files (configurable via `$maxLogFiles`).
- **Certificate Monitoring**: Events 1070–1076 cover certificate expiration and validity checks, providing status details for each certificate in the store.

---

## Additional Event Sources (quick reference)

- `CertificateExportScript` — observed in `Export_Cert_CCS.ps1` and several root/variant scripts. This source overlaps functionally with `CertificateExport` in places; monitoring should include both names or the scripts should be unified to a single canonical source.

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

- `Runtime QA` (temporary test writes) — `IIS_Cert_Auto_Package/Runtime_QA_Check.ps1` can write temporary test events under provided source names (used to validate event-write permissions). The script writes a unique marker and reads recent events to confirm visibility.

References:
- `IIS_Cert_Auto_Package/Export_Cert_CCS_Secure.ps1` and `Export_Cert_CCS.ps1` — event-source creation (`New-EventLog`) and many Event IDs enumerated above.
- `IIS_Cert_Auto_Package/UNC-Connectivity-Checker.ps1` — UNC/connectivity Event IDs and `UNC-Connectivity-Checker` source.

Recommendation: for monitoring and alerting, prefer the canonical mapping in this document (`Export_Cert_EventIDs.md`) for certificate-export events and add `UNC-Connectivity-Checker` mappings to any connectivity dashboards. Consider consolidating export script sources (`CertificateExport` vs `CertificateExportScript`) to simplify event collection.
# Certificate Export Script Event ID Information

This document lists all Event IDs defined in the `Export_Cert_CCS_Secure_Define.ps1` script, along with their associated log levels and event information. These events are logged to both a file (`C:\Logs\CertificateExport_<timestamp>.log`) and the Windows Event Log (Application log, source: `CertificateExport`). The Event IDs are aligned with the `Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational` log, starting from 1001.

| Event ID | Log Level | Event Information |
|----------|-----------|-------------------|
| 1001     | INFO      | Write access test to the CCS path succeeded with a binary file. |
| 1002     | ERROR     | Write access test to the CCS path failed: Binary file not created. |
| 1003     | ERROR     | Failed to test write access to the CCS path with a binary file. |
| 1004     | INFO      | Network connectivity test to the file server succeeded. |
| 1005     | WARNING   | Network connectivity test to the file server failed. |
| 1005     | INFO      | Deleted older backup file during PFX backup management. |
| 1006     | WARNING   | Failed to delete older backup file during PFX backup management. |
| 1006     | ERROR     | Failed to test network connectivity to the file server. |
| 1007     | INFO      | Created log directory for file-based logging. |
| 1007     | ERROR     | Failed to manage backups for a certificate's CN during PFX backup management. |
| 1008     | ERROR     | Failed to create log directory for file-based logging. |
| 1008     | ERROR     | Failed to sanitize filename during PFX file naming. |
| 1009     | INFO      | Created temporary directory for fallback PFX writes. |
| 1010     | ERROR     | Failed to create temporary directory for fallback PFX writes. |
| 1011     | ERROR     | CredentialManager module not found. |
| 1012     | INFO      | Successfully imported CredentialManager module. |
| 1013     | ERROR     | Failed to import CredentialManager module. |
| 1014     | ERROR     | No credential found for PFXCertPassword in Credential Manager. |
| 1015     | ERROR     | Retrieved PFX password is empty or null. |
| 1016     | INFO      | Successfully retrieved PFX password from Credential Manager (masked). |
| 1017     | ERROR     | Failed to retrieve PFX password from Credential Manager. |
| 1018     | ERROR     | CCS is not enabled in the registry. |
| 1019     | INFO      | CCS registry key found with physical path and export path details. |
| 1020     | ERROR     | CCS registry key not found. |
| 1021     | INFO      | Created output directory for PFX files. |
| 1022     | ERROR     | Failed to create output directory for PFX files. |
| 1023     | ERROR     | CCS path is not accessible. |
| 1024     | INFO      | CCS path is accessible. |
| 1025     | ERROR     | Error accessing CCS path. |
| 1026     | ERROR     | Output directory is not accessible. |
| 1027     | INFO      | Output directory is accessible. |
| 1028     | ERROR     | Insufficient write access to the output directory. |
| 1029     | WARNING   | Network connectivity to the file server is unreliable, proceeding with caution. |
| 1030     | ERROR     | Error accessing output directory. |
| 1031     | INFO      | Using defined SNI hostname(s). |
| 1032     | INFO      | Using defined node hostname(s). |
| 1033     | WARNING   | No certificates found in local computer store (Cert:\LocalMachine\My). |
| 1034     | INFO      | Found certificates in local computer store with their subjects. |
| 1035     | ERROR     | Failed to retrieve certificates from local computer store. |
| 1036     | INFO      | Certificate does not match any defined SNI hostname, skipping. |
| 1037     | WARNING   | Failed to extract Common Name for a certificate, skipping. |
| 1038     | WARNING   | No certificates in local store match defined SNI hostname(s). |
| 1039     | INFO      | Certificates to export (matching SNI) with their subjects. |
| 1040     | WARNING   | Certificate does not have a private key. |
| 1041     | WARNING   | Certificate private key is not exportable. |
| 1042     | WARNING   | Failed to extract Common Name for a certificate, skipping export. |
| 1043     | INFO      | Backed up existing certificate to a backup file. |
| 1044     | ERROR     | Failed to back up existing certificate to a backup file. |
| 1045     | INFO      | Attempting to export certificate to PFX for SNI or node hostname. |
| 1046     | INFO      | Successfully generated PFX bytes for a certificate. |
| 1047     | ERROR     | Failed to export certificate to PFX (possible private key issue or corruption). |
| 1048     | INFO      | Attempting to write PFX file to the output path. |
| 1049     | INFO      | Successfully exported certificate to PFX file. |
| 1050     | WARNING   | Failed to write PFX file to the output path with HRESULT details. |
| 1051     | ERROR     | All attempts to write PFX file to the output path failed. |
| 1052     | INFO      | Attempting fallback write to the temporary path. |
| 1053     | INFO      | Successfully wrote PFX file to the temporary path (fallback). |
| 1054     | INFO      | Verified fallback PFX file. |
| 1055     | INFO      | Successfully copied fallback PFX file to the output path. |
| 1056     | ERROR     | Failed to copy fallback PFX file to the output path. |
| 1057     | ERROR     | Failed to verify fallback PFX file. |
| 1058     | ERROR     | Fallback write to the temporary path failed. |
| 1059     | ERROR     | Failed to process export for a certificate for SNI or node hostname. |
| 1060     | INFO      | Verified exported PFX file. |
| 1061     | ERROR     | Failed to verify exported PFX file. |
| 1062     | ERROR     | Failed to process certificate for SNI hostname. |
| 1063     | ERROR     | Failed to process certificate. |
| 1064     | WARNING   | No certificates were successfully exported. |
| 1065     | INFO      | Certificate export completed successfully with the number of certificates exported. |
| 1066     | ERROR     | Error during certificate export (overall script failure). |
| 1067     | INFO      | Deleted older log file during log file housekeeping. |
| 1068     | WARNING   | Failed to delete older log file during log file housekeeping. |
| 1069     | ERROR     | Failed to manage log files during housekeeping. |
| 1070     | ERROR     | Certificate has expired. |
| 1071     | WARNING   | Certificate is nearing expiration within the warning period. |
| 1072     | INFO      | Certificate is valid with expiration date. |
| 1073     | WARNING   | Certificate has chain status issues. |
| 1074     | INFO      | Certificate has a valid chain. |
| 1075     | ERROR     | Failed to verify certificate chain. |
| 1076     | ERROR     | Failed to monitor certificate. |

## Notes
- **Event ID Range**: The Event IDs range from 1001 to 1076, aligned with the `Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational` log's context, starting from 1001 to reflect certificate lifecycle events.
- **Log Levels**: Events are categorized as `INFO`, `WARNING`, or `ERROR`, indicating the severity of the action or issue.
- **Event Information**: Each event describes specific actions or issues, such as directory creation, certificate monitoring, export processes, backup management, log file housekeeping, and error conditions.
- **Logging Destinations**: All events are logged to both the file at `C:\Logs\CertificateExport_<timestamp>.log` and the Windows Event Log (Application log, source: `CertificateExport`).
- **Housekeeping**: Events 1067–1069 manage the retention of `CertificateExport_*.log` files, keeping only the latest 5 files (configurable via `$maxLogFiles`).
- **Certificate Monitoring**: Events 1070–1076 cover certificate expiration and validity checks, providing status details for each certificate in the store.
