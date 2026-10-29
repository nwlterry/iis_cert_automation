# Changelog

## [Unreleased]
- Reviewed the deployed set only: CCS export/setup/node plus the four file-share scripts
- Removed the lab host name from `Setup_CCS_Node.ps1` and validated the CCS path
- UNC checker task now runs `unc_connectivity_checker_w_status.ps1` as SYSTEM (`UserId`, not `GroupId`)
- UNC status checker writes `UNC_Check_*.log`. Rotation no longer deletes certificate-export logs
- Credential-access probe script uses the same tight ACL as the password blob

## [Previous]
- Security review: PFX password is no longer written into a generated script or the event log
- Scheduled-task paths are rejected when they contain shell metacharacters
- PFX verification uses an ephemeral key set
- CredentialManager nupkg install is SHA256-pinned
- Host names and UNC paths moved to `config.example.json`
- `archive/` scripts are disabled
- Execution policy on production tasks is RemoteSigned
