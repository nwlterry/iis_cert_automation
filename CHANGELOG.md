# Changelog

## [Unreleased]
- Security review: PFX password is no longer written into a generated script or the event log
- Scheduled-task paths are rejected when they contain shell metacharacters
- PFX verification uses an ephemeral key set
- CredentialManager nupkg install is SHA256-pinned
- Host names and UNC paths moved to `config.example.json`
- `archive/` scripts are disabled
- Execution policy on production tasks is RemoteSigned

## [Previous]
- Major repository restructure: src/, tools/, docs/, archive/
- Professional README with badges and usage examples
- Added LICENSE and .gitignore
- Archived old versioned scripts
