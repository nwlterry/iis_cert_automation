# IIS Certificate Automation (CCS)

Export IIS certificates to a Centralized Certificate Store, configure IIS Central Certificate Provider, and register a SYSTEM scheduled task on renewal events.

## Layout

```
src/                         # production scripts
tools/                       # Runtime QA
docs/                        # event IDs and plan
IIS_Cert_Auto_Package/       # packaged drop
archive/                     # older script versions from repo root
CHANGELOG.md
LICENSE
GROUP.md
README.md
```

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File src/Setup-CCS-and-Task.ps1 `
  -CcsPhysicalPath "\\file-server\\IIS_Cert_Store" `
  -PfxPassword (Read-Host -AsSecureString "PFX Password")
```

Architecture diagrams: [eraser_project](https://github.com/nwlterry/eraser_project).

---

See [GROUP.md](GROUP.md) for sibling repositories. Catalog: https://github.com/nwlterry/nwlterry
