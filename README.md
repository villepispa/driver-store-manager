# Driver Store Manager

PowerShell module to **inventory**, **assess**, and **safely remove** third-party driver
packages in the Windows Driver Store using built-in tools.

## Quick start

```powershell
# From this directory (PowerShell 7+)
Import-Module .\src\DriverStoreManager\DriverStoreManager.psd1 -Force

# Inventory (no admin required on most systems)
Get-DsmDriverStoreInventory |
    Format-Table PublishedName, DriverClass, DeviceAssociation, DriverVersion

# Filter OEM scope + preserve policy
$inv = Get-DsmDriverStoreInventory
Invoke-DsmPreservePolicy -Inventory $inv -PreserveRulesPath .\data\preserve-rules.example.json

# Printer drivers (disconnected installed bucket)
$f = New-DsmDriverFilter -DriverClass 'Printer' -Association DisconnectedInstalled
Invoke-DsmDriverFilter -Inventory $inv -Filter $f

# Full audit report (Microsoft blocklist auto-refreshes; optional supplemental file)
.\scripts\Invoke-DsmDriverStoreAudit.ps1 -OutputPath .\audit-output `
    -PreserveRulesPath .\data\preserve-rules.example.json `
    -BlocklistPath .\data\blocklist-hashes.example.txt

# Refresh Microsoft blocklist cache manually
Update-DsmMicrosoftDriverBlocklist -Force
# or: .\scripts\Update-DsmMicrosoftDriverBlocklist.ps1 -Force

# Scan only (Microsoft cache + optional supplemental)
Test-DsmDriverVulnerabilities -Inventory (Get-DsmDriverStoreInventory)

## Testing

```powershell
# Unit + integration (PowerShell 7+; Pester 6 recommended)
.\tests\Invoke-DsmPester.ps1
# Or directly (Pester 6 configuration object):
# $c = New-PesterConfiguration; $c.Run.Path = '.\tests'; Invoke-Pester -Configuration $c

# Windows PowerShell 5.1 smoke (no live pnputil)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-DsmPs51SmokeTest.ps1
```

```powershell
Remove-DsmUnusedDriverPackages -PreserveRulesPath .\data\preserve-rules.example.json -WhatIf -PassThru

# Audit with cleanup preview JSON
.\scripts\Invoke-DsmDriverStoreAudit.ps1 -OutputPath .\audit-output -IncludeCleanupPreview

# DiskId catalog (all OEM drivers — JSON + CSV)
.\scripts\Export-DsmDriverDiskIdCatalog.ps1 -OutputPath .\audit-output
# Or combined with audit:
.\scripts\Invoke-DsmDriverStoreAudit.ps1 -OutputPath .\audit-output -IncludeCleanupPreview -ExportDiskIdCatalog
```

## Requirements

- Windows 10 22H2+ or Windows 11 (modern `pnputil` with `/format csv`)
- **PowerShell 5.1+** (module, Intune bundles) — **PowerShell 7+** recommended for dev/audit
- **Administrator** for `Remove-DsmUnusedDriverPackages` (deletion and export to protected paths)

## Module commands

| Command | Phase | Description |
|---------|-------|-------------|
| `Get-DsmDriverStoreInventory` | 3a | Enumerate packages; HWIDs + association buckets |
| `New-DsmDriverFilter` | 3b | Build filter object (wildcards, association) |
| `Invoke-DsmDriverFilter` | 3b | OEM-default scope + filter; returns counts/manifest |
| `New-DsmPreserveRule` | 3c | Build preserve rule objects |
| `Invoke-DsmPreservePolicy` | 3c | Apply rules; set Preserved on packages |
| `Get-DsmDriverStoreReport` | 3d | Global + scoped counts, listings, JSON/Markdown export |
| `Update-DsmMicrosoftDriverBlocklist` | 4 | Download/cache Microsoft vulnerable driver hashes |
| `Test-DsmDriverVulnerabilities` | 4 | Blocklist (auto + supplemental), Authenticode, orphan |
| `Remove-DsmUnusedDriverPackages` | 5 | Filter + preserve aware cleanup; export backup; `-PassThru` summary |

Build **Intune Proactive Remediation** scripts (PS 5.1, SYSTEM):

```powershell
.\scripts\Build-DsmIntuneScripts.ps1
# → dist/intune/Detect-DsmDriverStoreCompliance.ps1
# → dist/intune/Remediate-DsmDriverStore.ps1
```

## Documentation

- [CHANGELOG.md](CHANGELOG.md)
- [docs/issues.md](docs/issues.md)
- [architecture.md](docs/architecture.md)
- [commands-reference.md](docs/commands-reference.md)
- [safety-gates.md](docs/safety-gates.md)
- [intune-deployment.md](docs/intune-deployment.md)
- [lessons-learned.md](docs/lessons-learned.md)

## Output paths

`audit-output/`, `backups/`, and `docs/archive/` are gitignored. Keep large
`pnputil /export-driver` trees on a fast local disk; avoid syncing multi-GB exports
through cloud clients (for example Proton Drive). `docs/archive/` holds absorbed
session exports for local provenance only — living summary is
[lessons-learned.md § 1.1](docs/lessons-learned.md#11-v01-scaffold-session-2026-06-15).

## Origin

Scaffolded from a private Windows security workspace plan (2026-06-15). See
[CHANGELOG.md](CHANGELOG.md) `[0.1.0]` and
[lessons-learned.md § 1.1](docs/lessons-learned.md#11-v01-scaffold-session-2026-06-15).
