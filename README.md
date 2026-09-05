# Driver Store Manager

PowerShell module to **inventory**, **assess**, and **safely remove** third-party driver
packages in the Windows Driver Store using built-in tools. Includes **Microsoft Intune**
Proactive Remediation detect/remediate bundles (Windows PowerShell 5.1 / SYSTEM).

## Quick start

```powershell
# From this directory (PowerShell 7+)
Import-Module .\src\DriverStoreManager\DriverStoreManager.psd1 -Force

# Inventory (no admin required on most systems)
Get-DsmDriverStoreInventory |
    Format-Table PublishedName, DriverClass, DeviceAssociation, DriverVersion

# Filter OEM scope + preserve policy
$inv = Get-DsmDriverStoreInventory
Invoke-DsmPreservePolicy -Inventory $inv -PreserveRulesPath .\examples\preserve-rules.example.json

# Printer drivers (disconnected installed bucket)
$f = New-DsmDriverFilter -DriverClass 'Printer' -Association DisconnectedInstalled
Invoke-DsmDriverFilter -Inventory $inv -Filter $f

# Full audit report (Microsoft blocklist auto-refreshes; optional supplemental file)
.\scripts\Invoke-DsmDriverStoreAudit.ps1 -OutputPath .\audit-output `
    -PreserveRulesPath .\examples\preserve-rules.example.json `
    -BlocklistPath .\examples\blocklist-hashes.example.txt

# Refresh Microsoft blocklist cache manually
Update-DsmMicrosoftDriverBlocklist -Force
# or: .\scripts\Update-DsmMicrosoftDriverBlocklist.ps1 -Force

# Scan only (Microsoft cache + optional supplemental)
Test-DsmDriverVulnerabilities -Inventory (Get-DsmDriverStoreInventory)
```

Cleanup preview (module API — safer than running the Intune remediate bundle):

```powershell
Remove-DsmUnusedDriverPackages -PreserveRulesPath .\examples\preserve-rules.example.json -WhatIf -PassThru

# Audit with cleanup preview JSON
.\scripts\Invoke-DsmDriverStoreAudit.ps1 -OutputPath .\audit-output -IncludeCleanupPreview

# Repeatable run profile (loaded only when -SettingsPath is passed)
.\scripts\Invoke-DsmDriverStoreAudit.ps1 -SettingsPath .\examples\dsm.settings.example.json `
    -ShowEffectiveSettings
# Bound CLI keys replace the file (arrays replace, they do not union):
.\scripts\Invoke-DsmDriverStoreAudit.ps1 -SettingsPath .\examples\dsm.settings.example.json `
    -OutputPath .\audit-output

# DiskId catalog (all OEM drivers — JSON + CSV)
.\scripts\Export-DsmDriverDiskIdCatalog.ps1 -OutputPath .\audit-output
# Or combined with audit:
.\scripts\Invoke-DsmDriverStoreAudit.ps1 -OutputPath .\audit-output -IncludeCleanupPreview -ExportDiskIdCatalog
```

## Testing

```powershell
# Unit tests under tests/unit (PowerShell 7+; Pester 6 recommended)
.\tests\Invoke-DsmPester.ps1
# Or directly (Pester 6 configuration object):
# $c = New-PesterConfiguration; $c.Run.Path = '.\tests\unit'; Invoke-Pester -Configuration $c

# Windows PowerShell 5.1 smoke (no live pnputil) — build Intune bundles first
.\scripts\Build-DsmIntuneScripts.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-DsmPs51SmokeTest.ps1
```

## Validate

One-time Gallery deps (CurrentUser) if missing:

```powershell
Install-Module -Name Pester -MinimumVersion 5.5.0 -Scope CurrentUser -Force `
  -SkipPublisherCheck
Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force `
  -SkipPublisherCheck
```

Repo-root gate for agents and CI (Intune build → PS 5.1 smoke → Pester →
PSScriptAnalyzer). Lint fails on **Error and Warning**, matching WinGet.Audit
and spine-automation. Remaining exclusions are documented in
`PSScriptAnalyzerSettings.psd1` (`PSAvoidUsingWriteHost`,
`PSUseSingularNouns`). Fails fast with `DSM-VALIDATE-FAIL stage=deps` when those
modules are missing (does not auto-install). Rebuilds `dist/intune/` (Safety
tier 2).

```powershell
pwsh -NoProfile -File .\scripts\Invoke-DsmValidate.ps1 -AgentSummary
```

Individual stages:

```powershell
pwsh -NoProfile -File .\scripts\Build-DsmIntuneScripts.ps1 -AgentSummary
powershell.exe -NoProfile -File .\scripts\Invoke-DsmPs51SmokeTest.ps1 -AgentSummary
pwsh -NoProfile -File .\tests\Invoke-DsmPester.ps1 -AgentSummary
pwsh -NoProfile -File .\scripts\Invoke-DsmScriptAnalyzer.ps1 -AgentSummary
```

Optional Task palette (needs `CURSOR_CONFIG_ROOT`): `.vscode/tasks.json`.
GitHub Actions: [`.github/workflows/dual-host-ps.yml`](.github/workflows/dual-host-ps.yml)
runs Pester on `pwsh` and Windows PowerShell 5.1, then build + 5.1 smoke.

README remains the agent SSOT for this product — no `AGENTS.md`.

## Intune — build and test locally

Intune Proactive Remediation runs **Windows PowerShell 5.1** (64-bit, **SYSTEM**).
Edit module source under `src/`; generate upload scripts — do **not** hand-edit
`dist/intune/`. Full portal settings, exit codes, and pilot checklist:
[docs/intune-deployment.md](docs/intune-deployment.md).

### 1. Build standalone scripts

```powershell
# From repo root (PS 7+ or Windows PowerShell 5.1)
.\scripts\Build-DsmIntuneScripts.ps1
# Optional agent one-liner: .\scripts\Build-DsmIntuneScripts.ps1 -AgentSummary
# → dist/intune/Detect-DsmDriverStoreCompliance.ps1
# → dist/intune/Remediate-DsmDriverStore.ps1

# Path-only: bake on-endpoint paths (deploy the files separately).
# Preserve path → Detection and Remediation. Blocklist path → Detection only.
.\scripts\Build-DsmIntuneScripts.ps1 `
    -PreserveRulesPath 'C:\ProgramData\DriverStoreManager\config\preserve-rules.json' `
    -BlocklistPath 'C:\ProgramData\DriverStoreManager\config\blocklist-hashes.txt'

# Inline: embed content in the generated scripts (no Intune runtime params).
# Preserve rules → both scripts; each writes ProgramData itself so cleanup
# does not depend on Detection having run. Blocklist → Detection only
# (Gate 7, advisory; Remove-DsmUnusedDriverPackages has no BlocklistPath).
.\scripts\Build-DsmIntuneScripts.ps1 `
    -InlinePreserveRulesFile .\examples\preserve-rules.example.json `
    -InlineBlocklistFile .\examples\blocklist-hashes.example.txt
```

Rebuild after any `src/` or `scripts/intune/templates/` change before upload.

### 2. Automated local gate (recommended before upload)

```powershell
.\scripts\Build-DsmIntuneScripts.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-DsmPs51SmokeTest.ps1
```

The smoke test requires pre-built `dist/intune` bundles. It exercises PS 5.1
StrictMode paths, mocked `pnputil` fixtures, and Intune detection/remediation
gate logic **without** touching the live driver store.

### 3. Live detection dry-run (optional)

Mirrors Intune detection on this machine (writes under
`%ProgramData%\DriverStoreManager\reports\intune-detection\`). Prefer an elevated
**64-bit** Windows PowerShell 5.1 host:

```powershell
# Prefer SysWOW64? No — use 64-bit PowerShell (System32), same as Intune.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\dist\intune\Detect-DsmDriverStoreCompliance.ps1
$LASTEXITCODE
# 0 = compliant | 1 = non-compliant (orphan cleanup would remediate) | 2 = error
```

Review the newest `detection-summary_*.json` under ProgramData before deciding
whether remediation is appropriate.

### 4. Remediation — do not casually run the bundle

`Remediate-DsmDriverStore.ps1` **deletes** NeverAssociated orphan candidates
(export-before-delete, max 10 per run) and requires administrator / SYSTEM.
For local preview, use the module instead:

```powershell
Import-Module .\src\DriverStoreManager\DriverStoreManager.psd1 -Force
Remove-DsmUnusedDriverPackages -PreserveRulesPath .\examples\preserve-rules.example.json -WhatIf -PassThru
```

Only run the remediate bundle on an isolated VM / pilot device after reviewing
detection JSON and backups policy. See [safety-gates.md](docs/safety-gates.md).

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
| `Get-DsmSettings` / `Get-DsmSettingsOverlay` | — | Load opt-in JSON run profile; merge with bound CLI (DSM-040) |

### Settings file overlay (DSM-040)

A JSON run profile is used **only** when you pass `-SettingsPath`. Nothing is
auto-loaded from the repo or the working directory (unlike Hash Mass
Downloader’s `hmd.defaults.json`).

| Layer | When | Role |
|-------|------|------|
| Cmdlet defaults | Always | Safe built-ins |
| Settings JSON | `-SettingsPath` is bound and the file exists | Repeatable site/run profile |
| Bound CLI | `$PSBoundParameters.ContainsKey` | This invocation wins |

Unbound parameters take file values. Bound parameters replace them. Arrays
**replace** (they are not unioned). Relative paths in the file resolve against
the settings file’s directory. Missing, invalid, unknown, or forbidden keys
(`AllowDelete`, `Confirm`, `WhatIf`, `Force`) throw. Deletion still requires
explicit `-AllowDelete` and `-Confirm:$false`.

Example file: [`examples/dsm.settings.example.json`](examples/dsm.settings.example.json)
(copy it; do not point `-SettingsPath` at a file you have not reviewed).
`-ShowEffectiveSettings` (or `-Verbose` after a load) prints `Key=value (source)`.

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
