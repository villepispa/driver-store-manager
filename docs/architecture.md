# Architecture — Driver Store Manager

## Problem

Windows accumulates **third-party driver packages** in the Driver Store (`%SystemRoot%\System32\DriverStore\FileRepository`).
Old packages may:

- Expand attack surface (vulnerable kernel drivers remain installable)
- Clutter disk and complicate incident response
- Include **unsigned** or **blocklisted** drivers still present on disk

Security teams need a **repeatable, built-in-command workflow** — not ad hoc GUI Device Manager clicks.

## Design principles

1. **Parse, don't reinvent** — use `pnputil /format csv` and DISM cmdlets; avoid scraping text tables by hand where CSV exists.
2. **Normalize early** — one `DsmDriverPackage` object shape for inventory, scan, and cleanup.
3. **Signals, not verdicts** — vulnerability phase combines blocklist + signature + orphan status; operator decides remediation.
4. **Safe defaults** — cleanup is opt-in, `-WhatIf` by default, export-before-delete mandatory.
5. **OEM scope default** — all `oem#.inf` staged packages (any publisher); Windows built-in manifests only with `-IncludeWindowsBuiltIn`.

## Terminology

| Term | Meaning |
|------|---------|
| **Staged OEM package** | `PublishedName` matches `oem#.inf` — default scope |
| **Windows built-in driver** | Non-oem manifest (`c_swcomponent.inf`, …) — excluded unless `-IncludeWindowsBuiltIn` |
| **Publisher** | `Provider` / `Signer` from INF metadata — may read `Microsoft Corporation` on staged `oem#.inf`; does **not** imply built-in |

## OEM scope (Phase 3b)

| Check | Rule |
|-------|------|
| Published name (default) | `oem\d+\.inf` — in scope |
| Staged oem + Microsoft publisher | **In scope** — e.g. `oem159.inf` Voice Clarity (`Provider: Microsoft Corporation`) |
| Windows built-in manifest | Excluded by default (`c_swcomponent.inf`, `netvwifimp.inf`, …) |
| Lift | `-IncludeWindowsBuiltIn` adds non-oem#.inf manifests |

## Device association (three buckets)

| State | Meaning | Example |
|-------|---------|---------|
| `Connected` | Device online now | Docked USB NIC |
| `DisconnectedInstalled` | Device installed, not connected | Unplugged printer, offline USB dock |
| `NeverAssociated` | Staged only; no installed device | Old orphan OEM package |

`InUse` remains an alias for `Connected` for backward compatibility.

## Filter surface (Phase 3b)

`New-DsmDriverFilter` + `Invoke-DsmDriverFilter` — shared across report, scan, and cleanup.
Wildcards: PowerShell `-like`. INF names: ordinal case-insensitive.

Driver family keys (`Get-DsmDriverFamilyKey`): `Provider + OriginalName` (default) or HWID root.

## Preserve policy (Phase 3c)

`New-DsmPreserveRule` + `Invoke-DsmPreservePolicy` — marks `Preserved`, `PreserveReasons`,
`PreserveRuleNames` on packages. Cleanup and reports must honor preserve.

| RuleType | Behaviour |
|----------|-----------|
| `KeepLatest` | Latest package per family (when family matches filter) |
| `KeepVersion` | Exact/wildcard version + optional filter |
| `KeepPublishedName` | Explicit `oem#.inf` list |
| `KeepMatching` | All packages matching filter (printers, unplugged USB, …) |

JSON rules: `examples/preserve-rules.example.json`. Independent of `InUse`.

## Reporting (Phase 3d)

`Get-DsmDriverStoreReport` — pipeline: inventory → filter → preserve → vuln scan → metrics.

Dual emit: **Global** (OEM scope, no filter criteria) and **Scoped** (active filter). Each includes
`Summary` (all plan metrics) and `Listings` (connected, unused, preserved, version ladders,
vulnerable, deletable). Optional `-OutputPath` writes JSON + Markdown.

`Invoke-DsmDriverStoreAudit.ps1` delegates to this cmdlet (single source of truth).

## Object model

### `DsmDriverPackage`

| Property | Source | Purpose |
|----------|--------|---------|
| `PublishedName` | `pnputil` | e.g. `oem42.inf` — delete/export key |
| `OriginalName` | `pnputil` | Vendor INF name |
| `Provider` | `pnputil` | Publisher string |
| `DriverClass` | `pnputil` | Class name / GUID |
| `DriverVersion` | `pnputil` | Version resource |
| `DriverDate` | `pnputil` | Package date |
| `InUse` | device correlation | `true` when `DeviceAssociation = Connected` |
| `DeviceAssociation` | `enum-devices` all vs connected | `Connected`, `DisconnectedInstalled`, `NeverAssociated` |
| `ConnectedDeviceCount` | device correlation | Connected device references |
| `DisconnectedInstalledDeviceCount` | device correlation | Installed but not connected |
| `HardwareIds` | `enum-devices` instance IDs | Full IDs + roots for filter/grouping |
| `HardwareIdRoots` | parsed instance ID | e.g. `USB\VID_046D&PID_C52B` — used for `FamilyGroupBy = HwId` |
| `DeviceCount` | device correlation | Total distinct device descriptions |
| `Files` | `/files` | Driver image paths for hash/signature checks |
| `Signatures` | `Get-AuthenticodeSignature` | Per-file status (Phase 2) |
| `RiskSignals` | scanner | `Blocklisted`, `Unsigned`, `OrphanCandidate`, etc. |

## Pipelines

v0.1 established the core flow (inventory → vulnerability signals → export → delete).
Later phases added OEM scope, three-bucket association, filter/preserve, and reporting
around the same spine. See [lessons-learned.md § 1.1](lessons-learned.md#11-v01-scaffold-session-2026-06-15).

### Inventory pipeline

```text
pnputil /enum-drivers /files /devices /format csv
    → ConvertFrom-PnPUtilDriverCsv
    → Get-DsmDeviceDriverCorrelation (enum-devices all + connected)
    → Add-DsmDeviceCorrelationToInventory
    → optional Get-WindowsDriver -Online (validation / extra metadata)
    → [DsmDriverPackage[]]
```

### Vulnerability pipeline

```text
[DsmDriverPackage[]]
    → Test-DsmDriverVulnerabilities (.sys/.dll/.cat hash + Authenticode)
    → Microsoft blocklist auto-cache (aka.ms/VulnerableDriverBlockList, 7-day TTL)
    → Optional -BlocklistPath supplemental hashes (merged)
    → OrphanCandidate via Test-DsmPackageIsOrphanCandidate (aligned with report)
    → [DsmDriverPackage[]] with RiskSignals + FileAnalysis
    → Get-DsmDriverStoreReport (Vulnerable* counts, AdvisorySeverity, VulnerabilityManifest)
```

**Advisory severity (operator triage only):** `Critical` (blocklisted + connected) → `High`
(vulnerable in use) → `Medium` (vulnerable unused) → `Low` (signature only) → `Informational`
(orphan hygiene). Never auto-remediate from severity alone.

### Cleanup pipeline

```text
[RiskSignals contains OrphanCandidate] (operator-filtered)
    → pnputil /export-driver <PublishedName> <BackupRoot>
    → pnputil /delete-driver <PublishedName>   # no /force in default path
```

## Elevation model

| Operation | Admin required |
|-----------|----------------|
| `Get-DsmDriverStoreInventory` | Usually no |
| `Test-DsmDriverVulnerabilities` | No (reads files accessible to user) |
| `Remove-DsmUnusedDriverPackages` | **Yes** |

`Test-DsmElevation` in Private helpers returns a clear error record when elevation is missing.

## PowerShell 5.1 and Intune

| Concern | Approach |
|---------|----------|
| **Dual host** | Module targets **PS 5.1+**; PS 7+ used for dev/audit |
| **Intune delivery** | `Build-DsmIntuneScripts.ps1` merges sources → single detection + remediation `.ps1` |
| **Version gates** | `Dsm.Runtime.ps1`: `Test-DsmIsPowerShellCore`, `Join-DsmPath`, `Set-DsmContentUtf8` |
| **Endpoint state** | `%ProgramData%\DriverStoreManager\` (reports, backups) |

See [intune-deployment.md](intune-deployment.md).

Lessons from development (INF metadata, PS 5.1, Intune): [lessons-learned.md](lessons-learned.md).

## Future extensions (out of v1 scope)

- WDAC / CiPolicy integration for live enforcement status
- NVD API enrichment by driver version
- **Report export sinks** — file path (JSON/CSV), HTTPS webhook, Azure Blob, Event Hub
- **Vulnerability Management formats** — Microsoft Defender for Endpoint custom fields,
  Sentinel/Log Analytics JSON schema, CEF/Syslog for third-party SIEM
- **Restore from backup** — `Restore-DsmDriverPackages` from `pnputil /add-driver` +
  export tree under `backups/<timestamp>/`; batch restore with reboot policy
- HTML report template for SOC handoff
