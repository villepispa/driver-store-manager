# Changelog

All notable changes to **Driver Store Manager** are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning aligns with [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **DSM-036:** Filed Open — align PSA gate with siblings (fail on Warning).
  Forty-six Warnings remain after DSM-034 Error-only lint. See `docs/issues.md`.

## [0.8.0] — 2026-08-31

### Added

- **DSM-037:** `Build-DsmIntuneScripts.ps1` bakes detect/remediate knobs
  (`-OrphanThreshold`, `-RemediationMaxDeletes`, Microsoft blocklist flags,
  and others). Intune Detection and Remediation cannot take runtime parameters.
  Configuration files: **path-only** (`-PreserveRulesPath` /
  `-BlocklistPath`) or **inline** (`-InlinePreserveRulesFile` /
  `-InlineBlocklistFile`) so the generated scripts are self-contained. Preserve
  inline content is also baked into Remediation. Tests:
  `tests/Build-DsmIntuneScripts.Tests.ps1`. **82/82** Pester; `DSM-BUILD-OK`
  detectBytes=176798 config=none.
- **DSM-034:** Repo-root validate trio — `PSScriptAnalyzerSettings.psd1`,
  `scripts/Invoke-DsmScriptAnalyzer.ps1`, `scripts/Invoke-DsmValidate.ps1`
  (build → PS 5.1 smoke → Pester → lint). README **Validate**. Lint gate
  fails on **Error** only (Warning noise on a first full scan).
- **DSM-035:** Dual-host GitHub Actions (`.github/workflows/dual-host-ps.yml`)
  — Pester via `tests/Invoke-DsmPester.ps1` on `pwsh` and Windows PowerShell
  5.1, then Intune build + `Invoke-DsmPs51SmokeTest.ps1`.
- Call-through VS Code tasks (`.vscode/tasks.json`); ScriptSafetyGate default
  is `Invoke-DsmValidate.ps1` with TaskProfile **ControlledWrite**.
- Repo-root `.markdownlint-cli2.jsonc` ignores (`.cursor/`, `audit-output/`,
  drafts, `docs/archive/`) so `markdownlint-cli2` matches sibling products.

### Changed

- **`data/` → `examples/`** — sample preserve-rules JSON and supplemental
  blocklist hashes (not live endpoint payload).
- **`ModuleVersion`** — `DriverStoreManager.psd1` set to `0.8.0` for this
  release.

### Fixed

- `New-DsmCleanupResultRow` parameter `$Error` renamed to `$ErrorMessage`
  (`PSAvoidAssignmentToAutomaticVariable`). Result row property remains
  `Error`.

## [0.7.10] — 2026-07-28

### Changed

- **README / Intune docs** — Fixed broken Quick start / Testing fences; added
  **Intune — build and test locally** (build, PS 5.1 smoke, live detection dry-run,
  remediate caution). Mirrored short local path in `docs/intune-deployment.md`.
- **`ModuleVersion`** — `DriverStoreManager.psd1` set to `0.7.10` for this release.

## [0.7.9] — 2026-07-28

### Added

- **`-AgentSummary` on agent gates and orchestration** — `scripts/Invoke-DsmPs51SmokeTest.ps1`, `scripts/Build-DsmIntuneScripts.ps1`, `tests/Invoke-DsmPester.ps1`, `scripts/Invoke-DsmDriverStoreAudit.ps1`, `scripts/Export-DsmDriverDiskIdCatalog.ps1`, and `scripts/Update-DsmMicrosoftDriverBlocklist.ps1` emit one parseable success-stream line (`DSM-*-OK` / `DSM-*-FAIL`) for single-invocation agent Shell calls.
- **`tests/DriverStoreManager.CleanupMocks.Tests.ps1`** — Mocked elevation, successful delete, export/delete failure, and `MaxDeletes` regression tests (`DSM-027`).

### Changed

- **Docs** — Absorbed DSM v0.1 Cursor transcript facts into living docs; local export under `docs/archive/` (gitignored).
- **Script naming and headers** — Harmonized `scripts/` and `tests/` entry points to the workspace PowerShell naming/header standards: `Invoke-DriverStoreAudit.ps1` → `Invoke-DsmDriverStoreAudit.ps1`; Intune entry templates → `Detect-DsmDriverStoreCompliance.Entry.ps1` / `Remediate-DsmDriverStore.Entry.ps1`; `_drafts/smoke-inventory.ps1` → `Test-DsmInventorySmoke.ps1`; Safety tier + `Set-StrictMode` on catalog scripts.
- **`scripts/Invoke-DsmPs51SmokeTest.ps1`** — Runs under `Set-StrictMode`; uses test harness with mocked `pnputil`; exercises correlation, blocklist XML, preserve JSON, UTF-8 no-BOM writes, Intune bundle headers, and detection/remediation gate logic (`DSM-026`).
- **Strict Mode hardening** — `Get-DsmCsvRowValue`, `Get-DsmObjectPropertyValue`, and safe property reads in CSV parsing, preserve JSON, filter matching, report listings, and cleanup planning (required for PS 5.1 smoke and Intune bundles).
- **Pester 6** — Test harness setup moved to per-file `BeforeAll` (Pester 6 discovers and runs each file in isolation). Assertions migrated from `Should Be` to `Should-*` (`Should-Be`, `Should-NotBeNull`, `Should -Not -Throw`). Shared fixtures extracted to `tests/helpers/DsmTestFixtures.ps1`. `Invoke-DsmPester.ps1` targets Pester 5.5+ / 6.x, sets `Run.RepoRoot`, and exits non-zero on failure.

### Fixed

- **`DSM-033` StrictMode `Preserved` before init** — `Test-DsmPackageIsOrphanCandidate` / `Test-DsmPackageIsDeletableCandidate` (and related filters) read `Preserved` via `Get-DsmObjectPropertyValue`. Intune detect with `-IncludeVulnerabilityScan` called orphan logic before `Initialize-DsmPreserveAnnotations`, so `Set-StrictMode` threw `PropertyNotFoundStrict`. Also hardened `Compare-DsmDriverPackageRecency` (`DriverDate`/versions), `Get-DsmBlocklistHashes` (unary-comma HashSet), empty-scope `@($pkgs).Count`, and `Invoke-DsmPester -AgentSummary` (`Run.PassThru`). Regression + rebuild: **77/77** Pester; `DSM-BUILD-OK`.
- **`ModuleVersion`** — `DriverStoreManager.psd1` set to `0.7.9` for this release.

## [0.7.8] — 2026-07-12

### Fixed

- **Safety remediation batch (`DSM-002`–`DSM-013`, `DSM-022`–`DSM-025`, `DSM-028`–`DSM-030`)** — Intune detection triggers remediation only for orphan cleanup (Gate 7 advisory); remediation exits `2` on export/delete failures; explicit `-Confirm:$false` binding; inventory provenance validation; pre-delete association refresh; `SkippedInUse` / `SkippedDisconnectedInstalled` audit rows; blocklist scan degraded/unavailable state; ConfigCI Authenticode SHA-256 when available; `SignatureIndeterminate` for `UnknownError`; empty supplied blocklist binding; Strict Mode preserve defaults; TLS 1.2 for blocklist download; async `pnputil` pipe reads; explicit UTF-8 no-BOM writes; RFC 4180 driver CSV parsing; test isolation for blocklist cache and mocked fixtures.
- **INF metadata (`DSM-014`–`DSM-021`)** — UTF-8/Windows-1252 INF decoding; structured read failures; INF-aware `DriverVer` comments; approved-path validation; filename-only `OriginalName`; recursive `%token%` resolution with cycle guard; mtime/length cache invalidation.
- **Device correlation fail-closed (`DSM-001`)** — Modified `Get-DsmDeviceDriverCorrelation` to return `$null` on failure, and updated `Add-DsmDeviceCorrelationToInventory` to fail closed with an explicit `'Unknown'` association, preventing un-correlated packages from reaching deletion eligibility.
- **Report/orphan and filter fallback alignment** — Aligned `Test-DsmPackageIsOrphanCandidate`, `Measure-DsmDriverStoreScope` bucket counts, and `Test-DsmDriverPackageMatchesFilter` fallback logic to consistently handle empty/null `DeviceAssociation` based on `InUse` and `DeviceCount`.

### Added

- **`tests/Invoke-DsmPester.ps1`** — version-aware Pester runner (prefers Pester 5 when installed).

## [0.7.7] — 2026-07-09

### Added

- **Lessons learned** — `docs/lessons-learned.md` (journey, INF/PS/Intune/agent pitfalls).
- **Additional INF label fields** — `DisplayName`, `ExtensionDesc`, `DispName`,
  `DeviceName`, `SERVICE_DESC`, `SOURCEDISK1`, and quoted SWC model lines
  (`"Thunderbolt(TM) HSA Component" = …`).
- **`Test-DsmInfSubstantiveLabel`** — skips bare vendor tokens (`Intel`, `HP Inc.`, …)
  when a more descriptive label exists.

### Fixed

- **PS string unwrapping** — single-match pattern lists no longer collapse to a string,
  so `$mfg[0]` on `ManufacturerName = "Intel"` no longer becomes `"I"`.
- **Manufacturer vs install lines** — model-token scans ignore `[Manufacturer]`
  declarations and only parse hardware-ID install lines.

## [0.7.6] — 2026-07-09

### Added

- **Richer INF label extraction** — `Get-DsmInfFriendlyLabel` cascade: `DeviceDesc` / `_Desc`,
  `[OEMInf] VerifyMark`, expanded `[Strings]` disk keys (`DISK_NAME`, `Location`, …),
  `MfgName` / `ManufacturerName`, `*_svcdesc`, and first manufacturer model token.
- **`LabelSource`** on `Get-DsmInfMetadata`, `Get-DsmDriverPackageInfMetadata`, and
  `Export-DsmDriverDiskIdCatalog` CSV output.
- **INF path fallbacks** — `%WINDIR%\INF\<PublishedName>` and FileRepository lookup by
  `OriginalName` when pnputil file correlation is empty.

### Fixed

- **`[Strings]` parsing** — strip `;` comments (including `{PlaceHolder=…}` tails) before
  quoted-segment extraction; normalize ``- Installation Disk`` suffix variants.

## [0.7.4] — 2026-07-08

### Added

- **Mocked pnputil e2e tests** — `tests/DriverStoreManager.MockedPnPUtil.Tests.ps1` with fixture CSV
  (`tests/fixtures/pnputil-*.csv`) and `tests/helpers/Import-DsmTestHarness.ps1`.
- **PS 5.1 smoke script** — `scripts/Invoke-DsmPs51SmokeTest.ps1` for Windows PowerShell 5.1 hosts.

### Fixed

- **PS 5.1 markdown export** — replaced Unicode em-dash in `ConvertTo-DsmDriverStoreReportMarkdown`
  (PS 5.1 parser error on non-ASCII source).

## [0.7.3] — 2026-07-08

### Fixed

- **Per-package INF resolution** — when multiple `OriginalName` copies exist in FileRepository
  (e.g. four `cui_dch.inf` builds), correlate `pnputil` file names to the correct folder;
  tie-break with `DriverVersion` vs INF `DriverVer`. Fixes cleanup rows where `DriverVer`
  incorrectly matched a newer in-use sibling.

### Added

- **`[SourceDisksNames]` parsing** — resolves `%DiskId%` / `%DiskName%` tokens from `[Strings]`
  when direct `DiskId` keys are absent (improves DiskId catalog coverage).

## [0.7.2] — 2026-07-08

### Added

- **INF metadata** — `Get-DsmInfMetadata` reads `DriverVer` and `DiskId` from staged INF files
  under `FileRepository` (resolved via `OriginalName` when `oem#.inf` is not on disk);
  `DisplayName` strips the common ``Installation Disk`` suffix.
- **Cleanup enrichment** — preview/delete rows include `DriverVer`, `DiskId`, `DisplayName`, and
  `InUseNewerDriver` (published name, version, device names) when superseded by an in-use family member.
- **Live cleanup log** — `Write-DsmCleanupResultLog` prints candidate lines to the host.
- **`Export-DsmDriverDiskIdCatalog`** — catalog of all OEM drivers; script
  `scripts/Export-DsmDriverDiskIdCatalog.ps1`; audit switch `-ExportDiskIdCatalog`.

### Changed

- Cleanup preview JSON depth increased; summary adds `OldVersionsOfInUseFamiliesCount`.

## [0.7.1] — 2026-07-08

### Fixed

- **Export runtime helpers** — `Set-DsmContentUtf8`, `Join-DsmPath`, `Get-DsmProgramDataRoot` are now
  module exports (fixes `Invoke-DriverStoreAudit.ps1 -IncludeCleanupPreview`).
- **WhatIf leakage** — temp-file `Remove-Item` during inventory uses `-WhatIf:$false` so cleanup preview
  does not spam "Remove File" on pnputil CSV temps.
- **Audit script** — reuses report inventory for cleanup preview (single pnputil pass when preview requested).

## [0.7.0] — 2026-07-08

Phase 5 — filter + preserve aware safe cleanup.

### Added

- **`Get-DsmDriverStoreCleanupPlan`** (private) — Same scoped filter/preserve path as report; deletable candidates.
- **`Export-DsmDriverPackageBackup`** / **`Remove-DsmDriverPackageFromStore`** — pnputil export/delete helpers (no `/force`).
- **`-PassThru`** on `Remove-DsmUnusedDriverPackages` — returns `Results` + `Summary` delta object.
- **`-MaxDeletes`** cap; filter parameters aligned with `Get-DsmDriverStoreReport`.

### Changed

- **`Remove-DsmUnusedDriverPackages`** — Uses cleanup plan; elevation only when deleting; export failure skips delete.
- **`Invoke-DriverStoreAudit.ps1`** — `-IncludeCleanupPreview` writes Summary + Results JSON.
- Intune remediation — single `Remove-DsmUnusedDriverPackages -PassThru` call with preserve rules.

## [0.6.0] — 2026-07-08

Microsoft vulnerable driver blocklist auto-refresh (DSM-002).

### Added

- **`Dsm.Blocklist.ps1`** — Download/parse/cache Microsoft blocklist; `Get-DsmBlocklistHashSet`.
- **`Update-DsmMicrosoftDriverBlocklist`** — Public cmdlet + `scripts/Update-DsmMicrosoftDriverBlocklist.ps1`.
- Auto-refresh from `https://aka.ms/VulnerableDriverBlockList` (7-day TTL, `%ProgramData%` cache).
- `-UseMicrosoftBlocklist`, `-UpdateMicrosoftBlocklist`, `-MicrosoftBlocklistMaxAgeDays`, `-SkipMicrosoftBlocklist`.
- `VulnerabilityManifest` fields for Microsoft cache path, policy version, refresh status.

### Changed

- **`-BlocklistPath`** — Supplemental hashes merged with Microsoft auto-cache (not replaced).
- **`Invoke-DriverStoreAudit.ps1`** — Microsoft blocklist on by default during vulnerability scan.

## [0.5.0] — 2026-07-08

Phase 4 — vulnerability signals fully integrated into reports (single source of truth).

### Added

- **`Get-DsmPackageAdvisorySeverity`** / **`Get-DsmAdvisorySeverityRank`** — Advisory triage hints
  (`Critical` → `Informational`); never triggers auto-remediation.
- **`Test-DsmIsDriverImagePath`** — Limits hash/signature scans to `.sys`, `.dll`, `.cat`.
- **`VulnerabilityManifest`** on `Get-DsmDriverStoreReport` — scan metadata (blocklist path/count, options).
- **`AdvisorySeverity`** on listing rows; vulnerable drivers sorted by severity in report output.
- Markdown report section for vulnerable drivers (advisory) + vulnerability scan manifest.

### Changed

- **`Test-DsmDriverVulnerabilities`** — Orphan signal aligned with `Test-DsmPackageIsOrphanCandidate`;
  `-OrphanIncludesDisconnectedInstalled`; safe handling when `SignerCertificate` is null.
- **`Get-DsmDriverStoreReport`** — Vulnerability scan passes orphan/report alignment flag.
- Intune remediation template — `-OrphanIncludesDisconnectedInstalled` on vulnerability scan.
- **`ConvertFrom-PnPUtilDeviceCsv`** — Parses modern `InstanceId` / `DeviceDescription` headers (fixes `InUseCount`).

### Tests

- Blocklist matching, orphan alignment, advisory severity, report `VulnerabilityManifest`.

## [0.4.0] — 2026-07-08

Phase 3d — `Get-DsmDriverStoreReport` with Global/Scoped dual metrics and listings.

### Added

- **`Get-DsmDriverStoreReport`** — Full report pipeline; JSON + Markdown via `-OutputPath`.
- **`Measure-DsmDriverStoreScope`** (private) — All plan metrics, listings, version ladders,
  `EstimatedReclaimableBytes`.
- **`Dsm.Report.ps1`** — Old-version flags, orphan vs deletable logic, Markdown converter.

### Changed

- **Device CSV** — tolerate empty `Device Instance ID`; correlation failures no longer abort inventory.
- **Pipeline** — filter, preserve, vuln scan, and report accept empty/null inventory (PS 5.1/7).
- Intune detection template — Uses report `Global.Summary` for compliance checks.

## [0.3.0] — 2026-07-08

Phase 3c — preserve policy (DisplayLink, printers, unplugged USB examples).

### Added

- **`New-DsmPreserveRule`** / **`Invoke-DsmPreservePolicy`** — `KeepLatest`, `KeepVersion`,
  `KeepPublishedName`, `KeepMatching`; sets `Preserved`, `PreserveReasons`, `PreserveRuleNames`.
- **`Get-DsmPreserveRulesFromFile`** — JSON rule loader (private).
- **`data/preserve-rules.example.json`** — DisplayLink, printer, USB disconnected examples.

### Changed

- **`Remove-DsmUnusedDriverPackages`** — `-PreserveRule` / `-PreserveRulesPath`; skips preserved orphans.
- Intune remediation template — optional `$DsmPreserveRulesPath`.

## [0.2.0] — 2026-07-08

Phase 3b — filter model, OEM-default scope, device association buckets, HWID enrichment.
Phase 6b — PS 5.1 baseline + Intune standalone script builder.

### Added

- **`Dsm.Runtime.ps1`** — `Test-DsmIsPowerShellCore`, `Join-DsmPath`, `Set-DsmContentUtf8`,
  `Get-DsmProgramDataRoot` for PS 5.1 / PS 7 dual-host support.
- **`scripts/Build-DsmIntuneScripts.ps1`** — Builds `dist/intune/Detect-DsmDriverStoreCompliance.ps1`
  and `Remediate-DsmDriverStore.ps1` from module sources + templates.
- **`docs/intune-deployment.md`** — Proactive Remediation exit codes, pilot checklist, PS strategy.
- **`scripts/intune/bundle-order.json`** — Source merge manifest for Intune bundles.

- **`New-DsmDriverFilter`** / **`Invoke-DsmDriverFilter`** — Shared filter surface with wildcards
  (vendor, device, version, class/GUID, HWID, INF names, association bucket). OEM default:
  all `oem#.inf` packages (any publisher); Windows built-in manifests excluded;
  `-IncludeWindowsBuiltIn` adds built-in manifest names.
- **`Get-DsmDeviceDriverCorrelation`** — Parses `pnputil /enum-devices` (all + connected) for
  HWIDs and three-bucket `DeviceAssociation` (`Connected`, `DisconnectedInstalled`, `NeverAssociated`).
- **`Get-DsmDriverFamilyKey`** — Family key for version grouping (`Provider+OriginalName` or HWID root).

### Changed

- **OEM scope terminology** — Windows built-in manifests (non-oem#.inf) vs staged oem#.inf;
  `-IncludeWindowsBuiltIn` replaces `-IncludeMicrosoft`; `ExcludedWindowsBuiltInCount`
  replaces publisher-based exclusion counts. `oem159.inf` with `Microsoft Corporation`
  provider is staged OEM, not built-in.
- **`Get-DsmDriverStoreInventory`** — Enriches packages with `HardwareIds`, `DeviceAssociation`,
  connected/disconnected device counts (replaces simple in-use set).
- **`Remove-DsmUnusedDriverPackages`** — Orphan candidates limited to `NeverAssociated`; `Join-DsmPath` for PS 5.1.
- **`Test-DsmDriverVulnerabilities`** — `OrphanCandidate` only for `NeverAssociated` packages.
- **Module `PowerShellVersion`** — lowered to **5.1** (PS 7+ still supported).
- **`Invoke-DriverStoreAudit.ps1`** — PS 5.1+ (`#Requires -Version 5.1`).

### Documentation

- **`docs/architecture.md`** — OEM scope, association buckets, filter surface.
- **`docs/safety-gates.md`** — Gate 2 updated for three-bucket model.

## [0.1.0] — 2026-06-15

Initial release scaffolded from a private Windows security workspace plan (2026-06-15).
Living summary: [lessons-learned.md § 1.1](docs/lessons-learned.md#11-v01-scaffold-session-2026-06-15).
Redacted Cursor export kept locally under `docs/archive/` (gitignored; not published).

### Added

#### PowerShell module (`src/DriverStoreManager/`)

- **`Get-DsmDriverStoreInventory`** — Enumerates driver packages via `pnputil /enum-drivers /format csv`,
  parses UTF-16 CSV output, and correlates in-use devices from `pnputil /enum-devices`.
  Returns normalized `DsmDriverPackage` objects (`PublishedName`, `Provider`, `InUse`, `DeviceCount`, etc.).
- **`Test-DsmDriverVulnerabilities`** — Assesses inventory for risk signals: Authenticode signature status,
  SHA-256 blocklist matches, and orphan-candidate detection.
- **`Remove-DsmUnusedDriverPackages`** — Safe cleanup workflow: dry-run by default (`-WhatIf`),
  export-before-delete via `pnputil /export-driver`, deletion only with `-AllowDelete`.
  No `/force` on the public surface.
- **`Dsm.Common.ps1`** (private) — Shared helpers: CSV parsing (`ConvertFrom-PnPUtilDriverCsv`),
  elevation check (`Test-DsmElevation`), blocklist loader (`Get-DsmBlocklistHashes`).

#### Scripts

- **`scripts/Invoke-DriverStoreAudit.ps1`** — End-to-end audit: inventory + vulnerability scan with report output.
- **`scripts/_drafts/smoke-inventory.ps1`** — Ad-hoc inventory smoke test used during development.

#### Data

- **`data/blocklist-hashes.example.txt`** — Example SHA-256 blocklist format for vulnerability scanning.

#### Documentation

- **`README.md`** — Quick start, requirements, command summary.
- **`docs/architecture.md`** — Problem statement, design principles, object model, pipeline phases.
- **`docs/commands-reference.md`** — Built-in Windows tooling reference (`pnputil`, DISM).
- **`docs/safety-gates.md`** — Mandatory safety controls (inventory freshness, in-use exclusion,
  export-before-delete, elevation, dry-run defaults).

#### Tests

- **`tests/DriverStoreManager.Tests.ps1`** — Pester suite (v3-compatible):
  - CSV grouping and in-use detection
  - Elevation check returns boolean
  - Blocklist hash loader skips comments and invalid lines

### Fixed

- **`pnputil` CSV parser** — Corrected UTF-16 encoding handling and column mapping; initial parser
  returned zero packages before fix. Verified on development host: **158 packages** enumerated.

### Verified

- Built-in tooling present on target host: `pnputil.exe`, `driverquery.exe`, `Get-WindowsDriver` (DISM).
- Module smoke test: inventory enumeration successful; Pester **3/3 passed**.

### Workspace context (parent repo)

Created alongside the module as part of the Windows security management workspace:

- Git repository initialized (`main` branch).
- Workspace README, `.gitignore`, backlog, and plan index.
- PM tasks in `.cursor/project-management.json` (DSM-002, DSM-003).
