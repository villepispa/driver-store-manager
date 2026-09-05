# Driver Store Manager — issue register

This register tracks actionable findings for the project. The corresponding
machine-readable task state is `.cursor/project-management.json`.

Product IDs use the `DSM-` prefix. Release notes live in [CHANGELOG.md](../CHANGELOG.md)
(Keep a Changelog + SemVer).

## Workflow

- **Status:** `Open` → `In progress` → `Resolved` → `Verified`
- **Severity:** `High`, `Medium`, or `Low`
- Keep issue identifiers stable in commits, tests, and release notes.
- Add resolution evidence before changing an issue to `Verified`.

## Open issues

None.

## Resolved issues (2026-09-05 — 0.8.2 — DSM-039)

| ID | Summary | Evidence |
|----|---------|----------|
| DSM-039 | Align Pester layout with `hash-mass-downloader` (`tests/unit/`) | `DSM-PESTER-OK passed=83`; PCB `2026-09-05_tests-unit-layout` |

### DSM-039 — Pester suites under `tests/unit/`

- **Status:** Resolved
- **Severity:** Low
- **Area:** Tests / agent-ready layout
- **Impact:** Suites sat next to helpers, fixtures, and `_drafts`; a raw
  `Invoke-Pester -Path .\tests` could pick up drafts. Sibling products keep
  suites in `tests/unit/` and the runner at `tests/Invoke-<Prefix>Pester.ps1`.
- **Remediation:** Move `*.Tests.ps1` into `tests/unit/`; point runner default
  at that folder; keep helpers and fixtures at `tests/helpers/` and
  `tests/fixtures/`.
- **Evidence:** `pwsh -NoProfile -File .\tests\Invoke-DsmPester.ps1 -AgentSummary` → `DSM-PESTER-OK passed=83` (2026-09-05).
- **Resolution:** Layout + path updates 2026-09-05; PCB `2026-09-05_tests-unit-layout`.

## Resolved issues (2026-09-01 — 0.8.1 — DSM-036 / DSM-038)

| ID | Summary | Evidence |
|----|---------|----------|
| DSM-036 | Align PSA gate with WGA/spine (fail on Warning) | `DSM-LINT-OK findings=0`; `DSM-VALIDATE-OK`; README Validate notes Error+Warning |
| DSM-038 | Single-row pnputil CSV unwraps; PS 5.1 StrictMode `.Count` throws | Dual-host `Pester (powershell)` failed; local 5.1 `DSM-PESTER-OK passed=82` (1 inconclusive); pwsh **83/83**; wrap `@()` in `ConvertFrom-PnPUtilDriverCsv` |

### DSM-036 — PSA Warning-fail to match siblings

- **Status:** Resolved
- **Severity:** Low
- **Area:** Agent-ready gates / PSScriptAnalyzer
- **Impact:** Validate is softer than WinGet.Audit / spine-automation until Warnings are triaged
- **Proposed:** Fix or exclude cheap findings; then fail lint on Warning as well as Error
- **Remediation:** Fail on any Error/Warning. Exclude `PSAvoidUsingWriteHost` and `PSUseSingularNouns`. Fix unused detect knobs (Verbose advisory), empty catch, unused pipeline attributes, default-on switch → `[bool]`.
- **Evidence:** `DSM-LINT-OK findings=0 files=29`; `DSM-VALIDATE-OK` (Pester 83/83; PS 5.1 smoke OK).
- **Resolution:** Source + settings + README 2026-08-31; PCB `2026-08-31_dsm-036-psa-warning-fail`.

### DSM-038 — Single-row driver CSV Count under StrictMode

- **Status:** Resolved
- **Severity:** Medium
- **Area:** Inventory / PS 5.1
- **Evidence:** GitHub Actions `Pester (powershell)` — `Produces cleanup preview for never-associated fixture package`; `Dsm.Common.ps1:186`. Local: 5.1 `DSM-PESTER-OK passed=82`; pwsh **83/83**.
- **Impact:** One `oem#.inf` data row made `ConvertFrom-DsmCsvText` unwrap to a scalar; `.Count` is missing on PSCustomObject under PS 5.1 StrictMode. Inventory (and Intune detect) can throw instead of returning one package.
- **Remediation:** `$rows = @(ConvertFrom-DsmCsvText -Lines @($lines))`. Unit test under `Set-StrictMode -Version Latest`.
- **Resolution:** Source + unit test 2026-08-31; rebuild `dist/intune` after Pester.

## Resolved issues (2026-08-31 — 0.8.0 — DSM-034 / DSM-035 / DSM-037)

| ID | Summary | Evidence |
|----|---------|----------|
| DSM-037 | Parameterize Intune build; rename `data/` to `examples/` | Pester **82/82** (`Build-DsmIntuneScripts.Tests.ps1` 5/5); `DSM-BUILD-OK` detectBytes=176798 config=none |
| DSM-034 | Repo-root validate trio (PSA settings, ScriptAnalyzer, `Invoke-DsmValidate`) | Local `DSM-VALIDATE-OK` (Pester 77/77, lint findings=46 errors=0 files=29) |
| DSM-035 | Dual-host GitHub Actions (`dual-host-ps.yml`) | Workflow present; Pester via product runner (Pester 6+); smoke builds then `Invoke-DsmPs51SmokeTest.ps1` |

### DSM-037 — Intune build configuration and examples folder

- **Status:** Resolved
- **Severity:** Medium
- **Area:** Intune / build
- **Evidence:** `tests/Build-DsmIntuneScripts.Tests.ps1`; `DSM-PESTER-OK passed=82`; default `dist/intune` rebuild
- **Remediation:** Build-time knobs; path-only vs inline config files; `data/` renamed to `examples/`; preserve inline also baked into Remediation

### DSM-034 — Validate trio

- **Status:** Resolved
- **Severity:** Low
- **Area:** Agent-ready gates
- **Evidence:** `pwsh -NoProfile -File .\scripts\Invoke-DsmValidate.ps1 -AgentSummary` → `DSM-VALIDATE-OK` (2026-08-18). First run failed lint on `$Error` param; after rename, Error count 0. Lint fails on **Error** only.
- **Remediation:** Product PSA settings + orchestrator (Safety tier 2 because build writes `dist/intune`)

### DSM-035 — Dual-host CI

- **Status:** Resolved
- **Severity:** Low
- **Area:** CI
- **Evidence:** `.github/workflows/dual-host-ps.yml` (not yet proven on GitHub runners)
- **Remediation:** Copy of dual-host template customized for `tests/Invoke-DsmPester.ps1` and Intune build-before-smoke

## Resolved issues (2026-07-28 — DSM-033)

| ID | Summary | Evidence |
|----|---------|----------|
| DSM-033 | Intune detect / vuln scan read `Preserved` under `Set-StrictMode` before preserve annotations exist | `Get-DsmObjectPropertyValue` in orphan/deletable helpers + listings; `InModuleScope` regression; detect exits `0`/`1` without `PropertyNotFoundStrict` |

### DSM-033 — StrictMode `Preserved` missing during vulnerability orphan check

- **Status:** Resolved
- **Severity:** High
- **Area:** Intune detection / StrictMode
- **Evidence:** `Test-DsmDriverVulnerabilities` → `Test-DsmPackageIsOrphanCandidate` before `Measure-DsmDriverStoreScope` / `Initialize-DsmPreserveAnnotations`; stack from interactive `Detect-DsmDriverStoreCompliance.ps1`
- **Impact:** Detection always failed with exit `2` (`PropertyNotFoundStrict`) whenever vulnerability scan ran (default Intune detect path)
- **Remediation:** Treat missing `Preserved` as `$false` via `Get-DsmObjectPropertyValue`; harden related `Where-Object` / cleanup result rows
- **Resolution:** Source + `dist/intune` patched 2026-07-28; interactive detect completed without property error (exit `1` = orphans ≥ threshold on this host)

## Resolved issues (2026-07-13 — DSM-026 / DSM-027)

| ID | Summary | Evidence |
|----|---------|----------|
| DSM-026 | PS 5.1 smoke under `Set-StrictMode`; mocked correlation, blocklist XML, preserve JSON, UTF-8 no-BOM, bundle headers, detection/remediation gates | `scripts/Invoke-DsmPs51SmokeTest.ps1`; strict-mode fixes in `Dsm.Common.ps1`, `Dsm.Preserve.ps1`, `Dsm.Filter.ps1`, `Dsm.Report.ps1`, `Dsm.Cleanup.ps1` |
| DSM-027 | Mocked deletion/export regression coverage (elevation, success, export failure, delete failure, `MaxDeletes`) | `tests/DriverStoreManager.CleanupMocks.Tests.ps1`; 76/76 Pester pass via `tests/Invoke-DsmPester.ps1` |

## Resolved issues (2026-07-12 batch)

Resolved in module **v0.7.8**. Evidence: `tests/Invoke-DsmPester.ps1` (71/71 pass),
rebuilt `dist/intune/*.ps1`.

| ID | Summary |
|----|---------|
| DSM-002 | Detection triggers remediation only for orphan cleanup (Gate 7 advisory). |
| DSM-003 | Blocklist tests use `$TestDrive` via `$script:DsmMicrosoftBlocklistRootOverride`. |
| DSM-004 | `Assert-DsmInventoryProvenance` + `InventorySource = ModuleInventory`. |
| DSM-005 | `Update-DsmPackageDeletionEligibility` before each export/delete. |
| DSM-006 | Requires explicit `-Confirm:$false` in `$PSBoundParameters`. |
| DSM-007 | Remediation exits `2` when `ExportOrDeleteFailedCount` > 0. |
| DSM-008 | `ScanState` / `BlocklistDataAvailable`; detection exits `2` when unavailable. |
| DSM-009 | `Get-DsmDriverFileHashes` uses ConfigCI Authenticode SHA-256 when present. |
| DSM-010 | `UnknownError` → `SignatureIndeterminate`; only `Valid` is acceptable. |
| DSM-012 | Empty `-BlocklistHashes` respects `$PSBoundParameters.ContainsKey`. |
| DSM-013 | `SkippedInUse` / `SkippedDisconnectedInstalled` rows from plan exclusions. |
| DSM-014–021 | INF encoding, resilience, path trust, token recursion, cache invalidation. |
| DSM-022 | `Initialize-DsmPreserveAnnotations` in `Measure-DsmDriverStoreScope`. |
| DSM-023 | TLS 1.2 around blocklist download with restore. |
| DSM-024 | Async stdout/stderr read + 600s timeout in `Invoke-DsmPnPUtil`. |
| DSM-025 | Explicit UTF-8 no-BOM via `UTF8Encoding` on all hosts. |
| DSM-028 | `tests/Invoke-DsmPester.ps1` version-aware runner; README updated. |
| DSM-029 | Mocked e2e copies fixtures to `$TestDrive`. |
| DSM-030 | `ConvertFrom-DsmCsvText` for driver enum CSV. |

## Resolved issues (earlier)

### DSM-001 — Device-correlation failure becomes deletion eligibility

- **Status:** Verified
- **Severity:** High
- **Area:** Cleanup safety
- **Evidence:** `Private/Dsm.Common.ps1:49`;
  `Private/Dsm.DeviceCorrelation.ps1:230-232,270-277`
- **Requirement:** `safety-gates.md` Gate 2
- **Impact:** Failed or empty `pnputil` correlation maps unmatched packages to
  `NeverAssociated`, allowing installed or connected drivers to reach deletion.
- **Remediation:** Fail closed with an explicit `Unknown` association and abort
  cleanup when correlation fails or its schema is invalid.
- **Resolution:** Modified `Get-DsmDeviceDriverCorrelation` to return `$null` on failure, and updated `Add-DsmDeviceCorrelationToInventory` to check for `$null` correlation (or explicit `$null` parameter binding) and fail closed by marking all packages with `DeviceAssociation = 'Unknown'`. Added unit tests in `DriverStoreManager.Tests.ps1` to assert that failed correlation results in `Unknown` association, which prevents packages from being classified as orphan or deletable candidates.

### DSM-011 — Space-containing backup paths break pnputil arguments

- **Status:** Verified
- **Severity:** Low
- **Area:** Backup execution
- **Evidence:** `Private/Dsm.Common.ps1`
- **Requirement:** `safety-gates.md` Gate 3
- **Impact:** Unquoted arguments split documented backup paths containing
  spaces, preventing export and remediation; deletion remains aborted.
- **Remediation:** Apply correct Windows command-line quoting to every argument.
- **Resolution:** Added `ConvertTo-DsmWindowsArgumentString` and now quote every
  argument before assigning `ProcessStartInfo.Arguments`. Added unit coverage in
  `tests/DriverStoreManager.Tests.ps1` for space-containing path quoting.

### DSM-017 — Semicolons inside quoted INF labels are truncated

- **Status:** Verified
- **Severity:** Medium
- **Area:** INF label parsing
- **Evidence:** `Private/Dsm.InfMetadata.ps1`
- **Impact:** The parser treats a semicolon in a quoted label as a comment delimiter.
- **Remediation:** Strip comments only outside quoted segments; cover semicolons and escaped quotes.
- **Resolution:** Added `Remove-DsmInfInlineComment` and switched
  `Get-DsmInfParsedValue` to use it. Added regression tests for semicolon-bearing
  quoted labels in `tests/DriverStoreManager.Tests.ps1`.

### DSM-031 — pnputil non-zero exit could be suppressed when output file is used

- **Status:** Verified
- **Severity:** High
- **Area:** pnputil execution safety
- **Evidence:** `Private/Dsm.Common.ps1`
- **Impact:** Failed `pnputil` commands could continue with partial or stale output
  when `/output-file` was used.
- **Remediation:** Fail on all non-zero exit codes and report stderr/stdout details.
- **Resolution:** `Invoke-DsmPnPUtil` now throws on any non-zero exit code, with
  normalized error text from stderr or stdout.

### DSM-032 — INF `[Strings]` section parsing was case-sensitive

- **Status:** Verified
- **Severity:** Low
- **Area:** INF metadata parsing
- **Evidence:** `Private/Dsm.InfMetadata.ps1`
- **Impact:** INF files using `[STRINGS]` or mixed-case section names could lose
  metadata-derived labels.
- **Remediation:** Match `[Strings]` section names case-insensitively.
- **Resolution:** Updated string section detection to use case-insensitive
  comparison and added regression coverage in `tests/DriverStoreManager.Tests.ps1`.

## Activity

<!-- ISSUES-ACTIVITY+ -->
- **2026-08-31 17:00:00** — Resolved `DSM-038`: wrap single-row CSV parse in `@()` so PS 5.1 StrictMode `.Count` does not throw (`Pester (powershell)` CI).
- **2026-08-31 13:12:00** — Resolved `DSM-037`: parameterized Intune build (path vs inline config); `data/` → `examples/`; **82/82** Pester; `DSM-BUILD-OK`.
- **2026-08-31 12:50:00** — Filed `DSM-037`: parameterized Intune build (path vs inline config) and `data/` → `examples/` rename.
- **2026-07-28 07:40:40** — Resolved `DSM-033`: StrictMode-safe `Preserved` reads for orphan/deletable helpers; detect no longer throws `PropertyNotFoundStrict` on vuln scan path. Follow-up: sealed build/Pester, rebuilt bundles, **77/77** Pester (`DriverDate`/HashSet/`PassThru` hardening).
- **2026-07-28 07:12:21** — Reconciled PM state drift: `DSM-027` and Reliability milestone marked `done` in `.cursor/project-management.json` (canonical register already had no Open issues).
- **2026-07-13 17:04:00** — Resolved `DSM-026` and `DSM-027`: expanded PS 5.1 smoke (`Set-StrictMode`, mocked correlation/XML/preserve/UTF-8/bundles); added `DriverStoreManager.CleanupMocks.Tests.ps1`; strict-mode hardening across CSV, preserve, filter, report, and cleanup modules; 76/76 Pester pass; PS 5.1 smoke PASS.
- **2026-07-12 21:07:29** — Implemented safety, INF, Intune, and test fixes for `DSM-002`–`DSM-013`, `DSM-014`–`DSM-025`, `DSM-028`–`DSM-030`; 71/71 Pester tests pass via `tests/Invoke-DsmPester.ps1`; Intune bundles rebuilt.
- **2026-07-12 20:43:00** — Resolved `DSM-011`, `DSM-017`, `DSM-031`, and `DSM-032`; hardened `pnputil` execution (quoting + non-zero exit handling) and INF parsing (`[Strings]` case-insensitivity and quoted semicolon-safe comments), with new regression tests.
- **2026-07-12 20:30:00** — Resolved and verified `DSM-001`. Aligned report/orphan and filter fallback logic on empty DeviceAssociation.
- **2026-07-10 13:47:36** — Added `DSM-014`–`DSM-030` from focused PS 5.1,
  INF metadata, and test-path static review; findings do not duplicate
  `DSM-001`–`DSM-013`.
- **2026-07-10 13:26:06** — Imported `DSM-001`–`DSM-013` from the cleanup and
  vulnerability-path review against `safety-gates.md` and `lessons-learned.md`.
