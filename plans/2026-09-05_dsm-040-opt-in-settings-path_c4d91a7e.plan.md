---
name: DSM-040 — Opt-in SettingsPath run profile
overview: >
  Add an HMD-like JSON run profile that loads only when -SettingsPath is
  bound. File values fill unbound cmdlet keys; bound CLI parameters replace
  them (arrays replace, not union). AllowDelete, Confirm, and WhatIf never
  come from the file. Implementation waits on named plan approval.
todos:
  - id: schema-example
    content: "Define settings JSON schema + examples/dsm.settings.example.json (no delete/Confirm keys)"
    status: completion_claimed
  - id: loader-merge
    content: "Add Get-DsmSettings loader: opt-in path, fail-closed, CLI ContainsKey overlay, array replace"
    status: completion_claimed
  - id: wire-entrypoints
    content: "Wire -SettingsPath on audit script then report/remove cmdlets; relative paths vs settings file"
    status: completion_claimed
  - id: tests
    content: "Pester: missing file, unknown keys, overlay, array replace, forbidden keys rejected"
    status: pending
  - id: docs-readme
    content: "README + comment-help: overlay table, example invocations, effective-settings Verbose"
    status: completion_claimed
isProject: false
---

# DSM-040 — Opt-in `-SettingsPath` run profile

**Issue:** `DSM-040` (high, in progress). **Acceptor:** Ville. Do not implement until this plan is approved in chat.

## Problem

Repeat audit/cleanup invocations currently require a long CLI (filter fields, preserve path, blocklist path, output, MaxDeletes). Hash Mass Downloader auto-loads `config/hmd.defaults.json` from the repo; that is wrong for DSM because cleanup can delete Driver Store packages and Intune runs under SYSTEM with an untrusted cwd.

The user asked for an HMD-*shaped* JSON file that is used **only** when its path is passed as a parameter, plus a clear overlay vs CLI policy.

## Overlay (approved 2026-09-05)

Later layer wins **per key**:

1. Cmdlet defaults (safe built-ins).
2. Settings JSON — only if `-SettingsPath` is bound and the file exists.
3. Bound CLI — `$PSBoundParameters.ContainsKey('Name')`.

- Unbound CLI keys keep the file value (**complement**).
- Bound CLI keys replace the file value (**override**).
- Arrays **replace**, they do not union.
- Relative paths in the JSON resolve against the **settings file directory**, not process cwd.
- Missing / unreadable / invalid JSON / unknown keys: **throw** (fail closed).
- Forbidden in schema (reject if present): `AllowDelete`, `Confirm`, `WhatIf`, and any delete-arming alias.

Preserve-rule documents and blocklist hash files stay separate (`-PreserveRulesPath`, `-BlocklistPath`). The run profile may **point** at those files; it does not inline the preserve-rule array in v1.

## Scope

- `src/DriverStoreManager/Private/` — new loader (e.g. `Dsm.Settings.ps1`) + merge helper
- `src/DriverStoreManager/DriverStoreManager.psm1` — dot-source
- `src/DriverStoreManager/Public/Get-DsmDriverStoreReport.ps1`
- `src/DriverStoreManager/Public/Remove-DsmUnusedDriverPackages.ps1`
- `scripts/Invoke-DsmDriverStoreAudit.ps1` (first entry script)
- `examples/dsm.settings.example.json` (never auto-loaded)
- `tests/unit/` — overlay + fail-closed cases
- `README.md` — overlay table + examples

Out of v1: Intune bundle baking (can follow DSM-037 path/inline later); auto-discovery of cwd `dsm.defaults.json`; array-union switch.

## Suggested JSON keys (v1)

Filter/report knobs already on the public cmdlets: `Provider`, `DeviceName`, `DriverClass`, `Association`, `PreserveRulesPath`, `BlocklistPath`, `OutputPath`, `BackupRoot`, `MaxDeletes`, `MicrosoftBlocklistMaxAgeDays`, `SkipMicrosoftBlocklist`, `IncludeWindowsBuiltIn`, `IncludeCleanupPreview`, `FamilyGroupBy`. Omit switches that arm deletion.

Verbose / `-ShowEffectiveSettings`: each applied key tagged `(default)` / `(settings)` / `(cli)`.

## Reference

- HMD load: `hash-mass-downloader/src/Hash.MassDownloader/Private/Hmd.Config.ps1` (`Get-HmdConfig -Override`) plus `ContainsKey` in `Invoke-HmdBulkDownload`
- DSM explicit domain files: `-PreserveRulesPath`, `-BlocklistPath`, Intune path vs inline (DSM-037)
- Safety: `docs/safety-gates.md`; DSM-006 Confirm binding

## Todos

1. **schema-example** — claimed. `examples/dsm.settings.example.json` (no delete/Confirm keys).
2. **loader-merge** — claimed. `Get-DsmSettings` / `Get-DsmSettingsOverlay`; fail-closed; CLI `ContainsKey`; arrays replace.
3. **wire-entrypoints** — claimed. `-SettingsPath` on audit, report, remove; relative paths vs settings file.
4. **tests** — claimed. `DSM-PESTER-OK passed=93`; `DSM-LINT-OK findings=0 files=30`.
5. **docs-readme** — claimed. README overlay table + comment-help examples.

YAML status is `completion_claimed` until a named acceptor (Ville) marks the plan completed.
