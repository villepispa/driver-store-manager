# Safety gates — Driver Store Manager

Driver package removal can **disable hardware** or **prevent boot** if done carelessly.
These gates are enforced in code and must not be bypassed without a documented exception.

## Gate 1 — Inventory freshness

Before any delete operation, inventory must be collected in the **same session** (or within
a documented max age, default 15 minutes). `Remove-DsmUnusedDriverPackages` re-inventories
unless `-Inventory` is passed with a `CollectedAt` timestamp inside the window.

## Gate 2 — In-use packages are never deleted (default path)

Packages with `DeviceAssociation = Connected`, `InUse -eq $true`, or
`ConnectedDeviceCount -gt 0` are **excluded** from deletion.
Packages with `DeviceAssociation = DisconnectedInstalled` are also **excluded**
(installed but unplugged — e.g. printers, external USB). Only `NeverAssociated`
packages are default orphan candidates (subject to preserve policy in Phase 3c).

The cmdlet logs skipped packages as `SkippedInUse` or `SkippedDisconnectedInstalled`.

`/force` is **not exposed** in the public cmdlet surface.

## Gate 3 — Export before delete

Every package slated for removal is exported with:

```cmd
pnputil /export-driver <PublishedName> <BackupRoot>\<PublishedName>\
```

If export fails, delete is **aborted** for that package.

Default backup root: `backups/<yyyy-MM-dd_HHmmss>/` under the product repo (gitignored).

Keep large `pnputil /export-driver` trees and `audit-output/` on a **fast local disk**.
Do not sync multi-GB export folders through cloud sync clients (for example Proton Drive)
— they are gitignored for a reason and will thrash sync bandwidth.

## Gate 4 — Dry-run default

`Remove-DsmUnusedDriverPackages`:

- Supports `-WhatIf` (default **on** via `SupportsShouldProcess`)
- Requires `-Confirm:$false` **and** `-AllowDelete` to perform actual deletion

## Gate 5 — Administrator elevation

Deletion and export to system-protected locations require an elevated `pwsh` session.
Non-elevated calls return `ERROR_ELEVATION_REQUIRED` with remediation text.

## Gate 6 — Operator allow-list (optional)

`-IncludePublishedName` accepts explicit `oem#.inf` names. When provided, only those
packages are considered — still subject to Gates 2–5.

## Gate 6a — Filter + preserve (report-aligned)

Cleanup uses `Get-DsmDriverStoreCleanupPlan`: OEM scope, optional `Invoke-DsmDriverFilter`
criteria, then `Invoke-DsmPreservePolicy`. Only `NeverAssociated` non-preserved packages
in the **scoped** set are delete candidates (same as report `DeletableCandidateCount`).

## Gate 6b — Preserve policy

Packages with `Preserved = $true` (from `Invoke-DsmPreservePolicy`) are **never**
deleted. Preserve is independent of `InUse` — protects latest DisplayLink per family,
printer queue drivers, unplugged USB packages per operator rules.
See `examples/preserve-rules.example.json`.

## Gate 7 — Vulnerability scan is advisory

`Test-DsmDriverVulnerabilities` **never** auto-deletes blocklisted drivers.
It adds `RiskSignals` for human or SOAR review.

## Incident rollback

1. Locate export under `backups/<timestamp>/`
2. Re-add package: `pnputil /add-driver <exported.inf> /install`
3. Reboot if prompted

## What this tool does NOT do

- Replace WDAC or Memory integrity enforcement
- Guarantee CVE completeness
- Remove **Windows built-in** driver manifests (default scope is `oem#.inf` only; use `-IncludeWindowsBuiltIn` for built-in names)
