# Intune deployment — Driver Store Manager

Proactive Remediation on Windows endpoints runs scripts in **Windows PowerShell 5.1**
(64-bit, **SYSTEM**). Module source is maintained once; standalone upload scripts are
**generated** — do not hand-edit files under `dist/intune/`.

## Build standalone scripts

On a dev machine (PS 5.1 or PS 7+):

```powershell
cd projects\driver-store-manager
.\scripts\Build-DsmIntuneScripts.ps1
```

Outputs:

| File | Role |
|------|------|
| `dist/intune/Detect-DsmDriverStoreCompliance.ps1` | Detection script |
| `dist/intune/Remediate-DsmDriverStore.ps1` | Remediation script |

Source merge order: `scripts/intune/bundle-order.json`. Entry logic:
`scripts/intune/templates/Detect-DsmDriverStoreCompliance.Entry.ps1` and
`Remediate-DsmDriverStore.Entry.ps1`.

After changing module source, rebuild and re-upload to Intune.

## Local build and test

Quick path (also summarized in the [README](../README.md#intune--build-and-test-locally)):

```powershell
.\scripts\Build-DsmIntuneScripts.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-DsmPs51SmokeTest.ps1
```

Optional live detection (writes ProgramData reports; does not delete drivers):

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\dist\intune\Detect-DsmDriverStoreCompliance.ps1
$LASTEXITCODE   # 0 compliant | 1 non-compliant | 2 error
```

Do **not** casually run `Remediate-DsmDriverStore.ps1` on a daily driver — it deletes
orphans. Preview with `Remove-DsmUnusedDriverPackages -WhatIf` first.

## Intune portal settings

| Setting | Value |
|---------|--------|
| Run this script using logged-on credentials | **No** (SYSTEM) |
| Run script in 64-bit PowerShell | **Yes** |
| Detection script | `Detect-DsmDriverStoreCompliance.ps1` |
| Remediation script | `Remediate-DsmDriverStore.ps1` |

Schedule: start with **weekly** detection; pilot remediation on a test collection only.

## Exit codes

### Detection

| Code | Meaning |
|------|---------|
| `0` | Compliant — no remediation triggered |
| `1` | Non-compliant — remediation runs |
| `2` | Error (check `%ProgramData%\DriverStoreManager\reports\`) |

Default non-compliant when **orphan cleanup** is required: `DeletableCandidateCount` ≥
`$DsmOrphanThreshold` (default 1). Blocklist and signature findings remain **advisory**
(report only) and do not trigger remediation (Gate 7). Detection exits `2` when required
blocklist data is unavailable (`VulnerabilityManifest.ScanState = Unavailable`).

### Remediation

| Code | Meaning |
|------|---------|
| `0` | Completed (including zero candidates) |
| `2` | Error, missing elevation, or export/delete failures |

Remediation removes **NeverAssociated** orphan candidates only, export-before-delete,
max `$DsmRemediationMaxDeletes` (default 10) per run. Does not use `pnputil /force`.

## On-endpoint state

```text
%ProgramData%\DriverStoreManager\
  reports\intune-detection\detection-summary_*.json
  reports\intune-remediation\remediation-summary_*.json
  backups\<timestamp>\<oem#.inf>\
```

## PowerShell version strategy

| Host | Support |
|------|---------|
| **PS 5.1** (Intune) | Baseline — all bundled code must run here |
| **PS 7+** (dev / audit) | Preferred for interactive use; same module API |

Runtime helpers in `Dsm.Runtime.ps1`:

- `Test-DsmIsPowerShellCore` / `Test-DsmIsWindowsPowerShell51`
- `Join-DsmPath` — multi-segment paths (PS 5.1 `Join-Path` limitation)
- `Set-DsmContentUtf8` — UTF-8 writes on both editions
- `Get-DsmProgramDataRoot` — Intune state directory

When adding features: implement PS 5.1-safe path first; gate PS 7-only optimizations:

```powershell
if (Test-DsmIsPowerShellCore) {
    # PS 7+ enhancement (e.g. parallel, utf8NoBOM default)
}
```

Avoid in shared code: `??`, ternary `? :`, `ForEach-Object -Parallel`, chained
`Join-Path` with more than one child.

## Pilot checklist

1. Build scripts; verify byte size (Intune script size limits — monitor if module grows).
2. Deploy **detection only** to pilot group; review JSON summaries on a sample device.
3. Confirm `oem159.inf`-style staged packages appear in inventory (not confused with built-in).
4. Deploy remediation to isolated VMs; verify backups under `ProgramData` before production.
5. Re-run detection — confirm orphan count drops as expected.

## Blocklist in Intune

Bundle a blocklist file via a separate Intune win32/package delivery, or host on a
read-only SMB share. Set `$DsmBlocklistPath` for **supplemental** hashes merged with the
auto-updated Microsoft cache (downloaded from `https://aka.ms/VulnerableDriverBlockList`
into `%ProgramData%\DriverStoreManager\blocklist\microsoft\` every 7 days).

Detection uses the Microsoft cache by default; optional `$DsmBlocklistPath` adds more hashes.
Use `$DsmSkipMicrosoftBlocklist = $true` in a customized template for offline-only feeds.

Compliance checks (detection script):

| Flag | Summary metric |
|------|----------------|
| `$DsmDetectBlocklisted` | `BlocklistedInUseCount` > 0 |
| `$DsmDetectSignatureIssues` | `SignatureIssueCount` > 0 |
| `$DsmDetectOrphanCandidates` | `DeletableCandidateCount` ≥ threshold |

All metrics come from `Get-DsmDriverStoreReport` — same schema as `Invoke-DsmDriverStoreAudit.ps1`.

## Related

- [safety-gates.md](safety-gates.md) — deletion gates
- [architecture.md](architecture.md) — PS 5.1 / export / future extensions
