# Driver Store Manager — lessons learned

Captured after phases 1–6c and INF metadata enrichment (module **v0.7.7**, July 2026).
Use this when extending DSM, onboarding contributors, or feeding agent documentation.

**Companion (private Cursor config workspace — not shipped with this repo):**

- `<config-workspace>/docs/powershell/powershell.md` — topic hub (principles → methods → adaptation)
- `<config-workspace>/docs/principles/powershell-coding-principles.md` — module layout, safety gates, testing, agent workflow
- `<config-workspace>/docs/powershell/powershell-dual-host-guide.md` — PS 5.1 / Intune host pitfalls
- `<config-workspace>/docs/agent/agent-file-operations-guide.md` — Read/StrReplace/Shell discipline for agents
- `<config-workspace>/skills/powershell-coding/SKILL.md` — agent skill entry point

---

## 1. Journey summary

| Phase | Outcome |
| ----- | ------- |
| **1–2** | Workspace scaffold, architecture, safety gates |
| **3a–3d** | Inventory (`pnputil` CSV), filters, preserve policy, reports |
| **4** | Vulnerability signals (blocklist, Authenticode, orphans) in report |
| **5** | Filter + preserve aware cleanup (`-WhatIf`, export backup) |
| **6** | Pester suite, `Invoke-DsmDriverStoreAudit.ps1` |
| **6b** | PS 5.1 baseline, Intune single-file bundles |
| **6c** | Mocked `pnputil` e2e, PS 5.1 smoke script |
| **Post-6** | INF metadata (`DiskId`, `DisplayName`, `LabelSource`), catalog **118 → 160/160** labeled |

**Origin:** Private Windows security workspace plan (2026-06-15). Redacted Cursor
export kept locally under `docs/archive/` (gitignored). Living summary: § 1.1 below.

### 1.1 v0.1 scaffold session (2026-06-15)

Absorbed from the archived Cursor export (Cursor **3.7.40**):

| Fact | Detail |
| ---- | ------ |
| **Initial surface** | `Get-DsmDriverStoreInventory`, `Test-DsmDriverVulnerabilities`, `Remove-DsmUnusedDriverPackages` + `Invoke-DriverStoreAudit.ps1` |
| **Tooling triad** | Host had `pnputil.exe`, `driverquery.exe`, and `Get-WindowsDriver` (DISM); module spine = **`pnputil`** |
| **Parser bug** | First inventory pass returned **0** packages — `pnputil /format csv` is **UTF-16**; encoding + column map fixed |
| **Smoke** | **158** packages on the development host; Pester **3/3** (v3-compatible suite at the time) |
| **Git** | Parent workspace repo initialized; default branch renamed **`master` → `main`** |
| **Original backlog intent** | Harden blocklist/signature scan; e2e cleanup on a test VM; optional SOC HTML/JSON + Intune wrapper (later work reused some `DSM-*` IDs for different defects — see [issues.md](issues.md)) |
| **Storage** | `backups/` and `audit-output/` gitignored; large driver exports should stay on a fast local disk — avoid syncing multi-GB trees through cloud sync (e.g. Proton Drive) |

---

## 2. Domain lessons (Windows Driver Store)

### 2.1 `pnputil` is the spine — but incomplete alone

- **CSV encoding:** `/format csv` output is often **UTF-16 LE**. Parser must detect BOM before splitting lines. The v0.1 scaffold failed open with **zero packages** until encoding was fixed (see § 1.1).
- **Column drift:** Header names differ across Windows builds (`InstanceId` vs `Instance ID`, duplicate `DriverName`). Normalize with alias maps; test against golden fixtures.
- **File lists gap:** `/enum-drivers /files` is sometimes empty or partial. Do not assume `FileRepository` correlation always works from inventory alone.

### 2.2 INF metadata lives in more places than `DiskId`

Operator-readable names are scattered across INF sections. A single-key parser (`DiskId` only) left **42/160** packages unlabeled on a real host.

| Location | Examples | Notes |
| -------- | -------- | ----- |
| `[Strings]` | `DeviceDesc`, `.DisplayName`, `ExtensionDesc`, `Location`, `DISK_NAME`, `SERVICE_DESC` | Strip `;` comments and `{PlaceHolder=…}` **before** parsing quoted segments |
| `[Manufacturer]` model lines | `%CAMERA.DeviceDesc%=…, USB\…` | Distinguish **install lines** (HWID/SWC path) from **section declarations** (`%ATI% = ATI.Mfg, NTamd64…`) |
| Quoted model lines | `"Thunderbolt(TM) HSA Component" = …, SWC\…` | Common in SoftwareComponent INFs; not `%token%` syntax |
| `[OEMInf] VerifyMark` | Sunplus camera verify strings | Good fallback when disk keys are generic |
| `%WINDIR%\INF\oem#.inf` | Published copy | Often exists when FileRepository correlation fails |
| FileRepository by `OriginalName` | `heci.inf_amd64_…\heci.inf` | Tie-break duplicates with `DriverVer` vs inventory version |

**Cascade beats one field:** `Get-DsmInfFriendlyLabel` uses priority order + `LabelSource` for auditability. **Coverage ≠ quality:** 160/160 labeled still had **10 weak labels** until DisplayName / quoted-model / PS unwrap fixes.

### 2.3 Safety is policy, not a cmdlet flag

- **Orphan detection** must align with report math — divergent logic caused false cleanup candidates.
- **Preserve policy** is independent of `InUse`; “latest in family” and “keep named oem” are operator contracts.
- **Never `/force` delete** in default paths; export backup before removal.
- Document signals (blocklist, bad signature) as **signals**, not CVE verdicts.

### 2.4 FileRepository has many copies of the same `OriginalName`

Intel/AMD graphics stacks stage multiple `iigd_ext.inf` / `cui_dch.inf` folders. Resolve package → folder by:

1. Correlating `pnputil` file name hits (score directories)
2. Tie-breaking with **INF `DriverVer`** vs inventory `DriverVersion`

Wrong folder → wrong `DriverVer` on cleanup rows and false “superseded by newer in-use sibling” context.

---

## 3. PowerShell lessons

### 3.1 Dual host: PS 7 dev, PS 5.1 Intune

| Concern | Pattern |
| ------- | ------- |
| **Target** | `#Requires -Version 5.1` on module + Intune bundles |
| **Dev default** | PS 7 (`pwsh`) in Cursor agent terminal |
| **Validation** | Run Pester **and** `Invoke-DsmPs51SmokeTest.ps1` on **both** hosts before Intune rebuild |
| **Path join** | `Join-DsmPath` — PS 5.1 `Join-Path` accepts only one child |
| **UTF-8 write** | `Set-DsmContentUtf8` — BOM / `-NoNewline` differences |
| **Unicode in source** | PS 5.1 parser choked on em-dash in markdown export — keep report templates ASCII-safe or gate by host |

### 3.2 Single-element array unwrapping (critical bug class)

PowerShell unwraps **single-element arrays** to scalars. Indexing a string with `[0]` returns the **first character**:

```powershell
$mfg = Get-DsmInfStringKeysByPattern ...   # one match → "Intel"
$mfg[0]                                     # → 'I'  (char), not "Intel"
```

**Fix:** always force array context before indexing:

```powershell
$mfg = @(Get-DsmInfStringKeysByPattern ...)
$label = [string]$mfg[0]
```

Helpers: `Get-DsmObjectArray`, `Write-DsmObjectArray` in `Dsm.Runtime.ps1`.

**Test on PS 5.1** — PS 7 dev sessions may mask this if behavior differs or tests always use `@()` wrappers.

### 3.3 Inline `pwsh -Command` escaping

One-liners with `$_.Name`, `$( $c.Count )`, or nested quotes fail unpredictably when the outer shell expands variables. **Prefer:**

- `pwsh -NoProfile -File scripts/…ps1` for probes and summaries
- `scripts/_drafts/` for ad-hoc scripts until promoted

### 3.4 Test harness vs `Import-Module`

Pester suites live under `tests/unit/` (runner: `tests/Invoke-DsmPester.ps1`). Dot-source `tests/helpers/Import-DsmTestHarness.ps1` in **`BeforeAll`** (not at file top). Pester 6 discovers and runs each `*.Tests.ps1` in isolation — top-level dot-sourcing no longer runs before test execution. Shared package builders live in `tests/helpers/DsmTestFixtures.ps1`. Golden `pnputil` CSV lives in `tests/fixtures/`.

Use **`Should-Be`** / **`Should -Not -Throw`** (dashed operators). Bare `Should Be` fails on Pester 6 with a parameter-set error.

Dot-sourcing private scripts via `tests/helpers/Import-DsmTestHarness.ps1` avoids double-loading and matches Intune bundle order. Mocked `pnputil` e2e uses the same harness + fixture CSVs.

---

## 4. Agent / automation lessons

### 4.1 Probe real data before generalizing parsers

The INF enrichment session started from **118/160** catalog coverage. A probe script over live `C:\Windows\INF\oem#.inf` files surfaced:

- Weak `LabelSource` rows (`I`, bare `HP Inc.`)
- High-frequency `[Strings]` keys (`SERVICE_DESC`, `.DisplayName`, …) not yet mined
- Two failure modes: **path resolution** vs **label extraction**

**Pattern:** export machine-readable JSON (`ConvertTo-Json`) from inventory probes; avoid parsing prose counts from agent chat.

### 4.2 Separate “found INF” from “good label”

160/160 `DisplayName` was achievable while **10 labels were still useless**. Add:

- `LabelSource` column for debugging
- `Test-DsmInfSubstantiveLabel` to reject bare vendor tokens
- Weak-label report in catalog summarize scripts

### 4.3 Rebuild downstream bundles after core changes

`Dsm.InfMetadata.ps1` is in `scripts/intune/bundle-order.json`. After metadata changes:

1. Pester PS 7 + PS 5.1
2. `Invoke-DsmPs51SmokeTest.ps1`
3. `Build-DsmIntuneScripts.ps1`

### 4.4 File operations discipline

- **Read** INF/binary before inferring; hash binary assets when paths rename
- **StrReplace** for logs (`<!-- AL+ -->` sentinel), not `Add-Content`
- **Never** `Get-Content` → edit → `Set-Content` for repo files (use Read/Write/StrReplace tools)

See `<config-workspace>/docs/agent/agent-file-operations-guide.md` and
`<config-workspace>/docs/powershell/powershell-dual-host-guide.md`.

---

## 5. Testing strategy that paid off

| Layer | What | Why |
| ----- | ---- | --- |
| **Unit** | CSV parsers, filters, preserve, INF fixtures | Fast, no admin |
| **Golden fixtures** | `tests/fixtures/pnputil-enum-drivers.golden.csv` | Regression on column mapping |
| **Mocked e2e** | `DriverStoreManager.MockedPnPUtil.Tests.ps1` | Full pipeline without live store |
| **PS 5.1 smoke** | Live inventory + WhatIf cleanup | Catches host-edition-only bugs |
| **Live catalog export** | `Export-DsmDriverDiskIdCatalog.ps1` | End-to-end INF path + label quality on real machine |

**Add a test when a bug only reproduces on PS 5.1 or live data** — the `ManufacturerName → "I"` bug had no PS 7 failure signal.

---

## 6. Intune delivery

- **Single-file bundles** (~153 KB) merge 18 sources in fixed order; `#Requires -Version 5.1`, `Set-StrictMode -Version Latest`.
- **StrictMode is script-scoped** — module Pester does not see Intune-bundle StrictMode. Prefer `Get-DsmObjectPropertyValue` for optional annotations (`Preserved`, …), and `InModuleScope` + `Set-StrictMode` regressions (`DSM-033`).
- **Run as SYSTEM**, 64-bit; state under `%ProgramData%\DriverStoreManager\`.
- Detection/remediation entry templates stay thin; logic lives in merged `Private/*.ps1`.
- See [intune-deployment.md](intune-deployment.md).

---

## 7. What we would do differently

1. **Define PS 5.1 as a test matrix dimension from day one** — not only after Intune phase.
2. **Ship `LabelSource` + weak-label metrics with the first catalog export** — saves a second quality pass.
3. **INF probe script in `scripts/` earlier** — promoted from `_drafts` once schema stabilizes.
4. **Avoid inline Shell analytics** — draft `.ps1` with `param()` and JSON output for agent reruns.

---

## 8. References

| Doc | Purpose |
| --- | ------- |
| [architecture.md](architecture.md) | Components, elevation, PS 5.1 |
| [safety-gates.md](safety-gates.md) | Cleanup gates |
| [intune-deployment.md](intune-deployment.md) | Bundle upload, exit codes |
| [CHANGELOG.md](../CHANGELOG.md) | Version history |
| `docs/archive/` (gitignored) | Local historical session exports only |
| `<config-workspace>/docs/powershell/powershell.md` | PS topic hub — principles, methods, adaptation guides |
| `<config-workspace>/docs/principles/powershell-coding-principles.md` | Agent-facing PS + Windows security automation principles |
| `<config-workspace>/docs/powershell/powershell-dual-host-guide.md` | Agent-facing PS 5.1 / Intune host pitfalls |
| `<config-workspace>/docs/agent/agent-file-operations-guide.md` | Agent file-ops discipline (Read/StrReplace vs Shell) |
| `<config-workspace>/skills/powershell-coding/SKILL.md` | Agent skill entry — routes to principles + guides |
