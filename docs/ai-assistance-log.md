# AI assistance log — Driver Store Manager

Human-readable disclosure trail for substantive AI-assisted work.
Complements product `CHANGELOG.md` (release history) and each `.cursor/agent-log.md`
(per-turn agent mechanics). Newest-first. The `<!-- AAI+ -->` marker stays in the newest row's When cell.

| When | Phase / scope | Deliverable | Tool / model | Purpose | Verified by |
|------|---------------|-------------|--------------|---------|-------------|
| <!-- AAI+ --> 2026-10-12 18:23:40 | DSM-043 Intune settings bake | `-SettingsFile` and filter parameters on `Build-DsmIntuneScripts.ps1`; detection uses scoped summary; exclusions documented | Cursor Grok 4.7 [Tier 2: grok-4.7] | Intune bundles should take the same run-profile keys as the interactive audit, except keys that widen or retarget deletion | `Build-DsmIntuneScripts.Tests.ps1` 14/14; `DSM-BUILD-OK detectBytes=194202 sources=19` |
| 2026-10-12 16:28:55 | DSM-041 / DSM-042 Intune bundle | `bundle-order.json` includes `Dsm.Settings.ps1`; inline relative paths use PowerShell location; dist rebuilt | Cursor Grok 4.7 [Tier 2: grok-4.7] | Settings loader was missing from generated scripts; `ReadAllText` followed the .NET process directory | `Build-DsmIntuneScripts.Tests.ps1` 7/7; `DSM-BUILD-OK detectBytes=190557 sources=19` |
| 2026-09-05 17:04:47 | DSM-040 SettingsPath overlay | `Dsm.Settings.ps1`; `-SettingsPath` on report/remove/audit; `examples/dsm.settings.example.json`; Pester 93 | Cursor Grok 4.6 [Tier 2: cursor-grok-4.6] | Opt-in JSON run profile; CLI `ContainsKey` overlay; delete/Confirm keys forbidden | Local `DSM-PESTER-OK passed=93`; `DSM-LINT-OK findings=0 files=30` |
| 2026-09-05 16:31:31 | OSS-036 catch-up — AAI bootstrap | This file created from `templates/ai-assistance-log-template.md` | Cursor Agent [Tier 2, slug: unlogged] | Retroactive per-product AAI disclosure per `logging.mdc` § 4 — DSM had no AAI log yet at 2026-09-04 audit | Pending human review |
| 2026-09-05 | DSM-039 tests layout | Pester suites moved to `tests/unit/` matching HMD shape; runner default `unit` | Cursor Agent (see product CHANGELOG 0.8.2) | Sibling-product alignment; helpers/fixtures/_drafts no longer auto-discovered | Local `DSM-VALIDATE-OK` |
| 2026-09-01 | DSM-036 PSA severity | `Invoke-DsmScriptAnalyzer` fails on Error + Warning; ExcludeRules documented | Cursor Agent (see CHANGELOG 0.8.1) | Match WGA/spine PSA bar | Local `DSM-VALIDATE-OK` |

_Rows prior to 2026-09-05 are backfilled headline references — full session-level attribution lives in `CHANGELOG.md` and the (product-local) `.cursor/agent-log.md`. Going forward, add one AAI row per substantive phase boundary._
