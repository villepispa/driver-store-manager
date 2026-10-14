---
name: DSM-046 — MVP honors Intune settings
overview: "Bake the Intune builder switches and settings file into the enterprise MVP copies, limited to orphan cleanup features those scripts already implement."
todos:
  - id: file-story
    content: "File DSM-046 in issues.md, project-management.json, and this plan"
    status: completion_claimed
  - id: bake-mvp
    content: "Bake supported knobs into dist/intune/mvp and load an endpoint preserve-rules path"
    status: completion_claimed
  - id: tests-docs
    content: "Cover the bake in Pester and document which settings the MVP uses"
    status: completion_claimed
isProject: false
---

# DSM-046 — MVP honors Intune settings

**Issue:** `DSM-046`. **Acceptor:** Ville.

## Cut

`Build-DsmIntuneScripts.ps1` already bakes `-SettingsFile` and the builder parameters into the full bundles. The MVP copy was a raw source copy, so a Printer filter or a site preserve file never reached `dist/intune/mvp/`.

The built MVP scripts take the same inputs for features they already implement: orphan threshold, detect-orphan switch, max deletes, elevation requirement, Provider / DriverClass / PublishedName / OriginalName / HardwareId / Association (including `Any`), `IncludePublishedName`, inline preserve rules, and an on-endpoint preserve-rules path.

Blocklist, signature, DiskId, DISM, version filters, device name, class GUID, cleanup preview, and report family grouping stay on the full bundles. When a build sets one of those, the builder warns and still writes the full bundles.
