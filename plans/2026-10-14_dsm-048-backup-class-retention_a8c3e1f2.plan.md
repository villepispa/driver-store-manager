---
name: DSM-048 — Class backup folders and retention
overview: "Group export-before-delete backups by driver class, name an unknown package from the exported INF, and delete backups older than a configured number of days in the module and the enterprise MVP."
todos:
  - id: file-story
    content: "File DSM-048 in issues.md, project-management.json, and this plan"
    status: completion_claimed
  - id: layout-retention
    content: "Class folders, post-export INF rename, and retention in module cleanup and MVP remediate"
    status: completion_claimed
  - id: tests-docs
    content: "Cover the layout and retention in Pester and update the path docs"
    status: completion_claimed
isProject: false
---

# DSM-048 — Class backup folders and retention

**Issue:** `DSM-048`. **Acceptor:** Ville.

## Cut

Export-before-delete currently stores each package under a new timestamp directory. The same class is split across runs, and display-driver exports grow without a retention control.

The package path is `backups\<Class>\<original.inf>_<oem#.inf>` (for example `backups\Display\iigd_dch.inf_oem123.inf`). When inventory has no original name, the only `.inf` written by `pnputil /export-driver` supplies it. `BackupRetentionDays` (default 30, `0` keeps everything) deletes package folders, and legacy timestamp folders, older than that many days. The enterprise MVP remediate script does the same under `%ProgramData%\DriverStoreManager\backups`.
