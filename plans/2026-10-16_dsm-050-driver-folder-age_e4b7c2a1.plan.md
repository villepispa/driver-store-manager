---
name: DSM-050 — Driver folder age filter
overview: "Clean up a driver-store folder only when it is older than n days, in the module, both Intune bundles, and the enterprise MVP, so a previous driver can still be rolled back."
todos:
  - id: file-story
    content: "File DSM-050 in issues.md, project-management.json, and this plan"
    status: completion_claimed
  - id: age-filter
    content: "Apply DriverFolderMinAgeDays in cleanup, detection, the Intune builder, and both MVP scripts"
    status: completion_claimed
  - id: tests-docs
    content: "Cover the age filter in Pester and document the setting"
    status: completion_claimed
isProject: false
---

# DSM-050 — Driver folder age filter

**Issue:** `DSM-050`. **Acceptor:** Ville.

## Cut

Cleanup can remove a driver that was staged only a few minutes earlier. That removes the previous driver before an operator can roll back.

`DriverFolderMinAgeDays` keeps a folder until its creation time is older than that many days. `0` keeps every age. Intune builds default to 14. The module uses the FileRepository directory. The enterprise MVP uses the published INF under `%SystemRoot%\INF`. A missing date is not a cleanup candidate. Detection uses the same rule.
