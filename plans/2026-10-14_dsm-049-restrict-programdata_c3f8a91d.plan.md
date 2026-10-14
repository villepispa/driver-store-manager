---
name: DSM-049 — Restrict ProgramData access
overview: "Add a switch that limits %ProgramData%\\DriverStoreManager to SYSTEM full control and Administrators modify, in the full Intune bundles and the enterprise MVP."
todos:
  - id: file-story
    content: "File DSM-049 in issues.md, project-management.json, and this plan"
    status: completion_claimed
  - id: acl-switch
    content: "Apply the directory ACL from the module, both Intune entries, and both MVP scripts"
    status: completion_claimed
  - id: tests-docs
    content: "Cover the ACL in Pester and document the switch"
    status: completion_claimed
isProject: false
---

# DSM-049 — Restrict ProgramData access

**Issue:** `DSM-049`. **Acceptor:** Ville.

## Cut

`%ProgramData%\DriverStoreManager` inherits the default ProgramData access list, so a signed-in user can read exported drivers and reports. Those exports can contain vulnerable driver files.

`-RestrictProgramDataAccess` (default on for Intune builds, including the MVP) replaces that access list. SYSTEM gets full control. Administrators get modify. Inheritance is removed. The same rights are written on existing subfolders and files.
