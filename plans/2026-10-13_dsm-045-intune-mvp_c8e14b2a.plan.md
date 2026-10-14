---
name: DSM-045 — Enterprise Intune MVP
overview: "Add two standalone Intune scripts that only inventory oem drivers, apply preserve rules, and delete a capped set of NeverAssociated orphans."
todos:
  - id: file-story
    content: "File DSM-045 in issues.md, project-management.json, and this plan"
    status: completion_claimed
  - id: mvp-scripts
    content: "Write scripts/intune/mvp detect and remediate, top to bottom, with #section markers"
    status: completion_claimed
  - id: wire-test
    content: "Copy both scripts from the Intune build and cover them in Pester and the PS 5.1 smoke"
    status: completion_claimed
  - id: docs
    content: "Document the MVP in README, intune-deployment.md, and CHANGELOG Unreleased"
    status: completion_claimed
isProject: false
---

# DSM-045 — Enterprise Intune MVP

**Issue:** `DSM-045`. **Acceptor:** Ville.

## Problem

The generated Intune bundles are about 5,800 lines each because they merge the whole module. A reviewer cannot follow inventory, association, preserve, and delete without jumping across dozens of functions. Blocklist, DiskId, and the settings overlay are not on the delete path.

## Cut

Two source files under `scripts/intune/mvp/`. The build copies them to `dist/intune/mvp/`. Each file runs alone.

In scope: `pnputil` CSV inventory, OEM published names only, three association buckets, preserve rules (`KeepLatest`, `KeepMatching`, `KeepPublishedName`, `KeepVersion`), a small baked filter, JSON report, exit `0` / `1` / `2`, export-before-delete, max deletes, no `/force`. Device correlation failure exits `2` and does not treat packages as orphans.

Out of scope: Microsoft blocklist, Authenticode, DiskId / INF labels, DISM, settings-file overlay, Markdown, cleanup preview.

## Reading rules

`#section` marks the scroll order. A function exists only when it is used from more than two places, or it is long enough that a second copy would be worse, and the body is more than one line. Helpers sit above the first call. Policy is `#section Config`.

## Safety

Same gates as `docs/safety-gates.md` for orphan cleanup: fresh inventory, never delete Connected or DisconnectedInstalled, export before delete, elevation, preserve wins, vulnerability scan is absent so it cannot delete.
