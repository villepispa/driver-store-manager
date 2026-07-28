# Commands reference — built-in Windows tooling

All commands below are **in-box** on supported Windows 10/11 builds. Prefer these over
Sysinternals or third-party scanners unless a documented gap exists.

**Tooling triad (verified at v0.1 scaffold):** `pnputil.exe`, `driverquery.exe`, and
`Get-WindowsDriver` (DISM) were present on the development host. Driver Store Manager
is built around **`pnputil`** as the primary inventory/export/delete tool; DISM and
`driverquery` remain secondary cross-checks (IR / image servicing).

## pnputil (primary)

Driver Store and PnP device management. Run `pnputil /?` for the full list.

### Inventory

```cmd
pnputil /enum-drivers /files /devices /format csv /output-file "%TEMP%\dsm-drivers.csv"
pnputil /enum-devices /drivers /format csv /output-file "%TEMP%\dsm-devices-all.csv"
pnputil /enum-devices /connected /drivers /format csv /output-file "%TEMP%\dsm-devices-connected.csv"
```

PowerShell wrapper: `Get-DsmDriverStoreInventory` (this project).

### Export (backup before delete)

```cmd
pnputil /export-driver oem42.inf C:\Backup\driver-export
pnputil /export-driver * C:\Backup\all-drivers
```

### Delete (admin)

```cmd
pnputil /delete-driver oem42.inf
```

Avoid `/force` in automated tooling — it can remove in-use packages and cause instability.

Optional uninstall from devices first:

```cmd
pnputil /delete-driver oem42.inf /uninstall
```

## DISM — Get-WindowsDriver

Online enumeration of third-party drivers in the current OS image:

```powershell
Get-WindowsDriver -Online | Format-Table Driver, ClassName, Date, Version, ProviderName
```

Use as a **secondary** source to cross-check `pnputil` output. Export via:

```powershell
Export-WindowsDriver -Online -Destination C:\Backup\dism-drivers
```

## driverquery

Kernel drivers currently loaded (complements PnP Driver Store view):

```cmd
driverquery /v /fo csv
```

Useful for IR: compare **running** kernel drivers vs **staged** packages.

## PowerShell security cmdlets

```powershell
Get-AuthenticodeSignature -FilePath 'C:\Windows\System32\drivers\foo.sys'
Get-FileHash -Algorithm SHA256 -Path $driverFile
```

## Microsoft Vulnerable Driver Blocklist

Windows applies a blocklist via **Windows Security / Core isolation / Memory integrity**
and WDAC when enabled. Driver Store Manager **auto-refreshes** Microsoft's published list:

| Item | Value |
|------|--------|
| Source | `https://aka.ms/VulnerableDriverBlockList` |
| Cache | `%ProgramData%\DriverStoreManager\blocklist\microsoft\vulnerable-driver-hashes.sha256.txt` |
| TTL | 7 days (override with `-MicrosoftBlocklistMaxAgeDays`) |
| Manual refresh | `Update-DsmMicrosoftDriverBlocklist -Force` or `.\scripts\Update-DsmMicrosoftDriverBlocklist.ps1` |

`-BlocklistPath` remains supported: hashes from that file are **merged** with the Microsoft cache.
Use `-SkipMicrosoftBlocklist` for offline or custom-only feeds.

`Test-DsmDriverVulnerabilities` hashes driver `.sys`/`.dll`/`.cat` images from inventory
`Files` and matches against the combined set. This is a *signal* — not a substitute for keeping
Memory integrity enabled.

## Registry (informational)

Driver Store location:

```text
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching
```

Device class GUIDs:

```text
HKLM\SYSTEM\CurrentControlSet\Control\Class\{...}
```

Prefer `pnputil /enum-classes` over manual registry walks.

## References

- [PnPUtil command-line syntax](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/pnputil-command-line-syntax)
- [DISM driver servicing](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/add-and-remove-drivers-to-an-offline-windows-image)
- [Microsoft vulnerable driver blocklist](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-vulnerable-driver-blocklist)
