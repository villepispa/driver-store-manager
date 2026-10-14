function Test-DsmInventoryIsModuleSourced {
    <#
    .SYNOPSIS
        True when inventory objects were collected by Get-DsmDriverStoreInventory.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [psobject[]] $Inventory
    )

    foreach ($pkg in @($Inventory)) {
        if ($null -eq $pkg) { return $false }
        if ($pkg.InventorySource -ne 'ModuleInventory') { return $false }
        if (-not $pkg.CollectedAt) { return $false }
        if (-not $pkg.PSObject.Properties['PublishedName']) { return $false }
        if (-not $pkg.PSObject.Properties['DeviceAssociation']) { return $false }
    }

    return ($Inventory.Count -gt 0)
}

function Assert-DsmInventoryProvenance {
    <#
    .SYNOPSIS
        Validates caller-supplied inventory or refreshes from live collection.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject[]] $Inventory,

        [int] $InventoryMaxAgeMinutes = 15
    )

    $packages = @($Inventory | Where-Object { $null -ne $_ })
    if ($packages.Count -eq 0) {
        return @(Get-DsmDriverStoreInventory)
    }

    if (Test-DsmInventoryIsModuleSourced -Inventory $packages) {
        $freshCutoff = (Get-Date).AddMinutes(-1 * $InventoryMaxAgeMinutes)
        $stale = @($packages | Where-Object { $_.CollectedAt -lt $freshCutoff })
        if ($stale.Count -eq 0) {
            return $packages
        }

        Write-Warning 'Module-sourced inventory is stale; refreshing from live collection.'
        return @(Get-DsmDriverStoreInventory)
    }

    Write-Warning 'Caller-supplied inventory lacks module provenance; refreshing from live collection.'
    return @(Get-DsmDriverStoreInventory)
}

function Get-DsmDriverStoreCleanupPlan {
    <#
    .SYNOPSIS
        Resolves deletable driver packages using the same filter + preserve path as the report.
  .OUTPUTS
        PSCustomObject with Candidates, FilterResult, and exclusion counts.
    #>
    [CmdletBinding()]
    param(
        [psobject[]] $Inventory,

        [psobject] $Filter,

        [string[]] $Provider,
        [string[]] $DeviceName,
        [string[]] $DriverVersion,
        [version] $MinDriverVersion,
        [version] $MaxDriverVersion,
        [string[]] $DriverClass,
        [string[]] $ClassGuid,
        [string[]] $HardwareId,
        [string[]] $PublishedName,
        [string[]] $OriginalName,
        [ValidateSet('Any', 'Connected', 'DisconnectedInstalled', 'NeverAssociated', 'InUseOnly', 'UnusedOnly')]
        [string] $Association,

        [switch] $IncludeWindowsBuiltIn,

        [psobject[]] $PreserveRule,
        [string] $PreserveRulesPath,

        [string[]] $IncludePublishedName,

        [int] $InventoryMaxAgeMinutes = 15
    )

    if (-not $Inventory) {
        $Inventory = @(Get-DsmDriverStoreInventory)
    }
    else {
        $Inventory = @(Assert-DsmInventoryProvenance -Inventory $Inventory `
                -InventoryMaxAgeMinutes $InventoryMaxAgeMinutes)
    }

    $freshCutoff = (Get-Date).AddMinutes(-1 * $InventoryMaxAgeMinutes)
    $stale = @($Inventory | Where-Object {
            -not $_.CollectedAt -or $_.CollectedAt -lt $freshCutoff
        })
    if ($stale.Count -gt 0) {
        Write-Warning 'Inventory is stale or missing CollectedAt; refreshing.'
        $Inventory = @(Get-DsmDriverStoreInventory)
    }

    if (-not $Filter) {
        $filterParams = @{}
        if ($Provider) { $filterParams['Provider'] = $Provider }
        if ($DeviceName) { $filterParams['DeviceName'] = $DeviceName }
        if ($DriverVersion) { $filterParams['DriverVersion'] = $DriverVersion }
        if ($MinDriverVersion) { $filterParams['MinDriverVersion'] = $MinDriverVersion }
        if ($MaxDriverVersion) { $filterParams['MaxDriverVersion'] = $MaxDriverVersion }
        if ($DriverClass) { $filterParams['DriverClass'] = $DriverClass }
        if ($ClassGuid) { $filterParams['ClassGuid'] = $ClassGuid }
        if ($HardwareId) { $filterParams['HardwareId'] = $HardwareId }
        if ($PublishedName) { $filterParams['PublishedName'] = $PublishedName }
        if ($OriginalName) { $filterParams['OriginalName'] = $OriginalName }
        if ($Association) { $filterParams['Association'] = $Association }
        if ($filterParams.Count -gt 0) {
            $Filter = New-DsmDriverFilter @filterParams
        }
    }

    $filterResult = Invoke-DsmDriverFilter -Inventory $Inventory -Filter $Filter `
        -IncludeWindowsBuiltIn:$IncludeWindowsBuiltIn

    $scoped = if ($null -ne $filterResult.Filtered) {
        @($filterResult.Filtered)
    }
    else {
        @()
    }

    if (@($scoped).Count -gt 0) {
        Initialize-DsmPreserveAnnotations -Inventory $scoped
    }

    if ($PreserveRule -or $PreserveRulesPath) {
        if (@($scoped).Count -gt 0) {
            $scoped = @(Invoke-DsmPreservePolicy -Inventory $scoped `
                    -PreserveRule $PreserveRule -PreserveRulesPath $PreserveRulesPath).Inventory
        }
    }

    $preservedSkipped = @($scoped | Where-Object {
            [bool](Get-DsmObjectPropertyValue -Object $_ -Name 'Preserved')
        })
    $deletable = @($scoped | Where-Object { Test-DsmPackageIsDeletableCandidate -Package $_ })
    $notDeletableInScope = @($scoped | Where-Object {
            -not [bool](Get-DsmObjectPropertyValue -Object $_ -Name 'Preserved') `
                -and -not (Test-DsmPackageIsDeletableCandidate -Package $_)
        })

    if ($IncludePublishedName) {
        $allow = [System.Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
        $IncludePublishedName | ForEach-Object { [void]$allow.Add($_) }
        $deletable = @($deletable | Where-Object { $allow.Contains($_.PublishedName) })
    }

    return [pscustomobject]@{
        Inventory              = $Inventory
        ScopedPackages         = $scoped
        Candidates             = $deletable
        FilterResult           = $filterResult
        FilterManifest         = $filterResult.FilterManifest
        PreservedSkipped       = $preservedSkipped
        NotDeletableInScope    = $notDeletableInScope
        ScopeExcludedCount     = @( $filterResult.ScopeExcluded ).Count
        FilterExcludedCount    = @( $filterResult.FilterExcluded ).Count
        CandidateCount         = @( $deletable ).Count
        PreservedSkippedCount  = @( $preservedSkipped ).Count
        NotDeletableInScopeCount = @( $notDeletableInScope ).Count
        FamilyContext          = Initialize-DsmCleanupFamilyContext -Inventory $Inventory
    }
}

function Initialize-DsmCleanupFamilyContext {
  <#
    .SYNOPSIS
        Family/version flags and latest in-use driver per family for cleanup enrichment.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject[]] $Inventory
    )

    $inventory = @($Inventory | Where-Object { $null -ne $_ })
    Add-DsmOldVersionFlags -Packages $inventory

    $inUseByFamily = @{}
    foreach ($pkg in $inventory) {
        $deviceAssociation = Get-DsmObjectPropertyValue -Object $pkg -Name 'DeviceAssociation'
        $inUse = Get-DsmObjectPropertyValue -Object $pkg -Name 'InUse'
        $connected = $deviceAssociation -eq 'Connected' -or (
            -not $deviceAssociation -and $inUse)
        if (-not $connected) { continue }

        $key = Get-DsmObjectPropertyValue -Object $pkg -Name 'FamilyKey'
        if (-not $key) {
            $key = Get-DsmDriverFamilyKey -Package $pkg
        }
        if (-not $inUseByFamily.ContainsKey($key)) {
            $inUseByFamily[$key] = [System.Collections.Generic.List[object]]::new()
        }
        $inUseByFamily[$key].Add($pkg) | Out-Null
    }

    $latestInUseByFamily = @{}
    foreach ($key in $inUseByFamily.Keys) {
        $latestInUseByFamily[$key] = Get-DsmLatestPackageInFamily -Packages @($inUseByFamily[$key])
    }

    return [pscustomobject]@{
        Inventory             = $inventory
        InUseByFamily         = $inUseByFamily
        LatestInUseByFamily   = $latestInUseByFamily
    }
}

function New-DsmCleanupResultRow {
    <#
    .SYNOPSIS
        Builds one cleanup result row with INF metadata and in-use newer driver context.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject] $Package,

        [psobject] $FamilyContext,

        [string] $Action,

        [string] $BackupPath,

        [string] $ErrorMessage
    )

    $meta = Get-DsmDriverPackageInfMetadata -Package $Package
    $inUseNewer = $null

    if ($FamilyContext -and $Package.IsOldVersionOfInUseFamily) {
        $key = $Package.FamilyKey
        $newerPkg = $null
        if ($key -and $FamilyContext.LatestInUseByFamily.ContainsKey($key)) {
            $newerPkg = $FamilyContext.LatestInUseByFamily[$key]
        }

        if ($newerPkg) {
            $newerMeta = Get-DsmDriverPackageInfMetadata -Package $newerPkg
            $devices = @($newerPkg.Devices | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                Select-Object -Unique)
            $inUseNewer = [pscustomobject]@{
                PublishedName   = $newerPkg.PublishedName
                DriverVersion   = $newerPkg.DriverVersion
                DriverVer       = $newerMeta.DriverVer
                DisplayName     = $newerMeta.DisplayName
                DeviceNames     = $devices
            }
        }
    }

    return [pscustomobject]@{
        PublishedName              = $Package.PublishedName
        OriginalName               = $Package.OriginalName
        Provider                   = $Package.Provider
        DriverClass                = $Package.DriverClass
        DriverVersion              = $Package.DriverVersion
        DriverVer                  = $meta.DriverVer
        DiskId                     = $meta.DiskId
        DisplayName                = $meta.DisplayName
        DeviceAssociation          = $Package.DeviceAssociation
        IsOldVersionOfInUseFamily  = [bool]$Package.IsOldVersionOfInUseFamily
        InUseNewerDriver           = $inUseNewer
        Preserved                  = [bool](Get-DsmObjectPropertyValue -Object $Package -Name 'Preserved')
        Action                     = $Action
        Timestamp                  = Get-Date
        BackupPath                 = $BackupPath
        Error                      = $ErrorMessage
    }
}

function Write-DsmCleanupResultLog {
    <#
    .SYNOPSIS
        Writes cleanup candidate rows to the host for operator review.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Results,

        [string] $Title = 'Cleanup candidates'
    )

    if (-not $Results -or $Results.Count -eq 0) {
        Write-Host "$Title`: (none)" -ForegroundColor DarkGray
        return
    }

    Write-Host "`n$Title ($($Results.Count)):" -ForegroundColor Cyan
    foreach ($row in $Results) {
        $label = if ($row.DisplayName) { $row.DisplayName } else { $row.Provider }
        $ver = if ($row.DriverVer) { $row.DriverVer } else { $row.DriverVersion }
        $line = '{0,-12} {1,-36} DriverVer={2}' -f $row.PublishedName, $label, $ver
        if ($row.InUseNewerDriver) {
            $newer = $row.InUseNewerDriver
            $newerLabel = if ($newer.DisplayName) { $newer.DisplayName } else { $newer.PublishedName }
            $newerVer = if ($newer.DriverVer) { $newer.DriverVer } else { $newer.DriverVersion }
            $line += " -> in-use: $($newer.PublishedName) $newerLabel ($newerVer)"
        }
        Write-Host $line
    }
}

function Get-DsmSafePathSegment {
    <#
    .SYNOPSIS
        Makes one path segment safe as a Windows folder name.
    #>
    [CmdletBinding()]
    param(
        [string] $Name
    )

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return ''
    }

    $invalid = [System.IO.Path]::GetInvalidFileNameChars()
    $builder = New-Object System.Text.StringBuilder
    foreach ($ch in $Name.ToCharArray()) {
        if ($invalid -contains $ch) {
            [void]$builder.Append('_')
        }
        else {
            [void]$builder.Append($ch)
        }
    }

    $safe = $builder.ToString().Trim().TrimEnd('.')
    if ([string]::IsNullOrWhiteSpace($safe) -or $safe -eq '.' -or $safe -eq '..') {
        return ''
    }

    return $safe
}

function Get-DsmDriverBackupFolderName {
    <#
    .SYNOPSIS
        Backup child folder: original INF name, then the published oem name.
    .DESCRIPTION
        iigd_dch.inf_oem123.inf sorts the same original driver together and
        still shows which published package was exported. A missing original
        name keeps the published name alone.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $PublishedName,

        [string] $OriginalName
    )

    $safeOriginal = Get-DsmSafePathSegment -Name $OriginalName
    if ([string]::IsNullOrWhiteSpace($safeOriginal)) {
        return $PublishedName
    }

    return ('{0}_{1}' -f $safeOriginal, $PublishedName)
}

function Get-DsmBackupClassFolderName {
    <#
    .SYNOPSIS
        Class directory under the backup root. Blank or unsafe classes become Unknown.
    #>
    [CmdletBinding()]
    param(
        [string] $DriverClass
    )

    $safe = Get-DsmSafePathSegment -Name $DriverClass
    if ([string]::IsNullOrWhiteSpace($safe) -or $safe -eq '_export') {
        return 'Unknown'
    }

    return $safe
}

function Get-DsmExportedOriginalInfName {
    <#
    .SYNOPSIS
        Original INF file name from an export directory when inventory did not supply one.
    .DESCRIPTION
        pnputil /export-driver writes the original INF into the target directory.
        When that directory contains one INF, its file name is the original name.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $ExportDirectory,

        [string] $KnownOriginalName
    )

    if (-not [string]::IsNullOrWhiteSpace($KnownOriginalName)) {
        return $KnownOriginalName
    }

    $files = @(Get-ChildItem -LiteralPath $ExportDirectory -Filter '*.inf' -File -Recurse -ErrorAction SilentlyContinue)
    if ($files.Count -eq 1) {
        return $files[0].Name
    }

    if ($files.Count -gt 1) {
        foreach ($file in $files) {
            if ($file.Name -notmatch '^oem\d+\.inf$') {
                return $file.Name
            }
        }

        return $files[0].Name
    }

    return ''
}

function Export-DsmDriverPackageBackup {
    <#
    .SYNOPSIS
        Exports a driver package with pnputil /export-driver (no /force).
    .DESCRIPTION
        Stages the export, then moves it to BackupRoot\Class\original.inf_oem#.inf.
        When OriginalName is empty, the only INF in the export supplies the name.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $PublishedName,

        [Parameter(Mandatory)]
        [string] $BackupRoot,

        [string] $OriginalName,

        [string] $DriverClass
    )

    $stageParent = Join-DsmPath $BackupRoot '_export'
    $stageDir = Join-DsmPath $stageParent $PublishedName
    if (Test-Path -LiteralPath $stageDir) {
        Remove-Item -LiteralPath $stageDir -Recurse -Force
    }

    New-Item -ItemType Directory -Path $stageDir -Force | Out-Null
    Invoke-DsmPnPUtil -ArgumentList @(
        '/export-driver', $PublishedName, $stageDir
    ) | Out-Null

    $discovered = Get-DsmExportedOriginalInfName -ExportDirectory $stageDir -KnownOriginalName $OriginalName
    $folderName = Get-DsmDriverBackupFolderName -PublishedName $PublishedName -OriginalName $discovered
    $classFolder = Get-DsmBackupClassFolderName -DriverClass $DriverClass
    $destParent = Join-DsmPath $BackupRoot $classFolder
    if (-not (Test-Path -LiteralPath $destParent)) {
        New-Item -ItemType Directory -Path $destParent -Force | Out-Null
    }

    $dest = Join-DsmPath $destParent $folderName
    if (Test-Path -LiteralPath $dest) {
        Remove-Item -LiteralPath $dest -Recurse -Force
    }

    Move-Item -LiteralPath $stageDir -Destination $dest
    return $dest
}

function Remove-DsmOldDriverBackups {
    <#
    .SYNOPSIS
        Deletes package backup folders older than a number of days.
    .DESCRIPTION
        Compares each package folder's creation time. Also removes legacy
        backups\yyyy-MM-dd_HHmmss trees and staged exports of that age.
        Zero or negative days deletes nothing. Empty class folders are removed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $BackupRoot,

        [int] $OlderThanDays = 0
    )

    if ($OlderThanDays -le 0) {
        return 0
    }

    if (-not (Test-Path -LiteralPath $BackupRoot)) {
        return 0
    }

    $cutoff = (Get-Date).AddDays(-1 * $OlderThanDays)
    $removed = 0
    $packagePattern = '(?i)(^oem\d+\.inf$)|(_oem\d+\.inf$)'
    foreach ($child in @(Get-ChildItem -LiteralPath $BackupRoot -Directory -ErrorAction SilentlyContinue)) {
        if ($child.Name -eq '_export') {
            foreach ($staged in @(Get-ChildItem -LiteralPath $child.FullName -Directory -ErrorAction SilentlyContinue)) {
                if ($staged.CreationTime -lt $cutoff) {
                    Remove-Item -LiteralPath $staged.FullName -Recurse -Force
                    $removed++
                }
            }

            continue
        }

        if ($child.Name -match '^\d{4}-\d{2}-\d{2}_\d{6}$') {
            if ($child.CreationTime -lt $cutoff) {
                Remove-Item -LiteralPath $child.FullName -Recurse -Force
                $removed++
            }

            continue
        }

        foreach ($packageDir in @(Get-ChildItem -LiteralPath $child.FullName -Directory -ErrorAction SilentlyContinue)) {
            $isPackage = $packageDir.Name -match $packagePattern
            if ($isPackage -and $packageDir.CreationTime -lt $cutoff) {
                Remove-Item -LiteralPath $packageDir.FullName -Recurse -Force
                $removed++
            }
        }

        $left = @(Get-ChildItem -LiteralPath $child.FullName -Force -ErrorAction SilentlyContinue)
        if ($left.Count -eq 0) {
            Remove-Item -LiteralPath $child.FullName -Force
        }
    }

    return $removed
}

function Remove-DsmDriverPackageFromStore {
    <#
    .SYNOPSIS
        Deletes a staged driver package with pnputil /delete-driver (never /force).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $PublishedName
    )

    Invoke-DsmPnPUtil -ArgumentList @(
        '/delete-driver', $PublishedName
    ) | Out-Null
}
