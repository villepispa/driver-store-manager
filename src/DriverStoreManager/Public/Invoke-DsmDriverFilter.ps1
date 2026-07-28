function Invoke-DsmDriverFilter {
    <#
    .SYNOPSIS
        Applies OEM-default scope and optional filter criteria to driver inventory.
    .DESCRIPTION
        Default scope includes all oem#.inf staged packages (any publisher).
        Windows built-in manifests (non-oem INF names) are excluded unless
        -IncludeWindowsBuiltIn. Returns filtered packages plus scope/filter
        exclusions and FilterMatchRate for dual-count reporting (Phase 3d).
    .PARAMETER Inventory
        Driver package objects from Get-DsmDriverStoreInventory.
    .PARAMETER Filter
        Filter object from New-DsmDriverFilter, or pass filter fields directly.
    .PARAMETER IncludeWindowsBuiltIn
        Also include Windows built-in driver manifests (non-oem#.inf names such as
        c_swcomponent.inf). Does not affect oem#.inf scope — those are always in
        default scope regardless of Provider (e.g. oem159.inf Voice Clarity).
    .OUTPUTS
        PSCustomObject with Filtered, ScopeExcluded, FilterExcluded, counts, FilterManifest.
    .EXAMPLE
        $r = Get-DsmDriverStoreInventory | Invoke-DsmDriverFilter -Provider 'Synaptics*'
        $r.Filtered | Format-Table PublishedName, DriverVersion, DeviceAssociation
  .EXAMPLE
        $f = New-DsmDriverFilter -DriverClass 'Printer' -Association DisconnectedInstalled
        Invoke-DsmDriverFilter -Inventory $inv -Filter $f
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [AllowEmptyCollection()]
        [psobject[]] $Inventory = @(),

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

        [switch] $IncludeWindowsBuiltIn
    )

    begin {
        $allInput = [System.Collections.Generic.List[object]]::new()
    }

    process {
        foreach ($item in $Inventory) {
            $allInput.Add($item) | Out-Null
        }
    }

    end {
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

        $totalCount = $allInput.Count
        $scoped = [System.Collections.Generic.List[object]]::new()
        $scopeExcluded = [System.Collections.Generic.List[object]]::new()

        foreach ($pkg in $allInput) {
            if ($IncludeWindowsBuiltIn -or (Test-DsmOemDriverPackage -Package $pkg)) {
                $scoped.Add($pkg) | Out-Null
            }
            else {
                $scopeExcluded.Add($pkg) | Out-Null
            }
        }

        $scopedCount = $scoped.Count
        $filtered = [System.Collections.Generic.List[object]]::new()
        $filterExcluded = [System.Collections.Generic.List[object]]::new()

        $filterEmpty = Test-DsmDriverFilterIsEmpty -Filter $Filter

        foreach ($pkg in $scoped) {
            if ($filterEmpty -or (Test-DsmDriverPackageMatchesFilter -Package $pkg -Filter $Filter)) {
                $filtered.Add($pkg) | Out-Null
            }
            else {
                $filterExcluded.Add($pkg) | Out-Null
            }
        }

        $filteredCount = $filtered.Count
        $filterMatchRate = if ($scopedCount -gt 0) {
            [Math]::Round($filteredCount / $scopedCount, 4)
        }
        else {
            0.0
        }

        $excludedWindowsBuiltInCount = @($scopeExcluded | Where-Object {
                Test-DsmWindowsBuiltInDriverPackage -Package $_
            }).Count

        $windowsBuiltInInScopeCount = if ($IncludeWindowsBuiltIn) {
            @($scoped | Where-Object { Test-DsmWindowsBuiltInDriverPackage -Package $_ }).Count
        }
        else {
            0
        }

        [pscustomobject]@{
            Inventory                   = [object[]]@($allInput)
            Filtered                    = [object[]]@($filtered)
            ScopeExcluded               = [object[]]@($scopeExcluded)
            FilterExcluded              = [object[]]@($filterExcluded)
            TotalCount                  = $totalCount
            ScopedCount                 = $scopedCount
            FilteredCount               = $filteredCount
            ExcludedWindowsBuiltInCount = $excludedWindowsBuiltInCount
            WindowsBuiltInInScopeCount  = $windowsBuiltInInScopeCount
            FilterMatchRate             = $filterMatchRate
            FilterManifest              = New-DsmDriverFilterManifest -Filter $Filter -IncludeWindowsBuiltIn:$IncludeWindowsBuiltIn
            IncludeWindowsBuiltIn       = [bool]$IncludeWindowsBuiltIn
        }
    }
}
