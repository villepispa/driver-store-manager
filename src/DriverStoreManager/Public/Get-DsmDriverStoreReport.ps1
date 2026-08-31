function Get-DsmDriverStoreReport {
    <#
    .SYNOPSIS
        Builds global and scoped Driver Store reports with counts and listings.
    .DESCRIPTION
        Orchestrates filter, preserve, and vulnerability scan per plan pipeline.
        Emits Global (OEM scope, no filter criteria) and Scoped (active filter)
        summaries with identical metric shapes.
    .PARAMETER Inventory
        Pre-collected packages; collected automatically when omitted.
    .PARAMETER Filter
        Optional DsmDriverFilter for scoped section (or pass filter fields directly).
    .PARAMETER PreserveRule
        Preserve rules applied before metrics (both scopes when provided).
    .PARAMETER BlocklistPath
        Optional supplemental SHA256 hash file merged with the Microsoft auto-cache.
    .PARAMETER UseMicrosoftBlocklist
        When true (default), auto-refresh Microsoft's blocklist (7-day TTL) into ProgramData.
    .PARAMETER UpdateMicrosoftBlocklist
        Force a Microsoft blocklist download before scanning.
    .PARAMETER MicrosoftBlocklistMaxAgeDays
        Refresh Microsoft cache when older than this many days (default 7).
    .PARAMETER SkipMicrosoftBlocklist
        Disable Microsoft auto-update; use -BlocklistPath only (offline/custom).
    .PARAMETER IncludeVulnerabilityScan
        Run Test-DsmDriverVulnerabilities even without blocklist (signatures + orphans).
    .PARAMETER FamilyGroupBy
        ProviderOriginalName (default) or HwId for old-version family logic.
    .PARAMETER OutputPath
        Optional directory to write JSON and Markdown report files.
    .OUTPUTS
        PSCustomObject with Global, Scoped, FilterManifest, GeneratedAt.
    .EXAMPLE
        Get-DsmDriverStoreReport -BlocklistPath .\examples\blocklist-hashes.example.txt
    .EXAMPLE
        $f = New-DsmDriverFilter -Provider 'Synaptics*'
        Get-DsmDriverStoreReport -Filter $f -PreserveRulesPath .\examples\preserve-rules.example.json
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

        [string] $BlocklistPath,
        [bool] $UseMicrosoftBlocklist = $true,
        [switch] $UpdateMicrosoftBlocklist,
        [int] $MicrosoftBlocklistMaxAgeDays = 7,
        [switch] $SkipMicrosoftBlocklist,
        [switch] $IncludeVulnerabilityScan,
        [bool] $VulnerableIncludesSignature = $true,

        [ValidateSet('ProviderOriginalName', 'HwId')]
        [string] $FamilyGroupBy = 'ProviderOriginalName',

        [string] $OutputPath
    )

    if ($null -eq $Inventory) {
        $Inventory = @(Get-DsmDriverStoreInventory)
    }
    else {
        $Inventory = @($Inventory)
    }

    if ($Inventory.Count -eq 0) {
        Write-Warning 'Driver Store inventory is empty; report counts will be zero.'
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

    $globalFilterResult = Invoke-DsmDriverFilter -Inventory $Inventory `
        -IncludeWindowsBuiltIn:$IncludeWindowsBuiltIn
    $scopedFilterResult = Invoke-DsmDriverFilter -Inventory $Inventory -Filter $Filter `
        -IncludeWindowsBuiltIn:$IncludeWindowsBuiltIn

    $globalPkgs = Get-DsmObjectArray -InputObject $globalFilterResult.Filtered
    $scopedPkgs = Get-DsmObjectArray -InputObject $scopedFilterResult.Filtered

    if ($PreserveRule -or $PreserveRulesPath) {
        if (@($globalPkgs).Count -gt 0) {
            $globalPkgs = @(Invoke-DsmPreservePolicy -Inventory $globalPkgs `
                    -PreserveRule $PreserveRule -PreserveRulesPath $PreserveRulesPath).Inventory
        }
        if (@($scopedPkgs).Count -gt 0) {
            $scopedPkgs = @(Invoke-DsmPreservePolicy -Inventory $scopedPkgs `
                    -PreserveRule $PreserveRule -PreserveRulesPath $PreserveRulesPath).Inventory
        }
    }

    $useMsBlocklist = $UseMicrosoftBlocklist -and -not $SkipMicrosoftBlocklist
    $runVuln = $IncludeVulnerabilityScan -or $BlocklistPath -or $useMsBlocklist
    $blocklistResolved = $null
    if ($runVuln) {
        $blocklistResolved = Get-DsmBlocklistHashSet `
            -BlocklistPath $BlocklistPath `
            -UseMicrosoftBlocklist:$useMsBlocklist `
            -UpdateMicrosoftBlocklist:$UpdateMicrosoftBlocklist `
            -MicrosoftBlocklistMaxAgeDays $MicrosoftBlocklistMaxAgeDays

        $vulnScanParams = @{
            BlocklistHashes                      = $blocklistResolved.HashSet
            OrphanIncludesDisconnectedInstalled  = $true
        }
        if (@($globalPkgs).Count -gt 0) {
            $globalPkgs = Get-DsmObjectArray -InputObject @(
                Test-DsmDriverVulnerabilities -Inventory $globalPkgs @vulnScanParams)
        }
        if (@($scopedPkgs).Count -gt 0) {
            $scopedPkgs = Get-DsmObjectArray -InputObject @(
                Test-DsmDriverVulnerabilities -Inventory $scopedPkgs @vulnScanParams)
        }
    }

    $globalScope = Measure-DsmDriverStoreScope -Packages $globalPkgs `
        -FilterResult $globalFilterResult `
        -FamilyGroupBy $FamilyGroupBy `
        -IncludeSignatureInVulnerable:$VulnerableIncludesSignature `
        -OrphanIncludesDisconnectedInstalled

    $scopedScope = Measure-DsmDriverStoreScope -Packages $scopedPkgs `
        -FilterResult $scopedFilterResult `
        -FamilyGroupBy $FamilyGroupBy `
        -IncludeSignatureInVulnerable:$VulnerableIncludesSignature `
        -OrphanIncludesDisconnectedInstalled

    $vulnManifest = $null
    if ($runVuln) {
        $ms = $blocklistResolved.MicrosoftBlocklist
        $scanState = Get-DsmBlocklistScanState -BlocklistResolved $blocklistResolved `
            -UseMicrosoftBlocklist:$useMsBlocklist `
            -MicrosoftBlocklistMaxAgeDays $MicrosoftBlocklistMaxAgeDays
        $vulnManifest = [pscustomobject]@{
            ScanRan                             = $true
            ScanState                           = $scanState.ScanState
            BlocklistDataAvailable              = [bool]$scanState.BlocklistDataAvailable
            BlocklistDataDegraded               = [bool]$scanState.BlocklistDataDegraded
            BlocklistPath                       = $BlocklistPath
            BlocklistHashCount                  = $blocklistResolved.TotalCount
            SupplementalBlocklistPath           = $blocklistResolved.SupplementalPath
            SupplementalHashCount               = $blocklistResolved.SupplementalCount
            UseMicrosoftBlocklist               = [bool]$useMsBlocklist
            MicrosoftBlocklistCacheFile         = $ms.HashFile
            MicrosoftBlocklistMetadataFile      = $ms.MetadataFile
            MicrosoftBlocklistHashCount         = [int]$ms.HashCount
            MicrosoftBlocklistPolicyVersion     = $ms.PolicyVersion
            MicrosoftBlocklistUpdatedAt         = $ms.UpdatedAt
            MicrosoftBlocklistRefreshAttempted  = [bool]$ms.RefreshAttempted
            MicrosoftBlocklistRefreshUpdated    = [bool]$ms.RefreshUpdated
            MicrosoftBlocklistRefreshError      = $ms.Error
            MicrosoftBlocklistMaxAgeDays        = $MicrosoftBlocklistMaxAgeDays
            IncludeSignatureInVulnerable        = [bool]$VulnerableIncludesSignature
            OrphanIncludesDisconnectedInstalled = $true
            DriverImageExtensions               = @('.sys', '.dll', '.cat')
        }
    }

    $report = [pscustomobject]@{
        GeneratedAt            = Get-Date
        ComputerName           = $env:COMPUTERNAME
        PowerShellVersion      = $PSVersionTable.PSVersion.ToString()
        FamilyGroupBy          = $FamilyGroupBy
        Global                 = $globalScope
        Scoped                 = $scopedScope
        FilterManifest         = $scopedFilterResult.FilterManifest
        VulnerabilityManifest  = $vulnManifest
        TotalInventory         = $Inventory.Count
    }

    if ($OutputPath) {
        if (-not (Test-Path -LiteralPath $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        }

        $stamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
        $jsonPath = Join-DsmPath $OutputPath "driver-store-report_$stamp.json"
        $mdPath = Join-DsmPath $OutputPath "driver-store-report_$stamp.md"

        Set-DsmContentUtf8 -LiteralPath $jsonPath -Value ($report | ConvertTo-Json -Depth 8)
        Set-DsmContentUtf8 -LiteralPath $mdPath -Value (ConvertTo-DsmDriverStoreReportMarkdown -Report $report)

        $report | Add-Member -NotePropertyName OutputFiles -NotePropertyValue ([pscustomobject]@{
                Json     = $jsonPath
                Markdown = $mdPath
            }) -Force
    }

    return $report
}
