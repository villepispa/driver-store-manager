function Remove-DsmUnusedDriverPackages {
    <#
    .SYNOPSIS
        Exports and removes unused driver packages from the Driver Store.
    .DESCRIPTION
        Uses the same filter + preserve pipeline as Get-DsmDriverStoreReport. Default is
        preview mode unless -AllowDelete and -Confirm:$false are both set. Requires
        elevation for export/delete. Never uses pnputil /force. See docs/safety-gates.md.
    .PARAMETER BackupRoot
        Directory for pnputil /export-driver backups (default: project backups/<timestamp>).
    .PARAMETER Filter
        Optional DsmDriverFilter (same as report scoped section).
    .PARAMETER PreserveRule
        Preserve rules applied before candidate selection.
    .PARAMETER PreserveRulesPath
        JSON preserve rules file (see examples/preserve-rules.example.json).
    .PARAMETER IncludePublishedName
        Optional allow-list of oem#.inf names (intersected with deletable set).
    .PARAMETER MaxDeletes
        Cap the number of packages processed (0 = unlimited).
    .PARAMETER AllowDelete
        Must be set with -Confirm:$false to perform deletion. Never read from SettingsPath.
    .PARAMETER PassThru
        Return a single object with Results and Summary instead of streaming rows only.
    .PARAMETER SettingsPath
        Optional run-profile JSON. Loaded only when this parameter is bound.
        File values fill unbound keys; bound CLI parameters replace them.
        Arrays replace (no union). AllowDelete/Confirm/WhatIf are rejected in the file.
    .PARAMETER ShowEffectiveSettings
        Write each applied key and its source (default, settings, or cli).
    .EXAMPLE
        Remove-DsmUnusedDriverPackages -WhatIf
    .EXAMPLE
        Remove-DsmUnusedDriverPackages -PreserveRulesPath .\examples\preserve-rules.example.json -WhatIf
    .EXAMPLE
        $f = New-DsmDriverFilter -DriverClass 'Printer' -Association NeverAssociated
        Remove-DsmUnusedDriverPackages -Filter $f -WhatIf -PassThru
    .EXAMPLE
        Remove-DsmUnusedDriverPackages -AllowDelete -Confirm:$false -BackupRoot D:\dsm-backup
    .EXAMPLE
        Remove-DsmUnusedDriverPackages -SettingsPath .\examples\dsm.settings.example.json -WhatIf -PassThru
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
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

        [string] $BackupRoot,

        [string[]] $IncludePublishedName,

        [psobject[]] $PreserveRule,

        [string] $PreserveRulesPath,

        [int] $MaxDeletes = 0,

        [switch] $AllowDelete,

        [switch] $PassThru,

        [int] $InventoryMaxAgeMinutes = 15,

        [string] $SettingsPath,

        [switch] $ShowEffectiveSettings
    )

    $null = Set-DsmCallerSettingsOverlay -BoundParameters $PSBoundParameters

    $confirmExplicitlyDisabled = $PSBoundParameters.ContainsKey('Confirm') -and (
        $false -eq $PSBoundParameters['Confirm'])
    $performDelete = $AllowDelete -and $confirmExplicitlyDisabled -and -not $WhatIfPreference

    if ($performDelete -and -not (Test-DsmElevation)) {
        throw 'Administrator elevation required for driver export/delete. Start pwsh as Administrator.'
    }

    $planParams = @{
        Inventory              = $Inventory
        Filter                 = $Filter
        IncludeWindowsBuiltIn  = $IncludeWindowsBuiltIn
        PreserveRule           = $PreserveRule
        PreserveRulesPath      = $PreserveRulesPath
        IncludePublishedName   = $IncludePublishedName
        InventoryMaxAgeMinutes = $InventoryMaxAgeMinutes
    }
    if ($Provider) { $planParams['Provider'] = $Provider }
    if ($DeviceName) { $planParams['DeviceName'] = $DeviceName }
    if ($DriverVersion) { $planParams['DriverVersion'] = $DriverVersion }
    if ($MinDriverVersion) { $planParams['MinDriverVersion'] = $MinDriverVersion }
    if ($MaxDriverVersion) { $planParams['MaxDriverVersion'] = $MaxDriverVersion }
    if ($DriverClass) { $planParams['DriverClass'] = $DriverClass }
    if ($ClassGuid) { $planParams['ClassGuid'] = $ClassGuid }
    if ($HardwareId) { $planParams['HardwareId'] = $HardwareId }
    if ($PublishedName) { $planParams['PublishedName'] = $PublishedName }
    if ($OriginalName) { $planParams['OriginalName'] = $OriginalName }
    if ($Association) { $planParams['Association'] = $Association }

    $plan = Get-DsmDriverStoreCleanupPlan @planParams

    if (-not $BackupRoot) {
        $moduleRoot = Split-Path -Parent $PSScriptRoot
        $projectRoot = Split-Path -Parent (Split-Path -Parent $moduleRoot)
        $BackupRoot = Join-DsmPath $projectRoot 'backups' (Get-Date -Format 'yyyy-MM-dd_HHmmss')
    }

    if ($performDelete) {
        New-Item -ItemType Directory -Path $BackupRoot -Force | Out-Null
    }

    $candidates = @($plan.Candidates)
    if ($MaxDeletes -gt 0) {
        $candidates = @($candidates | Select-Object -First $MaxDeletes)
    }

    $familyContext = $plan.FamilyContext
    $results = [System.Collections.Generic.List[object]]::new()
    $deletedCount = 0
    $whatIfCount = 0
    $exportFailedCount = 0
    $skippedAllowDeleteCount = 0
    $skippedInUseCount = 0
    $skippedDisconnectedCount = 0

    foreach ($skipPkg in @($plan.NotDeletableInScope)) {
        $skipAction = switch ($skipPkg.DeviceAssociation) {
            'Connected' { 'SkippedInUse' }
            'DisconnectedInstalled' { 'SkippedDisconnectedInstalled' }
            default { $null }
        }
        if (-not $skipAction) { continue }

        $row = New-DsmCleanupResultRow -Package $skipPkg -FamilyContext $familyContext `
            -Action $skipAction
        $results.Add($row) | Out-Null
        if ($skipAction -eq 'SkippedInUse') {
            $skippedInUseCount++
        }
        else {
            $skippedDisconnectedCount++
        }
    }

    foreach ($pkg in $candidates) {
        $name = $pkg.PublishedName

        if (-not $performDelete) {
            $row = New-DsmCleanupResultRow -Package $pkg -FamilyContext $familyContext `
                -Action 'WhatIf'
            $whatIfCount++
            $results.Add($row) | Out-Null
            continue
        }

        if (-not $PSCmdlet.ShouldProcess($name, 'Export and delete unused driver package')) {
            $row = New-DsmCleanupResultRow -Package $pkg -FamilyContext $familyContext `
                -Action 'SkippedConfirmation'
            $skippedAllowDeleteCount++
            $results.Add($row) | Out-Null
            continue
        }

        $freshPkg = Update-DsmPackageDeletionEligibility -Package $pkg
        if (-not (Test-DsmPackageIsDeletableCandidate -Package $freshPkg)) {
            $skipAction = switch ($freshPkg.DeviceAssociation) {
                'Connected' { 'SkippedInUse' }
                'DisconnectedInstalled' { 'SkippedDisconnectedInstalled' }
                default { 'SkippedStaleEligibility' }
            }
            $row = New-DsmCleanupResultRow -Package $freshPkg -FamilyContext $familyContext `
                -Action $skipAction
            $results.Add($row) | Out-Null
            if ($skipAction -eq 'SkippedInUse') { $skippedInUseCount++ }
            elseif ($skipAction -eq 'SkippedDisconnectedInstalled') { $skippedDisconnectedCount++ }
            continue
        }

        try {
            $exportDir = Export-DsmDriverPackageBackup -PublishedName $name -BackupRoot $BackupRoot
            Remove-DsmDriverPackageFromStore -PublishedName $name
            $row = New-DsmCleanupResultRow -Package $pkg -FamilyContext $familyContext `
                -Action 'Deleted' -BackupPath $exportDir
            $deletedCount++
        }
        catch {
            $row = New-DsmCleanupResultRow -Package $pkg -FamilyContext $familyContext `
                -Action 'ExportOrDeleteFailed' -ErrorMessage $_.Exception.Message
            $exportFailedCount++
        }

        $results.Add($row) | Out-Null
    }

    Write-DsmCleanupResultLog -Results @($results)

    $summary = [ordered]@{
        Mode                      = if ($performDelete) { 'Delete' } else { 'WhatIf' }
        BackupRoot                = if ($performDelete) { $BackupRoot } else { $null }
        CandidateCount            = $candidates.Count
        DeletedCount              = $deletedCount
        WhatIfCount               = $whatIfCount
        ExportOrDeleteFailedCount = $exportFailedCount
        SkippedConfirmationCount  = $skippedAllowDeleteCount
        SkippedInUseCount         = $skippedInUseCount
        SkippedDisconnectedInstalledCount = $skippedDisconnectedCount
        PreservedSkippedCount     = $plan.PreservedSkippedCount
        FilterExcludedCount       = $plan.FilterExcludedCount
        ScopeExcludedCount        = $plan.ScopeExcludedCount
        NotDeletableInScopeCount  = $plan.NotDeletableInScopeCount
        OldVersionsOfInUseFamiliesCount = @($results | Where-Object { $_.IsOldVersionOfInUseFamily }).Count
        FilterManifest            = $plan.FilterManifest
        MaxDeletes                = $MaxDeletes
    }

    $output = [pscustomobject]@{
        Results = @($results)
        Summary = [pscustomobject]$summary
    }

    if ($PassThru) {
        return $output
    }

    return @($results)
}
