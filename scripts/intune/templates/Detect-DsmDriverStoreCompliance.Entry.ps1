# --- Intune detection entry (merged by Build-DsmIntuneScripts.ps1 from Detect-DsmDriverStoreCompliance.Entry.ps1) ---
$ErrorActionPreference = 'Stop'

# region DSM_BUILD_CONFIG
$DsmDetectBlocklisted = $true
$DsmDetectSignatureIssues = $true
$DsmDetectOrphanCandidates = $true
$DsmOrphanThreshold = 1
$DsmSkipMicrosoftBlocklist = $false
$DsmForceBlocklistUpdate = $false
$DsmBlocklistPath = $null
$DsmPreserveRulesPath = $null
$DsmInlineBlocklistContent = $null
$DsmInlinePreserveRulesContent = $null
$DsmFamilyGroupBy = $null
$DsmMicrosoftBlocklistMaxAgeDays = $null
$DsmIncludeCleanupPreview = $null
$DsmExportDiskIdCatalog = $null
$DsmUseMicrosoftBlocklist = $null
$DsmVulnerableIncludesSignature = $null
$DsmIncludeVulnerabilityScan = $null
$DsmFilter = @{}
$DsmIncludePublishedName = $null
$DsmInventoryMaxAgeMinutes = $null
$DsmIncludeDism = $null
$DsmShowEffectiveSettings = $null
$DsmRestrictProgramDataAccess = $true
# endregion DSM_BUILD_CONFIG

if ($DsmInlineBlocklistContent) {
    $inlineRoot = Get-DsmProgramDataRoot -ChildPath @('config', 'inline')
    if (-not (Test-Path -LiteralPath $inlineRoot)) {
        New-Item -ItemType Directory -Path $inlineRoot -Force | Out-Null
    }
    $DsmBlocklistPath = Join-DsmPath $inlineRoot 'blocklist-hashes.txt'
    Set-DsmContentUtf8 -LiteralPath $DsmBlocklistPath -Value $DsmInlineBlocklistContent
}

if ($DsmInlinePreserveRulesContent) {
    $inlineRoot = Get-DsmProgramDataRoot -ChildPath @('config', 'inline')
    if (-not (Test-Path -LiteralPath $inlineRoot)) {
        New-Item -ItemType Directory -Path $inlineRoot -Force | Out-Null
    }
    $DsmPreserveRulesPath = Join-DsmPath $inlineRoot 'preserve-rules.json'
    Set-DsmContentUtf8 -LiteralPath $DsmPreserveRulesPath -Value $DsmInlinePreserveRulesContent
}

$DsmReportRoot = Get-DsmProgramDataRoot -ChildPath @('reports', 'intune-detection')
if (-not (Test-Path -LiteralPath $DsmReportRoot)) {
    New-Item -ItemType Directory -Path $DsmReportRoot -Force | Out-Null
}

try {
    $reportParams = @{}
    if ($null -eq $DsmIncludeVulnerabilityScan -or $DsmIncludeVulnerabilityScan) {
        $reportParams['IncludeVulnerabilityScan'] = $true
    }
    else {
        $reportParams['IncludeVulnerabilityScan'] = $false
    }
    foreach ($dsmKey in @($DsmFilter.Keys)) {
        $reportParams[$dsmKey] = $DsmFilter[$dsmKey]
    }
    if ($DsmFamilyGroupBy) { $reportParams['FamilyGroupBy'] = $DsmFamilyGroupBy }
    if ($null -ne $DsmMicrosoftBlocklistMaxAgeDays) {
        $reportParams['MicrosoftBlocklistMaxAgeDays'] = $DsmMicrosoftBlocklistMaxAgeDays
    }
    if ($null -ne $DsmUseMicrosoftBlocklist) {
        $reportParams['UseMicrosoftBlocklist'] = [bool]$DsmUseMicrosoftBlocklist
    }
    if ($null -ne $DsmVulnerableIncludesSignature) {
        $reportParams['VulnerableIncludesSignature'] = [bool]$DsmVulnerableIncludesSignature
    }
    if ($DsmIncludeDism) {
        $reportParams['Inventory'] = @(Get-DsmDriverStoreInventory -IncludeDism)
    }
    if ($DsmBlocklistPath -and (Test-Path -LiteralPath $DsmBlocklistPath)) {
        $reportParams['BlocklistPath'] = $DsmBlocklistPath
    }
    if ($DsmSkipMicrosoftBlocklist) { $reportParams['SkipMicrosoftBlocklist'] = $true }
    if ($DsmForceBlocklistUpdate) { $reportParams['UpdateMicrosoftBlocklist'] = $true }
    if ($DsmPreserveRulesPath -and (Test-Path -LiteralPath $DsmPreserveRulesPath)) {
        $reportParams['PreserveRulesPath'] = $DsmPreserveRulesPath
    }
    if ($DsmShowEffectiveSettings) {
        foreach ($dsmKey in @($DsmFilter.Keys)) {
            Write-Host ('{0}={1} (intune)' -f $dsmKey, (@($DsmFilter[$dsmKey]) -join ','))
        }
    }

    $report = Get-DsmDriverStoreReport @reportParams -OutputPath $DsmReportRoot
    if ($report.OutputFiles -and $report.OutputFiles.FilteredCsv) {
        Write-Host ("DSM-FILTERED-DRIVERS count={0} file={1}" -f `
                $report.Scoped.Summary.TotalPackages, $report.OutputFiles.FilteredCsv)
    }
    # Scoped equals Global when no filter is baked. A baked filter (DriverClass, and so on)
    # must drive the compliance gate or remediation would delete a narrower set than detection counted.
    $summary = $report.Scoped.Summary

    if ($DsmIncludeCleanupPreview) {
        $previewParams = @{
            WhatIf   = $true
            PassThru = $true
        }
        foreach ($dsmKey in @($DsmFilter.Keys)) {
            $previewParams[$dsmKey] = $DsmFilter[$dsmKey]
        }
        if ($DsmPreserveRulesPath -and (Test-Path -LiteralPath $DsmPreserveRulesPath)) {
            $previewParams['PreserveRulesPath'] = $DsmPreserveRulesPath
        }
        if ($DsmIncludePublishedName) {
            $previewParams['IncludePublishedName'] = $DsmIncludePublishedName
        }
        if ($null -ne $DsmInventoryMaxAgeMinutes) {
            $previewParams['InventoryMaxAgeMinutes'] = $DsmInventoryMaxAgeMinutes
        }
        if ($DsmIncludeDism -and $reportParams.ContainsKey('Inventory')) {
            $previewParams['Inventory'] = $reportParams['Inventory']
        }
        $preview = Remove-DsmUnusedDriverPackages @previewParams
        $previewStamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
        $previewPath = Join-DsmPath $DsmReportRoot "cleanup-preview_$previewStamp.json"
        Set-DsmContentUtf8 -LiteralPath $previewPath -Value ($preview | ConvertTo-Json -Depth 6)
    }

    if ($DsmExportDiskIdCatalog) {
        $catalogParams = @{}
        if ($DsmIncludeDism -and $reportParams.ContainsKey('Inventory')) {
            $catalogParams['Inventory'] = $reportParams['Inventory']
        }
        $catalog = @(Export-DsmDriverDiskIdCatalog @catalogParams)
        $catalogStamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
        $catalogJson = Join-DsmPath $DsmReportRoot "diskid-catalog_$catalogStamp.json"
        $catalogCsv = Join-DsmPath $DsmReportRoot "diskid-catalog_$catalogStamp.csv"
        Set-DsmContentUtf8 -LiteralPath $catalogJson -Value ($catalog | ConvertTo-Json -Depth 4)
        $catalog | Export-Csv -LiteralPath $catalogCsv -NoTypeInformation -Encoding UTF8
    }

    # Gate 7: vulnerability signals are advisory — only orphan cleanup triggers remediation.
    $cleanupRequired = $false
    if ($DsmDetectOrphanCandidates -and $summary.DeletableCandidateCount -ge $DsmOrphanThreshold) {
        $cleanupRequired = $true
    }

    $vulnManifest = $report.VulnerabilityManifest
    if ($vulnManifest -and $vulnManifest.ScanState -eq 'Unavailable') {
        exit 2
    }

    # Advisory-only (Gate 7 still orphan cleanup). Knobs stay baked so
    # operators can see intended policy; they do not change the exit code.
    if ($DsmDetectBlocklisted -and $summary.BlocklistedInUseCount -gt 0) {
        Write-Verbose (
            'Advisory: BlocklistedInUseCount={0}' -f $summary.BlocklistedInUseCount
        )
    }
    if ($DsmDetectSignatureIssues -and $summary.SignatureIssueCount -gt 0) {
        Write-Verbose (
            'Advisory: SignatureIssueCount={0}' -f $summary.SignatureIssueCount
        )
    }

    if ($cleanupRequired) {
        exit 1
    }

    exit 0
}
catch {
    Write-Error $_
    exit 2
}
finally {
    if ($DsmRestrictProgramDataAccess) {
        $protectedRoot = Get-DsmProgramDataRoot
        if (-not (Test-Path -LiteralPath $protectedRoot)) {
            New-Item -ItemType Directory -Path $protectedRoot -Force | Out-Null
        }
        Set-DsmRestrictedDirectoryAcl -LiteralPath $protectedRoot
    }
}
