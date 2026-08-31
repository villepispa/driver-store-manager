#Requires -Version 5.1
<#
.SYNOPSIS
  Runs a one-shot Driver Store audit via Get-DsmDriverStoreReport; emits JSON and Markdown reports.

.DESCRIPTION
  **Safety tier: 2** (writes reports and optional preview/catalog files to -OutputPath; may refresh Microsoft blocklist cache under ProgramData).

  **Safety tier: 3** with -UpdateMicrosoftBlocklist or when the Microsoft cache auto-refresh runs (network GET to aka.ms).

  Orchestrates inventory, vulnerability scan, optional WhatIf cleanup preview, and optional DiskId catalog export.
  Exit 0 on success.

.PARAMETER OutputPath
  Directory for JSON and Markdown reports (created if missing). Default: ..\audit-output.

.PARAMETER BlocklistPath
  Optional supplemental SHA256 hash file merged with the auto-updated Microsoft cache.

.PARAMETER UpdateMicrosoftBlocklist
  Force download of Microsoft's vulnerable driver blocklist before scanning.

.PARAMETER SkipMicrosoftBlocklist
  Use only -BlocklistPath; disable Microsoft auto-update (offline or custom blocklist).

.PARAMETER MicrosoftBlocklistMaxAgeDays
  Refresh the Microsoft cache when older than this many days. Default: 7.

.PARAMETER PreserveRulesPath
  Optional preserve rules JSON (see examples/preserve-rules.example.json).

.PARAMETER IncludeCleanupPreview
  Emit WhatIf cleanup candidates to a separate JSON file under -OutputPath.

.PARAMETER ExportDiskIdCatalog
  Emit DiskId and DriverVer catalog JSON and CSV for OEM drivers under -OutputPath.

.PARAMETER IncludeDism
  Collect inventory via DISM in addition to pnputil (slower; richer metadata).

.PARAMETER IncludeWindowsBuiltIn
  Include Windows built-in driver manifests in scoped metrics and optional exports.

.PARAMETER AgentSummary
  Write exactly one line to the success stream so agents can use a single
  powershell/pwsh -NoProfile -File invocation (no Shell compound with
  if ($LASTEXITCODE)): DSM-AUDIT-OK packages=N deletable=M on exit 0;
  DSM-AUDIT-FAIL exit=N on failure.

.EXAMPLE
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-DsmDriverStoreAudit.ps1 `
    -OutputPath .\audit-output -BlocklistPath .\examples\blocklist-hashes.example.txt

.EXAMPLE
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-DsmDriverStoreAudit.ps1 `
    -OutputPath .\audit-output -PreserveRulesPath .\examples\preserve-rules.example.json -IncludeCleanupPreview

.EXAMPLE
  pwsh -NoProfile -File .\scripts\Invoke-DsmDriverStoreAudit.ps1 -OutputPath .\audit-output -AgentSummary

.NOTES
  Dual-host (PS 5.1 floor). Delegates to DriverStoreManager module cmdlets.

.LINK
  docs/architecture.md
#>
[CmdletBinding()]
param(
    [string] $OutputPath = (Join-Path $PSScriptRoot '..\audit-output'),

    [string] $BlocklistPath,

    [string] $PreserveRulesPath,

    [switch] $UpdateMicrosoftBlocklist,

    [switch] $SkipMicrosoftBlocklist,

    [int] $MicrosoftBlocklistMaxAgeDays = 7,

    [switch] $IncludeCleanupPreview,

    [switch] $ExportDiskIdCatalog,

    [switch] $IncludeDism,

    [switch] $IncludeWindowsBuiltIn,

    [switch] $AgentSummary
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
    $moduleRoot = Join-Path $PSScriptRoot '..\src\DriverStoreManager\DriverStoreManager.psd1'
    Import-Module $moduleRoot -Force

    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

    Write-Host "Building Driver Store report..." -ForegroundColor Cyan
    Write-Host "Host: PowerShell $($PSVersionTable.PSVersion)" -ForegroundColor DarkGray

    $reportParams = @{
        OutputPath               = $OutputPath
        IncludeVulnerabilityScan = $true
        IncludeWindowsBuiltIn    = $IncludeWindowsBuiltIn
    }
    if ($BlocklistPath) { $reportParams['BlocklistPath'] = $BlocklistPath }
    if ($PreserveRulesPath) { $reportParams['PreserveRulesPath'] = $PreserveRulesPath }
    if ($UpdateMicrosoftBlocklist) { $reportParams['UpdateMicrosoftBlocklist'] = $true }
    if ($SkipMicrosoftBlocklist) { $reportParams['SkipMicrosoftBlocklist'] = $true }
    if ($MicrosoftBlocklistMaxAgeDays -ne 7) {
        $reportParams['MicrosoftBlocklistMaxAgeDays'] = $MicrosoftBlocklistMaxAgeDays
    }

    if ($IncludeDism) {
        $reportParams['Inventory'] = @(Get-DsmDriverStoreInventory -IncludeDism)
    }
    elseif ($IncludeCleanupPreview -or $ExportDiskIdCatalog) {
        $reportParams['Inventory'] = @(Get-DsmDriverStoreInventory)
    }

    $report = Get-DsmDriverStoreReport @reportParams

    Write-Host "Wrote: $($report.OutputFiles.Json)" -ForegroundColor Green
    Write-Host "Wrote: $($report.OutputFiles.Markdown)" -ForegroundColor Green
    Write-Host ($report.Global.Summary | Format-List | Out-String)

    $previewCandidates = 0
    if ($IncludeCleanupPreview) {
        $stamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
        $cleanupParams = @{
            WhatIf                 = $true
            PassThru               = $true
            IncludeWindowsBuiltIn  = $IncludeWindowsBuiltIn
            InventoryMaxAgeMinutes = 15
        }
        if ($PreserveRulesPath) { $cleanupParams['PreserveRulesPath'] = $PreserveRulesPath }
        if ($reportParams['Inventory']) { $cleanupParams['Inventory'] = $reportParams['Inventory'] }

        $preview = Remove-DsmUnusedDriverPackages @cleanupParams
        $previewPath = Join-Path $OutputPath "driver-store-cleanup-preview_$stamp.json"
        Set-DsmContentUtf8 -LiteralPath $previewPath -Value ($preview | ConvertTo-Json -Depth 6)
        $previewCandidates = [int]$preview.Summary.CandidateCount
        Write-Host "Wrote cleanup preview: $previewPath ($previewCandidates candidates, $($preview.Summary.OldVersionsOfInUseFamiliesCount) superseded by in-use)" -ForegroundColor Green
    }

    $catalogCount = 0
    if ($ExportDiskIdCatalog) {
        $stamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
        $catalogParams = @{}
        if ($IncludeWindowsBuiltIn) { $catalogParams['IncludeWindowsBuiltIn'] = $true }
        if ($reportParams['Inventory']) { $catalogParams['Inventory'] = $reportParams['Inventory'] }

        $catalog = Export-DsmDriverDiskIdCatalog @catalogParams
        $catalogJson = Join-Path $OutputPath "driver-store-diskid-catalog_$stamp.json"
        $catalogCsv = Join-Path $OutputPath "driver-store-diskid-catalog_$stamp.csv"
        Set-DsmContentUtf8 -LiteralPath $catalogJson -Value ($catalog | ConvertTo-Json -Depth 4)
        $catalog | Export-Csv -LiteralPath $catalogCsv -NoTypeInformation -Encoding UTF8
        $catalogCount = @($catalog).Count
        Write-Host "Wrote DiskId catalog: $catalogJson ($catalogCount drivers)" -ForegroundColor Green
        Write-Host "Wrote DiskId catalog: $catalogCsv" -ForegroundColor Green
    }

    if ($AgentSummary) {
        $packages = 0
        $deletable = 0
        if ($null -ne $report.Global -and $null -ne $report.Global.Summary) {
            $packages = [int]$report.Global.Summary.TotalPackages
            $deletable = [int]$report.Global.Summary.DeletableCandidateCount
        }
        Write-Output ("DSM-AUDIT-OK packages={0} deletable={1} previewCandidates={2} catalog={3}" -f `
            $packages, $deletable, $previewCandidates, $catalogCount)
    }
}
catch {
    if ($AgentSummary) {
        $msg = $_.Exception.Message -replace '\s+', ' '
        Write-Output ("DSM-AUDIT-FAIL exit=1 detail={0}" -f $msg)
        exit 1
    }
    throw
}
