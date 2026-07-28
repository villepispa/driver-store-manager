#Requires -Version 5.1
<#
.SYNOPSIS
  Exports a DiskId and DriverVer catalog for OEM driver packages in the Driver Store.

.DESCRIPTION
  **Safety tier: 2** (writes JSON and CSV under -OutputPath; read-only against the Driver Store).

  Collects inventory via the DriverStoreManager module and parses INF DiskId fields.
  Exit 0 on success.

.PARAMETER OutputPath
  Directory for JSON and CSV output. Default: ..\audit-output.

.PARAMETER IncludeWindowsBuiltIn
  Include Windows built-in manifests (default scope is OEM only).

.PARAMETER AgentSummary
  Write exactly one line to the success stream so agents can use a single
  powershell/pwsh -NoProfile -File invocation (no Shell compound with
  if ($LASTEXITCODE)): DSM-DISKID-OK drivers=N withDiskId=M on exit 0;
  DSM-DISKID-FAIL exit=N on failure.

.EXAMPLE
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Export-DsmDriverDiskIdCatalog.ps1 `
    -OutputPath .\audit-output

.EXAMPLE
  pwsh -NoProfile -File .\scripts\Export-DsmDriverDiskIdCatalog.ps1 -OutputPath .\audit-output -AgentSummary

.NOTES
  Dual-host (PS 5.1 floor). Module: DriverStoreManager.

.LINK
  docs/lessons-learned.md
#>
[CmdletBinding()]
param(
    [string] $OutputPath = (Join-Path $PSScriptRoot '..\audit-output'),

    [switch] $IncludeWindowsBuiltIn,

    [switch] $AgentSummary
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
    $moduleRoot = Join-Path $PSScriptRoot '..\src\DriverStoreManager\DriverStoreManager.psd1'
    Import-Module $moduleRoot -Force

    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

    Write-Host 'Collecting driver inventory and reading INF DiskId fields...' -ForegroundColor Cyan
    $catalog = Export-DsmDriverDiskIdCatalog -IncludeWindowsBuiltIn:$IncludeWindowsBuiltIn

    $stamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
    $jsonPath = Join-Path $OutputPath "driver-store-diskid-catalog_$stamp.json"
    $csvPath = Join-Path $OutputPath "driver-store-diskid-catalog_$stamp.csv"

    Set-DsmContentUtf8 -LiteralPath $jsonPath -Value ($catalog | ConvertTo-Json -Depth 4)
    $catalog | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

    $driverCount = @($catalog).Count
    Write-Host "Wrote: $jsonPath ($driverCount drivers)" -ForegroundColor Green
    Write-Host "Wrote: $csvPath" -ForegroundColor Green

    $withDiskId = @($catalog | Where-Object { $_.DiskId }).Count
    Write-Host "DiskId parsed: $withDiskId / $driverCount" -ForegroundColor DarkGray

    if ($AgentSummary) {
        Write-Output ("DSM-DISKID-OK drivers={0} withDiskId={1}" -f $driverCount, $withDiskId)
    }
}
catch {
    if ($AgentSummary) {
        $msg = $_.Exception.Message -replace '\s+', ' '
        Write-Output ("DSM-DISKID-FAIL exit=1 detail={0}" -f $msg)
        exit 1
    }
    throw
}
