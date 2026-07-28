#Requires -Version 5.1
<#
.SYNOPSIS
  Downloads or refreshes the Microsoft vulnerable driver blocklist cache.

.DESCRIPTION
  **Safety tier: 3** (network GET to aka.ms; writes SHA256 hashes under ProgramData\DriverStoreManager).

  Fetches https://aka.ms/VulnerableDriverBlockList and updates the on-disk cache unless
  fresh within -MaxAgeDays. Exit 0 on success.

.PARAMETER Force
  Download even when the on-disk cache is newer than -MaxAgeDays.

.PARAMETER MaxAgeDays
  Skip download when cache is fresh. Default: 7.

.PARAMETER AgentSummary
  Write exactly one line to the success stream so agents can use a single
  powershell/pwsh -NoProfile -File invocation (no Shell compound with
  if ($LASTEXITCODE)): DSM-BLOCKLIST-OK updated=bool reason=… hashes=N on exit 0;
  DSM-BLOCKLIST-FAIL exit=N on failure.

.EXAMPLE
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Update-DsmMicrosoftDriverBlocklist.ps1 -Force

.EXAMPLE
  pwsh -NoProfile -File .\scripts\Update-DsmMicrosoftDriverBlocklist.ps1 -AgentSummary

.NOTES
  Dual-host (PS 5.1 floor). Thin wrapper around Update-DsmMicrosoftDriverBlocklist cmdlet.

.LINK
  docs/intune-deployment.md
#>
[CmdletBinding()]
param(
    [int] $MaxAgeDays = 7,

    [switch] $Force,

    [switch] $AgentSummary
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
    $moduleRoot = Join-Path $PSScriptRoot '..\src\DriverStoreManager\DriverStoreManager.psd1'
    Import-Module $moduleRoot -Force

    $result = Update-DsmMicrosoftDriverBlocklist -MaxAgeDays $MaxAgeDays -Force:$Force
    $result | Format-List

    if (-not $result.Updated -and $result.Reason -eq 'CacheFresh') {
        Write-Host 'Cache is fresh; use -Force to re-download.' -ForegroundColor DarkGray
    }

    if ($AgentSummary) {
        $hashCount = 0
        if ($null -ne $result.PSObject.Properties['HashCount']) {
            $hashCount = [int]$result.HashCount
        }
        Write-Output ("DSM-BLOCKLIST-OK updated={0} reason={1} hashes={2}" -f `
            [bool]$result.Updated, $result.Reason, $hashCount)
    }
}
catch {
    if ($AgentSummary) {
        $msg = $_.Exception.Message -replace '\s+', ' '
        Write-Output ("DSM-BLOCKLIST-FAIL exit=1 detail={0}" -f $msg)
        exit 1
    }
    throw
}
