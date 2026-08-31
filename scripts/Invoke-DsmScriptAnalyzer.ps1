#Requires -Version 5.1
<#
.SYNOPSIS
  Run PSScriptAnalyzer on Driver Store Manager scripts and module.

.DESCRIPTION
  **Safety tier: 1** (read-only static analysis; no network).

  Scans scripts/ (excluding _drafts/_archive) and src/DriverStoreManager
  using the repo-root PSScriptAnalyzerSettings.psd1. Does not depend on
  private catalog lint rules. Skips dist/ (generated Intune bundles).

.PARAMETER Path
  Optional extra roots or files. Default: scripts + src/DriverStoreManager
  under repo root.

.PARAMETER SettingsPath
  Optional settings .psd1. Default: ../PSScriptAnalyzerSettings.psd1.

.PARAMETER AgentSummary
  One success-stream line for bare pwsh -File:
  DSM-LINT-OK findings=0 files=N | DSM-LINT-FAIL exit=1 findings=N |
  DSM-LINT-MISS (module missing, exit 2). Fails on Error and Warning
  (WGA/spine). Remaining rules: PSScriptAnalyzerSettings.psd1 ExcludeRules.

.EXAMPLE
  pwsh -NoProfile -File .\scripts\Invoke-DsmScriptAnalyzer.ps1 -AgentSummary
#>
[CmdletBinding()]
param(
    [string[]] $Path = @(),

    [string] $SettingsPath = '',

    [switch] $AgentSummary
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')

if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
    if ($AgentSummary) {
        Write-Output 'DSM-LINT-MISS'
    }
    Write-Error 'PSScriptAnalyzer is not installed. Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force' -ErrorAction Continue
    exit 2
}

Import-Module PSScriptAnalyzer -ErrorAction Stop

if ([string]::IsNullOrWhiteSpace($SettingsPath)) {
    $SettingsPath = Join-Path $repoRoot.Path 'PSScriptAnalyzerSettings.psd1'
}
if (-not (Test-Path -LiteralPath $SettingsPath)) {
    if ($AgentSummary) {
        Write-Output 'DSM-LINT-FAIL exit=1 detail=settings-missing'
    }
    throw "Settings not found: $SettingsPath"
}

$targets = @()
if ($Path -and $Path.Count -gt 0) {
    foreach ($p in $Path) {
        if (-not [System.IO.Path]::IsPathRooted($p)) {
            $p = Join-Path $repoRoot.Path $p
        }
        if (-not (Test-Path -LiteralPath $p)) {
            throw "Path not found: $p"
        }
        $targets += (Resolve-Path -LiteralPath $p).Path
    }
}
else {
    $targets += (Join-Path $repoRoot.Path 'scripts')
    $targets += (Join-Path $repoRoot.Path 'src\DriverStoreManager')
}

$fileList = New-Object System.Collections.Generic.List[string]
foreach ($target in $targets) {
    $item = Get-Item -LiteralPath $target
    if ($item.PSIsContainer) {
        Get-ChildItem -LiteralPath $target -Recurse -File |
            Where-Object {
                $_.Extension -in '.ps1', '.psm1', '.psd1'
            } |
            ForEach-Object {
                $full = $_.FullName
                $norm = $full.Replace('\', '/')
                if ($norm -match '(^|/)(_drafts|_archive|dist)(/|$)') {
                    return
                }
                [void]$fileList.Add($full)
            }
    }
    else {
        [void]$fileList.Add($item.FullName)
    }
}

$uniqueFiles = @($fileList | Sort-Object -Unique)
$findings = @()
foreach ($scriptPath in $uniqueFiles) {
    $findings += @(
        Invoke-ScriptAnalyzer -Path $scriptPath -Settings $SettingsPath
    )
}

# Fail on any Error or Warning (WGA/spine). Settings ExcludeRules is the
# documented allow-list for remaining style noise (DSM-036).
$count = @($findings).Count
if ($count -gt 0) {
    $findings |
        Format-Table -AutoSize RuleName, Severity, ScriptName, Line, Message |
        Out-Host
    if ($AgentSummary) {
        Write-Output ('DSM-LINT-FAIL exit=1 findings={0}' -f $count)
    }
    exit 1
}

if ($AgentSummary) {
    Write-Output (
        'DSM-LINT-OK findings=0 files={0}' -f $uniqueFiles.Count
    )
}
exit 0
