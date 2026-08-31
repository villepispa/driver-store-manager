#Requires -Version 5.1
<#
.SYNOPSIS
  Runs Driver Store Manager Pester suites with Pester 5.5+ or 6.x.

.DESCRIPTION
  **Safety tier: 1** (executes unit tests; no production Driver Store mutations).

  Uses the Pester configuration object (v5/v6). Pester 6 discovers and runs each test file
  in isolation; harness setup lives in per-file BeforeAll blocks.
  Exit code follows Pester (-Exit).

.PARAMETER TestPath
  One or more *.Tests.ps1 paths. Default: core DriverStoreManager test files under tests/.

.PARAMETER AgentSummary
  Write exactly one line to the success stream so agents can use a single
  pwsh -NoProfile -File invocation (no Shell compound with if ($LASTEXITCODE)):
  DSM-PESTER-OK passed=N on exit 0; DSM-PESTER-FAIL exit=1 failed=N on failure.
  When set, Pester Exit is disabled so this script owns the exit code.

.EXAMPLE
  pwsh -NoProfile -File .\tests\Invoke-DsmPester.ps1

.EXAMPLE
  pwsh -NoProfile -File .\tests\Invoke-DsmPester.ps1 -AgentSummary

.EXAMPLE
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Invoke-DsmPester.ps1

.NOTES
  Install: Install-Module Pester -MinimumVersion 6.0.0 -Scope CurrentUser -Force

.LINK
  docs/pester-version-tracking.md
#>
[CmdletBinding()]
param(
    [string[]] $TestPath = @(
        (Join-Path $PSScriptRoot 'DriverStoreManager.Tests.ps1')
        (Join-Path $PSScriptRoot 'DriverStoreManager.MockedPnPUtil.Tests.ps1')
        (Join-Path $PSScriptRoot 'DriverStoreManager.CleanupMocks.Tests.ps1')
        (Join-Path $PSScriptRoot 'Build-DsmIntuneScripts.Tests.ps1')
    ),

    [switch] $AgentSummary
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$pester = Get-Module Pester -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
if (-not $pester) {
    if ($AgentSummary) {
        Write-Output 'DSM-PESTER-FAIL exit=2 detail=Pester-not-installed'
        exit 2
    }
    throw 'Pester is not installed. Install-Module Pester -MinimumVersion 6.0.0 -Scope CurrentUser'
}
if ($pester.Version -lt [version]'5.5.0') {
    if ($AgentSummary) {
        Write-Output ("DSM-PESTER-FAIL exit=2 detail=Pester-too-old version={0}" -f $pester.Version)
        exit 2
    }
    throw "Pester $($pester.Version) is too old. Install-Module Pester -MinimumVersion 6.0.0 -Scope CurrentUser"
}

Import-Module Pester -MinimumVersion $pester.Version -Force
Write-Host "Using Pester $($pester.Version)"

$projectRoot = Resolve-Path (Join-Path $PSScriptRoot '..')

$config = New-PesterConfiguration
$config.Run.Path = $TestPath
$config.Run.RepoRoot = $projectRoot.Path
$config.Run.Exit = -not $AgentSummary
$config.Run.PassThru = $true
$config.Output.Verbosity = 'Detailed'

$result = Invoke-Pester -Configuration $config

if ($AgentSummary) {
    $failed = 0
    $passed = 0
    if ($null -ne $result) {
        if ($null -ne $result.FailedCount) { $failed = [int]$result.FailedCount }
        elseif ($result.PSObject.Properties['Failed'] -and $null -ne $result.Failed) {
            $failed = @($result.Failed).Count
        }
        if ($null -ne $result.PassedCount) { $passed = [int]$result.PassedCount }
        elseif ($result.PSObject.Properties['Passed'] -and $null -ne $result.Passed) {
            $passed = @($result.Passed).Count
        }
    }
    if ($failed -gt 0) {
        Write-Output ("DSM-PESTER-FAIL exit=1 failed={0} passed={1}" -f $failed, $passed)
        exit 1
    }
    Write-Output ("DSM-PESTER-OK passed={0}" -f $passed)
    exit 0
}
