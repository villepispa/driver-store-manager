#Requires -Version 5.1
<#
.SYNOPSIS
  Repo-root validate gate: Intune build, PS 5.1 smoke, Pester, PSScriptAnalyzer.

.DESCRIPTION
  **Safety tier: 2** (rebuilds dist/intune via Build-DsmIntuneScripts.ps1;
  no network).

  Ordered stages: Gallery dep check → Intune bundle build → PS 5.1 smoke
  (via powershell.exe) → Pester (tests/unit) → ScriptAnalyzer. Prefer this
  entry for agents and CI discovery. Does not Install-Module (no network);
  prints the Install-Module pair when Pester or PSScriptAnalyzer is missing.

.PARAMETER SkipLint
  Skip PSScriptAnalyzer (e.g. when the module is unavailable locally).

.PARAMETER AgentSummary
  One success-stream line:
  DSM-VALIDATE-OK | DSM-VALIDATE-FAIL stage=<name> exit=N

.EXAMPLE
  pwsh -NoProfile -File .\scripts\Invoke-DsmValidate.ps1 -AgentSummary

.NOTES
  Cold host (CurrentUser):
  Install-Module Pester -MinimumVersion 5.5.0 -Scope CurrentUser -Force -SkipPublisherCheck
  Install-Module PSScriptAnalyzer -Scope CurrentUser -Force -SkipPublisherCheck

  ScriptSafetyGate TaskProfile for this script is ControlledWrite (build
  writes dist/intune).
#>
[CmdletBinding()]
param(
    [switch] $SkipLint,

    [switch] $AgentSummary
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$buildScript = Join-Path $PSScriptRoot 'Build-DsmIntuneScripts.ps1'
$smokeScript = Join-Path $PSScriptRoot 'Invoke-DsmPs51SmokeTest.ps1'
$pesterScript = Join-Path $repoRoot.Path 'tests\Invoke-DsmPester.ps1'
$lintScript = Join-Path $PSScriptRoot 'Invoke-DsmScriptAnalyzer.ps1'

function Test-DsmValidateDependency {
    $missing = @()
    $pester = Get-Module -ListAvailable -Name Pester |
        Sort-Object Version -Descending |
        Select-Object -First 1
    if (-not $pester -or $pester.Version -lt [version]'5.5.0') {
        $missing += 'Pester>=5.5'
    }
    if (-not $SkipLint) {
        if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
            $missing += 'PSScriptAnalyzer'
        }
    }
    if ($missing.Count -eq 0) {
        return
    }

    $hint = @(
        'Install-Module -Name Pester -MinimumVersion 5.5.0 -Scope CurrentUser -Force -SkipPublisherCheck'
        'Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force -SkipPublisherCheck'
    ) -join '; '
    if ($AgentSummary) {
        Write-Output (
            'DSM-VALIDATE-FAIL stage=deps exit=2 missing={0}' -f (
                ($missing -join ',')
            )
        )
    }
    else {
        Write-Error (
            "Missing Gallery modules: {0}. Run: {1}" -f (
                ($missing -join ', '),
                $hint
            )
        ) -ErrorAction Continue
    }
    exit 2
}

function Invoke-DsmStage {
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [string] $ScriptPath,

        [string] $HostExe = 'pwsh',

        [string[]] $ArgumentList = @()
    )

    if (-not (Test-Path -LiteralPath $ScriptPath)) {
        throw "Missing stage script ($Name): $ScriptPath"
    }

    $exeArgs = @('-NoProfile', '-File', $ScriptPath) + $ArgumentList
    if ($AgentSummary) {
        $exeArgs += '-AgentSummary'
    }

    & $HostExe @exeArgs
    $code = $LASTEXITCODE
    if ($null -eq $code) { $code = 0 }
    if ($code -ne 0) {
        if ($AgentSummary) {
            Write-Output ("DSM-VALIDATE-FAIL stage={0} exit={1}" -f $Name, $code)
        }
        exit $code
    }
}

Test-DsmValidateDependency

$powershellExe = Get-Command -Name powershell.exe -ErrorAction SilentlyContinue
if (-not $powershellExe) {
    if ($AgentSummary) {
        Write-Output 'DSM-VALIDATE-FAIL stage=smoke exit=2 detail=powershell.exe-missing'
    }
    else {
        Write-Error 'powershell.exe not found; PS 5.1 smoke requires Windows PowerShell.' -ErrorAction Continue
    }
    exit 2
}

Invoke-DsmStage -Name 'build' -ScriptPath $buildScript
Invoke-DsmStage -Name 'smoke' -ScriptPath $smokeScript -HostExe $powershellExe.Source
Invoke-DsmStage -Name 'pester' -ScriptPath $pesterScript

if (-not $SkipLint) {
    Invoke-DsmStage -Name 'lint' -ScriptPath $lintScript
}

if ($AgentSummary) {
    Write-Output 'DSM-VALIDATE-OK'
}
exit 0
