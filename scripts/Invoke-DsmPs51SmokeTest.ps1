#Requires -Version 5.1
<#
.SYNOPSIS
  Smoke-test Driver Store Manager on Windows PowerShell 5.1 with mocked pnputil fixtures.

.DESCRIPTION
  **Safety tier: 1** (read-only module and bundle checks; writes temp files under %TEMP% only).

  Validates Set-StrictMode paths, mocked pnputil correlation, blocklist XML, preserve JSON,
  UTF-8 no-BOM writes, and Intune detection/remediation logic without live pnputil.
  Exit 0 on success; exit 1 on failure.

.PARAMETER AgentSummary
  Write exactly one line to the success stream so agents can use a single
  powershell/pwsh -NoProfile -File invocation (no Shell compound with
  if ($LASTEXITCODE)): DSM-PS51-SMOKE-OK on exit 0;
  DSM-PS51-SMOKE-FAIL exit=1 failures=N on failure.

.EXAMPLE
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-DsmPs51SmokeTest.ps1

.EXAMPLE
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-DsmPs51SmokeTest.ps1 -AgentSummary

.NOTES
  Run on Windows PowerShell 5.1 before Intune upload. Requires pre-built dist/intune bundles.

.LINK
  docs/intune-deployment.md
#>
[CmdletBinding()]
param(
    [switch] $AgentSummary
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$failures = [System.Collections.Generic.List[string]]::new()

function Add-SmokeFailure {
    param([string] $Name, [string] $Detail)
    $msg = if ($Detail) { "$Name - $Detail" } else { $Name }
    $failures.Add($msg) | Out-Null
}

function Test-SmokeAssert {
    param(
        [bool] $Condition,
        [string] $Name,
        [string] $Detail
    )

    if (-not $Condition) {
        Add-SmokeFailure -Name $Name -Detail $Detail
    }
}

$projectRoot = Split-Path -Parent $PSScriptRoot
$harnessPath = Join-Path $projectRoot 'tests\helpers\Import-DsmTestHarness.ps1'
$fixtureRoot = Join-Path $projectRoot 'tests\fixtures'
$preserveRulesPath = Join-Path $projectRoot 'examples\preserve-rules.example.json'
$detectBundle = Join-Path $projectRoot 'dist\intune\Detect-DsmDriverStoreCompliance.ps1'
$remediateBundle = Join-Path $projectRoot 'dist\intune\Remediate-DsmDriverStore.ps1'
$smokeRoot = Join-Path $env:TEMP ("dsm-ps51-smoke_{0}" -f ([Guid]::NewGuid().ToString('N')))

Write-Host "Driver Store Manager PS 5.1 smoke - $($PSVersionTable.PSVersion)" -ForegroundColor Cyan

Test-SmokeAssert -Condition ($PSVersionTable.PSVersion.Major -lt 6) `
    -Name 'Host edition' -Detail "Expected Windows PowerShell 5.x, got $($PSVersionTable.PSVersion)"

. $harnessPath -MockPnPUtil -FixtureRoot $fixtureRoot

Test-SmokeAssert -Condition (-not (Test-DsmIsPowerShellCore)) `
    -Name 'Test-DsmIsPowerShellCore' -Detail 'Should be false on PS 5.1'

$inventory = @(Get-DsmDriverStoreInventory)
Test-SmokeAssert -Condition (@($inventory).Count -eq 2) `
    -Name 'Get-DsmDriverStoreInventory' -Detail "Expected 2 packages, got $(@($inventory).Count)"

$oem1 = $inventory | Where-Object PublishedName -eq 'oem1.inf' | Select-Object -First 1
$oem2 = $inventory | Where-Object PublishedName -eq 'oem2.inf' | Select-Object -First 1
Test-SmokeAssert -Condition ($null -ne $oem1 -and $oem1.DeviceAssociation -eq 'Connected') `
    -Name 'Device correlation (connected)' -Detail "oem1 association=$($oem1.DeviceAssociation)"
Test-SmokeAssert -Condition ($null -ne $oem2 -and $oem2.DeviceAssociation -eq 'DisconnectedInstalled') `
    -Name 'Device correlation (disconnected)' -Detail "oem2 association=$($oem2.DeviceAssociation)"

$blocklistXml = @'
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
  <FileRules>
    <Deny ID="ID_DENY_SAMPLE_SHA256" FriendlyName="sample.sys Hash Sha256"
          Hash="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" />
  </FileRules>
</SiPolicy>
'@
$blocklistSet = ConvertFrom-DsmMicrosoftBlocklistXml -PolicyXml ([xml]$blocklistXml)
$blocklistCount = @($blocklistSet).Count
Test-SmokeAssert -Condition ($blocklistCount -eq 1) `
    -Name 'ConvertFrom-DsmMicrosoftBlocklistXml' -Detail "Count=$blocklistCount"

Test-SmokeAssert -Condition (Test-Path -LiteralPath $preserveRulesPath) `
    -Name 'Preserve rules fixture' -Detail $preserveRulesPath

$report = Get-DsmDriverStoreReport -Inventory $inventory -SkipMicrosoftBlocklist `
    -PreserveRulesPath $preserveRulesPath
Test-SmokeAssert -Condition ($report.Global.Summary.TotalPackages -eq 2) `
    -Name 'Get-DsmDriverStoreReport + preserve JSON' `
    -Detail "TotalPackages=$($report.Global.Summary.TotalPackages)"

$cleanup = Remove-DsmUnusedDriverPackages -Inventory $inventory -WhatIf -PassThru
Test-SmokeAssert -Condition ($cleanup.Summary.Mode -eq 'WhatIf') `
    -Name 'Remove-DsmUnusedDriverPackages WhatIf' -Detail "Mode=$($cleanup.Summary.Mode)"

$detectReport = Get-DsmDriverStoreReport -Inventory $inventory -SkipMicrosoftBlocklist
$detectCleanupRequired = ($detectReport.Global.Summary.DeletableCandidateCount -ge 1)
Test-SmokeAssert -Condition (-not $detectCleanupRequired) `
    -Name 'Detection gate (fixture compliant)' `
    -Detail "DeletableCandidateCount=$($detectReport.Global.Summary.DeletableCandidateCount)"

function Test-DsmElevation { return $true }

$orphanInventory = @(
    [pscustomobject]@{
        PublishedName     = 'oem9.inf'
        OriginalName      = 'orphan.inf'
        Provider          = 'OrphanCo'
        DriverClass       = 'System'
        DriverVersion     = '1.0.0.0'
        DeviceAssociation = 'NeverAssociated'
        Devices           = @()
        Files             = @('orphan.sys')
        InUse             = $false
        DeviceCount       = 0
        CollectedAt       = Get-Date
        InventorySource   = 'ModuleInventory'
    }
)

New-Item -ItemType Directory -Path $smokeRoot -Force | Out-Null
$remediateBackup = Join-Path $smokeRoot 'remediation-backup'
$remediateRun = Remove-DsmUnusedDriverPackages -Inventory $orphanInventory -AllowDelete `
    -Confirm:$false -MaxDeletes 1 -BackupRoot $remediateBackup -PassThru
Test-SmokeAssert -Condition ($remediateRun.Summary.DeletedCount -eq 1) `
    -Name 'Remediation delete path (mocked)' `
    -Detail "DeletedCount=$($remediateRun.Summary.DeletedCount)"
Test-SmokeAssert -Condition ($remediateRun.Summary.ExportOrDeleteFailedCount -eq 0) `
    -Name 'Remediation export/delete failures' `
    -Detail "FailedCount=$($remediateRun.Summary.ExportOrDeleteFailedCount)"

$utfPath = Join-Path $env:TEMP ("dsm-ps51-smoke_{0}.txt" -f ([Guid]::NewGuid().ToString('N')))
try {
    Set-DsmContentUtf8 -LiteralPath $utfPath -Value 'smoke'
    $bytes = [System.IO.File]::ReadAllBytes($utfPath)
    $hasBom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
    Test-SmokeAssert -Condition (-not $hasBom) -Name 'Set-DsmContentUtf8 BOM' -Detail 'UTF-8 BOM present'
    Test-SmokeAssert -Condition ($bytes.Length -eq 5) `
        -Name 'Set-DsmContentUtf8 NoNewline' -Detail "Expected 5 bytes, got $($bytes.Length)"
}
finally {
    Remove-Item -LiteralPath $utfPath -Force -ErrorAction SilentlyContinue
}

foreach ($bundlePath in @($detectBundle, $remediateBundle)) {
    $bundleName = Split-Path -Leaf $bundlePath
    Test-SmokeAssert -Condition (Test-Path -LiteralPath $bundlePath) `
        -Name "Bundle exists ($bundleName)" -Detail $bundlePath
    if (Test-Path -LiteralPath $bundlePath) {
        $head = @(Get-Content -LiteralPath $bundlePath -TotalCount 12)
        $hasStrict = @($head | Where-Object { $_ -match 'Set-StrictMode\s+-Version\s+Latest' }).Count -gt 0
        Test-SmokeAssert -Condition $hasStrict `
            -Name "Bundle StrictMode ($bundleName)" -Detail 'Missing Set-StrictMode -Version Latest'
    }
}

Remove-Item -LiteralPath $smokeRoot -Recurse -Force -ErrorAction SilentlyContinue

if ($failures.Count -gt 0) {
    Write-Host "`nPS 5.1 smoke FAILED ($($failures.Count)):" -ForegroundColor Red
    foreach ($f in $failures) {
        Write-Host "  - $f" -ForegroundColor Red
    }
    if ($AgentSummary) {
        Write-Output ("DSM-PS51-SMOKE-FAIL exit=1 failures={0}" -f $failures.Count)
    }
    exit 1
}

Write-Host 'PS 5.1 smoke: PASS' -ForegroundColor Green
if ($AgentSummary) {
    Write-Output 'DSM-PS51-SMOKE-OK'
}
exit 0
