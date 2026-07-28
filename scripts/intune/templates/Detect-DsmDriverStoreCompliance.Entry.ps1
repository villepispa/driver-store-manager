# --- Intune detection entry (merged by Build-DsmIntuneScripts.ps1 from Detect-DsmDriverStoreCompliance.Entry.ps1) ---
$ErrorActionPreference = 'Stop'

$DsmDetectBlocklisted = $true
$DsmDetectSignatureIssues = $true
$DsmDetectOrphanCandidates = $true
$DsmOrphanThreshold = 1
$DsmBlocklistPath = $null
$DsmSkipMicrosoftBlocklist = $false
$DsmForceBlocklistUpdate = $false
$DsmPreserveRulesPath = $null

$DsmReportRoot = Get-DsmProgramDataRoot -ChildPath @('reports', 'intune-detection')
if (-not (Test-Path -LiteralPath $DsmReportRoot)) {
    New-Item -ItemType Directory -Path $DsmReportRoot -Force | Out-Null
}

try {
    $reportParams = @{
        IncludeVulnerabilityScan = $true
    }
    if ($DsmBlocklistPath -and (Test-Path -LiteralPath $DsmBlocklistPath)) {
        $reportParams['BlocklistPath'] = $DsmBlocklistPath
    }
    if ($DsmSkipMicrosoftBlocklist) { $reportParams['SkipMicrosoftBlocklist'] = $true }
    if ($DsmForceBlocklistUpdate) { $reportParams['UpdateMicrosoftBlocklist'] = $true }
    if ($DsmPreserveRulesPath -and (Test-Path -LiteralPath $DsmPreserveRulesPath)) {
        $reportParams['PreserveRulesPath'] = $DsmPreserveRulesPath
    }

    $report = Get-DsmDriverStoreReport @reportParams -OutputPath $DsmReportRoot
    $summary = $report.Global.Summary

    # Gate 7: vulnerability signals are advisory — only orphan cleanup triggers remediation.
    $cleanupRequired = $false
    if ($DsmDetectOrphanCandidates -and $summary.DeletableCandidateCount -ge $DsmOrphanThreshold) {
        $cleanupRequired = $true
    }

    $vulnManifest = $report.VulnerabilityManifest
    if ($vulnManifest -and $vulnManifest.ScanState -eq 'Unavailable') {
        exit 2
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
