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
