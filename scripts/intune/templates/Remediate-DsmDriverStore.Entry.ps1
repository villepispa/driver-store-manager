# --- Intune remediation entry (merged by Build-DsmIntuneScripts.ps1 from Remediate-DsmDriverStore.Entry.ps1) ---
$ErrorActionPreference = 'Stop'

# region DSM_BUILD_CONFIG
$DsmRemediationMaxDeletes = 10
$DsmRemediationRequireElevation = $true
$DsmPreserveRulesPath = $null
$DsmInlinePreserveRulesContent = $null
# endregion DSM_BUILD_CONFIG

if ($DsmInlinePreserveRulesContent) {
    $inlineRoot = Get-DsmProgramDataRoot -ChildPath @('config', 'inline')
    if (-not (Test-Path -LiteralPath $inlineRoot)) {
        New-Item -ItemType Directory -Path $inlineRoot -Force | Out-Null
    }
    $DsmPreserveRulesPath = Join-DsmPath $inlineRoot 'preserve-rules.json'
    Set-DsmContentUtf8 -LiteralPath $DsmPreserveRulesPath -Value $DsmInlinePreserveRulesContent
}

$DsmStateRoot = Get-DsmProgramDataRoot
$DsmBackupRoot = Join-DsmPath $DsmStateRoot 'backups' (Get-Date -Format 'yyyy-MM-dd_HHmmss')
$DsmReportRoot = Join-DsmPath $DsmStateRoot 'reports' 'intune-remediation'

foreach ($dir in @($DsmStateRoot, $DsmBackupRoot, $DsmReportRoot)) {
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

try {
    if ($DsmRemediationRequireElevation -and -not (Test-DsmElevation)) {
        Write-Error 'Remediation requires administrator / SYSTEM context.'
        exit 2
    }

    $cleanupParams = @{
        BackupRoot    = $DsmBackupRoot
        AllowDelete   = $true
        Confirm       = $false
        PassThru      = $true
        MaxDeletes    = $DsmRemediationMaxDeletes
    }
    if ($DsmPreserveRulesPath -and (Test-Path -LiteralPath $DsmPreserveRulesPath)) {
        $cleanupParams['PreserveRulesPath'] = $DsmPreserveRulesPath
    }

    $run = Remove-DsmUnusedDriverPackages @cleanupParams

    $stamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
    $summary = [pscustomobject]@{
        ScriptType            = 'IntuneRemediation'
        GeneratedAt           = Get-Date
        ComputerName          = $env:COMPUTERNAME
        PowerShellVersion     = $PSVersionTable.PSVersion.ToString()
        BackupRoot            = $DsmBackupRoot
        CleanupSummary        = $run.Summary
        Results               = @($run.Results)
    }

    $summaryPath = Join-DsmPath $DsmReportRoot "remediation-summary_$stamp.json"
    Set-DsmContentUtf8 -LiteralPath $summaryPath -Value ($summary | ConvertTo-Json -Depth 6)

    if ($run.Summary.ExportOrDeleteFailedCount -gt 0) {
        exit 2
    }

    exit 0
}
catch {
    Write-Error $_
    exit 2
}
