# DriverStoreManager — module root

$public = Join-Path $PSScriptRoot 'Public'
$private = Join-Path $PSScriptRoot 'Private'

$privateFiles = @(
    'Dsm.Runtime.ps1'
    'Dsm.Settings.ps1'
    'Dsm.Common.ps1'
    'Dsm.Blocklist.ps1'
    'Dsm.Filter.ps1'
    'Dsm.DeviceCorrelation.ps1'
    'Dsm.Preserve.ps1'
    'Dsm.InfMetadata.ps1'
    'Dsm.Report.ps1'
    'Dsm.Cleanup.ps1'
)

foreach ($name in $privateFiles) {
    $path = Join-Path $private $name
    if (Test-Path -LiteralPath $path) {
        . $path
    }
}

Get-ChildItem -Path $public -Filter '*.ps1' -ErrorAction SilentlyContinue |
    ForEach-Object { . $_.FullName }

$exportedPublic = Get-ChildItem -Path $public -Filter '*.ps1' |
    ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_.Name) }

# Runtime helpers used by orchestration scripts (Invoke-DsmDriverStoreAudit, Intune entry)
$runtimeHelpers = @(
    'Set-DsmContentUtf8'
    'Join-DsmPath'
    'Get-DsmProgramDataRoot'
    'Export-DsmDriverDiskIdCatalog'
    'Get-DsmSettings'
    'Get-DsmSettingsOverlay'
)

Export-ModuleMember -Function @($exportedPublic + $runtimeHelpers)
