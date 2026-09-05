param(
    [switch] $MockPnPUtil,

    [string] $FixtureRoot
)

$projectRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$moduleRoot = Join-Path $projectRoot 'src\DriverStoreManager'
if (-not $FixtureRoot) {
    $FixtureRoot = Join-Path $projectRoot 'tests\fixtures'
}

$privateOrder = @(
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

foreach ($name in $privateOrder) {
    . (Join-Path $moduleRoot "Private\$name")
}

if ($MockPnPUtil) {
    $driversFixture = Join-Path $FixtureRoot 'pnputil-enum-drivers.csv'
    $devicesAllFixture = Join-Path $FixtureRoot 'pnputil-enum-devices-all.csv'
    $devicesConnectedFixture = Join-Path $FixtureRoot 'pnputil-enum-devices-connected.csv'

    if (-not (Test-Path -LiteralPath $driversFixture)) {
        throw "Missing fixture: $driversFixture"
    }

    $script:DsmMockPnPUtilCalls = [System.Collections.Generic.List[string]]::new()

    function Invoke-DsmPnPUtil {
        param(
            [Parameter(Mandatory)]
            [string[]] $ArgumentList,

            [string] $OutputFile
        )

        $joined = ($ArgumentList -join ' ').ToLowerInvariant()
        [void]$script:DsmMockPnPUtilCalls.Add($joined)

        $fixturePath = $null
        if ($joined -match 'enum-drivers') {
            $fixturePath = $driversFixture
        }
        elseif ($joined -match 'enum-devices' -and $joined -match 'connected') {
            $fixturePath = $devicesConnectedFixture
        }
        elseif ($joined -match 'enum-devices') {
            $fixturePath = $devicesAllFixture
        }

        $lines = if ($fixturePath) {
            @(Get-Content -LiteralPath $fixturePath | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        }
        else {
            @()
        }

        if ($OutputFile) {
            Set-Content -LiteralPath $OutputFile -Value $lines -Encoding Unicode
            return $lines
        }

        return $lines
    }
}

Get-ChildItem -Path (Join-Path $moduleRoot 'Public') -Filter '*.ps1' |
    ForEach-Object { . $_.FullName }
