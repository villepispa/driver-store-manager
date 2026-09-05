BeforeAll {
    Get-Module DriverStoreManager -ErrorAction SilentlyContinue | Remove-Module -Force
    . (Join-Path $PSScriptRoot '..\helpers\Import-DsmTestHarness.ps1')
    . (Join-Path $PSScriptRoot '..\helpers\DsmTestFixtures.ps1')
}

Describe 'Import-DsmSettingsFile' {
    It 'Throws when the path is missing' {
        { Import-DsmSettingsFile -LiteralPath (Join-Path $TestDrive 'no-such.json') } |
            Should -Throw '*Settings file not found*'
    }

    It 'Throws on invalid JSON' {
        $path = Join-Path $TestDrive 'bad.json'
        Set-Content -LiteralPath $path -Value '{ not json' -Encoding utf8
        { Import-DsmSettingsFile -LiteralPath $path } |
            Should -Throw '*not valid JSON*'
    }

    It 'Throws on an unknown key' {
        $path = Join-Path $TestDrive 'unknown.json'
        Set-Content -LiteralPath $path -Value '{ "NotARealKey": true }' -Encoding utf8
        { Import-DsmSettingsFile -LiteralPath $path } |
            Should -Throw '*Unknown settings key*'
    }

    It 'Throws when AllowDelete is present' {
        $path = Join-Path $TestDrive 'forbid.json'
        Set-Content -LiteralPath $path -Value '{ "AllowDelete": true }' -Encoding utf8
        { Import-DsmSettingsFile -LiteralPath $path } |
            Should -Throw '*must not contain*'
    }

    It 'Throws when Confirm is present' {
        $path = Join-Path $TestDrive 'confirm.json'
        Set-Content -LiteralPath $path -Value '{ "Confirm": false }' -Encoding utf8
        { Import-DsmSettingsFile -LiteralPath $path } |
            Should -Throw '*must not contain*'
    }

    It 'Resolves relative paths against the settings file directory' {
        $dir = Join-Path $TestDrive 'profile'
        New-Item -ItemType Directory -Path $dir | Out-Null
        $path = Join-Path $dir 'dsm.settings.json'
        Set-Content -LiteralPath $path -Value '{ "PreserveRulesPath": "rules.json" }' -Encoding utf8
        $map = Import-DsmSettingsFile -LiteralPath $path
        $map['PreserveRulesPath'] | Should -Be ([System.IO.Path]::GetFullPath((Join-Path $dir 'rules.json')))
    }

    It 'Keeps a single JSON array element as an array (PS 5.1 unwrap)' {
        $path = Join-Path $TestDrive 'one-class.json'
        Set-Content -LiteralPath $path -Value '{ "DriverClass": ["Printer"] }' -Encoding utf8
        $map = Import-DsmSettingsFile -LiteralPath $path
        @($map['DriverClass']).Count | Should -Be 1
        @($map['DriverClass'])[0] | Should -Be 'Printer'
    }
}

Describe 'Get-DsmSettingsOverlay' {
    It 'Leaves assignments empty when SettingsPath is not bound' {
        $bound = @{ DriverClass = @('Display') }
        $ov = Get-DsmSettingsOverlay -BoundParameters $bound
        $ov.Loaded | Should -Be $false
        @($ov.Assignments.Keys).Count | Should -Be 0
        $ov.Effective[0].Source | Should -Be 'cli'
    }

    It 'Fills unbound keys from the file and lets CLI replace arrays' {
        $path = Join-Path $TestDrive 'mix.json'
        Set-Content -LiteralPath $path -Value (
            '{ "DriverClass": ["Printer","Net"], "MaxDeletes": 10, "Association": "NeverAssociated" }'
        ) -Encoding utf8

        $bound = @{
            SettingsPath = $path
            DriverClass  = @('Display')
        }
        $ov = Get-DsmSettingsOverlay -BoundParameters $bound
        $ov.Loaded | Should -Be $true
        $ov.Assignments['MaxDeletes'] | Should -Be 10
        $ov.Assignments['Association'] | Should -Be 'NeverAssociated'
        @($ov.Assignments.Keys) -contains 'DriverClass' | Should -Be $false
        ($ov.Effective | Where-Object { $_.Name -eq 'DriverClass' }).Source | Should -Be 'cli'
        @(($ov.Effective | Where-Object { $_.Name -eq 'DriverClass' }).Value) |
            Should -Be @('Display')
    }
}

Describe 'Get-DsmDriverStoreReport settings overlay' {
    It 'Applies DriverClass from SettingsPath when the CLI omits it' {
        $path = Join-Path $TestDrive 'report.json'
        Set-Content -LiteralPath $path -Value '{ "DriverClass": ["Printer"] }' -Encoding utf8
        $pkg = New-TestDsmPackage -DriverClass 'Printer'
        $report = Get-DsmDriverStoreReport -Inventory @($pkg) -SettingsPath $path `
            -SkipMicrosoftBlocklist
        @($report.FilterManifest.DriverClass) | Should -Be @('Printer')
    }
}
