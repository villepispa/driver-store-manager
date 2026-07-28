BeforeAll {
    Get-Module DriverStoreManager -ErrorAction SilentlyContinue | Remove-Module -Force
    . (Join-Path $PSScriptRoot 'helpers\Import-DsmTestHarness.ps1') -MockPnPUtil
}

Describe 'Mocked pnputil end-to-end pipeline' {
    It 'Collects inventory from fixture CSV via mocked pnputil' {
        $inventory = @(Get-DsmDriverStoreInventory)

        $inventory.Count | Should-Be 2
        $oem1 = $inventory | Where-Object PublishedName -eq 'oem1.inf' | Select-Object -First 1
        $oem2 = $inventory | Where-Object PublishedName -eq 'oem2.inf' | Select-Object -First 1

        $oem1.DeviceAssociation | Should-Be 'Connected'
        $oem1.InUse | Should-Be $true
        $oem2.DeviceAssociation | Should-Be 'DisconnectedInstalled'
        ($script:DsmMockPnPUtilCalls -match 'enum-drivers').Count | Should-Be 1
        ($script:DsmMockPnPUtilCalls -match 'enum-devices').Count | Should-Be 2
    }

    It 'Builds report counts from mocked inventory without live blocklist' {
        $inventory = @(Get-DsmDriverStoreInventory)
        $report = Get-DsmDriverStoreReport -Inventory $inventory `
            -SkipMicrosoftBlocklist -IncludeVulnerabilityScan

        $report.Global.Summary.TotalPackages | Should-Be 2
        $report.Global.Summary.InUseCount | Should-Be 1
        $report.Global.Summary.NeverAssociatedCount | Should-Be 0
        $report.Global.Summary.DisconnectedDeviceDriverCount | Should-Be 1
        $report.Global.Summary.DeletableCandidateCount | Should-Be 0
    }

    It 'Produces cleanup preview for never-associated fixture package' {
        $neverCsv = @(
            'DriverName,OriginalName,ProviderName,ClassName,DriverVersion,DeviceDescription,File'
            'oem9.inf,orphan.inf,OrphanCo,System,1.0.0.0,,orphan.sys'
        )
        $fixtureRoot = Join-Path $TestDrive 'mock-fixtures'
        $driversFixture = Join-Path $fixtureRoot 'pnputil-enum-drivers.csv'
        New-Item -ItemType Directory -Path $fixtureRoot -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'fixtures\pnputil-enum-devices-all.csv') `
            -Destination (Join-Path $fixtureRoot 'pnputil-enum-devices-all.csv')
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'fixtures\pnputil-enum-devices-connected.csv') `
            -Destination (Join-Path $fixtureRoot 'pnputil-enum-devices-connected.csv')
        Set-Content -LiteralPath $driversFixture -Value $neverCsv -Encoding ASCII
        $script:DsmMockPnPUtilCalls.Clear()

        Get-Module DriverStoreManager -ErrorAction SilentlyContinue | Remove-Module -Force
        . (Join-Path $PSScriptRoot 'helpers\Import-DsmTestHarness.ps1') `
            -MockPnPUtil -FixtureRoot $fixtureRoot

        $inventory = @(Get-DsmDriverStoreInventory)
        $inventory.Count | Should-Be 1

        $run = Remove-DsmUnusedDriverPackages -Inventory $inventory -WhatIf -PassThru
        $run.Summary.CandidateCount | Should-Be 1
        $run.Results[0].PublishedName | Should-Be 'oem9.inf'
        $run.Results[0].Action | Should-Be 'WhatIf'
    }
}
