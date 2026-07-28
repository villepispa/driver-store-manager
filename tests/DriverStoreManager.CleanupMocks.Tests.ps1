BeforeAll {
    . (Join-Path $PSScriptRoot 'helpers\DsmTestFixtures.ps1')
}

Describe 'Remove-DsmUnusedDriverPackages elevation and delete mocks' {
    BeforeEach {
        Get-Module DriverStoreManager -ErrorAction SilentlyContinue | Remove-Module -Force
        . (Join-Path $PSScriptRoot 'helpers\Import-DsmTestHarness.ps1') -MockPnPUtil
    }
    It 'Throws when elevation is missing for delete mode' {
        function Test-DsmElevation { return $false }

        $inv = @(
            (New-TestDsmPackage -PublishedName 'oem77.inf' -DeviceAssociation 'NeverAssociated')
        )

        { Remove-DsmUnusedDriverPackages -Inventory $inv -AllowDelete -Confirm:$false `
                -BackupRoot $TestDrive } | Should -Throw '*elevation*'
    }

    It 'Deletes candidates when elevation and export/delete succeed' {
        function Test-DsmElevation { return $true }

        $script:DsmMockExportCalls = [System.Collections.Generic.List[string]]::new()
        $script:DsmMockDeleteCalls = [System.Collections.Generic.List[string]]::new()

        function Export-DsmDriverPackageBackup {
            param(
                [string] $PublishedName,
                [string] $BackupRoot
            )

            [void]$script:DsmMockExportCalls.Add($PublishedName)
            return (Join-Path $BackupRoot $PublishedName)
        }

        function Remove-DsmDriverPackageFromStore {
            param([string] $PublishedName)

            [void]$script:DsmMockDeleteCalls.Add($PublishedName)
        }

        $inv = @(
            (New-TestDsmPackage -PublishedName 'oem88.inf' -DeviceAssociation 'NeverAssociated')
        )

        $run = Remove-DsmUnusedDriverPackages -Inventory $inv -AllowDelete -Confirm:$false `
            -BackupRoot $TestDrive -PassThru

        $run.Summary.Mode | Should-Be 'Delete'
        $run.Summary.DeletedCount | Should-Be 1
        $run.Summary.ExportOrDeleteFailedCount | Should-Be 0
        $run.Results[0].Action | Should-Be 'Deleted'
        $script:DsmMockExportCalls.Count | Should-Be 1
        $script:DsmMockDeleteCalls.Count | Should-Be 1
    }

    It 'Counts export failures without deleting' {
        function Test-DsmElevation { return $true }

        function Export-DsmDriverPackageBackup {
            param(
                [string] $PublishedName,
                [string] $BackupRoot
            )

            throw 'mock export failure'
        }

        function Remove-DsmDriverPackageFromStore {
            param([string] $PublishedName)

            throw 'delete should not run after export failure'
        }

        $inv = @(
            (New-TestDsmPackage -PublishedName 'oem89.inf' -DeviceAssociation 'NeverAssociated')
        )

        $run = Remove-DsmUnusedDriverPackages -Inventory $inv -AllowDelete -Confirm:$false `
            -BackupRoot $TestDrive -PassThru

        $run.Summary.DeletedCount | Should-Be 0
        $run.Summary.ExportOrDeleteFailedCount | Should-Be 1
        $run.Results[0].Action | Should-Be 'ExportOrDeleteFailed'
    }

    It 'Honors MaxDeletes when performing delete mode' {
        function Test-DsmElevation { return $true }

        function Export-DsmDriverPackageBackup {
            param(
                [string] $PublishedName,
                [string] $BackupRoot
            )

            return (Join-Path $BackupRoot $PublishedName)
        }

        function Remove-DsmDriverPackageFromStore {
            param([string] $PublishedName)
        }

        $inv = @(
            (New-TestDsmPackage -PublishedName 'oem10.inf' -OriginalName 'a.inf' `
                -Provider 'VendorA' -DeviceAssociation 'NeverAssociated')
            (New-TestDsmPackage -PublishedName 'oem11.inf' -OriginalName 'b.inf' `
                -Provider 'VendorB' -DeviceAssociation 'NeverAssociated')
        )

        $run = Remove-DsmUnusedDriverPackages -Inventory $inv -AllowDelete -Confirm:$false `
            -BackupRoot $TestDrive -MaxDeletes 1 -PassThru

        $run.Summary.CandidateCount | Should-Be 1
        $run.Summary.DeletedCount | Should-Be 1
        @($run.Results | Where-Object Action -eq 'Deleted').Count | Should-Be 1
    }

    It 'Counts delete failures after a successful export' {
        function Test-DsmElevation { return $true }

        function Export-DsmDriverPackageBackup {
            param(
                [string] $PublishedName,
                [string] $BackupRoot
            )

            return (Join-Path $BackupRoot $PublishedName)
        }

        function Remove-DsmDriverPackageFromStore {
            param([string] $PublishedName)

            throw 'mock delete failure'
        }

        $inv = @(
            (New-TestDsmPackage -PublishedName 'oem91.inf' -DeviceAssociation 'NeverAssociated')
        )

        $run = Remove-DsmUnusedDriverPackages -Inventory $inv -AllowDelete -Confirm:$false `
            -BackupRoot $TestDrive -PassThru

        $run.Summary.DeletedCount | Should-Be 0
        $run.Summary.ExportOrDeleteFailedCount | Should-Be 1
        $run.Results[0].Action | Should-Be 'ExportOrDeleteFailed'
    }
}
