BeforeAll {
    . (Join-Path $PSScriptRoot '..\helpers\DsmTestFixtures.ps1')
}

Describe 'Remove-DsmUnusedDriverPackages elevation and delete mocks' {
    BeforeEach {
        Get-Module DriverStoreManager -ErrorAction SilentlyContinue | Remove-Module -Force
        . (Join-Path $PSScriptRoot '..\helpers\Import-DsmTestHarness.ps1') -MockPnPUtil
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
                [string] $BackupRoot,
                [string] $OriginalName,
                [string] $DriverClass
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
                [string] $BackupRoot,
                [string] $OriginalName,
                [string] $DriverClass
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
                [string] $BackupRoot,
                [string] $OriginalName,
                [string] $DriverClass
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
                [string] $BackupRoot,
                [string] $OriginalName,
                [string] $DriverClass
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

    It 'Names the backup folder original.inf_oemnnn.inf' {
        Get-DsmDriverBackupFolderName -PublishedName 'oem123.inf' -OriginalName 'iigd_dch.inf' |
            Should-Be 'iigd_dch.inf_oem123.inf'
        Get-DsmDriverBackupFolderName -PublishedName 'oem123.inf' |
            Should-Be 'oem123.inf'
        Get-DsmDriverBackupFolderName -PublishedName 'oem123.inf' -OriginalName 'iigd\dch.inf' |
            Should-Be 'iigd_dch.inf_oem123.inf'
        Get-DsmBackupClassFolderName -DriverClass 'Display' | Should-Be 'Display'
        Get-DsmBackupClassFolderName -DriverClass '' | Should-Be 'Unknown'
    }

    It 'Renames an unknown export from the only INF and stores it under the class' {
        function Invoke-DsmPnPUtil {
            param(
                [Parameter(Mandatory)]
                [string[]] $ArgumentList,
                [string] $OutputFile
            )

            $dest = $ArgumentList[2]
            Set-Content -LiteralPath (Join-Path $dest 'iigd_dch.inf') -Value '[Version]' -Encoding ascii
            return @('OK')
        }

        $exportDir = Export-DsmDriverPackageBackup -PublishedName 'oem123.inf' -BackupRoot $TestDrive `
            -DriverClass 'Display'
        $exportDir | Should-Be (Join-Path $TestDrive 'Display\iigd_dch.inf_oem123.inf')
        Test-Path -LiteralPath (Join-Path $exportDir 'iigd_dch.inf') | Should-Be $true
        Test-Path -LiteralPath (Join-Path $TestDrive '_export\oem123.inf') | Should-Be $false
    }

    It 'Removes package backup folders older than the retention window' {
        $root = Join-Path $TestDrive 'backups'
        $old = Join-Path $root 'Display\iigd_dch.inf_oem1.inf'
        $fresh = Join-Path $root 'Display\iigd_dch.inf_oem2.inf'
        $legacy = Join-Path $root '2020-01-01_000000'
        New-Item -ItemType Directory -Path $old -Force | Out-Null
        New-Item -ItemType Directory -Path $fresh -Force | Out-Null
        New-Item -ItemType Directory -Path $legacy -Force | Out-Null
        (Get-Item -LiteralPath $old).CreationTime = (Get-Date).AddDays(-40)
        (Get-Item -LiteralPath $legacy).CreationTime = (Get-Date).AddDays(-40)

        $removed = Remove-DsmOldDriverBackups -BackupRoot $root -OlderThanDays 30
        $removed | Should-Be 2
        Test-Path -LiteralPath $old | Should-Be $false
        Test-Path -LiteralPath $fresh | Should-Be $true
        Test-Path -LiteralPath $legacy | Should-Be $false
        Remove-DsmOldDriverBackups -BackupRoot $root -OlderThanDays 0 | Should-Be 0
        Test-Path -LiteralPath $fresh | Should-Be $true
    }
}
