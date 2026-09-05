BeforeAll {
    Get-Module DriverStoreManager -ErrorAction SilentlyContinue | Remove-Module -Force
    . (Join-Path $PSScriptRoot '..\helpers\Import-DsmTestHarness.ps1')
    . (Join-Path $PSScriptRoot '..\helpers\DsmTestFixtures.ps1')
}

Describe 'Dsm.Runtime' {
    It 'Join-DsmPath joins multiple segments' {
        Join-DsmPath 'C:\ProgramData' 'DriverStoreManager' 'reports' |
            Should-Be (Join-Path (Join-Path 'C:\ProgramData' 'DriverStoreManager') 'reports')
    }

    It 'Test-DsmIsPowerShellCore returns a boolean' {
        ($r = Test-DsmIsPowerShellCore) -is [bool] | Should-Be $true
    }
}

Describe 'ConvertFrom-PnPUtilDriverCsv' {
    It 'Groups rows by published name and marks in-use when devices present' {
        $csv = @(
            'DriverName,OriginalName,ProviderName,ClassName,DriverVersion,DeviceDescription,File'
            'oem1.inf,foo.inf,Contoso,Display,10.0.1.0,GPU Adapter,foo.sys'
            'oem1.inf,,,,,,foo.inf'
            'oem2.inf,bar.inf,Fabrikam,Net,10.0.2.0,,bar.sys'
        )

        $result = ConvertFrom-PnPUtilDriverCsv -InputObject $csv

        $result.Count | Should-Be 2
        ($result | Where-Object { $_.PublishedName -eq 'oem1.inf' }).InUse | Should-Be $true
        ($result | Where-Object { $_.PublishedName -eq 'oem2.inf' }).InUse | Should-Be $false
    }

    It 'Parses a single data row under StrictMode (DSM-038)' {
        Set-StrictMode -Version Latest
        try {
            $csv = @(
                'DriverName,OriginalName,ProviderName,ClassName,DriverVersion,DeviceDescription,File'
                'oem9.inf,orphan.inf,OrphanCo,System,1.0.0.0,,orphan.sys'
            )
            $result = @(ConvertFrom-PnPUtilDriverCsv -InputObject $csv)
            $result.Count | Should-Be 1
            $result[0].PublishedName | Should-Be 'oem9.inf'
        }
        finally {
            Set-StrictMode -Off
        }
    }
}

Describe 'Test-DsmElevation' {
    It 'Returns a boolean' {
        $r = Test-DsmElevation
        ($r -is [bool]) | Should-Be $true
    }
}

Describe 'ConvertTo-DsmWindowsArgumentString' {
    It 'Leaves simple tokens unchanged' {
        ConvertTo-DsmWindowsArgumentString -Value '/enum-drivers' | Should-Be '/enum-drivers'
    }

    It 'Quotes values containing spaces' {
        ConvertTo-DsmWindowsArgumentString -Value 'C:\temp path\out.csv' |
            Should-Be '"C:\temp path\out.csv"'
    }
}

Describe 'Get-DsmBlocklistHashes' {
    It 'Loads valid SHA256 lines from supplemental file when Microsoft blocklist is skipped' {
        $temp = New-TemporaryFile
        try {
            @(
                '# comment'
                ('b' * 64)
                'not-a-hash'
            ) | Set-Content -LiteralPath $temp -Encoding utf8

            $set = Get-DsmBlocklistHashes -BlocklistPath $temp.FullName -UseMicrosoftBlocklist $false
            $set.Count | Should-Be 1
        }
        finally {
            Remove-Item -LiteralPath $temp.FullName -Force
        }
    }
}

Describe 'ConvertFrom-DsmMicrosoftBlocklistXml' {
    It 'Extracts SHA256 deny rules and FileAttrib hashes' {
        $xml = @'
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
  <FileRules>
    <Deny ID="ID_DENY_SAMPLE_SHA256" FriendlyName="sample.sys Hash Sha256"
          Hash="1111111111111111111111111111111111111111111111111111111111111111" />
    <Deny ID="ID_DENY_SAMPLE_SHA256_PAGE" FriendlyName="sample.sys Hash Page Sha256"
          Hash="2222222222222222222222222222222222222222222222222222222222222222" />
  </FileRules>
  <FileAttrib ID="ID_FILEATTRIB_GDRV"
    FriendlyName="gdrv.sys\3333333333333333333333333333333333333333333333333333333333333333 FileAttribute"
    FileName="gdrv.sys" />
</SiPolicy>
'@

        $doc = [xml]$xml
        $set = ConvertFrom-DsmMicrosoftBlocklistXml -PolicyXml $doc
        $set.Count | Should-Be 2
        ($set -contains '1111111111111111111111111111111111111111111111111111111111111111') | Should-Be $true
        ($set -contains '3333333333333333333333333333333333333333333333333333333333333333') | Should-Be $true
    }
}

Describe 'Get-DsmBlocklistHashSet' {
    It 'Merges supplemental hashes with Microsoft cache file when both exist' {
        $blocklistRoot = Join-Path $TestDrive 'blocklist-cache'
        $script:DsmMicrosoftBlocklistRootOverride = $blocklistRoot
        $paths = Get-DsmMicrosoftBlocklistPaths
        $supplemental = New-TemporaryFile
        try {
            New-Item -ItemType Directory -Path $paths.Directory -Force | Out-Null

            Set-DsmContentUtf8 -LiteralPath $paths.HashFile -Value @(
                'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
            )
            Set-DsmContentUtf8 -LiteralPath $paths.MetadataFile -Value (@{
                    UpdatedAt     = (Get-Date).ToString('o')
                    HashCount     = 1
                    PolicyVersion = 'test'
                } | ConvertTo-Json)

            Set-Content -LiteralPath $supplemental.FullName -Encoding UTF8 -Value @(
                'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'
            )

            $resolved = Get-DsmBlocklistHashSet `
                -BlocklistPath $supplemental.FullName `
                -UseMicrosoftBlocklist $true
            $resolved.TotalCount | Should-Be 2
            $resolved.SupplementalCount | Should-Be 1
        }
        finally {
            $script:DsmMicrosoftBlocklistRootOverride = $null
            Remove-Item -LiteralPath $supplemental.FullName -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Test-DsmOemDriverPackage' {
    It 'Accepts oem inf with third-party provider' {
        $pkg = New-TestDsmPackage -PublishedName 'oem42.inf' -Provider 'Synaptics'
        Test-DsmOemDriverPackage -Package $pkg | Should-Be $true
    }

    It 'Rejects non-oem published names' {
        $pkg = New-TestDsmPackage -PublishedName 'netvwifimp.inf' -Provider 'Contoso'
        Test-DsmOemDriverPackage -Package $pkg | Should-Be $false
    }

    It 'Accepts oem159.inf when Provider is Microsoft Corporation (staged, not built-in)' {
        $pkg = New-TestDsmPackage -PublishedName 'oem159.inf' -Provider 'Microsoft Corporation' `
            -OriginalName 'voiceclarityep_audio_component.inf_amd64_d5f0f6f169848993'
        Test-DsmOemDriverPackage -Package $pkg | Should-Be $true
        Test-DsmWindowsBuiltInDriverPackage -Package $pkg | Should-Be $false
    }
}

Describe 'Test-DsmWindowsBuiltInDriverPackage' {
    It 'Identifies Windows built-in manifest names' {
        $pkg = New-TestDsmPackage -PublishedName 'c_swcomponent.inf' -Provider 'Microsoft Corporation'
        Test-DsmWindowsBuiltInDriverPackage -Package $pkg | Should-Be $true
    }
}

Describe 'Get-DsmHardwareIdFromInstanceId' {
    It 'Extracts USB hardware ID root' {
        $id = 'USB\VID_046D&PID_C52B\6&328c17cc&0&3'
        Get-DsmHardwareIdFromInstanceId -InstanceId $id | Should-Be 'USB\VID_046D&PID_C52B'
    }
}

Describe 'ConvertFrom-PnPUtilDeviceCsv' {
    It 'Parses device rows and driver published name' {
        $csv = @(
            'Device Instance ID,Device Description,Driver Name'
            'USB\VID_03F0&PID_2B17\6&1,HP LaserJet,oem55.inf'
        )

        $result = ConvertFrom-PnPUtilDeviceCsv -InputObject $csv
        @($result).Count | Should-Be 1
        $result[0].DriverName | Should-Be 'oem55.inf'
        $result[0].HardwareIdRoot | Should-Be 'USB\VID_03F0&PID_2B17'
    }

    It 'Parses device row when instance ID column is empty' {
        $csv = @(
            'Driver Name,Device Description,Device Instance ID'
            'oem77.inf,Virtual Device,'
        )

        $result = ConvertFrom-PnPUtilDeviceCsv -InputObject $csv
        @($result).Count | Should-Be 1
        $result[0].DriverName | Should-Be 'oem77.inf'
        $result[0].HardwareIdRoot | Should-Be $null
    }

    It 'Parses modern pnputil CSV headers (InstanceId, DeviceDescription, duplicate DriverName)' {
        $csv = @(
            'InstanceId,DeviceDescription,ClassName,ClassGuid,ManufacturerName,Status,ProblemCode,ProblemStatus,DriverName,ExtensionDriverNames,DriverName,Rank'
            '"USB\VID_03F0&PID_2B17\6&1","HP LaserJet","USB","{guid}","HP","Started","","","oem55.inf",""'
            '"USB\VID_03F0&PID_2B17\6&1","","","","","","","","","","oem55.inf","00FF0001"'
        )

        $result = ConvertFrom-PnPUtilDeviceCsv -InputObject $csv
        @($result).Count | Should-Be 2
        $result[0].InstanceId | Should-Be 'USB\VID_03F0&PID_2B17\6&1'
        $result[0].DriverName | Should-Be 'oem55.inf'
        $result[0].Description | Should-Be 'HP LaserJet'
        $result[1].DriverName | Should-Be 'oem55.inf'
    }
}

Describe 'Invoke-DsmDriverFilter' {
    It 'Excludes Windows built-in manifests by default; includes all oem#.inf' {
        $inventory = @(
            (New-TestDsmPackage -PublishedName 'oem1.inf' -Provider 'Synaptics')
            (New-TestDsmPackage -PublishedName 'oem159.inf' -Provider 'Microsoft Corporation')
            (New-TestDsmPackage -PublishedName 'c_swcomponent.inf' -Provider 'Microsoft Corporation')
        )

        $result = Invoke-DsmDriverFilter -Inventory $inventory
        @($result.Filtered).Count | Should-Be 2
        @($result.Filtered | Where-Object PublishedName -eq 'oem1.inf').Count | Should-Be 1
        @($result.Filtered | Where-Object PublishedName -eq 'oem159.inf').Count | Should-Be 1
        $result.ExcludedWindowsBuiltInCount | Should-Be 1
    }

    It 'Includes Windows built-in manifests when IncludeWindowsBuiltIn is set' {
        $inventory = @(
            (New-TestDsmPackage -PublishedName 'oem1.inf' -Provider 'Synaptics')
            (New-TestDsmPackage -PublishedName 'c_swcomponent.inf' -Provider 'Microsoft Corporation')
        )

        $result = Invoke-DsmDriverFilter -Inventory $inventory -IncludeWindowsBuiltIn
        @($result.Filtered).Count | Should-Be 2
        $result.WindowsBuiltInInScopeCount | Should-Be 1
    }

    It 'Matches provider wildcard filter' {
        $inventory = @(
            (New-TestDsmPackage -PublishedName 'oem1.inf' -Provider 'Synaptics')
            (New-TestDsmPackage -PublishedName 'oem2.inf' -Provider 'Fabrikam')
        )

        $result = Invoke-DsmDriverFilter -Inventory $inventory -Provider 'Synaptics*'
        @($result.Filtered).Count | Should-Be 1
        $result.FilterMatchRate | Should-Be 0.5
    }

    It 'Filters by association bucket' {
        $inventory = @(
            (New-TestDsmPackage -PublishedName 'oem1.inf' -DeviceAssociation 'Connected' -InUse $true)
            (New-TestDsmPackage -PublishedName 'oem2.inf' -DeviceAssociation 'DisconnectedInstalled')
            (New-TestDsmPackage -PublishedName 'oem3.inf' -DeviceAssociation 'NeverAssociated')
        )

        $f = New-DsmDriverFilter -Association DisconnectedInstalled
        $result = Invoke-DsmDriverFilter -Inventory $inventory -Filter $f
        @($result.Filtered).Count | Should-Be 1
        $result.Filtered[0].PublishedName | Should-Be 'oem2.inf'
    }

    It 'Filters by association bucket with missing DeviceAssociation using fallback' {
        $inventory = @(
            (New-TestDsmPackage -PublishedName 'oem1.inf' -DeviceAssociation $null -InUse $true)
            (New-TestDsmPackage -PublishedName 'oem2.inf' -DeviceAssociation $null -InUse $false -Devices @('Some Device'))
            (New-TestDsmPackage -PublishedName 'oem3.inf' -DeviceAssociation $null -InUse $false -Devices @())
        )

        $f = New-DsmDriverFilter -Association DisconnectedInstalled
        $result = Invoke-DsmDriverFilter -Inventory $inventory -Filter $f
        @($result.Filtered).Count | Should-Be 1
        $result.Filtered[0].PublishedName | Should-Be 'oem2.inf'
    }

    It 'Matches hardware ID wildcard' {
        $inventory = @(
            (New-TestDsmPackage -PublishedName 'oem1.inf' -HardwareIds @('USB\VID_03F0&PID_2B17\serial'))
            (New-TestDsmPackage -PublishedName 'oem2.inf' -HardwareIds @('PCI\VEN_8086&DEV_15F3'))
        )

        $result = Invoke-DsmDriverFilter -Inventory $inventory -HardwareId 'USB\VID_*'
        @($result.Filtered).Count | Should-Be 1
        $result.Filtered[0].PublishedName | Should-Be 'oem1.inf'
    }
}

Describe 'Invoke-DsmPreservePolicy' {
    It 'KeepPublishedName preserves listed oem packages' {
        $inv = @(
            (New-TestDsmPackage -PublishedName 'oem10.inf')
            (New-TestDsmPackage -PublishedName 'oem11.inf')
        )
        $rule = New-DsmPreserveRule -RuleType KeepPublishedName -Name 'Keep10' `
            -PublishedName 'oem10.inf'

        $result = Invoke-DsmPreservePolicy -Inventory $inv -PreserveRule $rule
        ($result.Preserved | Where-Object PublishedName -eq 'oem10.inf').Preserved | Should-Be $true
        ($result.Inventory | Where-Object PublishedName -eq 'oem11.inf').Preserved | Should-Be $false
    }

    It 'KeepLatest preserves only newest in family' {
        $inv = @(
            (New-TestDsmPackage -PublishedName 'oem1.inf' -Provider 'Synaptics' `
                -OriginalName 'displaylink.inf' -DriverVersion '10.0.1.0')
            (New-TestDsmPackage -PublishedName 'oem2.inf' -Provider 'Synaptics' `
                -OriginalName 'displaylink.inf' -DriverVersion '10.0.2.0')
        )
        $rule = New-DsmPreserveRule -RuleType KeepLatest -Name 'DL' `
            -Filter (New-DsmDriverFilter -Provider 'Synaptics*')

        $result = Invoke-DsmPreservePolicy -Inventory $inv -PreserveRule $rule
        ($result.Inventory | Where-Object PublishedName -eq 'oem2.inf').Preserved | Should-Be $true
        ($result.Inventory | Where-Object PublishedName -eq 'oem1.inf').Preserved | Should-Be $false
    }

    It 'KeepMatching preserves printer class packages' {
        $inv = @(
            (New-TestDsmPackage -PublishedName 'oem20.inf' -DriverClass 'Printer')
            (New-TestDsmPackage -PublishedName 'oem21.inf' -DriverClass 'Net')
        )
        $rule = New-DsmPreserveRule -RuleType KeepMatching -Name 'Printers' `
            -Filter (New-DsmDriverFilter -DriverClass 'Printer')

        $result = Invoke-DsmPreservePolicy -Inventory $inv -PreserveRule $rule
        ($result.Inventory | Where-Object PublishedName -eq 'oem20.inf').Preserved | Should-Be $true
        $result.PreservedCount | Should-Be 1
    }

    It 'Loads rules from JSON file' {
        $json = @'
[
  {
    "Name": "TestKeep",
    "RuleType": "KeepPublishedName",
    "PublishedName": ["oem99.inf"]
  }
]
'@
        $temp = New-TemporaryFile
        try {
            Set-Content -LiteralPath $temp -Value $json -Encoding UTF8
            $inv = @(New-TestDsmPackage -PublishedName 'oem99.inf')
            $result = Invoke-DsmPreservePolicy -Inventory $inv -PreserveRulesPath $temp
            $result.PreservedCount | Should-Be 1
        }
        finally {
            Remove-Item -LiteralPath $temp -Force
        }
    }
}

Describe 'Test-DsmIsDriverImagePath' {
    It 'Accepts sys dll and cat extensions' {
        Test-DsmIsDriverImagePath -Path 'C:\drivers\foo.sys' | Should-Be $true
        Test-DsmIsDriverImagePath -Path 'C:\drivers\bar.dll' | Should-Be $true
        Test-DsmIsDriverImagePath -Path 'C:\drivers\pkg.cat' | Should-Be $true
        Test-DsmIsDriverImagePath -Path 'C:\drivers\readme.txt' | Should-Be $false
    }
}

Describe 'Test-DsmDriverVulnerabilities' {
    It 'Flags blocklisted driver image hashes' {
        $driverFile = Join-Path $TestDrive 'blocked.sys'
        Set-DsmTestAsciiFile -LiteralPath $driverFile -Value 'blocked-driver-bytes'
        $hash = (Get-FileHash -LiteralPath $driverFile -Algorithm SHA256).Hash

        $blocklist = Join-Path $TestDrive 'blocklist.txt'
        Set-Content -LiteralPath $blocklist -Value $hash -Encoding ascii

        $pkg = New-TestDsmPackage -PublishedName 'oem77.inf' -Files @(
            (Join-Path $TestDrive 'ignored.inf')
            $driverFile
        )

        $result = @(Test-DsmDriverVulnerabilities -Inventory @($pkg) -BlocklistPath $blocklist -UseMicrosoftBlocklist $false)
        ($result[0].RiskSignals -contains 'Blocklisted') | Should-Be $true
        @($result[0].FileAnalysis).Count | Should-Be 1
        $result[0].FileAnalysis[0].BlocklistMatch | Should-Be $true
    }

    It 'Marks orphan candidates using report-aligned logic' {
        $pkg = New-TestDsmPackage -PublishedName 'oem88.inf' -DeviceAssociation 'NeverAssociated'
        $result = @(Test-DsmDriverVulnerabilities -Inventory @($pkg) `
                -OrphanIncludesDisconnectedInstalled)
        ($result[0].RiskSignals -contains 'OrphanCandidate') | Should-Be $true
    }

    It 'Orphan/deletable helpers tolerate missing Preserved under StrictMode (DSM-033)' {
        # Harness dotsources Private/*.ps1 into the test scope (not Import-Module),
        # matching Intune bundles where Set-StrictMode applies to the same scope.
        Set-StrictMode -Version Latest
        try {
            $pkg = [pscustomobject]@{
                PublishedName     = 'oem88strict.inf'
                DeviceAssociation = 'NeverAssociated'
                InUse             = $false
                DeviceCount       = 0
            }
            { $null = Test-DsmPackageIsOrphanCandidate -Package $pkg } | Should -Not -Throw
            { $null = Test-DsmPackageIsDeletableCandidate -Package $pkg } | Should -Not -Throw
            (Test-DsmPackageIsOrphanCandidate -Package $pkg) | Should-Be $true
            (Test-DsmPackageIsDeletableCandidate -Package $pkg) | Should-Be $true
        }
        finally {
            Set-StrictMode -Off
        }
    }

    It 'Handles missing DeviceAssociation fallback for orphan candidates' {
        $pkg1 = New-TestDsmPackage -PublishedName 'oem88a.inf' -DeviceAssociation $null -InUse $false -Devices @('Some Device')
        $pkg2 = New-TestDsmPackage -PublishedName 'oem88b.inf' -DeviceAssociation $null -InUse $false -Devices @()

        $result1 = @(Test-DsmDriverVulnerabilities -Inventory @($pkg1) -OrphanIncludesDisconnectedInstalled:$false)
        ($result1[0].RiskSignals -contains 'OrphanCandidate') | Should-Be $false

        $result2 = @(Test-DsmDriverVulnerabilities -Inventory @($pkg1) -OrphanIncludesDisconnectedInstalled:$true)
        ($result2[0].RiskSignals -contains 'OrphanCandidate') | Should-Be $true

        $result3 = @(Test-DsmDriverVulnerabilities -Inventory @($pkg2) -OrphanIncludesDisconnectedInstalled:$false)
        ($result3[0].RiskSignals -contains 'OrphanCandidate') | Should-Be $true
    }

    It 'Skips non-image files for hash and signature checks' {
        $textFile = Join-Path $TestDrive 'notes.txt'
        Set-Content -LiteralPath $textFile -Value 'not-a-driver' -Encoding ascii
        $pkg = New-TestDsmPackage -PublishedName 'oem90.inf' -Files @($textFile)

        $result = @(Test-DsmDriverVulnerabilities -Inventory @($pkg))
        @($result[0].FileAnalysis).Count | Should-Be 0
    }
}

Describe 'Get-DsmPackageAdvisorySeverity' {
    It 'Escalates blocklisted connected packages to Critical' {
        $pkg = New-TestDsmPackage -PublishedName 'oem1.inf' -DeviceAssociation 'Connected' -InUse $true
        $pkg | Add-Member -NotePropertyName RiskSignals -NotePropertyValue @('Blocklisted') -Force

        Get-DsmPackageAdvisorySeverity -Package $pkg | Should-Be 'Critical'
    }

    It 'Rates signature-only packages as Low when signatures excluded from vulnerable count' {
        $pkg = New-TestDsmPackage -PublishedName 'oem2.inf' -DeviceAssociation 'NeverAssociated'
        $pkg | Add-Member -NotePropertyName RiskSignals -NotePropertyValue @('SignatureIssue') -Force

        Get-DsmPackageAdvisorySeverity -Package $pkg -IncludeSignatureInVulnerable $false |
            Should-Be 'Low'
    }

    It 'Rates signature-only unused packages as Medium when signatures count as vulnerable' {
        $pkg = New-TestDsmPackage -PublishedName 'oem2b.inf' -DeviceAssociation 'NeverAssociated'
        $pkg | Add-Member -NotePropertyName RiskSignals -NotePropertyValue @('SignatureIssue') -Force

        Get-DsmPackageAdvisorySeverity -Package $pkg | Should-Be 'Medium'
    }
}

Describe 'Measure-DsmDriverStoreScope' {
    It 'Counts association buckets and deletable vs orphan' {
        $pkgs = @(
            (New-TestDsmPackage -PublishedName 'oem1.inf' -DeviceAssociation 'Connected' -InUse $true)
            (New-TestDsmPackage -PublishedName 'oem2.inf' -DeviceAssociation 'DisconnectedInstalled')
            (New-TestDsmPackage -PublishedName 'oem3.inf' -DeviceAssociation 'NeverAssociated')
        )

        $result = Measure-DsmDriverStoreScope -Packages $pkgs -OrphanIncludesDisconnectedInstalled
        $result.Summary.InUseCount | Should-Be 1
        $result.Summary.DisconnectedDeviceDriverCount | Should-Be 1
        $result.Summary.NeverAssociatedCount | Should-Be 1
        $result.Summary.OrphanCandidateCount | Should-Be 2
        $result.Summary.DeletableCandidateCount | Should-Be 1
    }

    It 'Handles missing DeviceAssociation using fallback logic on InUse and DeviceCount' {
        $pkgs = @(
            (New-TestDsmPackage -PublishedName 'oem1.inf' -DeviceAssociation $null -InUse $true)
            (New-TestDsmPackage -PublishedName 'oem2.inf' -DeviceAssociation $null -InUse $false -Devices @('Some Device'))
            (New-TestDsmPackage -PublishedName 'oem3.inf' -DeviceAssociation $null -InUse $false -Devices @())
        )

        $result = Measure-DsmDriverStoreScope -Packages $pkgs -OrphanIncludesDisconnectedInstalled
        $result.Summary.InUseCount | Should-Be 1
        $result.Summary.DisconnectedDeviceDriverCount | Should-Be 1
        $result.Summary.NeverAssociatedCount | Should-Be 1
        $result.Summary.OrphanCandidateCount | Should-Be 2
        $result.Summary.DeletableCandidateCount | Should-Be 1
    }

    It 'Counts old versions in family' {
        $pkgs = @(
            (New-TestDsmPackage -PublishedName 'oem1.inf' -Provider 'Contoso' `
                -OriginalName 'foo.inf' -DriverVersion '1.0.0' -DeviceAssociation 'Connected' -InUse $true)
            (New-TestDsmPackage -PublishedName 'oem2.inf' -Provider 'Contoso' `
                -OriginalName 'foo.inf' -DriverVersion '2.0.0' -DeviceAssociation 'NeverAssociated')
        )

        $result = Measure-DsmDriverStoreScope -Packages $pkgs
        $result.Summary.OldVersionCount | Should-Be 1
        $result.Summary.OldVersionsOfInUseFamiliesCount | Should-Be 1
    }

    It 'Excludes preserved packages from deletable count' {
        $pkgs = @(
            (New-TestDsmPackage -PublishedName 'oem9.inf' -DeviceAssociation 'NeverAssociated')
        )
        $pkgs[0] | Add-Member -NotePropertyName Preserved -NotePropertyValue $true -Force

        $result = Measure-DsmDriverStoreScope -Packages $pkgs
        $result.Summary.PreservedCount | Should-Be 1
        $result.Summary.DeletableCandidateCount | Should-Be 0
    }
}

Describe 'Get-DsmDriverStoreReport' {
    It 'Returns Global and Scoped sections with matching metric shapes' {
        $inv = @(
            (New-TestDsmPackage -PublishedName 'oem1.inf' -Provider 'Synaptics')
            (New-TestDsmPackage -PublishedName 'oem2.inf' -Provider 'Fabrikam')
        )

        $report = Get-DsmDriverStoreReport -Inventory $inv `
            -Filter (New-DsmDriverFilter -Provider 'Synaptics*') `
            -IncludeVulnerabilityScan `
            -SkipMicrosoftBlocklist

        $report.Global.Summary.TotalPackages | Should-Be 2
        $report.Scoped.Summary.TotalPackages | Should-Be 1
        ($report.Global.Summary.PSObject.Properties.Name -contains 'EstimatedReclaimableBytes') | Should-Be $true
        $report.FilterManifest | Should-NotBeNull
    }

    It 'Handles empty inventory without binding errors' {
        $report = Get-DsmDriverStoreReport -Inventory @() -IncludeVulnerabilityScan -SkipMicrosoftBlocklist
        $report.Global.Summary.TotalPackages | Should-Be 0
        $report.Scoped.Summary.TotalPackages | Should-Be 0
        $report.Global | Should-NotBeNull
    }

    It 'Includes vulnerability manifest and advisory severity on scanned packages' {
        $driverFile = Join-Path $TestDrive 'vuln.sys'
        Set-DsmTestAsciiFile -LiteralPath $driverFile -Value 'vuln-driver'
        $hash = (Get-FileHash -LiteralPath $driverFile -Algorithm SHA256).Hash
        $blocklist = Join-Path $TestDrive 'bl.txt'
        Set-Content -LiteralPath $blocklist -Value $hash -Encoding ascii

        $inv = @(
            (New-TestDsmPackage -PublishedName 'oem50.inf' -Provider 'Contoso' `
                -DeviceAssociation 'Connected' -InUse $true -Files @($driverFile))
        )

        $report = Get-DsmDriverStoreReport -Inventory $inv -BlocklistPath $blocklist -SkipMicrosoftBlocklist
        $report.VulnerabilityManifest.ScanRan | Should-Be $true
        $report.VulnerabilityManifest.BlocklistHashCount | Should-Be 1
        $report.Global.Summary.VulnerableCount | Should-Be 1
        $report.Global.Summary.BlocklistedInUseCount | Should-Be 1
        $report.Global.Listings.VulnerableDrivers[0].AdvisorySeverity | Should-Be 'Critical'
    }
}

Describe 'Get-DsmInfMetadata' {
    It 'Parses DriverVer and DiskId and normalizes DisplayName' {
        $inf = @'
[Version]
DriverVer=01/15/2024,15.0.0.0

[Strings]
DiskId = "Intel(R) Management Engine WMI Provider Installation Disk"
'@
        $path = Join-Path $TestDrive 'sample.inf'
        Set-Content -LiteralPath $path -Value $inf -Encoding UTF8

        $meta = Get-DsmInfMetadata -LiteralPath $path -NoCache
        $meta.DriverVer | Should-Be '01/15/2024 15.0.0.0'
        $meta.DiskId | Should-Be 'Intel(R) Management Engine WMI Provider Installation Disk'
        $meta.DisplayName | Should-Be 'Intel(R) Management Engine WMI Provider'
    }

    It 'Parses INF [Strings] section case-insensitively' {
        $inf = @'
[Version]
DriverVer=01/15/2024,15.0.0.0

[STRINGS]
DiskId = "Contoso Camera Installation Disk"
'@
        $path = Join-Path $TestDrive 'upper-strings.inf'
        Set-Content -LiteralPath $path -Value $inf -Encoding UTF8

        $meta = Get-DsmInfMetadata -LiteralPath $path -NoCache
        $meta.DiskId | Should-Be 'Contoso Camera Installation Disk'
    }

    It 'Preserves semicolons inside quoted INF labels' {
        $inf = @'
[Version]
DriverVer=01/15/2024,15.0.0.0

[Strings]
DiskId = "Contoso; Camera Installation Disk"
'@
        $path = Join-Path $TestDrive 'quoted-semicolon.inf'
        Set-Content -LiteralPath $path -Value $inf -Encoding UTF8

        $meta = Get-DsmInfMetadata -LiteralPath $path -NoCache
        $meta.DiskId | Should-Be 'Contoso; Camera Installation Disk'
    }

    It 'Resolves DiskId from SourceDisksNames string tokens' {
        $inf = @'
[Version]
DriverVer=03/31/2024,1.46.2024.0221

[SourceDisksNames]
1 = %DiskId%

[Strings]
DiskId = "Intel(R) Dynamic Application Loader Host Interface Installation Disk"
'@
        $path = Join-Path $TestDrive 'dal-sample.inf'
        Set-Content -LiteralPath $path -Value $inf -Encoding UTF8

        $meta = Get-DsmInfMetadata -LiteralPath $path -NoCache
        $meta.DiskId | Should-Be 'Intel(R) Dynamic Application Loader Host Interface Installation Disk'
        $meta.DisplayName | Should-Be 'Intel(R) Dynamic Application Loader Host Interface'
    }

    It 'Prefers DeviceDesc over DISK_NAME for AMD Crash Defender style INFs' {
        $inf = @'
[Version]
DriverVer=09/30/2025, 23.19.0.3

[Manufacturer]
%AMD% = AMDFENDR_KM, NTAMD64.10.0...16299

[AMDFENDR_KM.NTAMD64.10.0...16299]
%AMDFENDR_Desc%=AMDFENDR_INSTALL, ROOT\AMDLOG

[Strings]
AMD = "AMD"
AMDFENDR_Desc = "AMD Crash Defender"
DISK_NAME = "AMD Crash Defender Install Disk"
'@
        $path = Join-Path $TestDrive 'amdfendr.inf'
        Set-Content -LiteralPath $path -Value $inf -Encoding ASCII

        $meta = Get-DsmInfMetadata -LiteralPath $path -NoCache
        $meta.DisplayName | Should-Be 'AMD Crash Defender'
        $meta.LabelSource | Should-Be 'DeviceDesc'
    }

    It 'Resolves Intel HECI Location and DeviceDesc labels' {
        $inf = @'
[Version]
DriverVer=03/20/2025,2512.7.3.0

[SourceDisksNames]
1=%Location%,

[Manufacturer]
%MfgName% = Intel,NTamd64.10.0...17763

[Intel.NTamd64.10.0...17763]
%TEE_DeviceDesc1%=TEE_DDI_x64, PCI\VEN_8086&DEV_7E70

[Strings]
MfgName = "Intel"
TEE_DeviceDesc1 = "Intel(R) Management Engine Interface #1"
Location = "Intel(R) Management Engine Interface installation"
'@
        $path = Join-Path $TestDrive 'heci.inf'
        Set-Content -LiteralPath $path -Value $inf -Encoding ASCII

        $meta = Get-DsmInfMetadata -LiteralPath $path -NoCache
        $meta.DisplayName | Should-Be 'Intel(R) Management Engine Interface #1'
        $meta.LabelSource | Should-Be 'DeviceDesc'
    }

    It 'Resolves camera DeviceDesc and strips PlaceHolder comments from disk labels' {
        $inf = @'
[Version]
DriverVer=10/16/2023,5.0.8.63

[OEMInf]
VerifyMark="SunplusIT HP HD Webcam [Fixed]"

[Manufacturer]
%Foxlink.MfgName%=Foxlink.Section,NTamd64.10.0...16000

[Foxlink.Section.NTamd64.10.0...16000]
%CAMERA.DeviceDesc%=SPUVCb.Device_x64,USB\VID_05C8&PID_082F&MI_02

[Strings]
Foxlink.MfgName = "Foxlink"
CAMERA.DeviceDesc = "HP IR Camera"
DiskName = "USB WebCam Driver Install Disk"
'@
        $path = Join-Path $TestDrive 'spuvcbvir4.inf'
        Set-Content -LiteralPath $path -Value $inf -Encoding ASCII

        $meta = Get-DsmInfMetadata -LiteralPath $path -NoCache
        $meta.DisplayName | Should-Be 'HP IR Camera'
        $meta.LabelSource | Should-Be 'DeviceDesc'

        $sst = @'
[Strings]
DiskId = "Intel(R) Smart Sound Technology (Intel(R) SST) Bus - Installation Disk" ; {PlaceHolder="High Definition Audio"}
'@
        $sstPath = Join-Path $TestDrive 'intcaudiobus-strings.inf'
        Set-Content -LiteralPath $sstPath -Value $sst -Encoding ASCII
        $sstMeta = Get-DsmInfMetadata -LiteralPath $sstPath -NoCache
        $sstMeta.DisplayName | Should-Be 'Intel(R) Smart Sound Technology (Intel(R) SST) Bus'
    }

    It 'Resolves iCLS Location label from [Strings]' {
        $inf = @'
[Version]
DriverVer=03/28/2025,1.76.95.0

[SourceDisksNames]
1 = %Location%

[Strings]
ManufacturerName = "Intel"
Location = "Intel(R) iCLS Client"
'@
        $path = Join-Path $TestDrive 'iclsclient.inf'
        Set-Content -LiteralPath $path -Value $inf -Encoding ASCII

        $meta = Get-DsmInfMetadata -LiteralPath $path -NoCache
        $meta.DisplayName | Should-Be 'Intel(R) iCLS Client'
        $meta.LabelSource | Should-Be 'StringsDiskLabel'
    }

    It 'Resolves DisplayName tokens for Intel extension INFs without truncating ManufacturerName' {
        $inf = @'
[Version]
DriverVer=10/08/2024,2441.7.0.0

[Manufacturer]
%ManufacturerName%=Intel, NTamd64.10.0...16299

[Intel.NTamd64.10.0...16299]
%ImssHsaExtension.DisplayName% = SolLmsExtension_install, "PCI\VEN_8086&DEV_9D3D&CC_0700"

[Strings]
ManufacturerName = "Intel"
ImssHsaExtension.DisplayName = "Intel(R) SOL LMS Extension"
'@
        $path = Join-Path $TestDrive 'sollmsextension.inf'
        Set-Content -LiteralPath $path -Value $inf -Encoding ASCII

        $meta = Get-DsmInfMetadata -LiteralPath $path -NoCache
        $meta.DisplayName | Should-Be 'Intel(R) SOL LMS Extension'
        $meta.LabelSource | Should-Be 'DeviceDesc'
    }

    It 'Resolves quoted SWC model labels and ExtensionDesc strings' {
        $thunderbolt = @'
[Version]
DriverVer=07/27/2023,1.41.1379.0

[Manufacturer]
%Intel% = Thunderbolt,NTamd64.10.0...16299

[Thunderbolt.NTamd64.10.0...16299]
"Thunderbolt(TM) HSA Component" = Thunderbolt_HSA_Install, SWC\PROVIDER_Intel&&COMPONENT_ThunderboltHSA

[Strings]
Intel = "Intel(R) Corporation"
'@
        $tbPath = Join-Path $TestDrive 'tbthostcontrollerhsacomponent.inf'
        Set-Content -LiteralPath $tbPath -Value $thunderbolt -Encoding ASCII
        $tbMeta = Get-DsmInfMetadata -LiteralPath $tbPath -NoCache
        $tbMeta.DisplayName | Should-Be 'Thunderbolt(TM) HSA Component'
        $tbMeta.LabelSource | Should-Be 'QuotedModel'

        $hp = @'
[Version]
DriverVer=03/10/2026,8.10.52.464

[Manufacturer]
%Mfg% = HP,NTamd64.10.0...19041

[HP.NTamd64.10.0...19041]
%HP.ExtensionDesc% = HpqKbFiltrExtension_Install, SWD\COMPANIONDEVICES\HPQKBFILTR_8D6D0F41

[Strings]
Mfg = "HP Inc."
HP.ExtensionDesc = "HP LAN/WLAN/WWAN Switching and Hotkey Service"
'@
        $hpPath = Join-Path $TestDrive 'hpqkbfiltrextension.inf'
        Set-Content -LiteralPath $hpPath -Value $hp -Encoding ASCII
        $hpMeta = Get-DsmInfMetadata -LiteralPath $hpPath -NoCache
        $hpMeta.DisplayName | Should-Be 'HP LAN/WLAN/WWAN Switching and Hotkey Service'
        $hpMeta.LabelSource | Should-Be 'DeviceDesc'
    }

    It 'Prefers descriptive model strings over bare manufacturer tokens' {
        $inf = @'
[Version]
DriverVer=10/15/2024,32.2510.0.0

[Manufacturer]
%ATI% = ATI.Mfg, NTamd64.10.0...16299

[ATI.Mfg.NTamd64.10.0...16299]
%ExtendedGraphics%=ExtendedGraphics, SWC\VID1002&PID0001

[Strings]
ATI = "Advanced Micro Devices, Inc."
ExtendedGraphics = "AMD-UWP Version Control"
'@
        $path = Join-Path $TestDrive 'uwppair.inf'
        Set-Content -LiteralPath $path -Value $inf -Encoding ASCII

        $meta = Get-DsmInfMetadata -LiteralPath $path -NoCache
        $meta.DisplayName | Should-Be 'AMD-UWP Version Control'
        $meta.LabelSource | Should-Be 'ModelString'
    }
}

Describe 'Get-DsmDriverPackageInfPath' {
    It 'Picks the FileRepository folder that matches package files and DriverVersion' {
        $repo = Join-Path $TestDrive 'FileRepository'
        $oldDir = Join-Path $repo 'cui_dch.inf_amd64_old'
        $newDir = Join-Path $repo 'cui_dch.inf_amd64_new'
        New-Item -ItemType Directory -Path $oldDir, $newDir -Force | Out-Null

        Set-Content -LiteralPath (Join-Path $oldDir 'marker.dll') -Value 'old' -Encoding ASCII
        Set-Content -LiteralPath (Join-Path $newDir 'marker.dll') -Value 'new' -Encoding ASCII
        Set-Content -LiteralPath (Join-Path $oldDir 'cui_dch.inf') -Value @(
            '[Version]',
            'DriverVer=08/13/2024,31.0.101.2130',
            '[Strings]',
            'DiskId = "Old Graphics"'
        ) -Encoding ASCII
        Set-Content -LiteralPath (Join-Path $newDir 'cui_dch.inf') -Value @(
            '[Version]',
            'DriverVer=08/28/2025,31.0.101.2137',
            '[Strings]',
            'DiskId = "New Graphics"'
        ) -Encoding ASCII

        $script:DsmFileRepositoryRootOverride = $repo
        $script:DsmFileRepositoryFileIndex = $null
        $script:DsmInfMetadataCache = @{}

        $pkg = New-TestDsmPackage -PublishedName 'oem45.inf' -OriginalName 'cui_dch.inf' `
            -DriverVersion '08/13/2024 31.0.101.2130' -Files @('marker.dll')

        $path = Get-DsmDriverPackageInfPath -Package $pkg
        $meta = Get-DsmInfMetadata -LiteralPath $path -NoCache

        $path | Should-Be (Join-Path $oldDir 'cui_dch.inf')
        $meta.DriverVer | Should-Be '08/13/2024 31.0.101.2130'
        $meta.DiskId | Should-Be 'Old Graphics'

        $script:DsmFileRepositoryRootOverride = $null
        $script:DsmFileRepositoryFileIndex = $null
    }
}

Describe 'New-DsmCleanupResultRow' {
    It 'Includes DriverVer and in-use newer driver context for superseded families' {
        $inv = @(
            (New-TestDsmPackage -PublishedName 'oem1.inf' -Provider 'Intel' `
                -OriginalName 'me.inf' -DriverVersion '14.0.0.0' `
                -DeviceAssociation 'Connected' -InUse $true -Devices @('Intel ME'))
            (New-TestDsmPackage -PublishedName 'oem2.inf' -Provider 'Intel' `
                -OriginalName 'me.inf' -DriverVersion '13.0.0.0' `
                -DeviceAssociation 'NeverAssociated')
        )
        $inv[0] | Add-Member -NotePropertyName CollectedAt -NotePropertyValue (Get-Date) -Force
        $inv[1] | Add-Member -NotePropertyName CollectedAt -NotePropertyValue (Get-Date) -Force

        $ctx = Initialize-DsmCleanupFamilyContext -Inventory $inv
        $row = New-DsmCleanupResultRow -Package $inv[1] -FamilyContext $ctx -Action 'WhatIf'

        $row.DriverVersion | Should-Be '13.0.0.0'
        $row.IsOldVersionOfInUseFamily | Should-Be $true
        $row.InUseNewerDriver.PublishedName | Should-Be 'oem1.inf'
        $row.InUseNewerDriver.DriverVersion | Should-Be '14.0.0.0'
    }
}

Describe 'Get-DsmDriverFamilyKey' {
    It 'Uses provider and original name by default' {
        $pkg = New-TestDsmPackage -Provider 'Synaptics' -OriginalName 'displaylink.inf'
        Get-DsmDriverFamilyKey -Package $pkg | Should-Be 'PO|Synaptics|displaylink.inf'
    }

    It 'Uses HWID root when FamilyGroupBy is HwId' {
        $pkg = New-TestDsmPackage -HardwareIdRoots @('USB\VID_046D&PID_C52B')
        Get-DsmDriverFamilyKey -Package $pkg -FamilyGroupBy HwId | Should-Be 'HWID|USB\VID_046D&PID_C52B'
    }
}

Describe 'Get-DsmDriverStoreCleanupPlan' {
    It 'Applies filter and preserve before selecting deletable candidates' {
        $inv = @(
            (New-TestDsmPackage -PublishedName 'oem1.inf' -Provider 'Synaptics' `
                -DeviceAssociation 'NeverAssociated')
            (New-TestDsmPackage -PublishedName 'oem2.inf' -Provider 'Fabrikam' `
                -DeviceAssociation 'NeverAssociated')
            (New-TestDsmPackage -PublishedName 'oem3.inf' -Provider 'Synaptics' `
                -DeviceAssociation 'Connected' -InUse $true)
        )
        $inv[0] | Add-Member -NotePropertyName CollectedAt -NotePropertyValue (Get-Date) -Force
        $inv[1] | Add-Member -NotePropertyName CollectedAt -NotePropertyValue (Get-Date) -Force
        $inv[2] | Add-Member -NotePropertyName CollectedAt -NotePropertyValue (Get-Date) -Force

        $rule = New-DsmPreserveRule -RuleType KeepPublishedName -Name 'KeepOem2' `
            -PublishedName 'oem2.inf'

        $plan = Get-DsmDriverStoreCleanupPlan -Inventory $inv `
            -Filter (New-DsmDriverFilter -Provider 'Synaptics*') `
            -PreserveRule $rule

        $plan.CandidateCount | Should-Be 1
        $plan.Candidates[0].PublishedName | Should-Be 'oem1.inf'
        $plan.PreservedSkippedCount | Should-Be 0
        $plan.FilterExcludedCount | Should-Be 1
        $plan.NotDeletableInScopeCount | Should-Be 1
    }
}

Describe 'Remove-DsmUnusedDriverPackages' {
    It 'Returns WhatIf summary without requiring elevation' {
        $inv = @(
            (New-TestDsmPackage -PublishedName 'oem55.inf' -DeviceAssociation 'NeverAssociated')
        )
        $inv[0] | Add-Member -NotePropertyName CollectedAt -NotePropertyValue (Get-Date) -Force

        $run = Remove-DsmUnusedDriverPackages -Inventory $inv -WhatIf -PassThru
        $run.Summary.Mode | Should-Be 'WhatIf'
        $run.Summary.CandidateCount | Should-Be 1
        $run.Results[0].Action | Should-Be 'WhatIf'
    }
}

Describe 'Add-DsmDeviceCorrelationToInventory' {
    It 'Fails closed by setting DeviceAssociation to Unknown when correlation failed' {
        $inv = @(
            (New-TestDsmPackage -PublishedName 'oem1.inf')
        )

        $result = Add-DsmDeviceCorrelationToInventory -Inventory $inv -Correlation $null
        $result[0].DeviceAssociation | Should-Be 'Unknown'
        $result[0].InUse | Should-Be $false
    }

    It 'Sets DeviceAssociation to NeverAssociated when correlation succeeded but empty' {
        $inv = @(
            (New-TestDsmPackage -PublishedName 'oem1.inf')
        )

        $result = Add-DsmDeviceCorrelationToInventory -Inventory $inv -Correlation @{}
        $result[0].DeviceAssociation | Should-Be 'NeverAssociated'
        $result[0].InUse | Should-Be $false
    }
}

Describe 'Remove-DsmUnusedDriverPackages safety gates' {
    It 'Requires explicit Confirm binding even when ConfirmPreference is None' {
        $ConfirmPreference = 'None'
        $inv = @(
            (New-TestDsmPackage -PublishedName 'oem77.inf' -DeviceAssociation 'NeverAssociated')
        )

        $run = Remove-DsmUnusedDriverPackages -Inventory $inv -AllowDelete -PassThru
        $run.Summary.Mode | Should-Be 'WhatIf'
    }

    It 'Emits skip rows for in-scope non-deletable packages' {
        $inv = @(
            (New-TestDsmPackage -PublishedName 'oem1.inf' -DeviceAssociation 'Connected' -InUse $true)
            (New-TestDsmPackage -PublishedName 'oem2.inf' -DeviceAssociation 'NeverAssociated')
        )

        $run = Remove-DsmUnusedDriverPackages -Inventory $inv -WhatIf -PassThru
        @($run.Results | Where-Object Action -eq 'SkippedInUse').Count | Should-Be 1
        @($run.Results | Where-Object Action -eq 'WhatIf').Count | Should-Be 1
    }
}

Describe 'Test-DsmDriverVulnerabilities blocklist binding' {
    It 'Treats an empty supplied blocklist as intentional skip of Microsoft lookup' {
        $empty = [System.Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
        $inv = @(
            (New-TestDsmPackage -PublishedName 'oem1.inf' -Files @())
        )

        { Test-DsmDriverVulnerabilities -Inventory $inv -BlocklistHashes $empty } | Should -Not -Throw
    }
}

Describe 'Get-DsmInfMetadata resilience' {
    It 'Parses DriverVer before inline comments' {
        $inf = @'
[Version]
DriverVer=08/13/2024,31.0.101.2130 ; stale comment
[Strings]
DiskId = "Graphics Driver"
'@
        $path = Join-Path $TestDrive 'comment-driverver.inf'
        Set-Content -LiteralPath $path -Value $inf -Encoding ASCII
        $meta = Get-DsmInfMetadata -LiteralPath $path -NoCache
        $meta.DriverVer | Should-Be '08/13/2024 31.0.101.2130'
    }

    It 'Invalidates cache when the INF file changes on disk' {
        $path = Join-Path $TestDrive 'rewrite.inf'
        Set-Content -LiteralPath $path -Value @(
            '[Version]'
            'DriverVer=01/01/2024,1.0.0.0'
            '[Strings]'
            'DiskId = "First"'
        ) -Encoding ASCII

        $first = Get-DsmInfMetadata -LiteralPath $path
        Start-Sleep -Milliseconds 50
        Set-Content -LiteralPath $path -Value @(
            '[Version]'
            'DriverVer=02/02/2025,2.0.0.0'
            '[Strings]'
            'DiskId = "Second"'
        ) -Encoding ASCII

        $second = Get-DsmInfMetadata -LiteralPath $path
        $second.DiskId | Should-Be 'Second'
    }
}

Describe 'Set-DsmContentUtf8' {
    It 'Writes UTF-8 without BOM on PowerShell 7' {
        if (-not (Test-DsmIsPowerShellCore)) {
            Set-ItResult -Inconclusive -Because 'BOM assertion runs on PowerShell 7+'
        }

        $path = Join-Path $TestDrive 'utf8.txt'
        Set-DsmContentUtf8 -LiteralPath $path -Value 'plain'
        $bytes = [System.IO.File]::ReadAllBytes($path)
        $bytes[0] | Should-NotBe -Expected 0xEF
    }
}

Describe 'Get-DsmDriverStoreReport strict fields' {
    It 'Initializes preserve fields for packages without preserve policy' {
        $inv = @(
            (New-TestDsmPackage -PublishedName 'oem1.inf')
        )
        $report = Get-DsmDriverStoreReport -Inventory $inv -SkipMicrosoftBlocklist
        { $null = $report.Global.Listings.UnusedDrivers[0].Preserved } | Should -Not -Throw
        $report.Global.Listings.UnusedDrivers[0].Preserved | Should-Be $false
    }
}
