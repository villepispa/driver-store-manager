BeforeAll {
    $script:ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    $script:BuildScript = Join-Path $script:ProjectRoot 'scripts\Build-DsmIntuneScripts.ps1'

    function Invoke-DsmIntuneBuildUnderTest {
        param(
            [hashtable] $BuildParameters = @{}
        )

        $outDir = Join-Path $TestDrive 'intune'
        $BuildParameters['OutputDirectory'] = $outDir
        & $script:BuildScript @BuildParameters | Out-Null
        return $outDir
    }
}

Describe 'Build-DsmIntuneScripts configuration' {
    It 'Default build keeps null config paths and default knobs' {
        $outDir = Invoke-DsmIntuneBuildUnderTest
        $detect = Get-Content -LiteralPath (Join-Path $outDir 'Detect-DsmDriverStoreCompliance.ps1') -Raw -Encoding UTF8
        $remediate = Get-Content -LiteralPath (Join-Path $outDir 'Remediate-DsmDriverStore.ps1') -Raw -Encoding UTF8

        $detect.Contains("`$DsmOrphanThreshold = 1") | Should-Be $true
        $detect.Contains("`$DsmBlocklistPath = `$null") | Should-Be $true
        $detect.Contains("`$DsmPreserveRulesPath = `$null") | Should-Be $true
        $detect.Contains("`$DsmInlineBlocklistContent = `$null") | Should-Be $true
        $detect.Contains("`$DsmInlinePreserveRulesContent = `$null") | Should-Be $true
        $detect.Contains("`$DsmFilter = @{}") | Should-Be $true
        $detect.Contains("`$DsmIncludeCleanupPreview = `$null") | Should-Be $true
        $detect.Contains('$summary = $report.Scoped.Summary') | Should-Be $true
        $detect.Contains('function Set-DsmCallerSettingsOverlay') | Should-Be $true
        $detect.Contains('#region DSM source: Private/Dsm.Settings.ps1') | Should-Be $true
        $remediate.Contains("`$DsmRemediationMaxDeletes = 10") | Should-Be $true
        $remediate.Contains("`$DsmPreserveRulesPath = `$null") | Should-Be $true
        $remediate.Contains('function Set-DsmCallerSettingsOverlay') | Should-Be $true
        Test-Path -LiteralPath (Join-Path $outDir 'mvp\Detect-DsmDriverStoreCompliance.ps1') | Should-Be $true
        Test-Path -LiteralPath (Join-Path $outDir 'mvp\Remediate-DsmDriverStore.ps1') | Should-Be $true
    }

    It 'Report lists the MVP copies next to the full bundles' {
        $outDir = Join-Path $TestDrive 'report'
        $shown = & $script:BuildScript -OutputDirectory $outDir | Out-String
        $shown.Contains('MvpDetectionScript') | Should-Be $true
        $shown.Contains('MvpRemediationScript') | Should-Be $true
        $shown.Contains('MvpDetectionLines') | Should-Be $true
        $shown.Contains('MvpRemediationLines') | Should-Be $true
        $shown.Contains('MvpDetectionBytes') | Should-Be $true
        $shown.Contains('MvpRemediationBytes') | Should-Be $true
        Test-Path -LiteralPath (Join-Path $outDir 'mvp\Detect-DsmDriverStoreCompliance.ps1') | Should-Be $true
        Test-Path -LiteralPath (Join-Path $outDir 'mvp\Remediate-DsmDriverStore.ps1') | Should-Be $true
    }

    It 'Private bundle order matches DriverStoreManager.psm1 privateFiles' {
        $psm1Path = Join-Path $script:ProjectRoot 'src\DriverStoreManager\DriverStoreManager.psm1'
        $psm1 = Get-Content -LiteralPath $psm1Path -Raw -Encoding UTF8
        $match = [regex]::Match($psm1, '(?s)\$privateFiles = @\((.*?)\)')
        $match.Success | Should-Be $true
        $modulePrivate = @(
            [regex]::Matches($match.Groups[1].Value, "'([^']+\.ps1)'") |
                ForEach-Object { 'Private/' + $_.Groups[1].Value }
        )
        $manifestPath = Join-Path $script:ProjectRoot 'scripts\intune\bundle-order.json'
        $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $bundlePrivate = @($manifest.sources | Where-Object { $_ -like 'Private/*' })
        ($bundlePrivate -join '|') | Should-Be ($modulePrivate -join '|')
    }

    It 'Path mode bakes on-endpoint paths into detect and remediate' {
        $blocklistPath = "C:\ProgramData\DriverStoreManager\config\O'Brien\blocklist-hashes.txt"
        $preservePath = 'C:\ProgramData\DriverStoreManager\config\preserve-rules.json'
        $outDir = Invoke-DsmIntuneBuildUnderTest -BuildParameters @{
            BlocklistPath     = $blocklistPath
            PreserveRulesPath = $preservePath
            OrphanThreshold   = 3
            RemediationMaxDeletes = 2
            SkipMicrosoftBlocklist = $true
        }
        $detect = Get-Content -LiteralPath (Join-Path $outDir 'Detect-DsmDriverStoreCompliance.ps1') -Raw -Encoding UTF8
        $remediate = Get-Content -LiteralPath (Join-Path $outDir 'Remediate-DsmDriverStore.ps1') -Raw -Encoding UTF8

        $detect.Contains("`$DsmBlocklistPath = 'C:\ProgramData\DriverStoreManager\config\O''Brien\blocklist-hashes.txt'") | Should-Be $true
        $detect.Contains("`$DsmPreserveRulesPath = 'C:\ProgramData\DriverStoreManager\config\preserve-rules.json'") | Should-Be $true
        $detect.Contains("`$DsmOrphanThreshold = 3") | Should-Be $true
        $detect.Contains("`$DsmSkipMicrosoftBlocklist = `$true") | Should-Be $true
        $detect.Contains("`$DsmInlineBlocklistContent = `$null") | Should-Be $true
        $remediate.Contains("`$DsmPreserveRulesPath = 'C:\ProgramData\DriverStoreManager\config\preserve-rules.json'") | Should-Be $true
        $remediate.Contains("`$DsmRemediationMaxDeletes = 2") | Should-Be $true
        $remediate.Contains("`$DsmBlocklistPath =") | Should-Be $false
        $mvpDetect = Get-Content -LiteralPath (Join-Path $outDir 'mvp\Detect-DsmDriverStoreCompliance.ps1') -Raw -Encoding UTF8
        $mvpRemediate = Get-Content -LiteralPath (Join-Path $outDir 'mvp\Remediate-DsmDriverStore.ps1') -Raw -Encoding UTF8
        $mvpDetect.Contains("`$MvpOrphanThreshold = 3") | Should-Be $true
        $mvpDetect.Contains("`$MvpPreserveRulesPath = 'C:\ProgramData\DriverStoreManager\config\preserve-rules.json'") | Should-Be $true
        $mvpDetect.Contains('O''Brien') | Should-Be $false
        $mvpRemediate.Contains("`$MvpMaxDeletes = 2") | Should-Be $true
        $mvpRemediate.Contains("`$MvpPreserveRulesPath = 'C:\ProgramData\DriverStoreManager\config\preserve-rules.json'") | Should-Be $true
        $mvpRemediate.Contains('O''Brien') | Should-Be $false
    }

    It 'Inline mode embeds file content in generated scripts (blocklist Detection; preserve both)' {
        $bl = Join-Path $TestDrive 'bl.txt'
        $pr = Join-Path $TestDrive 'pr.json'
        @(
            '# fixture'
            'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        ) | Set-Content -LiteralPath $bl -Encoding utf8
        '[{"Name":"Keep printers","RuleType":"KeepMatching","Filter":{"DriverClass":["Printer"]}}]' |
            Set-Content -LiteralPath $pr -Encoding utf8

        $outDir = Invoke-DsmIntuneBuildUnderTest -BuildParameters @{
            InlineBlocklistFile      = $bl
            InlinePreserveRulesFile  = $pr
        }
        $detect = Get-Content -LiteralPath (Join-Path $outDir 'Detect-DsmDriverStoreCompliance.ps1') -Raw -Encoding UTF8
        $remediate = Get-Content -LiteralPath (Join-Path $outDir 'Remediate-DsmDriverStore.ps1') -Raw -Encoding UTF8

        $detect.Contains('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA') | Should-Be $true
        $detect.Contains('Keep printers') | Should-Be $true
        $detect.Contains('DsmInlineBlocklistContent') | Should-Be $true
        $detect.Contains("Get-DsmProgramDataRoot -ChildPath @('config', 'inline')") | Should-Be $true
        $remediate.Contains('Keep printers') | Should-Be $true
        $remediate.Contains('DsmInlinePreserveRulesContent') | Should-Be $true
        $remediate.Contains('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA') | Should-Be $false
    }

    It 'Rejects path and inline for the same blocklist file' {
        $bl = Join-Path $TestDrive 'conflict-bl.txt'
        'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB' |
            Set-Content -LiteralPath $bl -Encoding utf8
        {
            Invoke-DsmIntuneBuildUnderTest -BuildParameters @{
                BlocklistPath       = 'C:\ProgramData\DriverStoreManager\config\blocklist-hashes.txt'
                InlineBlocklistFile = $bl
            }
        } | Should -Throw '*Cannot set both -BlocklistPath and -InlineBlocklistFile*'
    }

    It 'Rejects a missing inline preserve-rules file' {
        $missing = Join-Path $TestDrive 'missing-preserve.json'
        {
            Invoke-DsmIntuneBuildUnderTest -BuildParameters @{
                InlinePreserveRulesFile = $missing
            }
        } | Should -Throw '*Inline preserve-rules file not found*'
    }

    It 'Resolves relative inline paths against the PowerShell location' {
        $caller = Join-Path $TestDrive 'caller'
        $cfg = Join-Path $caller 'config'
        New-Item -ItemType Directory -Path $cfg -Force | Out-Null
        $hash = 'D' * 64
        Set-Content -LiteralPath (Join-Path $cfg 'blocklist-hashes.txt') -Value $hash -Encoding utf8
        $rules = '[{"Name":"Site printers","RuleType":"KeepMatching","Filter":{"DriverClass":["Printer"]}}]'
        Set-Content -LiteralPath (Join-Path $cfg 'preserve-rules.json') -Value $rules -Encoding utf8

        $decoy = Join-Path $TestDrive 'userprofile-decoy'
        New-Item -ItemType Directory -Path $decoy -Force | Out-Null

        $previousLocation = (Get-Location).ProviderPath
        $previousDotNet = [System.IO.Directory]::GetCurrentDirectory()
        try {
            Set-Location -LiteralPath $caller
            [System.IO.Directory]::SetCurrentDirectory($decoy)

            $outDir = Invoke-DsmIntuneBuildUnderTest -BuildParameters @{
                InlineBlocklistFile     = '.\config\blocklist-hashes.txt'
                InlinePreserveRulesFile = '.\config\preserve-rules.json'
            }
            $detect = Get-Content -LiteralPath (Join-Path $outDir 'Detect-DsmDriverStoreCompliance.ps1') -Raw -Encoding UTF8
            $remediate = Get-Content -LiteralPath (Join-Path $outDir 'Remediate-DsmDriverStore.ps1') -Raw -Encoding UTF8
            $detect.Contains($hash) | Should-Be $true
            $detect.Contains('Site printers') | Should-Be $true
            $remediate.Contains('Site printers') | Should-Be $true
            $remediate.Contains($hash) | Should-Be $false
        }
        finally {
            Set-Location -LiteralPath $previousLocation
            [System.IO.Directory]::SetCurrentDirectory($previousDotNet)
        }
    }

    It 'Bakes safe settings-file keys and inlines sibling preserve and blocklist files' {
        $root = Join-Path $TestDrive 'profile'
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        $hash = 'E' * 64
        Set-Content -LiteralPath (Join-Path $root 'blocklist-hashes.txt') -Value $hash -Encoding utf8
        $rules = '[{"Name":"Site printers","RuleType":"KeepMatching","Filter":{"DriverClass":["Printer"]}}]'
        Set-Content -LiteralPath (Join-Path $root 'preserve-rules.json') -Value $rules -Encoding utf8
        @'
{
  "DriverClass": ["Printer"],
  "Association": "NeverAssociated",
  "PreserveRulesPath": "preserve-rules.json",
  "BlocklistPath": "blocklist-hashes.txt",
  "MaxDeletes": 4,
  "MicrosoftBlocklistMaxAgeDays": 3,
  "IncludeWindowsBuiltIn": false,
  "IncludeCleanupPreview": true,
  "FamilyGroupBy": "HwId"
}
'@ | Set-Content -LiteralPath (Join-Path $root 'dsm.settings.json') -Encoding utf8

        $outDir = Invoke-DsmIntuneBuildUnderTest -BuildParameters @{
            SettingsFile = (Join-Path $root 'dsm.settings.json')
        }
        $detect = Get-Content -LiteralPath (Join-Path $outDir 'Detect-DsmDriverStoreCompliance.ps1') -Raw -Encoding UTF8
        $remediate = Get-Content -LiteralPath (Join-Path $outDir 'Remediate-DsmDriverStore.ps1') -Raw -Encoding UTF8

        $detect.Contains("DriverClass = @('Printer')") | Should-Be $true
        $detect.Contains("Association = 'NeverAssociated'") | Should-Be $true
        $detect.Contains("`$DsmFamilyGroupBy = 'HwId'") | Should-Be $true
        $detect.Contains("`$DsmMicrosoftBlocklistMaxAgeDays = 3") | Should-Be $true
        $detect.Contains("`$DsmIncludeCleanupPreview = `$true") | Should-Be $true
        $detect.Contains($hash) | Should-Be $true
        $detect.Contains('Site printers') | Should-Be $true
        $config = [regex]::Match($detect, '(?s)# region DSM_BUILD_CONFIG\r?\n.*?# endregion DSM_BUILD_CONFIG').Value
        $config.Contains('IncludeWindowsBuiltIn') | Should-Be $false
        $remediate.Contains("DriverClass = @('Printer')") | Should-Be $true
        $remediate.Contains("`$DsmRemediationMaxDeletes = 4") | Should-Be $true
        $remediate.Contains('Site printers') | Should-Be $true
        $remediate.Contains($hash) | Should-Be $false
    }

    It 'Bound builder parameters replace settings-file values' {
        $root = Join-Path $TestDrive 'override'
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        '{"DriverClass":["Printer"],"MaxDeletes":4}' |
            Set-Content -LiteralPath (Join-Path $root 'dsm.settings.json') -Encoding utf8

        $outDir = Invoke-DsmIntuneBuildUnderTest -BuildParameters @{
            SettingsFile          = (Join-Path $root 'dsm.settings.json')
            DriverClass           = @('Display')
            RemediationMaxDeletes = 2
        }
        $detect = Get-Content -LiteralPath (Join-Path $outDir 'Detect-DsmDriverStoreCompliance.ps1') -Raw -Encoding UTF8
        $remediate = Get-Content -LiteralPath (Join-Path $outDir 'Remediate-DsmDriverStore.ps1') -Raw -Encoding UTF8

        $detect.Contains("DriverClass = @('Display')") | Should-Be $true
        $detect.Contains("DriverClass = @('Printer')") | Should-Be $false
        $remediate.Contains("`$DsmRemediationMaxDeletes = 2") | Should-Be $true
    }

    It 'Resolves a relative settings file against the PowerShell location' {
        $caller = Join-Path $TestDrive 'settings-caller'
        New-Item -ItemType Directory -Path $caller -Force | Out-Null
        '{"DriverClass":["Net"],"IncludeWindowsBuiltIn":false}' |
            Set-Content -LiteralPath (Join-Path $caller 'dsm.settings.json') -Encoding utf8
        $decoy = Join-Path $TestDrive 'settings-decoy'
        New-Item -ItemType Directory -Path $decoy -Force | Out-Null

        $previousLocation = (Get-Location).ProviderPath
        $previousDotNet = [System.IO.Directory]::GetCurrentDirectory()
        try {
            Set-Location -LiteralPath $caller
            [System.IO.Directory]::SetCurrentDirectory($decoy)
            $outDir = Invoke-DsmIntuneBuildUnderTest -BuildParameters @{
                SettingsFile = '.\dsm.settings.json'
            }
            $detect = Get-Content -LiteralPath (Join-Path $outDir 'Detect-DsmDriverStoreCompliance.ps1') -Raw -Encoding UTF8
            $detect.Contains("DriverClass = @('Net')") | Should-Be $true
        }
        finally {
            Set-Location -LiteralPath $previousLocation
            [System.IO.Directory]::SetCurrentDirectory($previousDotNet)
        }
    }

    It 'Rejects IncludeWindowsBuiltIn true' {
        $path = Join-Path $TestDrive 'inbox-true.json'
        '{"IncludeWindowsBuiltIn":true}' | Set-Content -LiteralPath $path -Encoding utf8
        {
            Invoke-DsmIntuneBuildUnderTest -BuildParameters @{ SettingsFile = $path }
        } | Should -Throw '*IncludeWindowsBuiltIn cannot be enabled for Intune*'
    }

    It 'Rejects OutputPath in a settings file' {
        $path = Join-Path $TestDrive 'output-path.json'
        '{"OutputPath":"C:\\temp\\dsm-out"}' | Set-Content -LiteralPath $path -Encoding utf8
        {
            Invoke-DsmIntuneBuildUnderTest -BuildParameters @{ SettingsFile = $path }
        } | Should -Throw '*OutputPath is excluded from Intune builds*'
    }

    It 'Rejects AllowDelete in a settings file' {
        $path = Join-Path $TestDrive 'allow-delete.json'
        '{"AllowDelete":true}' | Set-Content -LiteralPath $path -Encoding utf8
        {
            Invoke-DsmIntuneBuildUnderTest -BuildParameters @{ SettingsFile = $path }
        } | Should -Throw '*AllowDelete*'
    }

    It 'Bakes the example run profile' {
        $example = Join-Path $script:ProjectRoot 'examples\dsm.settings.example.json'
        $outDir = Invoke-DsmIntuneBuildUnderTest -BuildParameters @{
            SettingsFile = $example
        }
        $detect = Get-Content -LiteralPath (Join-Path $outDir 'Detect-DsmDriverStoreCompliance.ps1') -Raw -Encoding UTF8
        $remediate = Get-Content -LiteralPath (Join-Path $outDir 'Remediate-DsmDriverStore.ps1') -Raw -Encoding UTF8

        $detect.Contains("DriverClass = @('Printer')") | Should-Be $true
        $detect.Contains("Association = 'NeverAssociated'") | Should-Be $true
        $detect.Contains("`$DsmFamilyGroupBy = 'ProviderOriginalName'") | Should-Be $true
        $detect.Contains("`$DsmIncludeCleanupPreview = `$true") | Should-Be $true
        $detect.Contains('DisplayLink latest per family') | Should-Be $true
        $detect.Contains('17927B93B2D6AB4271C158F039CAE2D60591D6A14458F5A5690AEC86F5D54229') | Should-Be $true
        $remediate.Contains("DriverClass = @('Printer')") | Should-Be $true
        $remediate.Contains('DisplayLink latest per family') | Should-Be $true
        $remediate.Contains('17927B93B2D6AB4271C158F039CAE2D60591D6A14458F5A5690AEC86F5D54229') | Should-Be $false
        $mvpDetect = Get-Content -LiteralPath (Join-Path $outDir 'mvp\Detect-DsmDriverStoreCompliance.ps1') -Raw -Encoding UTF8
        $mvpRemediate = Get-Content -LiteralPath (Join-Path $outDir 'mvp\Remediate-DsmDriverStore.ps1') -Raw -Encoding UTF8
        $mvpDetect.Contains("`$MvpFilterDriverClass = @('Printer')") | Should-Be $true
        $mvpDetect.Contains("`$MvpFilterAssociation = 'NeverAssociated'") | Should-Be $true
        $mvpDetect.Contains('DisplayLink latest per family') | Should-Be $true
        $mvpDetect.Contains('17927B93B2D6AB4271C158F039CAE2D60591D6A14458F5A5690AEC86F5D54229') | Should-Be $false
        $mvpRemediate.Contains("`$MvpFilterDriverClass = @('Printer')") | Should-Be $true
        $mvpRemediate.Contains("`$MvpMaxDeletes = 10") | Should-Be $true
        $mvpRemediate.Contains('17927B93B2D6AB4271C158F039CAE2D60591D6A14458F5A5690AEC86F5D54229') | Should-Be $false
    }

    It 'Bakes supported switches into the MVP and omits unsupported keys' {
        $rules = Join-Path $TestDrive 'mvp-rules.json'
        '[{"Name":"Site net","RuleType":"KeepMatching","Filter":{"DriverClass":["Net"]}}]' |
            Set-Content -LiteralPath $rules -Encoding utf8
        $outDir = Invoke-DsmIntuneBuildUnderTest -BuildParameters @{
            OrphanThreshold             = 4
            DetectOrphanCandidates      = $false
            RemediationMaxDeletes       = 2
            RemediationRequireElevation = $false
            DriverClass                 = @('Net')
            IncludePublishedName        = @('oem9.inf')
            InlinePreserveRulesFile     = $rules
            DeviceName                  = @('Contoso')
            BlocklistPath               = 'C:\ProgramData\DriverStoreManager\config\blocklist-hashes.txt'
        }
        $mvpDetect = Get-Content -LiteralPath (Join-Path $outDir 'mvp\Detect-DsmDriverStoreCompliance.ps1') -Raw -Encoding UTF8
        $mvpRemediate = Get-Content -LiteralPath (Join-Path $outDir 'mvp\Remediate-DsmDriverStore.ps1') -Raw -Encoding UTF8
        $mvpDetect.Contains("`$MvpOrphanThreshold = 4") | Should-Be $true
        $mvpDetect.Contains("`$MvpDetectOrphanCandidates = `$false") | Should-Be $true
        $mvpDetect.Contains("`$MvpFilterDriverClass = @('Net')") | Should-Be $true
        $mvpDetect.Contains("`$MvpIncludePublishedName = @('oem9.inf')") | Should-Be $true
        $mvpDetect.Contains('Site net') | Should-Be $true
        $mvpDetect.Contains('Contoso') | Should-Be $false
        $mvpDetect.Contains('blocklist-hashes.txt') | Should-Be $false
        $mvpRemediate.Contains("`$MvpMaxDeletes = 2") | Should-Be $true
        $mvpRemediate.Contains("`$MvpRequireElevation = `$false") | Should-Be $true
        $mvpRemediate.Contains('Site net') | Should-Be $true
        $mvpRemediate.Contains('Contoso') | Should-Be $false
    }
}
