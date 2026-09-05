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
        $remediate.Contains("`$DsmRemediationMaxDeletes = 10") | Should-Be $true
        $remediate.Contains("`$DsmPreserveRulesPath = `$null") | Should-Be $true
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
}
