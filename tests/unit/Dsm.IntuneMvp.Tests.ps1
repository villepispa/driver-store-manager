BeforeAll {
    $script:ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    $script:MvpDir = Join-Path $script:ProjectRoot 'scripts\intune\mvp'
    $script:DetectScript = Join-Path $script:MvpDir 'Detect-DsmDriverStoreCompliance.ps1'
    $script:RemediateScript = Join-Path $script:MvpDir 'Remediate-DsmDriverStore.ps1'
    $script:FixtureSource = Join-Path $script:ProjectRoot 'tests\fixtures'
    . (Join-Path $script:ProjectRoot 'tests\helpers\DsmTestFixtures.ps1')

    function New-MvpFixtureSet {
        param([string] $Root, [string[]] $ExtraDriverLines)
        New-Item -ItemType Directory -Path $Root -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $script:FixtureSource 'pnputil-enum-devices-all.csv') `
            -Destination (Join-Path $Root 'pnputil-enum-devices-all.csv')
        Copy-Item -LiteralPath (Join-Path $script:FixtureSource 'pnputil-enum-devices-connected.csv') `
            -Destination (Join-Path $Root 'pnputil-enum-devices-connected.csv')
        $drivers = @(Get-Content -LiteralPath (Join-Path $script:FixtureSource 'pnputil-enum-drivers.csv'))
        foreach ($line in @($ExtraDriverLines)) {
            if (-not [string]::IsNullOrWhiteSpace($line)) { $drivers += $line }
        }
        Set-Content -LiteralPath (Join-Path $Root 'pnputil-enum-drivers.csv') -Value $drivers -Encoding Ascii
    }

    function Invoke-MvpChild {
        param(
            [Parameter(Mandatory)] [string] $ScriptPath,
            [Parameter(Mandatory)] [string] $FixtureRoot,
            [Parameter(Mandatory)] [string] $StateRoot,
            [switch] $ApplyStateAcl
        )
        $previous = @{
            DSM_MVP_STUB_PNPUTIL    = $env:DSM_MVP_STUB_PNPUTIL
            DSM_MVP_FIXTURE_ROOT    = $env:DSM_MVP_FIXTURE_ROOT
            DSM_MVP_STATE_ROOT      = $env:DSM_MVP_STATE_ROOT
            DSM_MVP_STUB_LOG        = $env:DSM_MVP_STUB_LOG
            DSM_MVP_ASSUME_ELEVATED = $env:DSM_MVP_ASSUME_ELEVATED
            DSM_MVP_SKIP_STATE_ACL  = $env:DSM_MVP_SKIP_STATE_ACL
            DSM_MVP_INF_ROOT        = $env:DSM_MVP_INF_ROOT
        }
        $logPath = Join-Path $StateRoot 'pnputil-stub.log'
        New-Item -ItemType Directory -Path $StateRoot -Force | Out-Null
        $env:DSM_MVP_STUB_PNPUTIL = '1'
        $env:DSM_MVP_FIXTURE_ROOT = $FixtureRoot
        $env:DSM_MVP_STATE_ROOT = $StateRoot
        $env:DSM_MVP_STUB_LOG = $logPath
        $env:DSM_MVP_ASSUME_ELEVATED = '1'
        if ($ApplyStateAcl) { $env:DSM_MVP_SKIP_STATE_ACL = '0' }
        else { $env:DSM_MVP_SKIP_STATE_ACL = '1' }
        try {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = (Get-Process -Id $PID).Path
            $psi.Arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $ScriptPath + '"'
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.CreateNoWindow = $true
            $proc = [System.Diagnostics.Process]::Start($psi)
            $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
            $stderrTask = $proc.StandardError.ReadToEndAsync()
            [void]$proc.WaitForExit()
            [void]$stdoutTask.Wait()
            [void]$stderrTask.Wait()
            $logText = ''
            try {
                if (Test-Path -LiteralPath $logPath) {
                    $logText = [System.IO.File]::ReadAllText($logPath)
                }
            }
            catch {
                $logText = ''
            }
            return [pscustomobject]@{
                ExitCode = $proc.ExitCode
                StdOut   = [string]$stdoutTask.Result
                StdErr   = [string]$stderrTask.Result
                Log      = $logText
            }
        }
        finally {
            $env:DSM_MVP_STUB_PNPUTIL = $previous.DSM_MVP_STUB_PNPUTIL
            $env:DSM_MVP_FIXTURE_ROOT = $previous.DSM_MVP_FIXTURE_ROOT
            $env:DSM_MVP_STATE_ROOT = $previous.DSM_MVP_STATE_ROOT
            $env:DSM_MVP_STUB_LOG = $previous.DSM_MVP_STUB_LOG
            $env:DSM_MVP_ASSUME_ELEVATED = $previous.DSM_MVP_ASSUME_ELEVATED
            $env:DSM_MVP_SKIP_STATE_ACL = $previous.DSM_MVP_SKIP_STATE_ACL
            $env:DSM_MVP_INF_ROOT = $previous.DSM_MVP_INF_ROOT
        }
    }

    function Get-MvpSharedSpine {
        param([string] $Path, [string] $EndMarker)
        $lines = @(Get-Content -LiteralPath $Path)
        $start = 0
        $end = $lines.Count
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i].Trim() -eq '#section Helpers') { $start = $i }
            if ($lines[$i].Trim() -eq $EndMarker) { $end = $i; break }
        }
        return ($lines[$start..($end - 1)] -join "`n")
    }
}

Describe 'Enterprise Intune MVP scripts' {
    It 'Stays inside the review budget and does not call pnputil /force' {
        $detectLines = @(Get-Content -LiteralPath $script:DetectScript)
        $remediateLines = @(Get-Content -LiteralPath $script:RemediateScript)
        $total = $detectLines.Count + $remediateLines.Count
        $total | Should -BeGreaterThan 700
        $total | Should -BeLessThan 2000
        ($detectLines -join "`n") | Should -Not -Match '''/force'''
        ($remediateLines -join "`n") | Should -Not -Match '''/force'''
        ($detectLines -join "`n") | Should -Match '#section Compliance gate'
        ($remediateLines -join "`n") | Should -Match '#section Export and delete'
    }

    It 'Keeps the shared spine identical through the deletable list' {
        $detectSpine = Get-MvpSharedSpine -Path $script:DetectScript -EndMarker '#section Report'
        $remediateSpine = Get-MvpSharedSpine -Path $script:RemediateScript -EndMarker '#section Elevation'
        $detectSpine | Should -Be $remediateSpine
    }

    It 'Exits 0 when every oem package is connected or disconnected' {
        $fixture = Join-Path $TestDrive 'compliant'
        $state = Join-Path $TestDrive 'compliant-state'
        New-MvpFixtureSet -Root $fixture
        $run = Invoke-MvpChild -ScriptPath $script:DetectScript -FixtureRoot $fixture -StateRoot $state
        $run.ExitCode | Should -Be 0
        $run.StdOut | Should -Match 'DSM-MVP-DETECT deletable=0'
        $run.StdOut | Should -Match 'DSM-MVP-DETECT Connected=oem1.inf'
        $run.StdOut | Should -Match 'DSM-MVP-DETECT DisconnectedInstalled=oem2.inf'
        $run.StdOut | Should -Match 'DSM-MVP-DETECT Preserved=\(none\)'
        $run.StdOut | Should -Match 'DSM-MVP-DETECT DeletablePublishedNames=\(none\)'
    }

    It 'Exits 1 for a NeverAssociated orphan and keeps a printer' {
        $fixture = Join-Path $TestDrive 'orphan'
        $state = Join-Path $TestDrive 'orphan-state'
        New-MvpFixtureSet -Root $fixture -ExtraDriverLines @(
            'oem8.inf,print.inf,Contoso,Printer,1.0.0.0,,print.sys'
            'oem9.inf,orphan.inf,OrphanCo,System,1.0.0.0,,orphan.sys'
        )
        $run = Invoke-MvpChild -ScriptPath $script:DetectScript -FixtureRoot $fixture -StateRoot $state
        $run.ExitCode | Should -Be 1
        $reportFile = Get-ChildItem -LiteralPath (Join-Path $state 'intune-mvp-detection') -Filter 'driver-store-report_*.json' |
            Select-Object -First 1
        $report = Get-Content -LiteralPath $reportFile.FullName -Raw | ConvertFrom-Json
        $report.DeletableCandidateCount | Should -Be 1
        @($report.DeletablePublishedNames) -contains 'oem9.inf' | Should -Be $true
        @($report.DeletablePublishedNames) -contains 'oem8.inf' | Should -Be $false
        @($report.ConnectedPublishedNames) | Should -Be @('oem1.inf')
        @($report.DisconnectedInstalledPublishedNames) | Should -Be @('oem2.inf')
        @($report.PreservedPublishedNames) | Should -Be @('oem8.inf')
        $run.StdOut | Should -Match 'DSM-MVP-DETECT Preserved=oem8.inf'
        $run.StdOut | Should -Match 'DSM-MVP-DETECT DeletablePublishedNames=oem9.inf'
    }

    It 'Preserves the latest package in a KeepLatest family' {
        $fixture = Join-Path $TestDrive 'latest'
        $state = Join-Path $TestDrive 'latest-state'
        New-MvpFixtureSet -Root $fixture -ExtraDriverLines @(
            'oem3.inf,dl.inf,DisplayLink,Display,1.0.0.0,,a.sys'
            'oem4.inf,dl.inf,DisplayLink,Display,2.0.0.0,,b.sys'
        )
        $run = Invoke-MvpChild -ScriptPath $script:DetectScript -FixtureRoot $fixture -StateRoot $state
        $run.ExitCode | Should -Be 1
        $reportFile = Get-ChildItem -LiteralPath (Join-Path $state 'intune-mvp-detection') -Filter 'driver-store-report_*.json' |
            Select-Object -First 1
        $report = Get-Content -LiteralPath $reportFile.FullName -Raw | ConvertFrom-Json
        @($report.DeletablePublishedNames) | Should -Be @('oem3.inf')
    }

    It 'Exits 2 when device correlation fixtures are missing' {
        $fixture = Join-Path $TestDrive 'nocorrelation'
        $state = Join-Path $TestDrive 'nocorrelation-state'
        New-MvpFixtureSet -Root $fixture -ExtraDriverLines @('oem9.inf,orphan.inf,OrphanCo,System,1.0.0.0,,orphan.sys')
        Remove-Item -LiteralPath (Join-Path $fixture 'pnputil-enum-devices-all.csv') -Force
        $run = Invoke-MvpChild -ScriptPath $script:DetectScript -FixtureRoot $fixture -StateRoot $state
        $run.ExitCode | Should -Be 2
    }

    It 'Exports then deletes only the orphan' {
        $fixture = Join-Path $TestDrive 'delete'
        $state = Join-Path $TestDrive 'delete-state'
        New-MvpFixtureSet -Root $fixture -ExtraDriverLines @(
            'oem8.inf,print.inf,Contoso,Printer,1.0.0.0,,print.sys'
            'oem9.inf,orphan.inf,OrphanCo,System,1.0.0.0,,orphan.sys'
        )
        $run = Invoke-MvpChild -ScriptPath $script:RemediateScript -FixtureRoot $fixture -StateRoot $state
        $run.ExitCode | Should -Be 0
        $run.StdOut | Should -Match 'DSM-MVP-REMEDIATE deleted=1 failed=0'
        $exportAt = $run.Log.IndexOf('export-driver oem9.inf')
        $deleteAt = $run.Log.IndexOf('delete-driver oem9.inf')
        $exportAt | Should -BeGreaterThan -1
        $deleteAt | Should -BeGreaterThan $exportAt
        $packageDir = Join-Path $state 'backups\System\orphan.inf_oem9.inf'
        Test-Path -LiteralPath $packageDir | Should -Be $true
        $run.Log | Should -Not -Match 'delete-driver oem1.inf'
        $run.Log | Should -Not -Match 'delete-driver oem8.inf'
        $summaryFile = Get-ChildItem -LiteralPath (Join-Path $state 'reports\intune-mvp-remediation') -Filter 'remediation-summary_*.json' |
            Select-Object -First 1
        $summary = Get-Content -LiteralPath $summaryFile.FullName -Raw | ConvertFrom-Json
        $summary.DeletedCount | Should -Be 1
        $summary.ExportOrDeleteFailedCount | Should -Be 0
        $deleted = @($summary.Results | Where-Object { $_.Action -eq 'Deleted' })
        $deleted[0].PublishedName | Should -Be 'oem9.inf'
        $deleted[0].DriverClass | Should -Be 'System'
        $deleted[0].BackupPath | Should -Match 'System'
        $run.StdOut | Should -Match 'PublishedName=oem9.inf Class=System Action=Deleted'
        $run.StdOut | Should -Match 'DSM-MVP-REMEDIATE Connected=oem1.inf'
        $run.StdOut | Should -Match 'DSM-MVP-REMEDIATE DisconnectedInstalled=oem2.inf'
        $run.StdOut | Should -Match 'DSM-MVP-REMEDIATE Preserved=oem8.inf'
        $run.StdOut | Should -Match 'DSM-MVP-REMEDIATE DeletablePublishedNames=oem9.inf'
        $failedFile = Get-ChildItem -LiteralPath (Join-Path $state 'reports\intune-mvp-remediation') -Filter 'export-or-delete-failed_*.json' |
            Select-Object -First 1
        $failed = Get-Content -LiteralPath $failedFile.FullName -Raw | ConvertFrom-Json
        $failed.ExportOrDeleteFailedCount | Should -Be 0
    }

    It 'Deletes only a published INF older than the configured age' {
        $fixture = Join-Path $TestDrive 'age'
        $state = Join-Path $TestDrive 'age-state'
        $infRoot = Join-Path $TestDrive 'age-inf'
        New-Item -ItemType Directory -Path $infRoot -Force | Out-Null
        New-MvpFixtureSet -Root $fixture -ExtraDriverLines @(
            'oem9.inf,orphan.inf,OrphanCo,System,1.0.0.0,,orphan.sys'
            'oem10.inf,fresh.inf,FreshCo,System,1.0.0.0,,fresh.sys'
        )
        $oldInf = Join-Path $infRoot 'oem9.inf'
        $newInf = Join-Path $infRoot 'oem10.inf'
        Set-Content -LiteralPath $oldInf -Value 'old' -Encoding Ascii
        Set-Content -LiteralPath $newInf -Value 'new' -Encoding Ascii
        (Get-Item -LiteralPath $oldInf).CreationTime = (Get-Date).AddDays(-40)
        $scriptPath = Join-Path $TestDrive 'Remediate-Age.ps1'
        $text = [System.IO.File]::ReadAllText($script:RemediateScript)
        $text = $text.Replace('$MvpDriverFolderMinAgeDays = 0', '$MvpDriverFolderMinAgeDays = 10')
        [System.IO.File]::WriteAllText($scriptPath, $text)
        $env:DSM_MVP_INF_ROOT = $infRoot
        try {
            $run = Invoke-MvpChild -ScriptPath $scriptPath -FixtureRoot $fixture -StateRoot $state
        }
        finally {
            Remove-Item Env:DSM_MVP_INF_ROOT -ErrorAction SilentlyContinue
        }
        $run.ExitCode | Should -Be 0
        $run.StdOut | Should -Match 'DSM-MVP-REMEDIATE deleted=1 failed=0'
        $run.Log | Should -Match 'delete-driver oem9.inf'
        $run.Log | Should -Not -Match 'delete-driver oem10.inf'
        $run.Log | Should -Not -Match 'delete-driver oem3.inf'
    }

    It 'Loads preserve rules from an endpoint path and fails closed when that file is missing' {
        $kept = Join-Path $TestDrive 'keep-system.json'
        @(
            '['
            '  {"Name":"Keep system and printers","RuleType":"KeepMatching","Filter":{"DriverClass":["System","Printer"]}}'
            ']'
        ) | Set-Content -LiteralPath $kept -Encoding utf8
        $scriptPath = Join-Path $TestDrive 'Detect-WithPath.ps1'
        $text = [System.IO.File]::ReadAllText($script:DetectScript)
        $quotedKept = $kept.Replace("'", "''")
        $oldPathLine = '$MvpPreserveRulesPath = ' + "''"
        $newPathLine = '$MvpPreserveRulesPath = ''' + $quotedKept + "'"
        $text = $text.Replace($oldPathLine, $newPathLine)
        [System.IO.File]::WriteAllText($scriptPath, $text)
        $fixture = Join-Path $TestDrive 'path-rules'
        $state = Join-Path $TestDrive 'path-rules-state'
        New-MvpFixtureSet -Root $fixture -ExtraDriverLines @(
            'oem8.inf,print.inf,Contoso,Printer,1.0.0.0,,print.sys'
            'oem9.inf,orphan.inf,OrphanCo,System,1.0.0.0,,orphan.sys'
        )
        $run = Invoke-MvpChild -ScriptPath $scriptPath -FixtureRoot $fixture -StateRoot $state
        $run.ExitCode | Should -Be 0

        $missingPath = Join-Path $TestDrive 'missing-rules.json'
        $missingScript = Join-Path $TestDrive 'Detect-MissingPath.ps1'
        $missingText = [System.IO.File]::ReadAllText($script:DetectScript)
        $quotedMissing = $missingPath.Replace("'", "''")
        $missingText = $missingText.Replace($oldPathLine, ('$MvpPreserveRulesPath = ''' + $quotedMissing + "'"))
        [System.IO.File]::WriteAllText($missingScript, $missingText)
        $missingRun = Invoke-MvpChild -ScriptPath $missingScript -FixtureRoot $fixture -StateRoot (Join-Path $TestDrive 'missing-path-state')
        $missingRun.ExitCode | Should -Be 2
        $missingRun.StdErr | Should -Match 'Preserve rules file not found'
    }

    It 'Limits the state folder to SYSTEM full control and Administrators modify' {
        $fixture = Join-Path $TestDrive 'acl-fixture'
        $state = Join-Path $TestDrive 'acl-state'
        New-MvpFixtureSet -Root $fixture -ExtraDriverLines @('oem9.inf,orphan.inf,OrphanCo,System,1.0.0.0,,orphan.sys')
        $run = $null
        try {
            $run = Invoke-MvpChild -ScriptPath $script:RemediateScript -FixtureRoot $fixture -StateRoot $state -ApplyStateAcl
            $run.ExitCode | Should -Be 0
            $run.StdErr | Should -BeNullOrEmpty
        }
        finally {
            Reset-DsmTestRestrictedAcl -LiteralPath $state
        }
    }
}
