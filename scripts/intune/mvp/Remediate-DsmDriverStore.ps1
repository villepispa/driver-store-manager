#Requires -Version 5.1
<#
.SYNOPSIS
  Intune remediation for the enterprise driver-store MVP.

.DESCRIPTION
  **Safety tier: 2**

  Standalone Windows PowerShell 5.1 script for Intune Proactive Remediation.
  It inventories staged oem*.inf packages, classifies device association, applies
  the preserve rules in #section Config, exports each deletable package, then
  deletes at most the configured number. Only NeverAssociated packages that are
  not preserved are deleted. The pnputil force switch is not used. A fresh association
  check runs again before each delete. Blocklist and DiskId stay in the full module.

  Test seams (unset on Intune devices): DSM_MVP_STUB_PNPUTIL=1 reads CSV
  fixtures from DSM_MVP_FIXTURE_ROOT and does not call pnputil. DSM_MVP_STATE_ROOT
  replaces ProgramData. DSM_MVP_ASSUME_ELEVATED=1 skips the administrator check.
  A stub without fixtures exits 2.

.EXAMPLE
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\intune\mvp\Remediate-DsmDriverStore.ps1

.NOTES
  Upload the built copy under dist/intune/mvp. The build bakes the same
  switches and settings file the full bundles use, for the filters and preserve
  rules this script implements. Blocklist and DiskId stay in the full module.
  Exit 0 completed, 2 error or missing elevation. Do not run this on a daily driver.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#section Config
$MvpMaxDeletes = 10
$MvpRequireElevation = $true
$MvpFilterDriverClass = @()
$MvpFilterProvider = @()
$MvpFilterPublishedName = @()
$MvpFilterHardwareId = @()
$MvpFilterOriginalName = @()
$MvpFilterAssociation = ''
$MvpIncludePublishedName = @()
$MvpPreserveRulesPath = ''
$MvpPreserveRulesJson = @'
[
  {
    "Name": "DisplayLink latest per family",
    "RuleType": "KeepLatest",
    "FamilyGroupBy": "ProviderOriginalName",
    "Filter": {
      "Provider": ["*DisplayLink*", "Synaptics*"]
    }
  },
  {
    "Name": "Printer queue drivers",
    "RuleType": "KeepMatching",
    "Filter": {
      "DriverClass": ["Printer", "PrintQueue"]
    }
  },
  {
    "Name": "Unplugged USB device drivers",
    "RuleType": "KeepMatching",
    "Filter": {
      "HardwareId": ["USB\\VID_*"],
      "Association": "DisconnectedInstalled"
    }
  }
]
'@

#section Helpers
function Get-MvpNote {
    param($Object, [string] $Name)
    if ($null -eq $Object) { return $null }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $null }
    return $prop.Value
}

function Get-MvpField {
    param($Row, [string[]] $Names)
    foreach ($name in @($Names)) {
        $value = Get-MvpNote -Object $Row -Name $name
        if (-not [string]::IsNullOrWhiteSpace([string]$value)) {
            return [string]$value
        }
    }
    return ''
}

function Get-MvpPatternList {
    param($Value)
    if ($null -eq $Value) { return ,[string[]]@() }
    if ($Value -is [string]) {
        if ([string]::IsNullOrWhiteSpace($Value)) { return ,[string[]]@() }
        return ,[string[]]@($Value)
    }
    $patterns = New-Object System.Collections.Generic.List[string]
    foreach ($item in $Value) {
        if (-not [string]::IsNullOrWhiteSpace([string]$item)) {
            [void]$patterns.Add([string]$item)
        }
    }
    return ,$patterns.ToArray()
}

function Test-MvpLikeAny {
    param([string[]] $Values, [string[]] $Patterns)
    if ($null -eq $Patterns -or $Patterns.Count -eq 0) { return $true }
    foreach ($pattern in $Patterns) {
        foreach ($value in $Values) {
            if ([string]::IsNullOrWhiteSpace($value)) { continue }
            if ($value -like $pattern) { return $true }
        }
    }
    return $false
}

function ConvertFrom-MvpCsv {
    param([string[]] $Lines)
    $clean = New-Object System.Collections.Generic.List[string]
    foreach ($line in $Lines) {
        if (-not [string]::IsNullOrWhiteSpace($line)) { [void]$clean.Add($line) }
    }
    if ($clean.Count -lt 2) { return ,[object[]]@() }

    $splitPattern = ',(?=(?:[^"]*"[^"]*")*[^"]*$)'
    $headers = New-Object System.Collections.Generic.List[string]
    foreach ($header in ($clean[0] -split $splitPattern)) {
        [void]$headers.Add($header.Trim().Trim('"'))
    }
    $rows = New-Object System.Collections.Generic.List[object]
    for ($rowIndex = 1; $rowIndex -lt $clean.Count; $rowIndex++) {
        $cols = New-Object System.Collections.Generic.List[string]
        foreach ($col in ($clean[$rowIndex] -split $splitPattern)) {
            [void]$cols.Add($col.Trim().Trim('"'))
        }
        $obj = [ordered]@{}
        for ($colIndex = 0; $colIndex -lt $headers.Count; $colIndex++) {
            $key = $headers[$colIndex]
            $val = ''
            if ($colIndex -lt $cols.Count) { $val = $cols[$colIndex] }
            $existing = ''
            if ($obj.Contains($key)) { $existing = [string]$obj[$key] }
            if ([string]::IsNullOrWhiteSpace($existing)) { $obj[$key] = $val }
        }
        [void]$rows.Add([pscustomobject]$obj)
    }
    return ,$rows.ToArray()
}

function Test-MvpPackageMatches {
    param($Package, $Filter)
    if ($null -eq $Filter) { return $true }

    $providerPatterns = Get-MvpPatternList -Value (Get-MvpNote -Object $Filter -Name 'Provider')
    if ($providerPatterns.Count -gt 0) {
        $providerValues = @([string]$Package.Provider, [string]$Package.Signer)
        if (-not (Test-MvpLikeAny -Values $providerValues -Patterns $providerPatterns)) { return $false }
    }

    $classPatterns = Get-MvpPatternList -Value (Get-MvpNote -Object $Filter -Name 'DriverClass')
    if ($classPatterns.Count -gt 0) {
        if (-not (Test-MvpLikeAny -Values @([string]$Package.DriverClass) -Patterns $classPatterns)) { return $false }
    }

    $publishedPatterns = Get-MvpPatternList -Value (Get-MvpNote -Object $Filter -Name 'PublishedName')
    if ($publishedPatterns.Count -gt 0) {
        if (-not (Test-MvpLikeAny -Values @([string]$Package.PublishedName) -Patterns $publishedPatterns)) { return $false }
    }

    $originalPatterns = Get-MvpPatternList -Value (Get-MvpNote -Object $Filter -Name 'OriginalName')
    if ($originalPatterns.Count -gt 0) {
        if (-not (Test-MvpLikeAny -Values @([string]$Package.OriginalName) -Patterns $originalPatterns)) { return $false }
    }

    $hardwarePatterns = Get-MvpPatternList -Value (Get-MvpNote -Object $Filter -Name 'HardwareId')
    if ($hardwarePatterns.Count -gt 0) {
        if (-not (Test-MvpLikeAny -Values @($Package.HardwareIds) -Patterns $hardwarePatterns)) { return $false }
    }

    $association = [string](Get-MvpNote -Object $Filter -Name 'Association')
    if (-not [string]::IsNullOrWhiteSpace($association) -and $association -ne 'Any') {
        $actual = [string]$Package.DeviceAssociation
        if ($association -eq 'InUseOnly') { $association = 'Connected' }
        if ($association -eq 'UnusedOnly') {
            if ($actual -eq 'Connected') { return $false }
        }
        elseif ($actual -ne $association) { return $false }
    }

    return $true
}

function Test-MvpIsNewer {
    param($Left, $Right)
    $leftVersion = $null
    $rightVersion = $null
    [void][version]::TryParse([string]$Left.DriverVersion, [ref]$leftVersion)
    [void][version]::TryParse([string]$Right.DriverVersion, [ref]$rightVersion)
    if ($leftVersion -and $rightVersion) {
        if ($leftVersion -gt $rightVersion) { return $true }
        if ($leftVersion -lt $rightVersion) { return $false }
    }
    elseif ($leftVersion -and -not $rightVersion) { return $true }
    elseif ($rightVersion -and -not $leftVersion) { return $false }

    $leftDate = [datetime]::MinValue
    $rightDate = [datetime]::MinValue
    $leftDateOk = [datetime]::TryParse([string]$Left.DriverDate, [ref]$leftDate)
    $rightDateOk = [datetime]::TryParse([string]$Right.DriverDate, [ref]$rightDate)
    if ($leftDateOk -and $rightDateOk) {
        $dateCmp = [datetime]::Compare($leftDate, $rightDate)
        if ($dateCmp -gt 0) { return $true }
        if ($dateCmp -lt 0) { return $false }
    }
    elseif ($leftDateOk -and -not $rightDateOk) { return $true }
    elseif ($rightDateOk -and -not $leftDateOk) { return $false }

    return ([string]::Compare([string]$Left.PublishedName, [string]$Right.PublishedName, [StringComparison]::OrdinalIgnoreCase) -gt 0)
}

function Invoke-MvpPnPUtil {
    param([Parameter(Mandatory)] [string[]] $ArgumentList)

    $joined = (@($ArgumentList) -join ' ')
    if ($env:DSM_MVP_STUB_PNPUTIL -eq '1') {
        $stubLog = $env:DSM_MVP_STUB_LOG
        if (-not [string]::IsNullOrWhiteSpace($stubLog)) {
            $utf8 = New-Object System.Text.UTF8Encoding $false
            [System.IO.File]::AppendAllText($stubLog, ($joined.ToLowerInvariant() + "`n"), $utf8)
        }
        $lookup = $joined.ToLowerInvariant()
        $fixtureName = $null
        if ($lookup -match 'enum-drivers') { $fixtureName = 'pnputil-enum-drivers.csv' }
        elseif ($lookup -match 'enum-devices' -and $lookup -match 'connected') { $fixtureName = 'pnputil-enum-devices-connected.csv' }
        elseif ($lookup -match 'enum-devices') { $fixtureName = 'pnputil-enum-devices-all.csv' }
        elseif ($lookup -match 'export-driver' -or $lookup -match 'delete-driver') { return @('OK') }
        else { throw "MVP stub cannot run: $joined" }
        $fixtureRoot = $env:DSM_MVP_FIXTURE_ROOT
        if ([string]::IsNullOrWhiteSpace($fixtureRoot)) { throw 'DSM_MVP_FIXTURE_ROOT is required when the pnputil stub is on.' }
        $fixturePath = Join-Path $fixtureRoot $fixtureName
        if (-not (Test-Path -LiteralPath $fixturePath)) { throw "MVP stub fixture missing: $fixturePath" }
        return @(Get-Content -LiteralPath $fixturePath)
    }

    $exe = Join-Path $env:WINDIR 'System32\pnputil.exe'
    if (-not (Test-Path -LiteralPath $exe)) { throw "pnputil not found at $exe" }

    $outputFile = $null
    $argsForProcess = New-Object System.Collections.Generic.List[string]
    foreach ($arg in @($ArgumentList)) { [void]$argsForProcess.Add([string]$arg) }
    if ($joined -match '/format' -and $joined -match 'csv') {
        $outputFile = [System.IO.Path]::GetTempFileName()
        [void]$argsForProcess.Add('/output-file')
        [void]$argsForProcess.Add($outputFile)
    }

    $quoted = New-Object System.Collections.Generic.List[string]
    foreach ($arg in $argsForProcess) {
        if ($arg -notmatch '[\s"]') {
            [void]$quoted.Add($arg)
            continue
        }
        $escaped = $arg -replace '(\\*)"', '$1$1\"'
        $escaped = $escaped -replace '(\\+)$', '$1$1'
        [void]$quoted.Add('"' + $escaped + '"')
    }

    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $exe
        $psi.Arguments = ($quoted -join ' ')
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
        $stderrTask = $proc.StandardError.ReadToEndAsync()
        if (-not $proc.WaitForExit(600000)) {
            try { $proc.Kill() } catch { Write-Verbose $_.Exception.Message }
            throw 'pnputil timed out after 600 seconds.'
        }
        [void]$stdoutTask.Wait()
        [void]$stderrTask.Wait()
        if ($proc.ExitCode -ne 0) {
            $errorText = $stderrTask.Result
            if ([string]::IsNullOrWhiteSpace($errorText)) { $errorText = $stdoutTask.Result }
            if ([string]::IsNullOrWhiteSpace($errorText)) { $errorText = 'no stdout/stderr output' }
            throw "pnputil failed (exit $($proc.ExitCode)): $($errorText.Trim())"
        }
        if ($outputFile -and (Test-Path -LiteralPath $outputFile)) {
            return @(Get-Content -LiteralPath $outputFile -Encoding Unicode)
        }
        return @(($stdoutTask.Result -split "`r?`n"))
    }
    finally {
        if ($outputFile) {
            Remove-Item -LiteralPath $outputFile -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-MvpDeviceAssociation {
    $allLines = @(Invoke-MvpPnPUtil -ArgumentList @('/enum-devices', '/drivers', '/format', 'csv'))
    $connectedLines = @(Invoke-MvpPnPUtil -ArgumentList @('/enum-devices', '/connected', '/drivers', '/format', 'csv'))
    $allDevices = ConvertFrom-MvpCsv -Lines $allLines
    $connectedDevices = ConvertFrom-MvpCsv -Lines $connectedLines

    $connectedIds = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($device in $connectedDevices) {
        $instanceId = Get-MvpField -Row $device -Names @('InstanceId', 'Instance ID', 'Device Instance ID', 'Device Instance Id')
        if (-not [string]::IsNullOrWhiteSpace($instanceId)) { [void]$connectedIds.Add($instanceId) }
    }

    $byPublished = @{}
    foreach ($device in $allDevices) {
        $driverName = Get-MvpField -Row $device -Names @('DriverName', 'Driver Name', 'Published Name', 'PublishedName')
        if ($driverName -notmatch '^oem\d+\.inf$') { continue }
        $instanceId = Get-MvpField -Row $device -Names @('InstanceId', 'Instance ID', 'Device Instance ID', 'Device Instance Id')
        $hardwareIds = New-Object System.Collections.Generic.List[string]
        if (-not [string]::IsNullOrWhiteSpace($instanceId)) {
            [void]$hardwareIds.Add($instanceId)
            $parts = $instanceId -split '\\'
            if (@($parts).Count -ge 2) {
                $root = $parts[0] + '\' + $parts[1]
                if ($root -ne $instanceId) { [void]$hardwareIds.Add($root) }
            }
        }
        if (-not $byPublished.ContainsKey($driverName)) {
            $byPublished[$driverName] = [pscustomobject]@{
                HardwareIds                      = (New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase))
                ConnectedDeviceCount             = 0
                DisconnectedInstalledDeviceCount = 0
            }
        }
        $entry = $byPublished[$driverName]
        foreach ($hardwareId in $hardwareIds) { [void]$entry.HardwareIds.Add($hardwareId) }
        if (-not [string]::IsNullOrWhiteSpace($instanceId) -and $connectedIds.Contains($instanceId)) {
            $entry.ConnectedDeviceCount++
        }
        else {
            $entry.DisconnectedInstalledDeviceCount++
        }
    }

    $result = @{}
    foreach ($key in @($byPublished.Keys)) {
        $entry = $byPublished[$key]
        $association = 'NeverAssociated'
        if ($entry.ConnectedDeviceCount -gt 0) { $association = 'Connected' }
        elseif ($entry.DisconnectedInstalledDeviceCount -gt 0) { $association = 'DisconnectedInstalled' }
        $result[$key] = [pscustomobject]@{
            HardwareIds                      = @($entry.HardwareIds)
            ConnectedDeviceCount             = $entry.ConnectedDeviceCount
            DisconnectedInstalledDeviceCount = $entry.DisconnectedInstalledDeviceCount
            DeviceAssociation                = $association
        }
    }
    return $result
}

function Add-MvpPreserve {
    param($Package, [string] $Reason)
    $Package.Preserved = $true
    $reasons = New-Object System.Collections.Generic.List[string]
    foreach ($existing in @($Package.PreserveReasons)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$existing)) { [void]$reasons.Add([string]$existing) }
    }
    if (-not $reasons.Contains($Reason)) { [void]$reasons.Add($Reason) }
    $Package.PreserveReasons = @($reasons.ToArray())
}

try {
    #section Inventory
    $driverLines = @(Invoke-MvpPnPUtil -ArgumentList @('/enum-drivers', '/format', 'csv'))
    $driverRows = ConvertFrom-MvpCsv -Lines $driverLines
    $grouped = @{}
    foreach ($row in $driverRows) {
        $published = Get-MvpField -Row $row -Names @('DriverName', 'Published Name', 'PublishedName', 'Driver Name')
        if ($published -notmatch '^oem\d+\.inf$') { continue }
        if (-not $grouped.ContainsKey($published)) {
            $grouped[$published] = [pscustomobject]@{
                PublishedName    = $published
                OriginalName     = ''
                Provider         = ''
                Signer           = ''
                DriverClass      = ''
                DriverVersion    = ''
                DriverDate       = ''
                HardwareIds      = @()
                DeviceAssociation = 'NeverAssociated'
                ConnectedDeviceCount = 0
                DisconnectedInstalledDeviceCount = 0
                Preserved        = $false
                PreserveReasons  = @()
            }
        }
        $pkg = $grouped[$published]
        foreach ($pair in @(
                @{ Prop = 'OriginalName'; Names = @('OriginalName', 'Original Name') }
                @{ Prop = 'Provider'; Names = @('ProviderName', 'Provider Name') }
                @{ Prop = 'Signer'; Names = @('SignerName', 'Signer Name') }
                @{ Prop = 'DriverClass'; Names = @('ClassName', 'Class Name') }
                @{ Prop = 'DriverVersion'; Names = @('DriverVersion', 'Driver Version') }
                @{ Prop = 'DriverDate'; Names = @('DriverDate', 'Driver Date') }
            )) {
            $current = [string](Get-MvpNote -Object $pkg -Name $pair.Prop)
            if (-not [string]::IsNullOrWhiteSpace($current)) { continue }
            $incoming = Get-MvpField -Row $row -Names $pair.Names
            if (-not [string]::IsNullOrWhiteSpace($incoming)) {
                $pkg.($pair.Prop) = $incoming
            }
        }
    }
    $packages = New-Object System.Collections.Generic.List[object]
    foreach ($groupedKey in $grouped.Keys) {
        [void]$packages.Add($grouped[$groupedKey])
    }

    #section Association
    $association = Get-MvpDeviceAssociation
    foreach ($pkg in $packages) {
        $match = $null
        if ($association.ContainsKey($pkg.PublishedName)) { $match = $association[$pkg.PublishedName] }
        if ($null -eq $match) { continue }
        $pkg.HardwareIds = @($match.HardwareIds)
        $pkg.ConnectedDeviceCount = $match.ConnectedDeviceCount
        $pkg.DisconnectedInstalledDeviceCount = $match.DisconnectedInstalledDeviceCount
        $pkg.DeviceAssociation = $match.DeviceAssociation
    }

    #section Preserve
    $rulesText = $MvpPreserveRulesJson
    if (-not [string]::IsNullOrWhiteSpace([string]$MvpPreserveRulesPath)) {
        if (-not (Test-Path -LiteralPath $MvpPreserveRulesPath)) {
            throw "Preserve rules file not found: $MvpPreserveRulesPath"
        }
        $rulesText = [System.IO.File]::ReadAllText($MvpPreserveRulesPath)
    }
    $parsedRules = $rulesText | ConvertFrom-Json
    foreach ($rule in $parsedRules) {
        $ruleType = [string](Get-MvpNote -Object $rule -Name 'RuleType')
        $ruleFilter = Get-MvpNote -Object $rule -Name 'Filter'
        if ($ruleType -eq 'KeepPublishedName') {
            $names = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            foreach ($name in Get-MvpPatternList -Value (Get-MvpNote -Object $rule -Name 'PublishedName')) {
                [void]$names.Add($name)
            }
            foreach ($pkg in $packages) {
                if ($names.Contains([string]$pkg.PublishedName)) { Add-MvpPreserve -Package $pkg -Reason 'KeepPublishedName' }
            }
        }
        elseif ($ruleType -eq 'KeepMatching') {
            if ($null -eq $ruleFilter) { continue }
            foreach ($pkg in $packages) {
                if (Test-MvpPackageMatches -Package $pkg -Filter $ruleFilter) {
                    Add-MvpPreserve -Package $pkg -Reason 'KeepMatching'
                }
            }
        }
        elseif ($ruleType -eq 'KeepVersion') {
            $targetVersion = [string](Get-MvpNote -Object $rule -Name 'DriverVersion')
            if ([string]::IsNullOrWhiteSpace($targetVersion)) { continue }
            foreach ($pkg in $packages) {
                if ($null -ne $ruleFilter -and -not (Test-MvpPackageMatches -Package $pkg -Filter $ruleFilter)) { continue }
                if ([string]$pkg.DriverVersion -like $targetVersion) { Add-MvpPreserve -Package $pkg -Reason 'KeepVersion' }
            }
        }
        elseif ($ruleType -eq 'KeepLatest') {
            $families = @{}
            foreach ($pkg in $packages) {
                $familyKey = 'PO|' + [string]$pkg.Provider + '|' + [string]$pkg.OriginalName
                if (-not $families.ContainsKey($familyKey)) {
                    $families[$familyKey] = (New-Object System.Collections.Generic.List[object])
                }
                [void]$families[$familyKey].Add($pkg)
            }
            foreach ($familyKey in $families.Keys) {
                $memberList = $families[$familyKey]
                $inScope = $false
                $latest = $null
                foreach ($member in $memberList) {
                    if (Test-MvpPackageMatches -Package $member -Filter $ruleFilter) { $inScope = $true }
                    if ($null -eq $latest) { $latest = $member }
                    elseif (Test-MvpIsNewer -Left $member -Right $latest) { $latest = $member }
                }
                if (-not $inScope -or $null -eq $latest) { continue }
                Add-MvpPreserve -Package $latest -Reason 'KeepLatest'
            }
        }
        else {
            throw "Unknown preserve RuleType: $ruleType"
        }
    }

    $scopeFilter = [pscustomobject]@{
        DriverClass   = @($MvpFilterDriverClass)
        Provider      = @($MvpFilterProvider)
        PublishedName = @($MvpFilterPublishedName)
        HardwareId    = @($MvpFilterHardwareId)
        OriginalName  = @($MvpFilterOriginalName)
        Association   = $MvpFilterAssociation
    }
    $allow = $null
    if (@($MvpIncludePublishedName).Count -gt 0) {
        $allow = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($name in @($MvpIncludePublishedName)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$name)) { [void]$allow.Add([string]$name) }
        }
    }

    $deletable = New-Object System.Collections.Generic.List[object]
    $connectedCount = 0
    $disconnectedCount = 0
    $neverCount = 0
    $preservedCount = 0
    foreach ($pkg in $packages) {
        if ($pkg.DeviceAssociation -eq 'Connected') { $connectedCount++ }
        elseif ($pkg.DeviceAssociation -eq 'DisconnectedInstalled') { $disconnectedCount++ }
        elseif ($pkg.DeviceAssociation -eq 'NeverAssociated') { $neverCount++ }
        if ($pkg.Preserved) { $preservedCount++ }
        if ($null -ne $allow -and -not $allow.Contains([string]$pkg.PublishedName)) { continue }
        if (-not (Test-MvpPackageMatches -Package $pkg -Filter $scopeFilter)) { continue }
        if ($pkg.DeviceAssociation -ne 'NeverAssociated') { continue }
        if ($pkg.Preserved) { continue }
        [void]$deletable.Add($pkg)
    }

    #section Elevation
    if ($MvpRequireElevation -and $env:DSM_MVP_ASSUME_ELEVATED -ne '1') {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal $identity
        $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            Write-Error 'Remediation requires administrator / SYSTEM context.'
            exit 2
        }
    }

    #section Export and delete
    $mvpBase = $env:DSM_MVP_STATE_ROOT
    if ([string]::IsNullOrWhiteSpace($mvpBase)) {
        $mvpBase = Join-Path $env:ProgramData 'DriverStoreManager'
    }
    $stamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
    $backupRoot = Join-Path (Join-Path $mvpBase 'backups') $stamp
    $reportRoot = Join-Path (Join-Path $mvpBase 'reports') 'intune-mvp-remediation'
    foreach ($dir in @($backupRoot, $reportRoot)) {
        if (-not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }

    $results = New-Object System.Collections.Generic.List[object]
    $deletedCount = 0
    $failedCount = 0
    foreach ($pkg in $deletable) {
        if ($deletedCount -ge $MvpMaxDeletes) { break }
        $fresh = Get-MvpDeviceAssociation
        $stillOrphan = $false
        if (-not $fresh.ContainsKey([string]$pkg.PublishedName)) {
            $stillOrphan = $true
        }
        else {
            $freshRow = $fresh[[string]$pkg.PublishedName]
            if ([string]$freshRow.DeviceAssociation -eq 'NeverAssociated') { $stillOrphan = $true }
        }
        if (-not $stillOrphan) {
            [void]$results.Add([pscustomobject]@{
                    PublishedName = [string]$pkg.PublishedName
                    Action        = 'SkippedNotOrphan'
                })
            continue
        }

        $exportDir = Join-Path $backupRoot ([string]$pkg.PublishedName)
        if (-not (Test-Path -LiteralPath $exportDir)) {
            New-Item -ItemType Directory -Path $exportDir -Force | Out-Null
        }
        try {
            Invoke-MvpPnPUtil -ArgumentList @('/export-driver', [string]$pkg.PublishedName, $exportDir) | Out-Null
        }
        catch {
            $failedCount++
            [void]$results.Add([pscustomobject]@{
                    PublishedName = [string]$pkg.PublishedName
                    Action        = 'ExportFailed'
                    Error         = [string]$_.Exception.Message
                })
            continue
        }
        try {
            Invoke-MvpPnPUtil -ArgumentList @('/delete-driver', [string]$pkg.PublishedName) | Out-Null
        }
        catch {
            $failedCount++
            [void]$results.Add([pscustomobject]@{
                    PublishedName = [string]$pkg.PublishedName
                    Action        = 'DeleteFailed'
                    Error         = [string]$_.Exception.Message
                })
            continue
        }
        $deletedCount++
        [void]$results.Add([pscustomobject]@{
                PublishedName = [string]$pkg.PublishedName
                Action        = 'Deleted'
                BackupPath    = $exportDir
            })
    }

    #section Summary
    $summaryPath = Join-Path $reportRoot ("remediation-summary_{0}.json" -f $stamp)
    $summary = [pscustomobject]@{
        ScriptType                 = 'IntuneMvpRemediation'
        GeneratedAt                = ([DateTimeOffset]::Now.ToString('o'))
        ComputerName               = [string]$env:COMPUTERNAME
        TotalOemPackages           = $packages.Count
        ConnectedCount             = $connectedCount
        DisconnectedInstalledCount = $disconnectedCount
        NeverAssociatedCount       = $neverCount
        PreservedCount             = $preservedCount
        DeletableCandidateCount    = $deletable.Count
        DeletedCount               = $deletedCount
        ExportOrDeleteFailedCount  = $failedCount
        BackupRoot                 = $backupRoot
        Results                    = $results.ToArray()
    }
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($summaryPath, ($summary | ConvertTo-Json -Depth 5), $utf8NoBom)
    Write-Host ("DSM-MVP-REMEDIATE deleted={0} failed={1} file={2}" -f $deletedCount, $failedCount, $summaryPath)
    if ($failedCount -gt 0) { exit 2 }
    exit 0
}
catch {
    [Console]::Error.WriteLine($_.Exception.ToString())
    [Console]::Error.WriteLine($_.ScriptStackTrace)
    exit 2
}
