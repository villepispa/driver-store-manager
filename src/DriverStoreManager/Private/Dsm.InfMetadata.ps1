$script:DsmInfMetadataCache = @{}
$script:DsmFileRepositoryFileIndex = $null
$script:DsmFileRepositoryRootOverride = $null

function Get-DsmFileRepositoryRoot {
    if ($script:DsmFileRepositoryRootOverride) {
        return $script:DsmFileRepositoryRootOverride
    }

    return Join-Path $env:WINDIR 'System32\DriverStore\FileRepository'
}

function Initialize-DsmFileRepositoryFileIndex {
    if ($null -ne $script:DsmFileRepositoryFileIndex) {
        return $script:DsmFileRepositoryFileIndex
    }

    $index = @{}
    $repo = Get-DsmFileRepositoryRoot
    if (-not (Test-Path -LiteralPath $repo)) {
        $script:DsmFileRepositoryFileIndex = $index
        return $index
    }

    foreach ($file in Get-ChildItem -LiteralPath $repo -Recurse -File -ErrorAction SilentlyContinue) {
        $leaf = $file.Name
        if (-not $index.ContainsKey($leaf)) {
            $index[$leaf] = [System.Collections.Generic.List[string]]::new()
        }
        $index[$leaf].Add($file.FullName) | Out-Null
    }

    $script:DsmFileRepositoryFileIndex = $index
    return $index
}

function ConvertTo-DsmNormalizedDriverVer {
    param(
        [string] $DriverVer
    )

    if ([string]::IsNullOrWhiteSpace($DriverVer)) {
        return $null
    }

    $normalized = $DriverVer.Trim().Trim('"')
    $normalized = Remove-DsmInfInlineComment -Raw $normalized
    $normalized = $normalized.TrimEnd(';').Trim()
    $normalized = $normalized -replace '\s+', ''
    if ($normalized -match '^(\d{1,2}/\d{1,2}/\d{4}),(.+)$') {
        return '{0} {1}' -f $Matches[1], $Matches[2]
    }

    return $normalized
}

function Remove-DsmInfInlineComment {
    <#
    .SYNOPSIS
        Removes INF inline comments while preserving semicolons inside quoted values.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Raw
    )

    if ([string]::IsNullOrEmpty($Raw)) {
        return $Raw
    }

    $builder = [System.Text.StringBuilder]::new()
    $inQuotes = $false
    for ($i = 0; $i -lt $Raw.Length; $i++) {
        $ch = $Raw[$i]
        if ($ch -eq '"') {
            $inQuotes = -not $inQuotes
            [void]$builder.Append($ch)
            continue
        }

        if (-not $inQuotes -and $ch -eq ';') {
            break
        }

        [void]$builder.Append($ch)
    }

    return $builder.ToString().Trim()
}

function Test-DsmDriverVerEquivalent {
    param(
        [string] $Left,
        [string] $Right
    )

    $a = ConvertTo-DsmNormalizedDriverVer -DriverVer $Left
    $b = ConvertTo-DsmNormalizedDriverVer -DriverVer $Right
    if (-not $a -or -not $b) {
        return $false
    }

    return ($a -eq $b)
}

function Get-DsmInfParsedValue {
    <#
    .SYNOPSIS
        Parses an INF value (quoted segments, inline comments, multi-part graphics strings).
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Raw
    )

    if ([string]::IsNullOrWhiteSpace($Raw)) {
        return $null
    }

    $s = Remove-DsmInfInlineComment -Raw $Raw

    if ($s.StartsWith('"')) {
        $parts = [regex]::Matches($s, '"([^"]*)"') |
            ForEach-Object { $_.Groups[1].Value.Trim() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        if (@($parts).Count -gt 0) {
            return (($parts) -join ' ').Trim()
        }
    }

    return $s.Trim('"').Trim()
}

function Get-DsmInfStringsTable {
    param(
        [Parameter(Mandatory)]
        [string] $Text
    )

    $table = @{}
    $inStrings = $false

    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -match '^\s*\[([^\]]+)\]\s*$') {
            $inStrings = ($Matches[1] -ieq 'Strings')
            continue
        }

        if (-not $inStrings) { continue }
        if ($line -match '^\s*;') { continue }

        $eq = $line.IndexOf('=')
        if ($eq -lt 1) { continue }

        $key = $line.Substring(0, $eq).Trim()
        $value = Get-DsmInfParsedValue -Raw $line.Substring($eq + 1)
        if ($key -and $value) {
            $table[$key] = $value
        }
    }

    return $table
}

function Resolve-DsmInfStringToken {
    param(
        [string] $Value,
        [hashtable] $StringsTable,

        [int] $MaxDepth = 8,

        [System.Collections.Generic.HashSet[string]] $Seen
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }

    if (-not $Seen) {
        $Seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    }

    $token = $Value.Trim().Trim('"').Trim()
    if ($token -notmatch '^%(.+)%$') {
        return $token
    }

    if ($MaxDepth -le 0) {
        return $null
    }

    $key = $Matches[1]
    if ($Seen.Contains($key)) {
        return $null
    }

    [void]$Seen.Add($key)
    if (-not $StringsTable.ContainsKey($key)) {
        return $null
    }

    return Resolve-DsmInfStringToken -Value $StringsTable[$key] -StringsTable $StringsTable `
        -MaxDepth ($MaxDepth - 1) -Seen $Seen
}

function Get-DsmInfOemVerifyMark {
    param(
        [Parameter(Mandatory)]
        [string] $Text
    )

    if ($Text -match '(?im)^\s*VerifyMark\s*=\s*"?([^"\r\n;]+)"?\s*') {
        return $Matches[1].Trim()
    }

    return $null
}

function Get-DsmInfStringKeysByPattern {
    param(
        [hashtable] $StringsTable,
        [string[]] $SuffixPatterns,
        [string[]] $ExactKeys = @()
    )

    $results = [System.Collections.Generic.List[string]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    foreach ($key in $ExactKeys) {
        if ($StringsTable.ContainsKey($key) -and $StringsTable[$key]) {
            if ($seen.Add($StringsTable[$key])) {
                $results.Add($StringsTable[$key]) | Out-Null
            }
        }
    }

    foreach ($entry in $StringsTable.GetEnumerator()) {
        $key = [string]$entry.Key
        $value = [string]$entry.Value
        if ([string]::IsNullOrWhiteSpace($value)) { continue }

        $matched = $false
        foreach ($pattern in $SuffixPatterns) {
            if ($key -match $pattern) {
                $matched = $true
                break
            }
        }

        if (-not $matched) { continue }
        if ($seen.Add($value)) {
            $results.Add($value) | Out-Null
        }
    }

    return @($results.ToArray())
}

function Test-DsmInfSubstantiveLabel {
    <#
    .SYNOPSIS
        True when a label is useful for operators (not a bare vendor token).
    #>
    [CmdletBinding()]
    param(
        [string] $Label
    )

    if ([string]::IsNullOrWhiteSpace($Label)) {
        return $false
    }

    $trimmed = $Label.Trim()
    if ($trimmed.Length -lt 4) {
        return $false
    }

    if ($trimmed -match '(?i)^(intel|amd|ati|hp|microsoft|realtek|synaptics|foxlink|sunplusit|intel corporation|advanced micro devices|hp inc\.?)$') {
        return $false
    }

    if ($trimmed -match '(?i)^(intel|amd|hp|microsoft|realtek|synaptics)(\s+corporation|\s+inc\.?|\s+l\.?p\.?)?$') {
        return $false
    }

    return $true
}

function Test-DsmInfModelInstallLine {
    param(
        [string] $Line
    )

    if ([string]::IsNullOrWhiteSpace($Line)) {
        return $false
    }

    $eq = $Line.IndexOf('=')
    if ($eq -lt 0) {
        return $false
    }

    $rhs = $Line.Substring($eq + 1).Trim()
    if ($rhs -match '(?i)\\') {
        return $true
    }

    if ($rhs -match '(?i)^(needs_|no_drv|pci_drv)') {
        return $true
    }

    return $false
}

function Get-DsmInfQuotedModelLabels {
    param(
        [Parameter(Mandatory)]
        [string] $Text
    )

    $results = [System.Collections.Generic.List[string]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -match '^\s*;') { continue }
        if ($line -notmatch '^\s*"([^"]+)"\s*=') { continue }
        if (-not (Test-DsmInfModelInstallLine -Line $line)) { continue }

        $label = $Matches[1].Trim()
        if (-not (Test-DsmInfSubstantiveLabel -Label $label)) { continue }
        if ($seen.Add($label)) {
            $results.Add($label) | Out-Null
        }
    }

    return @($results.ToArray())
}

function Get-DsmInfStringsDescriptionLabels {
    param(
        [Parameter(Mandatory)]
        [hashtable] $StringsTable
    )

    $keyPatterns = @(
        '(?i)\.DisplayName$'
        '(?i)^DisplayName$'
        '(?i)ExtensionDesc$'
        '(?i)DispName'
        '(?i)^DeviceName$'
        '(?i)\.DeviceDesc$'
        '(?i)_DeviceDesc\d*$'
        '(?i)DeviceDesc\d*$'
        '(?i)_Desc\d*$'
        '(?i)_Desc$'
        '(?i)Desc$'
    )

    $exactKeys = @(
        'SERVICE_DESC'
        'SERVICE_NAME'
        'PROVIDER_NAME'
        'COMPANY_NAME'
    )

    $values = Get-DsmInfStringKeysByPattern -StringsTable $StringsTable `
        -ExactKeys $exactKeys `
        -SuffixPatterns $keyPatterns

    $filtered = [System.Collections.Generic.List[string]]::new()
    foreach ($value in @($values)) {
        if (Test-DsmInfSubstantiveLabel -Label $value) {
            $filtered.Add($value) | Out-Null
        }
    }

    return @($filtered.ToArray())
}

function Get-DsmInfModelDisplayTokens {
    param(
        [Parameter(Mandatory)]
        [string] $Text,

        [Parameter(Mandatory)]
        [hashtable] $StringsTable
    )

    $tokens = [System.Collections.Generic.List[string]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -match '^\s*;') { continue }
        if ($line -notmatch '^\s*%([^%]+)%\s*=') { continue }
        if (-not (Test-DsmInfModelInstallLine -Line $line)) { continue }

        $key = $Matches[1].Trim()
        if ($key -match '(?i)svcdesc|classdesc|providername$|^provider$|^intel$|^amd$|^ati$|^mfg$|^manufacturername$') {
            continue
        }

        if ($key -notmatch '(?i)devicedesc|\.desc$|_desc\d*$|_desc$|\.displayname$|displayname$|extensiondesc$|dispname|devicename') {
            continue
        }

        $resolved = Resolve-DsmInfStringToken -Value "%$key%" -StringsTable $StringsTable
        if (-not $resolved) { continue }
        if ($seen.Add($resolved)) {
            $tokens.Add($resolved) | Out-Null
        }
    }

    if ($tokens.Count -eq 0) {
        $fromStrings = Get-DsmInfStringKeysByPattern -StringsTable $StringsTable `
            -SuffixPatterns @(
                '(?i)\.DeviceDesc$'
                '(?i)_DeviceDesc\d*$'
                '(?i)DeviceDesc\d*$'
                '(?i)_Desc\d*$'
                '(?i)_Desc$'
                '(?i)\.DisplayName$'
                '(?i)^DisplayName$'
                '(?i)ExtensionDesc$'
                '(?i)DispName'
                '(?i)^DeviceName$'
                '(?i)Desc$'
            )
        foreach ($value in $fromStrings) {
            if ($seen.Add($value)) {
                $tokens.Add($value) | Out-Null
            }
        }
    }

    return $tokens
}

function Get-DsmInfFirstModelStringLabel {
    param(
        [Parameter(Mandatory)]
        [string] $Text,

        [Parameter(Mandatory)]
        [hashtable] $StringsTable
    )

    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -match '^\s*;') { continue }
        if ($line -notmatch '^\s*%([^%]+)%\s*=') { continue }
        if (-not (Test-DsmInfModelInstallLine -Line $line)) { continue }

        $key = $Matches[1].Trim()
        if (-not $StringsTable.ContainsKey($key)) { continue }

        $value = $StringsTable[$key]
        if ([string]::IsNullOrWhiteSpace($value)) { continue }
        if (-not (Test-DsmInfSubstantiveLabel -Label $value)) { continue }

        if ($value.Length -ge 6) {
            return $value
        }
    }

    return $null
}

function Get-DsmInfDiskLabelFromStrings {
    param(
        [Parameter(Mandatory)]
        [hashtable] $StringsTable
    )

    $exactKeys = @(
        'DiskId'
        'DiskName'
        'DISK_NAME'
        'Disk_Name'
        'Disk'
        'Location'
        'LOCATION'
        'InstallDisk'
        'InstallationDisk'
        'MediaName'
        'InstallationMedia'
        'SOURCEDISK1'
        'SourceDisk1'
    )

    foreach ($key in $exactKeys) {
        if ($StringsTable.ContainsKey($key) -and $StringsTable[$key]) {
            return $StringsTable[$key]
        }
    }

    return $null
}

function Get-DsmInfDiskLabelFromSourceDisks {
    param(
        [Parameter(Mandatory)]
        [string] $Text,

        [Parameter(Mandatory)]
        [hashtable] $StringsTable
    )

    if ($Text -notmatch '(?is)\[SourceDisksNames[^\]]*\]\s*(.+?)(?=\n\[|\z)') {
        return $null
    }

    foreach ($line in ($Matches[1] -split "`r?`n")) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -match '^\s*;') { continue }
        if ($line -match '^\s*\d+\s*=\s*(.+?)\s*$') {
            $raw = $Matches[1].Trim().TrimEnd(',')
            $first = ($raw -split ',')[0].Trim()
            $resolved = Resolve-DsmInfStringToken -Value $first -StringsTable $StringsTable
            if ($resolved) {
                return $resolved
            }
        }
    }

    return $null
}

function Get-DsmInfFriendlyLabel {
    <#
    .SYNOPSIS
        Resolves the best operator-facing label from an INF (device desc, disk, OEM mark, etc.).
  .OUTPUTS
        PSCustomObject with Label and LabelSource.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Text
    )

    $strings = Get-DsmInfStringsTable -Text $Text

    $deviceDesc = @(Get-DsmInfModelDisplayTokens -Text $Text -StringsTable $strings)
    if ($deviceDesc.Count -gt 0) {
        return [pscustomobject]@{
            Label       = [string]$deviceDesc[0]
            LabelSource = 'DeviceDesc'
        }
    }

    $quotedModels = @(Get-DsmInfQuotedModelLabels -Text $Text)
    if ($quotedModels.Count -gt 0) {
        return [pscustomobject]@{
            Label       = [string]$quotedModels[0]
            LabelSource = 'QuotedModel'
        }
    }

    $stringDesc = @(Get-DsmInfStringsDescriptionLabels -StringsTable $strings)
    if ($stringDesc.Count -gt 0) {
        return [pscustomobject]@{
            Label       = [string]$stringDesc[0]
            LabelSource = 'StringsDesc'
        }
    }

    $verifyMark = Get-DsmInfOemVerifyMark -Text $Text
    if ($verifyMark) {
        return [pscustomobject]@{
            Label       = $verifyMark
            LabelSource = 'OemVerifyMark'
        }
    }

    $diskFromStrings = Get-DsmInfDiskLabelFromStrings -StringsTable $strings
    if ($diskFromStrings) {
        return [pscustomobject]@{
            Label       = $diskFromStrings
            LabelSource = 'StringsDiskLabel'
        }
    }

    $diskFromSource = Get-DsmInfDiskLabelFromSourceDisks -Text $Text -StringsTable $strings
    if ($diskFromSource) {
        return [pscustomobject]@{
            Label       = $diskFromSource
            LabelSource = 'SourceDisksNames'
        }
    }

    foreach ($pattern in @('DiskId', 'DiskName', 'DISK_NAME', 'Location')) {
        if ($Text -match "(?im)^\s*$pattern\s*=\s*(.+?)\s*(?:;|$)") {
            $parsed = Get-DsmInfParsedValue -Raw $Matches[1]
            if ($parsed) {
                return [pscustomobject]@{
                    Label       = $parsed
                    LabelSource = $pattern
                }
            }
        }
    }

    $mfg = @(Get-DsmInfStringKeysByPattern -StringsTable $strings `
        -ExactKeys @('MfgName', 'ManufacturerName', 'ProviderName') `
        -SuffixPatterns @('(?i)\.MfgName$'))
    if ($mfg.Count -gt 0 -and (Test-DsmInfSubstantiveLabel -Label $mfg[0])) {
        return [pscustomobject]@{
            Label       = [string]$mfg[0]
            LabelSource = 'MfgName'
        }
    }

    $svc = @(Get-DsmInfStringKeysByPattern -StringsTable $strings `
        -SuffixPatterns @(
            '(?i)_svcdesc$'
            '(?i)svcdesc$'
            '(?i)_SvcDesc$'
            '(?i)_DESC$'
        ) `
        -ExactKeys @('SERVICE_DESC'))
    if ($svc.Count -gt 0 -and (Test-DsmInfSubstantiveLabel -Label $svc[0])) {
        return [pscustomobject]@{
            Label       = [string]$svc[0]
            LabelSource = 'ServiceDesc'
        }
    }

    $gfx = Get-DsmInfFirstModelStringLabel -Text $Text -StringsTable $strings
    if ($gfx -and (Test-DsmInfSubstantiveLabel -Label $gfx)) {
        return [pscustomobject]@{
            Label       = $gfx
            LabelSource = 'ModelString'
        }
    }

    return $null
}

function Get-DsmInfDiskLabel {
    param(
        [Parameter(Mandatory)]
        [string] $Text
    )

    $friendly = Get-DsmInfFriendlyLabel -Text $Text
    if ($friendly) {
        return $friendly.Label
    }

    return $null
}

function Test-DsmInfOriginalNameLeaf {
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string] $OriginalName
    )

    if ([string]::IsNullOrWhiteSpace($OriginalName)) {
        return $false
    }

    $leaf = [System.IO.Path]::GetFileName($OriginalName)
    if ($leaf -ne $OriginalName) {
        return $false
    }

    if ($leaf -match '[\\/\*\?<>|:"]') {
        return $false
    }

    return ($leaf -match '\.inf$')
}

function Test-DsmInfPathIsApprovedRoot {
    param(
        [Parameter(Mandatory)]
        [string] $LiteralPath
    )

    if (-not (Test-Path -LiteralPath $LiteralPath)) {
        return $false
    }

    $full = [System.IO.Path]::GetFullPath($LiteralPath)
    $approvedRoots = @(
        (Join-Path $env:WINDIR 'INF')
        (Get-DsmFileRepositoryRoot)
    )

    foreach ($root in $approvedRoots) {
        if (-not $root -or -not (Test-Path -LiteralPath $root)) { continue }
        $rootFull = [System.IO.Path]::GetFullPath($root)
        if ($full.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

function Find-DsmFileRepositoryInfByOriginalName {
    <#
    .SYNOPSIS
        Locates a staged INF in FileRepository when pnputil file lists are incomplete.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $OriginalName,

        [string] $DriverVersion
    )

    if (-not (Test-DsmInfOriginalNameLeaf -OriginalName $OriginalName)) {
        return $null
    }

    $repo = Get-DsmFileRepositoryRoot
    if (-not (Test-Path -LiteralPath $repo)) {
        return $null
    }

    $stem = [System.IO.Path]::GetFileNameWithoutExtension($OriginalName)
    $dirs = @(Get-ChildItem -LiteralPath $repo -Directory -Filter ($stem + '.inf_*') `
            -ErrorAction SilentlyContinue)

    if ($dirs.Count -eq 0) {
        return $null
    }

    $candidates = [System.Collections.Generic.List[string]]::new()
    foreach ($dir in $dirs) {
        $infPath = Join-Path $dir.FullName $OriginalName
        if (-not (Test-Path -LiteralPath $infPath)) {
            $infPath = Get-ChildItem -LiteralPath $dir.FullName -Filter '*.inf' -File `
                -ErrorAction SilentlyContinue |
                Select-Object -First 1 -ExpandProperty FullName
        }

        if ($infPath -and (Test-Path -LiteralPath $infPath)) {
            $candidates.Add($infPath) | Out-Null
        }
    }

    if ($candidates.Count -eq 0) {
        return $null
    }

    if ($candidates.Count -eq 1) {
        return $candidates[0]
    }

    if ($DriverVersion) {
        foreach ($candidate in $candidates) {
            $meta = Get-DsmInfMetadata -LiteralPath $candidate -NoCache
            if ($meta -and (Test-DsmDriverVerEquivalent -Left $meta.DriverVer -Right $DriverVersion)) {
                return $candidate
            }
        }
    }

    return $candidates[0]
}

function Get-DsmDriverPackageRepositoryDir {
    <#
    .SYNOPSIS
        Locates the FileRepository folder for a staged package by correlating pnputil file names.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject] $Package
    )

    $fileIndex = Initialize-DsmFileRepositoryFileIndex
    $packageFiles = @($Package.Files | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($packageFiles.Count -eq 0) {
        return $null
    }

    $dirScores = @{}
    foreach ($file in $packageFiles) {
        $leaf = [System.IO.Path]::GetFileName($file)
        if (-not $fileIndex.ContainsKey($leaf)) { continue }

        foreach ($fullPath in @($fileIndex[$leaf])) {
            $dir = [System.IO.Path]::GetDirectoryName($fullPath)
            if (-not $dirScores.ContainsKey($dir)) {
                $dirScores[$dir] = 0
            }
            $dirScores[$dir]++
        }
    }

    if ($dirScores.Count -eq 0) {
        return $null
    }

    $maxScore = ($dirScores.Values | Measure-Object -Maximum).Maximum
    $topDirs = @($dirScores.GetEnumerator() | Where-Object { $_.Value -eq $maxScore } |
        ForEach-Object { $_.Key })

    if ($topDirs.Count -eq 1) {
        return $topDirs[0]
    }

    if ($Package.DriverVersion) {
        $versionMatches = [System.Collections.Generic.List[string]]::new()
        foreach ($dir in $topDirs) {
            $infName = if ($Package.OriginalName) { $Package.OriginalName } else { $Package.PublishedName }
            $infPath = Join-Path $dir $infName
            if (-not (Test-Path -LiteralPath $infPath)) {
                $infPath = Get-ChildItem -LiteralPath $dir -Filter '*.inf' -File -ErrorAction SilentlyContinue |
                    Select-Object -First 1 -ExpandProperty FullName
            }

            if ([string]::IsNullOrWhiteSpace($infPath)) { continue }
            $meta = Get-DsmInfMetadata -LiteralPath $infPath -NoCache
            if ($meta -and (Test-DsmDriverVerEquivalent -Left $meta.DriverVer -Right $Package.DriverVersion)) {
                $versionMatches.Add($dir) | Out-Null
            }
        }

        if ($versionMatches.Count -eq 1) {
            return $versionMatches[0]
        }
    }

    return $topDirs[0]
}

function Get-DsmDriverPackageInfPath {
    <#
    .SYNOPSIS
        Resolves the on-disk INF path for a driver package from pnputil file listings.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject] $Package
    )

    $target = $Package.PublishedName
    if (-not $target) { return $null }

    foreach ($file in @($Package.Files)) {
        if ([string]::IsNullOrWhiteSpace($file)) { continue }
        if (-not (Test-Path -LiteralPath $file)) { continue }
        if (-not (Test-DsmInfPathIsApprovedRoot -LiteralPath $file)) { continue }
        $leaf = [System.IO.Path]::GetFileName($file)
        if ($leaf -eq $target -or $file -match '\.inf$') {
            return $file
        }
    }

    $repoDir = Get-DsmDriverPackageRepositoryDir -Package $Package
    if ($repoDir) {
        $candidates = @()
        if ($Package.OriginalName) {
            $candidates += Join-Path $repoDir $Package.OriginalName
        }

        $candidates += Join-Path $repoDir $target
        foreach ($candidate in $candidates) {
            if (Test-Path -LiteralPath $candidate) {
                return $candidate
            }
        }

        $anyInf = Get-ChildItem -LiteralPath $repoDir -Filter '*.inf' -File -ErrorAction SilentlyContinue |
            Select-Object -First 1 -ExpandProperty FullName
        if ($anyInf) {
            return $anyInf
        }
    }

    $publishedInf = Join-Path (Join-Path $env:WINDIR 'INF') $target
    if (Test-Path -LiteralPath $publishedInf) {
        return $publishedInf
    }

    if ($Package.OriginalName) {
        $byOriginal = Find-DsmFileRepositoryInfByOriginalName `
            -OriginalName $Package.OriginalName `
            -DriverVersion $Package.DriverVersion
        if ($byOriginal) {
            return $byOriginal
        }
    }

    return $null
}

function Read-DsmInfText {
    param(
        [Parameter(Mandatory)]
        [string] $LiteralPath
    )

    if (-not (Test-Path -LiteralPath $LiteralPath)) {
        return $null
    }

    try {
        $bytes = [System.IO.File]::ReadAllBytes($LiteralPath)
    }
    catch {
        Write-Verbose "Could not read INF bytes from $LiteralPath`: $($_.Exception.Message)"
        return $null
    }

    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        return [System.Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2)
    }

    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
        return [System.Text.Encoding]::BigEndianUnicode.GetString($bytes, 2, $bytes.Length - 2)
    }

    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        return [System.Text.Encoding]::UTF8.GetString($bytes, 3, $bytes.Length - 3)
    }

    $utf8 = [System.Text.Encoding]::UTF8.GetString($bytes)
    if ($utf8 -notmatch '[^\u0000-\u007F]' -or -not ($utf8 -match '[\uFFFD]')) {
        return $utf8
    }

    return [System.Text.Encoding]::GetEncoding(1252).GetString($bytes)
}

function ConvertTo-DsmInfDisplayName {
    <#
    .SYNOPSIS
        Normalizes INF DiskId / DiskName text for operator-readable labels.
    #>
    [CmdletBinding()]
    param(
        [string] $DiskId
    )

    if ([string]::IsNullOrWhiteSpace($DiskId)) {
        return $null
    }

    $name = $DiskId.Trim().Trim('"').Trim()

    $semi = $name.IndexOf(';')
    if ($semi -ge 0) {
        $name = $name.Substring(0, $semi).Trim()
    }

    if ($name -match '\{PlaceHolder=') {
        $name = ($name -replace '\s*\{PlaceHolder=.*$', '').Trim()
    }

    $suffixes = @(
        ' - Installation Disk'
        ' Installation Disk'
        ' - Install Disk'
        ' Install Disk'
        ' Installation DISK'
        ' INSTALLATION DISK'
        ' Installation Media'
        ' Setup Disk'
        ' DRIVER DISK'
        ' Driver Disk'
        ' Driver Install Disk'
        ' installation'
    )
    foreach ($suffix in $suffixes) {
        if ($name.EndsWith($suffix, [StringComparison]::OrdinalIgnoreCase)) {
            $name = $name.Substring(0, $name.Length - $suffix.Length).TrimEnd()
            break
        }
    }

    return $name.TrimEnd('.', '"', ' ').Trim()
}

function Get-DsmInfMetadata {
    <#
    .SYNOPSIS
        Reads DriverVer and DiskId (or DiskName) from a staged driver INF.
    .OUTPUTS
        PSCustomObject with InfPath, DriverVer, DiskId, DisplayName.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $LiteralPath,

        [switch] $NoCache
    )

    if (-not $NoCache -and $script:DsmInfMetadataCache.ContainsKey($LiteralPath)) {
        $cached = $script:DsmInfMetadataCache[$LiteralPath]
        if (Test-Path -LiteralPath $LiteralPath) {
            $item = Get-Item -LiteralPath $LiteralPath
            if ($cached.CacheLength -eq $item.Length -and $cached.CacheLastWriteUtc -eq $item.LastWriteTimeUtc) {
                return $cached.Metadata
            }
        }
    }

    try {
        $text = Read-DsmInfText -LiteralPath $LiteralPath
    }
    catch {
        return [pscustomobject]@{
            InfPath        = $LiteralPath
            DriverVer      = $null
            DiskId         = $null
            DisplayName    = $null
            LabelSource    = $null
            MetadataStatus = 'ReadFailed'
            Error          = $_.Exception.Message
        }
    }

    if ([string]::IsNullOrWhiteSpace($text)) {
        return [pscustomobject]@{
            InfPath        = $LiteralPath
            DriverVer      = $null
            DiskId         = $null
            DisplayName    = $null
            LabelSource    = $null
            MetadataStatus = 'Unavailable'
            Error          = 'INF text empty or unreadable.'
        }
    }

    $driverVer = $null
    if ($text -match '(?im)^\s*DriverVer\s*=\s*(.+)$') {
        $driverVer = ConvertTo-DsmNormalizedDriverVer -DriverVer (Get-DsmInfParsedValue -Raw $Matches[1])
    }

    $friendly = Get-DsmInfFriendlyLabel -Text $text
    $diskId = if ($friendly) { $friendly.Label } else { $null }

    $result = [pscustomobject]@{
        InfPath        = $LiteralPath
        DriverVer      = $driverVer
        DiskId         = $diskId
        DisplayName    = ConvertTo-DsmInfDisplayName -DiskId $diskId
        LabelSource    = if ($friendly) { $friendly.LabelSource } else { $null }
        MetadataStatus = 'Available'
        Error          = $null
    }

    if (-not $NoCache) {
        $item = Get-Item -LiteralPath $LiteralPath
        $script:DsmInfMetadataCache[$LiteralPath] = [pscustomobject]@{
            Metadata         = $result
            CacheLength      = $item.Length
            CacheLastWriteUtc = $item.LastWriteTimeUtc
        }
    }

    return $result
}

function Get-DsmDriverPackageInfMetadata {
    <#
    .SYNOPSIS
        INF metadata for a DsmDriverPackage (DriverVer, DiskId, DisplayName).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject] $Package
    )

    $infPath = Get-DsmDriverPackageInfPath -Package $Package
    if (-not $infPath) {
        return [pscustomobject]@{
            InfPath        = $null
            DriverVer      = $Package.DriverVersion
            DiskId         = $null
            DisplayName    = $null
            LabelSource    = $null
            MetadataSource = 'InventoryOnly'
            MetadataStatus = 'PathNotFound'
        }
    }

    if (-not (Test-DsmInfPathIsApprovedRoot -LiteralPath $infPath)) {
        return [pscustomobject]@{
            InfPath        = $infPath
            DriverVer      = $Package.DriverVersion
            DiskId         = $null
            DisplayName    = $null
            LabelSource    = $null
            MetadataSource = 'RejectedPath'
            MetadataStatus = 'RejectedPath'
        }
    }

    $meta = Get-DsmInfMetadata -LiteralPath $infPath
    if (-not $meta) {
        return [pscustomobject]@{
            InfPath        = $infPath
            DriverVer      = $Package.DriverVersion
            DiskId         = $null
            DisplayName    = $null
            LabelSource    = $null
            MetadataSource = 'InventoryOnly'
            MetadataStatus = 'Unavailable'
        }
    }

    if ($meta.MetadataStatus -and $meta.MetadataStatus -ne 'Available') {
        return [pscustomobject]@{
            InfPath        = $meta.InfPath
            DriverVer      = $Package.DriverVersion
            DiskId         = $null
            DisplayName    = $null
            LabelSource    = $null
            MetadataSource = 'Inf'
            MetadataStatus = $meta.MetadataStatus
            Error          = $meta.Error
        }
    }

    $driverVer = if ($meta.DriverVer) { $meta.DriverVer } else { $Package.DriverVersion }
    if ($Package.DriverVersion -and $meta.DriverVer -and -not (
            Test-DsmDriverVerEquivalent -Left $meta.DriverVer -Right $Package.DriverVersion)) {
        Write-Verbose (
            "DriverVer mismatch for $($Package.PublishedName): inventory=$($Package.DriverVersion) inf=$($meta.DriverVer) path=$infPath"
        )
    }

    return [pscustomobject]@{
        InfPath        = $meta.InfPath
        DriverVer      = $driverVer
        DiskId         = $meta.DiskId
        DisplayName    = $meta.DisplayName
        LabelSource    = $meta.LabelSource
        MetadataSource = 'Inf'
    }
}

function Export-DsmDriverDiskIdCatalog {
    <#
    .SYNOPSIS
        Builds a DiskId / DriverVer catalog for all OEM driver packages in inventory.
    #>
    [CmdletBinding()]
    param(
        [psobject[]] $Inventory,

        [switch] $IncludeWindowsBuiltIn
    )

    if (-not $Inventory) {
        $Inventory = @(Get-DsmDriverStoreInventory)
    }
    else {
        $Inventory = @($Inventory)
    }

    $scoped = Invoke-DsmDriverFilter -Inventory $Inventory `
        -IncludeWindowsBuiltIn:$IncludeWindowsBuiltIn

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($pkg in @($scoped.Filtered | Sort-Object PublishedName)) {
        $meta = Get-DsmDriverPackageInfMetadata -Package $pkg
        $rows.Add([pscustomobject]@{
                PublishedName     = $pkg.PublishedName
                OriginalName      = $pkg.OriginalName
                Provider          = $pkg.Provider
                DriverClass       = $pkg.DriverClass
                DriverVersion     = $pkg.DriverVersion
                DriverVer         = $meta.DriverVer
                DiskId            = $meta.DiskId
                DisplayName       = $meta.DisplayName
                LabelSource       = $meta.LabelSource
                InfPath           = $meta.InfPath
                DeviceAssociation = $pkg.DeviceAssociation
                InUse             = [bool]$pkg.InUse
            }) | Out-Null
    }

    return @($rows)
}
