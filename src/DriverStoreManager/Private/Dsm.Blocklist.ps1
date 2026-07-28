function Get-DsmMicrosoftBlocklistUri {
    'https://aka.ms/VulnerableDriverBlockList'
}

$script:DsmMicrosoftBlocklistRootOverride = $null

function Get-DsmMicrosoftBlocklistPaths {
    <#
    .SYNOPSIS
        Cache locations for the auto-refreshed Microsoft vulnerable driver blocklist.
    #>
    [CmdletBinding()]
    param()

    $root = if ($script:DsmMicrosoftBlocklistRootOverride) {
        $script:DsmMicrosoftBlocklistRootOverride
    }
    else {
        Get-DsmProgramDataRoot -ChildPath @('blocklist', 'microsoft')
    }
    [pscustomobject]@{
        Directory  = $root
        HashFile   = Join-DsmPath $root 'vulnerable-driver-hashes.sha256.txt'
        MetadataFile = Join-DsmPath $root 'blocklist-metadata.json'
        ZipFile    = Join-DsmPath $root 'VulnerableDriverBlockList.zip'
        ExtractDir = Join-DsmPath $root 'extract'
    }
}

function ConvertFrom-DsmMicrosoftBlocklistXml {
    <#
    .SYNOPSIS
        Extracts file SHA256 hashes from Microsoft DriverPolicy / SiPolicy XML.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [xml] $PolicyXml
    )

    $ns = New-Object System.Xml.XmlNamespaceManager($PolicyXml.NameTable)
    $ns.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')

    $hashSet = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )

    $denyNodes = $PolicyXml.SelectNodes('//ns:Deny[@Hash]', $ns)
    foreach ($node in $denyNodes) {
        $hash = [string]$node.Hash
        if ($hash.Length -ne 64) { continue }

        $id = [string]$node.ID
        $friendly = [string]$node.FriendlyName
        $include = $false

        if ($id -match '_SHA256' -and $id -notmatch '_PAGE') {
            $include = $true
        }
        elseif ($friendly -match ' Hash Sha256$' -and $friendly -notmatch 'Hash Page') {
            $include = $true
        }

        if ($include) {
            [void]$hashSet.Add($hash.ToUpperInvariant())
        }
    }

    $attribNodes = $PolicyXml.SelectNodes('//ns:FileAttrib', $ns)
    foreach ($node in $attribNodes) {
        $friendly = [string]$node.FriendlyName
        if ($friendly -match '([A-Fa-f0-9]{64})') {
            [void]$hashSet.Add($Matches[1].ToUpperInvariant())
        }
    }

    return $hashSet
}

function Get-DsmMicrosoftBlocklistMetadata {
    [CmdletBinding()]
    param(
        [string] $MetadataFile
    )

    if (-not $MetadataFile) {
        $MetadataFile = (Get-DsmMicrosoftBlocklistPaths).MetadataFile
    }

    if (-not (Test-Path -LiteralPath $MetadataFile)) {
        return $null
    }

    try {
        return (Get-Content -LiteralPath $MetadataFile -Raw -Encoding UTF8 | ConvertFrom-Json)
    }
    catch {
        Write-Warning "Could not read blocklist metadata: $($_.Exception.Message)"
        return $null
    }
}

function Test-DsmMicrosoftBlocklistStale {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [int] $MaxAgeDays = 7,

        [string] $MetadataFile,

        [string] $HashFile
    )

    $paths = Get-DsmMicrosoftBlocklistPaths
    if (-not $MetadataFile) { $MetadataFile = $paths.MetadataFile }
    if (-not $HashFile) { $HashFile = $paths.HashFile }

    if (-not (Test-Path -LiteralPath $HashFile)) {
        return $true
    }

    $meta = Get-DsmMicrosoftBlocklistMetadata -MetadataFile $MetadataFile
    if (-not $meta -or -not $meta.UpdatedAt) {
        return $true
    }

    try {
        $updated = [datetime]$meta.UpdatedAt
    }
    catch {
        return $true
    }

    $age = (Get-Date) - $updated
    return ($age.TotalDays -ge $MaxAgeDays)
}

function Invoke-DsmMicrosoftBlocklistRefresh {
    <#
    .SYNOPSIS
        Downloads and caches SHA256 hashes from Microsoft's vulnerable driver blocklist.
    .DESCRIPTION
        Fetches https://aka.ms/VulnerableDriverBlockList, parses DriverPolicy_Enforced.xml
        (or SiPolicy_Enforced.xml), and writes hashes under ProgramData\DriverStoreManager.
    .PARAMETER MaxAgeDays
        When not forcing, skip download if cache is newer than this many days.
    .PARAMETER Force
        Download even when cache is fresh.
    .OUTPUTS
        PSCustomObject with Updated, HashCount, HashFile, MetadataFile, PolicyVersion.
    #>
    [CmdletBinding()]
    param(
        [int] $MaxAgeDays = 7,

        [switch] $Force
    )

    $paths = Get-DsmMicrosoftBlocklistPaths
    if (-not (Test-Path -LiteralPath $paths.Directory)) {
        New-Item -ItemType Directory -Path $paths.Directory -Force | Out-Null
    }

    if (-not $Force -and -not (Test-DsmMicrosoftBlocklistStale -MaxAgeDays $MaxAgeDays)) {
        $existing = Get-DsmMicrosoftBlocklistMetadata
        return [pscustomobject]@{
            Updated       = $false
            Reason        = 'CacheFresh'
            HashCount     = [int]$existing.HashCount
            HashFile      = $paths.HashFile
            MetadataFile  = $paths.MetadataFile
            PolicyVersion = $existing.PolicyVersion
            UpdatedAt     = $existing.UpdatedAt
        }
    }

    $uri = Get-DsmMicrosoftBlocklistUri
    $previousTls = [Net.ServicePointManager]::SecurityProtocol
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $uri -OutFile $paths.ZipFile -UseBasicParsing
    }
    catch {
        throw "Failed to download Microsoft vulnerable driver blocklist from $uri`: $($_.Exception.Message)"
    }
    finally {
        [Net.ServicePointManager]::SecurityProtocol = $previousTls
    }

    if (Test-Path -LiteralPath $paths.ExtractDir) {
        Remove-Item -LiteralPath $paths.ExtractDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    New-Item -ItemType Directory -Path $paths.ExtractDir -Force | Out-Null
    Expand-Archive -LiteralPath $paths.ZipFile -DestinationPath $paths.ExtractDir -Force

    $xmlFile = Get-ChildItem -LiteralPath $paths.ExtractDir -Filter 'DriverPolicy_Enforced.xml' -Recurse |
        Select-Object -First 1
    if (-not $xmlFile) {
        $xmlFile = Get-ChildItem -LiteralPath $paths.ExtractDir -Filter 'SiPolicy_Enforced.xml' -Recurse |
            Select-Object -First 1
    }
    if (-not $xmlFile) {
        throw 'Microsoft blocklist ZIP did not contain DriverPolicy_Enforced.xml or SiPolicy_Enforced.xml.'
    }

    [xml] $policyXml = Get-Content -LiteralPath $xmlFile.FullName -Raw -Encoding UTF8
    $hashSet = ConvertFrom-DsmMicrosoftBlocklistXml -PolicyXml $policyXml
    if ($hashSet.Count -eq 0) {
        throw 'No SHA256 hashes were extracted from the Microsoft blocklist XML.'
    }

    $sorted = @($hashSet | Sort-Object)
    Set-DsmContentUtf8 -LiteralPath $paths.HashFile -Value ($sorted -join "`r`n")

    $policyVersion = $null
    $versionNode = $policyXml.SelectSingleNode('//*[local-name()="VersionEx"]')
    if ($versionNode) {
        $policyVersion = [string]$versionNode.InnerText
    }

    $updatedAt = Get-Date
    $metadata = [ordered]@{
        UpdatedAt     = $updatedAt.ToString('o')
        SourceUrl     = $uri
        PolicyVersion = $policyVersion
        HashCount     = $hashSet.Count
        XmlFile       = $xmlFile.Name
        XmlFullName   = $xmlFile.FullName
    }
    Set-DsmContentUtf8 -LiteralPath $paths.MetadataFile -Value ($metadata | ConvertTo-Json -Depth 3)

    Remove-Item -LiteralPath $paths.ZipFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $paths.ExtractDir -Recurse -Force -ErrorAction SilentlyContinue

    return [pscustomobject]@{
        Updated       = $true
        Reason        = 'Downloaded'
        HashCount     = $hashSet.Count
        HashFile      = $paths.HashFile
        MetadataFile  = $paths.MetadataFile
        PolicyVersion = $policyVersion
        UpdatedAt     = $metadata.UpdatedAt
    }
}

function Import-DsmBlocklistHashFile {
    <#
    .SYNOPSIS
        Loads SHA256 hashes from a local text file into a hash set.
    #>
    [CmdletBinding()]
    param(
        [string] $BlocklistPath,

        [System.Collections.Generic.HashSet[string]] $Into
    )

    if (-not $Into) {
        $Into = [System.Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
    }

    if (-not $BlocklistPath -or -not (Test-Path -LiteralPath $BlocklistPath)) {
        return $Into
    }

    Get-Content -LiteralPath $BlocklistPath -Encoding UTF8 | ForEach-Object {
        $h = $_.Trim()
        if ($h -match '^[A-Fa-f0-9]{64}$') {
            [void]$Into.Add($h.ToUpperInvariant())
        }
    }

    return $Into
}

function Get-DsmBlocklistHashSet {
    <#
    .SYNOPSIS
        Resolves the effective blocklist: auto-updated Microsoft cache plus optional -BlocklistPath.
    .PARAMETER BlocklistPath
        Optional supplemental or override hash file (merged with Microsoft cache when enabled).
    .PARAMETER UseMicrosoftBlocklist
        When true (default), refresh/use the Microsoft cache under ProgramData.
    .PARAMETER UpdateMicrosoftBlocklist
        Force a Microsoft download even if cache is fresh.
    .PARAMETER MicrosoftBlocklistMaxAgeDays
        Refresh Microsoft cache when older than this many days (default 7).
    #>
    [CmdletBinding()]
    param(
        [string] $BlocklistPath,

        [bool] $UseMicrosoftBlocklist = $true,

        [switch] $UpdateMicrosoftBlocklist,

        [int] $MicrosoftBlocklistMaxAgeDays = 7
    )

    $set = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )

    $msInfo = [ordered]@{
        Enabled          = [bool]$UseMicrosoftBlocklist
        RefreshAttempted = $false
        RefreshUpdated   = $false
        HashFile         = $null
        MetadataFile     = $null
        HashCount        = 0
        PolicyVersion    = $null
        UpdatedAt        = $null
        Error            = $null
    }

    if ($UseMicrosoftBlocklist) {
        $paths = Get-DsmMicrosoftBlocklistPaths
        $msInfo.HashFile = $paths.HashFile
        $msInfo.MetadataFile = $paths.MetadataFile

        try {
            $stale = $UpdateMicrosoftBlocklist -or (
                Test-DsmMicrosoftBlocklistStale -MaxAgeDays $MicrosoftBlocklistMaxAgeDays)
            if ($stale) {
                $msInfo.RefreshAttempted = $true
                $refresh = Invoke-DsmMicrosoftBlocklistRefresh `
                    -MaxAgeDays $MicrosoftBlocklistMaxAgeDays `
                    -Force:$UpdateMicrosoftBlocklist
                $msInfo.RefreshUpdated = [bool]$refresh.Updated
                $msInfo.HashCount = [int]$refresh.HashCount
                $msInfo.PolicyVersion = $refresh.PolicyVersion
                $msInfo.UpdatedAt = $refresh.UpdatedAt
            }
            else {
                $meta = Get-DsmMicrosoftBlocklistMetadata
                if ($meta) {
                    $msInfo.HashCount = [int]$meta.HashCount
                    $msInfo.PolicyVersion = $meta.PolicyVersion
                    $msInfo.UpdatedAt = $meta.UpdatedAt
                }
            }

            Import-DsmBlocklistHashFile -BlocklistPath $paths.HashFile -Into $set | Out-Null
            $msInfo.HashCount = $set.Count
        }
        catch {
            $msInfo.Error = $_.Exception.Message
            Write-Warning "Microsoft blocklist refresh failed; using cache if available: $($_.Exception.Message)"
            Import-DsmBlocklistHashFile -BlocklistPath $paths.HashFile -Into $set | Out-Null
            if ($set.Count -eq 0) {
                Write-Warning 'No Microsoft blocklist cache available; blocklist matching disabled until refresh succeeds.'
            }
            else {
                $meta = Get-DsmMicrosoftBlocklistMetadata
                if ($meta) {
                    $msInfo.UpdatedAt = $meta.UpdatedAt
                    $msInfo.PolicyVersion = $meta.PolicyVersion
                }
                $msInfo.HashCount = $set.Count
            }
        }
    }

    $supplementalCount = 0
    if ($BlocklistPath) {
        $before = $set.Count
        Import-DsmBlocklistHashFile -BlocklistPath $BlocklistPath -Into $set | Out-Null
        $supplementalCount = $set.Count - $before
    }

    $result = [pscustomobject]@{
        HashSet            = $set
        TotalCount         = $set.Count
        MicrosoftBlocklist = [pscustomobject]$msInfo
        SupplementalPath   = $BlocklistPath
        SupplementalCount  = $supplementalCount
    }

    return $result
}

function Get-DsmDriverFileHashes {
    <#
    .SYNOPSIS
        Resolves WDAC Authenticode SHA-256 when available, plus whole-file SHA-256.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $LiteralPath
    )

    $wholeFile = (Get-FileHash -LiteralPath $LiteralPath -Algorithm SHA256).Hash.ToUpperInvariant()
    $authenticode = $null

    if (Get-Command New-CIPolicyRule -ErrorAction SilentlyContinue) {
        try {
            $rules = @(New-CIPolicyRule -Level Hash -DriverFilePath $LiteralPath -ErrorAction Stop)
            foreach ($rule in $rules) {
                $name = [string]$rule.Name
                if ($name -match 'Hash Sha256\s+([A-Fa-f0-9]{64})') {
                    $authenticode = $Matches[1].ToUpperInvariant()
                    break
                }
            }
        }
        catch {
            Write-Verbose "ConfigCI hash lookup failed for $LiteralPath`: $($_.Exception.Message)"
        }
    }

    return [pscustomobject]@{
        WholeFileSha256      = $wholeFile
        AuthenticodeSha256   = $authenticode
        BlocklistMatchHashes = @(
            $(if ($authenticode) { $authenticode })
            $wholeFile
        ) | Select-Object -Unique
    }
}

function Get-DsmBlocklistScanState {
    <#
    .SYNOPSIS
        Derives vulnerability scan availability from blocklist resolution metadata.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject] $BlocklistResolved,

        [bool] $UseMicrosoftBlocklist,

        [int] $MicrosoftBlocklistMaxAgeDays = 7
    )

    if (-not $UseMicrosoftBlocklist) {
        return [pscustomobject]@{
            ScanState              = 'Complete'
            BlocklistDataAvailable = $true
            BlocklistDataDegraded  = $false
        }
    }

    $ms = $BlocklistResolved.MicrosoftBlocklist
    $hashCount = [int]$BlocklistResolved.TotalCount
    $hasError = -not [string]::IsNullOrWhiteSpace([string]$ms.Error)
    $stale = Test-DsmMicrosoftBlocklistStale -MaxAgeDays $MicrosoftBlocklistMaxAgeDays `
        -MetadataFile $ms.MetadataFile -HashFile $ms.HashFile

    if ($hashCount -eq 0 -and ($hasError -or $stale)) {
        return [pscustomobject]@{
            ScanState              = 'Unavailable'
            BlocklistDataAvailable = $false
            BlocklistDataDegraded  = $true
        }
    }

    if ($hasError -or $stale) {
        return [pscustomobject]@{
            ScanState              = 'Degraded'
            BlocklistDataAvailable = ($hashCount -gt 0)
            BlocklistDataDegraded  = $true
        }
    }

    return [pscustomobject]@{
        ScanState              = 'Complete'
        BlocklistDataAvailable = ($hashCount -gt 0)
        BlocklistDataDegraded  = $false
    }
}

function Get-DsmBlocklistHashes {
    <#
    .SYNOPSIS
        Returns SHA256 blocklist hashes (Microsoft auto-cache plus optional supplemental file).
    #>
    [CmdletBinding()]
    param(
        [string] $BlocklistPath,

        [bool] $UseMicrosoftBlocklist = $true,

        [switch] $UpdateMicrosoftBlocklist,

        [int] $MicrosoftBlocklistMaxAgeDays = 7
    )

    $resolved = Get-DsmBlocklistHashSet @PSBoundParameters
    # Unary comma: keep HashSet intact when it has 0–1 elements (PS unwraps otherwise).
    return , $resolved.HashSet
}
