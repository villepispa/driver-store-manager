function Test-DsmWindowsBuiltInDriverPackage {
    <#
    .SYNOPSIS
        True for Windows built-in driver manifests (non-oem#.inf published names).
    .DESCRIPTION
        Built-in manifests use in-box INF names (e.g. c_swcomponent.inf). Staged
        oem#.inf packages are never built-in, even when Provider is Microsoft Corporation.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [psobject] $Package
    )

    return ($Package.PublishedName -notmatch '^oem\d+\.inf$')
}

function Test-DsmOemDriverPackage {
    <#
    .SYNOPSIS
        True for staged Driver Store packages published as oem#.inf (any publisher).
    .DESCRIPTION
        Default scope includes all oem#.inf packages. Windows built-in manifests
        (non-oem names) are excluded unless -IncludeWindowsBuiltIn is set on
        Invoke-DsmDriverFilter. Publisher (e.g. Microsoft Corporation on oem159.inf)
        does not affect scope — only the published INF name does.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [psobject] $Package
    )

    return ($Package.PublishedName -match '^oem\d+\.inf$')
}

function Test-DsmInboxDriverPackage {
    <#
    .SYNOPSIS
        Deprecated alias for Test-DsmWindowsBuiltInDriverPackage.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [psobject] $Package
    )

    return (Test-DsmWindowsBuiltInDriverPackage -Package $Package)
}

function Get-DsmDriverVersionParsed {
    [CmdletBinding()]
    param(
        [string] $VersionString
    )

    if ([string]::IsNullOrWhiteSpace($VersionString)) {
        return $null
    }

    $parsed = $null
    if ([version]::TryParse($VersionString, [ref]$parsed)) {
        return $parsed
    }

    if ($VersionString -match '(\d+\.\d+(?:\.\d+)*)') {
        if ([version]::TryParse($Matches[1], [ref]$parsed)) {
            return $parsed
        }
    }

    return $null
}

function Test-DsmLikeAny {
    param(
        [string[]] $Values,
        [string[]] $Patterns
    )

    if (-not $Patterns -or $Patterns.Count -eq 0) {
        return $true
    }

    foreach ($pattern in $Patterns) {
        foreach ($value in $Values) {
            if ([string]::IsNullOrWhiteSpace($value)) { continue }
            if ($value -like $pattern) {
                return $true
            }
        }
    }

    return $false
}

function Test-DsmDriverPackageMatchesFilter {
    <#
    .SYNOPSIS
        Tests a single package against a DsmDriverFilter object.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [psobject] $Package,

        [Parameter(Mandatory)]
        [psobject] $Filter
    )

    $providerFields = @(
        (Get-DsmObjectPropertyValue -Object $Package -Name 'Provider')
        (Get-DsmObjectPropertyValue -Object $Package -Name 'Signer')
        (Get-DsmObjectPropertyValue -Object $Package -Name 'DismProvider')
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    if ($Filter.Provider -and -not (Test-DsmLikeAny -Values $providerFields -Patterns @($Filter.Provider))) {
        return $false
    }

    $deviceNames = @(Get-DsmObjectPropertyValue -Object $Package -Name 'Devices')
    if ($Filter.DeviceName -and -not (Test-DsmLikeAny -Values $deviceNames -Patterns @($Filter.DeviceName))) {
        return $false
    }

    if ($Filter.DriverClass -and -not (Test-DsmLikeAny -Values @(Get-DsmObjectPropertyValue -Object $Package -Name 'DriverClass') -Patterns @($Filter.DriverClass))) {
        return $false
    }

    if ($Filter.ClassGuid -and -not (Test-DsmLikeAny -Values @(Get-DsmObjectPropertyValue -Object $Package -Name 'ClassGuid') -Patterns @($Filter.ClassGuid))) {
        return $false
    }

    if ($Filter.PublishedName -and -not (Test-DsmLikeAny -Values @(Get-DsmObjectPropertyValue -Object $Package -Name 'PublishedName') -Patterns @($Filter.PublishedName))) {
        return $false
    }

    if ($Filter.OriginalName -and -not (Test-DsmLikeAny -Values @(Get-DsmObjectPropertyValue -Object $Package -Name 'OriginalName') -Patterns @($Filter.OriginalName))) {
        return $false
    }

    $hwValues = @(Get-DsmObjectPropertyValue -Object $Package -Name 'HardwareIds') `
        + @(Get-DsmObjectPropertyValue -Object $Package -Name 'HardwareIdRoots')
    if ($Filter.HardwareId -and -not (Test-DsmLikeAny -Values $hwValues -Patterns @($Filter.HardwareId))) {
        return $false
    }

    $versionText = Get-DsmObjectPropertyValue -Object $Package -Name 'DriverVersion'
    $dismVersion = Get-DsmObjectPropertyValue -Object $Package -Name 'DismVersion'
    if ($dismVersion -and -not $versionText) {
        $versionText = $dismVersion
    }

    if ($Filter.DriverVersion) {
        if (-not (Test-DsmLikeAny -Values @($versionText) -Patterns @($Filter.DriverVersion))) {
            return $false
        }
    }

    $parsedVersion = Get-DsmDriverVersionParsed -VersionString $versionText
    if ($Filter.MinDriverVersion) {
        if (-not $parsedVersion -or $parsedVersion -lt $Filter.MinDriverVersion) {
            return $false
        }
    }

    if ($Filter.MaxDriverVersion) {
        if (-not $parsedVersion -or $parsedVersion -gt $Filter.MaxDriverVersion) {
            return $false
        }
    }

    $association = Get-DsmObjectPropertyValue -Object $Package -Name 'DeviceAssociation'
    if (-not $association) {
        $inUse = Get-DsmObjectPropertyValue -Object $Package -Name 'InUse'
        $deviceCount = Get-DsmObjectPropertyValue -Object $Package -Name 'DeviceCount'
        if ($inUse) { $association = 'Connected' }
        elseif ($deviceCount -gt 0) { $association = 'DisconnectedInstalled' }
        else { $association = 'NeverAssociated' }
    }

    switch ($Filter.Association) {
        'Connected' { if ($association -ne 'Connected') { return $false } }
        'DisconnectedInstalled' { if ($association -ne 'DisconnectedInstalled') { return $false } }
        'NeverAssociated' { if ($association -ne 'NeverAssociated') { return $false } }
        'InUseOnly' { if ($association -ne 'Connected') { return $false } }
        'UnusedOnly' {
            if ($association -eq 'Connected') { return $false }
        }
        default { }
    }

    return $true
}

function Get-DsmDriverFamilyKey {
    <#
    .SYNOPSIS
        Driver family key for version grouping (Provider+OriginalName or HWID root).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject] $Package,

        [ValidateSet('ProviderOriginalName', 'HwId')]
        [string] $FamilyGroupBy = 'ProviderOriginalName'
    )

    if ($FamilyGroupBy -eq 'HwId') {
        $root = @($Package.HardwareIdRoots) | Select-Object -First 1
        if ($root) {
            return "HWID|$root"
        }
    }

    $provider = if ($Package.Provider) { $Package.Provider } else { '' }
    $original = if ($Package.OriginalName) { $Package.OriginalName } else { '' }
    return "PO|$provider|$original"
}

function Test-DsmDriverFilterIsEmpty {
    param([psobject] $Filter)

    if (-not $Filter) { return $true }

    $props = @(
        'Provider', 'DeviceName', 'DriverVersion', 'MinDriverVersion', 'MaxDriverVersion',
        'DriverClass', 'ClassGuid', 'HardwareId', 'PublishedName', 'OriginalName'
    )

    foreach ($name in $props) {
        $value = $Filter.$name
        if ($null -ne $value -and $value -ne '') {
            return $false
        }
    }

    if ($Filter.Association -and $Filter.Association -ne 'Any') {
        return $false
    }

    return $true
}

function New-DsmDriverFilterManifest {
    param(
        [psobject] $Filter,
        [switch] $IncludeWindowsBuiltIn
    )

    $manifest = [ordered]@{
        IncludeWindowsBuiltIn = [bool]$IncludeWindowsBuiltIn
    }

    if (-not $Filter) {
        return $manifest
    }

    foreach ($name in @(
            'Provider', 'DeviceName', 'DriverVersion', 'MinDriverVersion', 'MaxDriverVersion',
            'DriverClass', 'ClassGuid', 'HardwareId', 'PublishedName', 'OriginalName', 'Association'
        )) {
        $value = $Filter.$name
        if ($null -ne $value -and $value -ne '') {
            $manifest[$name] = $value
        }
    }

    return $manifest
}
