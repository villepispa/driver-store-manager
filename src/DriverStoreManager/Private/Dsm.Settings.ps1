function Get-DsmForbiddenSettingsKey {
    <#
    .SYNOPSIS
        Keys that must never appear in a settings JSON file.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    return @(
        'AllowDelete'
        'Confirm'
        'WhatIf'
        'Force'
        'ConfirmImpact'
        'ShouldProcess'
        'SettingsPath'
    )
}

function Get-DsmAllowedSettingsKeyMap {
    <#
    .SYNOPSIS
        Canonical settings keys and value kinds for the run-profile schema.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    return [ordered]@{
        Provider                      = 'array'
        DeviceName                    = 'array'
        DriverVersion                 = 'array'
        MinDriverVersion              = 'version'
        MaxDriverVersion              = 'version'
        DriverClass                   = 'array'
        ClassGuid                     = 'array'
        HardwareId                    = 'array'
        PublishedName                 = 'array'
        OriginalName                  = 'array'
        Association                   = 'association'
        IncludeWindowsBuiltIn         = 'bool'
        PreserveRulesPath             = 'path'
        BlocklistPath                 = 'path'
        OutputPath                    = 'path'
        BackupRoot                    = 'path'
        MaxDeletes                    = 'int'
        MicrosoftBlocklistMaxAgeDays  = 'int'
        SkipMicrosoftBlocklist        = 'bool'
        UpdateMicrosoftBlocklist      = 'bool'
        IncludeCleanupPreview         = 'bool'
        FamilyGroupBy                 = 'family'
        IncludePublishedName          = 'array'
        InventoryMaxAgeMinutes        = 'int'
        ExportDiskIdCatalog           = 'bool'
        IncludeDism                   = 'bool'
        IncludeVulnerabilityScan      = 'bool'
        UseMicrosoftBlocklist         = 'bool'
        VulnerableIncludesSignature   = 'bool'
        ShowEffectiveSettings         = 'bool'
    }
}

function ConvertTo-DsmSettingsDisplayValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        $InputObject
    )

    if ($null -eq $InputObject) {
        return '<null>'
    }

    if ($InputObject -is [System.Array]) {
        $bits = foreach ($el in @($InputObject)) { [string]$el }
        return ($bits -join ',')
    }

    if ($InputObject -is [bool] -or $InputObject -is [switch]) {
        return ([bool]$InputObject).ToString().ToLowerInvariant()
    }

    return [string]$InputObject
}

function Write-DsmEffectiveSettings {
    <#
    .SYNOPSIS
        Writes overlay rows as Verbose (and Host when -AsHost).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Item,

        [switch] $AsHost
    )

    foreach ($row in @($Item)) {
        $line = '{0}={1} ({2})' -f $row.Name, (ConvertTo-DsmSettingsDisplayValue -InputObject $row.Value), $row.Source
        Write-Verbose $line
        if ($AsHost) {
            Write-Host $line -ForegroundColor DarkGray
        }
    }
}

function ConvertTo-DsmSettingsValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [string] $Kind,

        [AllowNull()]
        $InputObject,

        [Parameter(Mandatory)]
        [string] $BaseDirectory
    )

    if ($null -eq $InputObject) {
        throw "Settings key '$Name' must not be null."
    }

    switch ($Kind) {
        'array' {
            $items = @()
            if ($InputObject -is [string]) {
                $items = @($InputObject)
            }
            else {
                foreach ($el in @($InputObject)) {
                    $items += [string]$el
                }
            }
            $arr = [string[]]$items
            if ($arr.Count -le 1) {
                return , $arr
            }
            return $arr
        }
        'bool' {
            return [bool]$InputObject
        }
        'int' {
            return [int]$InputObject
        }
        'version' {
            return [version]([string]$InputObject)
        }
        'association' {
            $allowed = @(
                'Any'
                'Connected'
                'DisconnectedInstalled'
                'NeverAssociated'
                'InUseOnly'
                'UnusedOnly'
            )
            $text = [string]$InputObject
            if ($allowed -notcontains $text) {
                throw "Settings key '$Name' value '$text' is not a valid Association."
            }
            return $text
        }
        'family' {
            $allowed = @('ProviderOriginalName', 'HwId')
            $text = [string]$InputObject
            if ($allowed -notcontains $text) {
                throw "Settings key '$Name' value '$text' is not a valid FamilyGroupBy."
            }
            return $text
        }
        'path' {
            $text = [string]$InputObject
            if ([string]::IsNullOrWhiteSpace($text)) {
                throw "Settings key '$Name' must not be empty."
            }
            if (-not [System.IO.Path]::IsPathRooted($text)) {
                $text = [System.IO.Path]::GetFullPath((Join-Path $BaseDirectory $text))
            }
            return $text
        }
        default {
            throw "Internal: unknown settings kind '$Kind' for '$Name'."
        }
    }
}

function Get-DsmCanonicalSettingsKey {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        $AllowedMap
    )

    foreach ($k in $AllowedMap.Keys) {
        if ($k -eq $Name) {
            return [string]$k
        }
    }

    return $null
}

function Import-DsmSettingsFile {
    <#
    .SYNOPSIS
        Load and validate a DSM run-profile JSON file (fail closed).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $LiteralPath
    )

    if ([string]::IsNullOrWhiteSpace($LiteralPath)) {
        throw 'SettingsPath is empty. Pass a path to a JSON settings file.'
    }

    $resolved = $LiteralPath
    if (-not [System.IO.Path]::IsPathRooted($LiteralPath)) {
        $resolved = [System.IO.Path]::GetFullPath(
            (Join-Path (Get-Location).ProviderPath $LiteralPath))
    }

    if (-not (Test-Path -LiteralPath $resolved)) {
        throw "Settings file not found: $resolved"
    }

    $raw = Get-Content -LiteralPath $resolved -Raw -Encoding UTF8
    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw "Settings file is empty: $resolved"
    }

    try {
        $obj = $raw | ConvertFrom-Json
    }
    catch {
        throw "Settings file is not valid JSON: $resolved. $($_.Exception.Message)"
    }

    if ($null -eq $obj) {
        throw "Settings file must be a JSON object: $resolved"
    }

    if ($obj -is [System.Array]) {
        throw "Settings file must be a JSON object: $resolved"
    }

    $baseDir = Split-Path -Parent $resolved
    $allowed = Get-DsmAllowedSettingsKeyMap
    $forbidden = @(Get-DsmForbiddenSettingsKey)
    $map = [ordered]@{}

    foreach ($p in $obj.PSObject.Properties) {
        $name = [string]$p.Name
        $isForbidden = $false
        foreach ($f in $forbidden) {
            if ($f -eq $name) {
                $isForbidden = $true
                break
            }
        }

        if ($isForbidden) {
            throw ("Settings file must not contain '{0}' " +
                '(deletion/confirm knobs are CLI-only): {1}') -f $name, $resolved
        }

        $canon = Get-DsmCanonicalSettingsKey -Name $name -AllowedMap $allowed
        if (-not $canon) {
            $listed = @($allowed.Keys) -join ', '
            throw "Unknown settings key '$name' in $resolved. Allowed: $listed"
        }

        $map[$canon] = ConvertTo-DsmSettingsValue -Name $canon -Kind $allowed[$canon] `
            -InputObject $p.Value -BaseDirectory $baseDir
    }

    return $map
}

function Get-DsmSettings {
    <#
    .SYNOPSIS
        Load a DSM run-profile JSON file. Does not auto-discover a defaults path.
    .PARAMETER LiteralPath
        Path passed by the caller (same as -SettingsPath on cmdlets).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Alias('Path')]
        [string] $LiteralPath
    )

    return Import-DsmSettingsFile -LiteralPath $LiteralPath
}

function Get-DsmSettingsOverlay {
    <#
    .SYNOPSIS
        Merge settings JSON with bound CLI parameters. CLI wins on ContainsKey.
    .DESCRIPTION
        Loads the file only when BoundParameters contains SettingsPath.
        Unbound keys take file values (complement). Bound keys stay CLI
        (override). Arrays replace; they are not unioned.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary] $BoundParameters
    )

    $assignments = [ordered]@{}
    $effective = @()
    $loaded = $null

    if ($BoundParameters.ContainsKey('SettingsPath')) {
        $loaded = Import-DsmSettingsFile -LiteralPath ([string]$BoundParameters['SettingsPath'])
    }

    $allowed = Get-DsmAllowedSettingsKeyMap
    foreach ($key in $allowed.Keys) {
        $fromFile = $false
        $fileVal = $null
        if ($null -ne $loaded -and $loaded.Contains($key)) {
            $fromFile = $true
            $fileVal = $loaded[$key]
        }

        $fromCli = $BoundParameters.ContainsKey($key)
        if ($fromCli) {
            $effective += [pscustomobject]@{
                Name   = $key
                Value  = $BoundParameters[$key]
                Source = 'cli'
            }
        }
        elseif ($fromFile) {
            $assignments[$key] = $fileVal
            $effective += [pscustomobject]@{
                Name   = $key
                Value  = $fileVal
                Source = 'settings'
            }
        }
    }

    $show = $false
    if ($BoundParameters.ContainsKey('ShowEffectiveSettings')) {
        $show = [bool]$BoundParameters['ShowEffectiveSettings']
    }
    elseif (@($assignments.Keys) -contains 'ShowEffectiveSettings') {
        $show = [bool]$assignments['ShowEffectiveSettings']
    }

    if ($null -ne $loaded) {
        Write-DsmEffectiveSettings -Item $effective -AsHost:$show
    }
    elseif ($show) {
        Write-DsmEffectiveSettings -Item $effective -AsHost
    }

    $result = [pscustomobject]@{
        Loaded = [bool]($null -ne $loaded)
    }
    $result | Add-Member -NotePropertyName Assignments -NotePropertyValue $assignments
    $result | Add-Member -NotePropertyName Effective -NotePropertyValue $effective
    return $result
}

function Set-DsmCallerSettingsOverlay {
    <#
    .SYNOPSIS
        Apply unbound settings-file values onto the caller's local variables.
    .NOTES
        Must be invoked directly from the public cmdlet or script (Scope 1).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary] $BoundParameters
    )

    $overlay = Get-DsmSettingsOverlay -BoundParameters $BoundParameters
    foreach ($k in @($overlay.Assignments.Keys)) {
        Set-Variable -Name $k -Value $overlay.Assignments[$k] -Scope 1
    }

    return $overlay
}
