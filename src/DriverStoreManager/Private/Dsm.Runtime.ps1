function Get-DsmPowerShellVersion {
    <#
    .SYNOPSIS
        Returns the host PowerShell version as [version].
    #>
    [CmdletBinding()]
    [OutputType([version])]
    param()

    return $PSVersionTable.PSVersion
}

function Test-DsmIsPowerShellCore {
    <#
    .SYNOPSIS
        True when running PowerShell 6+ (PowerShell Core / pwsh).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    return ($PSVersionTable.PSVersion.Major -ge 6)
}

function Test-DsmIsWindowsPowerShell51 {
    <#
    .SYNOPSIS
        True when running Windows PowerShell 5.1 (typical Intune host).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    return (-not (Test-DsmIsPowerShellCore) -and $PSVersionTable.PSVersion.Major -eq 5)
}

function Join-DsmPath {
    <#
    .SYNOPSIS
        Joins path segments; safe on Windows PowerShell 5.1 (single Join-Path child limit).
    .EXAMPLE
        Join-DsmPath $env:ProgramData 'DriverStoreManager' 'reports'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromRemainingArguments = $true)]
        [string[]] $Segment
    )

    if (-not $Segment -or $Segment.Count -eq 0) {
        return $null
    }

    $result = $Segment[0]
    for ($i = 1; $i -lt $Segment.Count; $i++) {
        if ([string]::IsNullOrWhiteSpace($Segment[$i])) { continue }
        $result = Join-Path -Path $result -ChildPath $Segment[$i]
    }

    return $result
}

function Write-DsmObjectArray {
    <#
    .SYNOPSIS
        Returns a value as an array even when it has a single element (PS 5.1 unwrap safe).
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [AllowNull()]
        $InputObject
    )

    $arr = @($InputObject)
    if ($arr.Count -le 1) {
        return ,$arr
    }

    return $arr
}

function Get-DsmObjectArray {
    <#
    .SYNOPSIS
        Normalizes a value that may have been unwrapped from a single-element array (PS 5.1).
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [AllowNull()]
        $InputObject
    )

    if ($null -eq $InputObject) {
        return @()
    }

    return @($InputObject)
}

function Get-DsmObjectPropertyValue {
    <#
    .SYNOPSIS
        Reads a note property safely under Set-StrictMode.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object] $Object,

        [Parameter(Mandatory)]
        [string] $Name
    )

    if ($null -eq $Object) { return $null }

    $prop = $Object.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $null }

    return $prop.Value
}

function Set-DsmContentUtf8 {
    <#
    .SYNOPSIS
        Writes text as UTF-8 (no BOM) on PS 5.1 and PS 7+.
    .DESCRIPTION
        Writes the string exactly as provided; does not append a trailing newline.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $LiteralPath,

        [Parameter(Mandatory, ValueFromPipeline)]
        [object] $Value
    )

    process {
        $text = if ($null -eq $Value) { '' } else { [string]$Value }
        $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
        [System.IO.File]::WriteAllText($LiteralPath, $text, $utf8NoBom)
    }
}

function Get-DsmProgramDataRoot {
    <#
    .SYNOPSIS
        Default on-endpoint state directory (Intune reports, logs, backups).
    #>
    [CmdletBinding()]
    param(
        [string[]] $ChildPath
    )

    $segments = @($env:ProgramData, 'DriverStoreManager')
    if ($ChildPath) {
        $segments += $ChildPath
    }

    return (Join-DsmPath @segments)
}
