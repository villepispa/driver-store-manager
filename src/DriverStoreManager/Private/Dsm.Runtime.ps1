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

function Set-DsmRestrictedItemAcl {
    <#
    .SYNOPSIS
        Replaces one file or directory access list with SYSTEM full and Administrators modify.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $LiteralPath,

        [switch] $Directory
    )

    $system = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-18'
    $admins = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $acl = Get-Acl -LiteralPath $LiteralPath
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) {
        try {
            [void]$acl.RemoveAccessRule($rule)
        }
        catch {
            Write-Verbose $_.Exception.Message
        }
    }

    if ($Directory) {
        $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
        $propagate = [System.Security.AccessControl.PropagationFlags]::None
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $system, 'FullControl', $inherit, $propagate, $allow)))
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $admins, 'Modify', $inherit, $propagate, $allow)))
    }
    else {
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $system, 'FullControl', $allow)))
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $admins, 'Modify', $allow)))
    }

    Set-Acl -LiteralPath $LiteralPath -AclObject $acl
    $winIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $winPrincipal = New-Object Security.Principal.WindowsPrincipal $winIdentity
    if ($winPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        try {
            $owned = Get-Acl -LiteralPath $LiteralPath
            $owned.SetOwner($admins)
            Set-Acl -LiteralPath $LiteralPath -AclObject $owned
        }
        catch {
            Write-Verbose $_.Exception.Message
        }
    }
}

function Set-DsmRestrictedDirectoryAcl {
    <#
    .SYNOPSIS
        Limits a directory tree to SYSTEM full control and Administrators modify.
    .DESCRIPTION
        Removes inherited access, including the default ProgramData entries for
        signed-in users. Existing subfolders and files are rewritten. New
        children inherit the directory entries.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $LiteralPath
    )

    if (-not (Test-Path -LiteralPath $LiteralPath)) {
        New-Item -ItemType Directory -Path $LiteralPath -Force | Out-Null
    }

    $root = Get-Item -LiteralPath $LiteralPath -Force
    if (-not $root.PSIsContainer) {
        throw "Restricted ACL target must be a directory: $LiteralPath"
    }

    $files = @(Get-ChildItem -LiteralPath $root.FullName -Recurse -Force -File -ErrorAction SilentlyContinue)
    foreach ($file in $files) {
        Set-DsmRestrictedItemAcl -LiteralPath $file.FullName
    }

    $directories = @(Get-ChildItem -LiteralPath $root.FullName -Recurse -Force -Directory -ErrorAction SilentlyContinue)
    $orderedDirs = @($directories | Sort-Object { $_.FullName.Length } -Descending)
    foreach ($dir in $orderedDirs) {
        Set-DsmRestrictedItemAcl -LiteralPath $dir.FullName -Directory
    }

    Set-DsmRestrictedItemAcl -LiteralPath $root.FullName -Directory
}
