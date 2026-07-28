function Test-DsmElevation {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertTo-DsmWindowsArgumentString {
    <#
    .SYNOPSIS
        Quotes one argument for ProcessStartInfo.Arguments on Windows.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Value
    )

    if ($null -eq $Value) {
        return '""'
    }

    if ($Value -notmatch '[\s"]') {
        return $Value
    }

    $escaped = $Value -replace '(\\*)"', '$1$1\"'
    $escaped = $escaped -replace '(\\+)$', '$1$1'
    return '"' + $escaped + '"'
}

function ConvertFrom-DsmCsvText {
    <#
    .SYNOPSIS
        Parses RFC 4180-style CSV text into row objects (PS 5.1 compatible).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]] $Lines
    )

    if (-not $Lines -or $Lines.Count -eq 0) {
        return @()
    }

    $nonEmpty = @($Lines | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($nonEmpty.Count -lt 2) {
        return @()
    }

    $csvText = ($nonEmpty -join "`r`n")
    return @(ConvertFrom-Csv -InputObject $csvText)
}

function Invoke-DsmPnPUtil {
    <#
    .SYNOPSIS
        Runs pnputil with argument list and returns stdout lines.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]] $ArgumentList,

        [string] $OutputFile
    )

    $exe = Join-Path $env:WINDIR 'System32\pnputil.exe'
    if (-not (Test-Path -LiteralPath $exe)) {
        throw "pnputil not found at $exe"
    }

    $pnpArgs = [System.Collections.Generic.List[string]]::new()
    $pnpArgs.AddRange($ArgumentList)
    if ($OutputFile) {
        $pnpArgs.Add('/output-file')
        $pnpArgs.Add($OutputFile)
    }

    $quotedArguments = foreach ($arg in $pnpArgs) {
        ConvertTo-DsmWindowsArgumentString -Value $arg
    }

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $exe
    $psi.Arguments = ($quotedArguments -join ' ')
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true

    $proc = [System.Diagnostics.Process]::Start($psi)
    $stdoutAsync = $proc.StandardOutput.ReadToEndAsync()
    $stderrAsync = $proc.StandardError.ReadToEndAsync()

    if (-not $proc.WaitForExit(600000)) {
        try { $proc.Kill() } catch { }
        throw 'pnputil timed out after 600 seconds.'
    }

    [void]$stdoutAsync.Wait()
    [void]$stderrAsync.Wait()
    $stdout = $stdoutAsync.Result
    $stderr = $stderrAsync.Result

    if ($proc.ExitCode -ne 0) {
        $errorText = if (-not [string]::IsNullOrWhiteSpace($stderr)) {
            $stderr.Trim()
        }
        elseif (-not [string]::IsNullOrWhiteSpace($stdout)) {
            $stdout.Trim()
        }
        else {
            'no stdout/stderr output'
        }
        throw "pnputil failed (exit $($proc.ExitCode)): $errorText"
    }

    if ($OutputFile -and (Test-Path -LiteralPath $OutputFile)) {
        # pnputil /format csv writes UTF-16 LE on current Windows builds
        return Get-Content -LiteralPath $OutputFile -Encoding unicode
    }

    return $stdout -split "`r?`n"
}

function Get-DsmCsvRowValue {
    <#
    .SYNOPSIS
        Reads the first non-empty CSV column value (Set-StrictMode safe).
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [psobject] $Row,

        [Parameter(Mandatory)]
        [string[]] $Names
    )

    if ($null -eq $Row) { return $null }

    foreach ($name in $Names) {
        $prop = $Row.PSObject.Properties[$name]
        if ($null -eq $prop) { continue }
        $value = [string]$prop.Value
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            return $value
        }
    }

    return $null
}

function ConvertFrom-PnPUtilDriverCsv {
    <#
    .SYNOPSIS
        Parses pnputil /enum-drivers /format csv into grouped driver package objects.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string[]] $InputObject
    )

    begin {
        $lines = [System.Collections.Generic.List[string]]::new()
    }

    process {
        foreach ($line in $InputObject) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            $lines.Add($line) | Out-Null
        }
    }

    end {
        if ($lines.Count -lt 2) { return (Write-DsmObjectArray) }

        $rows = ConvertFrom-DsmCsvText -Lines @($lines)
        if ($rows.Count -eq 0) { return (Write-DsmObjectArray) }

        $packages = [ordered]@{}

        foreach ($dict in $rows) {
            $published = Get-DsmCsvRowValue -Row $dict -Names @(
                'DriverName', 'Published Name', 'PublishedName', 'Driver Name'
            )
            if (-not $published) { continue }

            if (-not $packages.Contains($published)) {
                $packages[$published] = [ordered]@{
                    PublishedName = $published
                    OriginalName  = (Get-DsmCsvRowValue -Row $dict -Names @('OriginalName', 'Original Name'))
                    Provider      = (Get-DsmCsvRowValue -Row $dict -Names @('ProviderName', 'Provider Name'))
                    DriverClass   = (Get-DsmCsvRowValue -Row $dict -Names @('ClassName', 'Class Name'))
                    ClassGuid     = (Get-DsmCsvRowValue -Row $dict -Names @('ClassGuid', 'Class GUID'))
                    DriverVersion = (Get-DsmCsvRowValue -Row $dict -Names @('DriverVersion', 'Driver Version'))
                    DriverDate    = (Get-DsmCsvRowValue -Row $dict -Names @('Driver Date'))
                    Signer        = (Get-DsmCsvRowValue -Row $dict -Names @('SignerName', 'Signer Name'))
                    Devices       = [System.Collections.Generic.List[string]]::new()
                    Files         = [System.Collections.Generic.List[string]]::new()
                }
            }

            $device = Get-DsmCsvRowValue -Row $dict -Names @('DeviceDescription', 'Device Description')
            if ($device) { $packages[$published].Devices.Add($device) | Out-Null }

            $filePath = Get-DsmCsvRowValue -Row $dict -Names @('File', 'File Path', 'Filename')
            if ($filePath) { $packages[$published].Files.Add($filePath) | Out-Null }
        }

        $packageList = foreach ($key in $packages.Keys) {
            $p = $packages[$key]
            $deviceList = @($p.Devices | Select-Object -Unique)
            $fileList = @($p.Files | Select-Object -Unique)
            [pscustomobject]@{
                PublishedName = $p.PublishedName
                OriginalName  = $p.OriginalName
                Provider      = $p.Provider
                DriverClass   = $p.DriverClass
                ClassGuid     = $p.ClassGuid
                DriverVersion = $p.DriverVersion
                DriverDate    = $p.DriverDate
                Signer        = $p.Signer
                DeviceCount   = $deviceList.Count
                InUse         = ($deviceList.Count -gt 0)
                Devices       = $deviceList
                Files         = $fileList
                CollectedAt   = Get-Date
                InventorySource = 'ModuleInventory'
            }
        }

        return (Write-DsmObjectArray -InputObject $packageList)
    }
}

function Get-DsmInUsePublishedNames {
    <#
    .SYNOPSIS
        Secondary correlation: published INF names referenced by connected devices.
    #>
    [CmdletBinding()]
    param()

    $temp = [System.IO.Path]::GetTempFileName()
    try {
        $lines = Invoke-DsmPnPUtil -ArgumentList @(
            '/enum-devices', '/connected', '/drivers', '/format', 'csv'
        ) -OutputFile $temp

        $names = [System.Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )

        foreach ($line in $lines) {
            if ($line -match '\.inf' -and $line -notmatch '^Device Instance ID,') {
                $parts = $line -split ','
                foreach ($part in $parts) {
                    $trim = $part.Trim('"').Trim()
                    if ($trim -match '^(oem\d+\.inf)$') {
                        [void]$names.Add($Matches[1])
                    }
                }
            }
        }

        return $names
    }
    finally {
        Remove-Item -LiteralPath $temp -Force -WhatIf:$false -ErrorAction SilentlyContinue
    }
}

function Test-DsmIsDriverImagePath {
    <#
    .SYNOPSIS
        True when a path is a driver image type scanned for hash/signature (sys, dll, cat).
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $false
    }

    $ext = [System.IO.Path]::GetExtension($Path)
    return $ext -in @('.sys', '.dll', '.cat')
}
