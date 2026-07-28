function Get-DsmDriverStoreInventory {
    <#
    .SYNOPSIS
        Enumerates third-party driver packages in the Windows Driver Store.
    .DESCRIPTION
        Uses pnputil CSV export with optional file and device correlation, then
        enriches in-use status from connected devices. Optionally merges DISM
        Get-WindowsDriver metadata when the DISM module is available.
    .OUTPUTS
        System.Management.Automation.PSCustomObject — DsmDriverPackage records
    .EXAMPLE
        Get-DsmDriverStoreInventory | Where-Object InUse | Format-Table
    #>
    [CmdletBinding()]
    param(
        [switch] $IncludeDism,

        [ValidateSet('csv', 'xml')]
        [string] $Format = 'csv'
    )

    $temp = [System.IO.Path]::GetTempFileName()
    try {
        $argList = @('/enum-drivers', '/files', '/devices', '/format', $Format)
        $lines = @(Invoke-DsmPnPUtil -ArgumentList $argList -OutputFile $temp |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

        if ($Format -eq 'csv') {
            $packages = ConvertFrom-PnPUtilDriverCsv -InputObject $lines
        }
        else {
            throw 'XML format parsing is not implemented in v0.1; use -Format csv.'
        }

        $correlation = @{}
        try {
            $correlation = Get-DsmDeviceDriverCorrelation
        }
        catch {
            Write-Warning "Device correlation skipped: $($_.Exception.Message)"
        }

        if ($packages) {
            $packages = Add-DsmDeviceCorrelationToInventory -Inventory $packages -Correlation $correlation
        }
        else {
            $packages = @()
        }

        if ($IncludeDism -and (Get-Command Get-WindowsDriver -ErrorAction SilentlyContinue)) {
            $dismDrivers = Get-WindowsDriver -Online -ErrorAction SilentlyContinue
            $dismByName = @{}
            foreach ($d in $dismDrivers) {
                if ($d.Driver) { $dismByName[$d.Driver] = $d }
            }

            foreach ($pkg in $packages) {
                $match = $dismByName[$pkg.OriginalName]
                if ($match) {
                    $pkg | Add-Member -NotePropertyName DismProvider -NotePropertyValue $match.ProviderName -Force
                    $pkg | Add-Member -NotePropertyName DismVersion -NotePropertyValue $match.Version -Force
                    $pkg | Add-Member -NotePropertyName DismDate -NotePropertyValue $match.Date -Force
                }
            }
        }

        return (Write-DsmObjectArray -InputObject $packages)
    }
    finally {
        Remove-Item -LiteralPath $temp -Force -WhatIf:$false -ErrorAction SilentlyContinue
    }
}
