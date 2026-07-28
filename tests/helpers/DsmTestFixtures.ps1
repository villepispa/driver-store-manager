function New-TestDsmPackage {
    param(
        [string] $PublishedName = 'oem1.inf',
        [string] $Provider = 'Contoso',
        [string] $OriginalName = 'foo.inf',
        [string] $DriverClass = 'Display',
        [string] $DriverVersion = '10.0.1.0',
        [string] $DeviceAssociation = 'NeverAssociated',
        [string[]] $Devices = @(),
        [string[]] $HardwareIds = @(),
        [string[]] $HardwareIdRoots = @(),
        [string[]] $Files = @(),
        [bool] $InUse = $false
    )

    [pscustomobject]@{
        PublishedName     = $PublishedName
        OriginalName      = $OriginalName
        Provider          = $Provider
        DriverClass       = $DriverClass
        DriverVersion     = $DriverVersion
        DeviceAssociation = $DeviceAssociation
        Devices           = $Devices
        HardwareIds       = $HardwareIds
        HardwareIdRoots   = $HardwareIdRoots
        Files             = $Files
        InUse             = $InUse
        DeviceCount       = $Devices.Count
        CollectedAt       = Get-Date
        InventorySource   = 'ModuleInventory'
    }
}

function Set-DsmTestAsciiFile {
    param(
        [Parameter(Mandatory)]
        [string] $LiteralPath,

        [Parameter(Mandatory)]
        [string] $Value
    )

    [System.IO.File]::WriteAllText($LiteralPath, $Value, [System.Text.Encoding]::ASCII)
}
