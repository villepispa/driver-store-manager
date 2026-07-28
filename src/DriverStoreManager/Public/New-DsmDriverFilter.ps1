function New-DsmDriverFilter {
    <#
    .SYNOPSIS
        Builds a filter object for Invoke-DsmDriverFilter.
    .DESCRIPTION
        Wildcards use PowerShell -like semantics (*, ?). Multiple patterns in the same
        dimension are OR'd; dimensions are AND'd. OEM scope (oem#.inf) is applied
        separately via -IncludeWindowsBuiltIn on Invoke-DsmDriverFilter.
    .EXAMPLE
        New-DsmDriverFilter -Provider 'Synaptics*','*DisplayLink*' -Association Connected
    .EXAMPLE
        New-DsmDriverFilter -HardwareId 'USB\VID_*' -DriverClass 'Printer'
    #>
    [CmdletBinding()]
    param(
        [string[]] $Provider,

        [string[]] $DeviceName,

        [string[]] $DriverVersion,

        [version] $MinDriverVersion,

        [version] $MaxDriverVersion,

        [string[]] $DriverClass,

        [string[]] $ClassGuid,

        [string[]] $HardwareId,

        [string[]] $PublishedName,

        [string[]] $OriginalName,

        [ValidateSet('Any', 'Connected', 'DisconnectedInstalled', 'NeverAssociated', 'InUseOnly', 'UnusedOnly')]
        [string] $Association = 'Any'
    )

    [pscustomobject]@{
        Provider         = $Provider
        DeviceName       = $DeviceName
        DriverVersion    = $DriverVersion
        MinDriverVersion = $MinDriverVersion
        MaxDriverVersion = $MaxDriverVersion
        DriverClass      = $DriverClass
        ClassGuid        = $ClassGuid
        HardwareId       = $HardwareId
        PublishedName    = $PublishedName
        OriginalName     = $OriginalName
        Association      = $Association
    }
}
