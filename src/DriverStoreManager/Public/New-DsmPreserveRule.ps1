function New-DsmPreserveRule {
    <#
    .SYNOPSIS
        Builds a preserve rule for Invoke-DsmPreservePolicy.
    .DESCRIPTION
        Preserve is independent of InUse — keeps staged drivers for unplugged USB,
        offline printers, DisplayLink docks, etc.
    .PARAMETER RuleType
        KeepLatest, KeepVersion, KeepPublishedName, or KeepMatching.
    .PARAMETER Name
        Operator label (appears in PreserveRuleNames on packages).
    .PARAMETER Filter
        DsmDriverFilter object — scopes KeepLatest families or selects packages.
    .PARAMETER FamilyGroupBy
        ProviderOriginalName (default) or HwId for KeepLatest grouping.
    .PARAMETER PublishedName
        oem#.inf list for KeepPublishedName.
    .PARAMETER DriverVersion
        Wildcard version for KeepVersion (e.g. 10.0.*).
    .EXAMPLE
        New-DsmPreserveRule -RuleType KeepLatest -Name 'DisplayLink' `
            -Filter (New-DsmDriverFilter -Provider '*DisplayLink*','Synaptics*')
    .EXAMPLE
        New-DsmPreserveRule -RuleType KeepMatching -Name 'Printers' `
            -Filter (New-DsmDriverFilter -DriverClass 'Printer')
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('KeepLatest', 'KeepVersion', 'KeepPublishedName', 'KeepMatching')]
        [string] $RuleType,

        [string] $Name,

        [psobject] $Filter,

        [ValidateSet('ProviderOriginalName', 'HwId')]
        [string] $FamilyGroupBy = 'ProviderOriginalName',

        [string[]] $PublishedName,

        [string] $DriverVersion
    )

    if (-not $Name) {
        $Name = $RuleType
    }

    [pscustomobject]@{
        RuleType      = $RuleType
        Name          = $Name
        Filter        = $Filter
        FamilyGroupBy = $FamilyGroupBy
        PublishedName = $PublishedName
        DriverVersion = $DriverVersion
    }
}
