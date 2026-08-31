function Invoke-DsmPreservePolicy {
    <#
    .SYNOPSIS
        Applies preserve rules to driver inventory packages.
    .DESCRIPTION
        Marks packages with Preserved, PreserveReasons, and PreserveRuleNames.
        Preserved packages must be excluded from cleanup. Independent of InUse.
    .PARAMETER Inventory
        Driver packages (from Get-DsmDriverStoreInventory or post-filter).
    .PARAMETER PreserveRule
        One or more rules from New-DsmPreserveRule.
    .PARAMETER PreserveRulesPath
        JSON file (array of rules) — merged with -PreserveRule.
    .OUTPUTS
        PSCustomObject with Inventory, Preserved, PreservedCount, RuleManifest.
    .EXAMPLE
        $rules = @(
            (New-DsmPreserveRule -RuleType KeepLatest -Name 'DisplayLink' `
                -Filter (New-DsmDriverFilter -Provider '*DisplayLink*'))
            (New-DsmPreserveRule -RuleType KeepMatching -Name 'Printers' `
                -Filter (New-DsmDriverFilter -DriverClass 'Printer'))
        )
        Invoke-DsmPreservePolicy -Inventory $inv -PreserveRule $rules
    .EXAMPLE
        Invoke-DsmPreservePolicy -Inventory $inv -PreserveRulesPath .\examples\preserve-rules.example.json
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [psobject[]] $Inventory = @(),

        [psobject[]] $PreserveRule,

        [string] $PreserveRulesPath
    )

    $rules = [System.Collections.Generic.List[object]]::new()
    if ($PreserveRule) {
        foreach ($r in $PreserveRule) {
            $rules.Add($r) | Out-Null
        }
    }

    if ($PreserveRulesPath) {
        foreach ($r in (Get-DsmPreserveRulesFromFile -Path $PreserveRulesPath)) {
            $rules.Add($r) | Out-Null
        }
    }

    $packages = @($Inventory)
    Initialize-DsmPreserveAnnotations -Inventory $packages

    foreach ($rule in $rules) {
        Invoke-DsmPreserveRule -Inventory $packages -Rule $rule
    }

    $preserved = @($packages | Where-Object {
            [bool](Get-DsmObjectPropertyValue -Object $_ -Name 'Preserved')
        })
    $manifest = @($rules | ForEach-Object {
            [ordered]@{
                Name          = $_.Name
                RuleType      = $_.RuleType
                FamilyGroupBy = $_.FamilyGroupBy
                DriverVersion = $_.DriverVersion
                PublishedName = $_.PublishedName
                HasFilter     = [bool]$_.Filter
            }
        })

    return [pscustomobject]@{
        Inventory      = $packages
        Preserved      = $preserved
        PreservedCount = $preserved.Count
        RuleCount      = $rules.Count
        RuleManifest   = $manifest
    }
}
