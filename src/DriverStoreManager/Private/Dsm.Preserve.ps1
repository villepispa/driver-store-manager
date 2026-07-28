function Compare-DsmDriverPackageRecency {
    <#
    .SYNOPSIS
        Compares two driver packages; newer sorts after older (return 1 if A newer than B).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject] $PackageA,

        [Parameter(Mandatory)]
        [psobject] $PackageB
    )

    $verA = Get-DsmDriverVersionParsed -VersionString (
        Get-DsmObjectPropertyValue -Object $PackageA -Name 'DriverVersion')
    $verB = Get-DsmDriverVersionParsed -VersionString (
        Get-DsmObjectPropertyValue -Object $PackageB -Name 'DriverVersion')
    if (-not $verA -and (Get-DsmObjectPropertyValue -Object $PackageA -Name 'DismVersion')) {
        $verA = Get-DsmDriverVersionParsed -VersionString (
            Get-DsmObjectPropertyValue -Object $PackageA -Name 'DismVersion')
    }
    if (-not $verB -and (Get-DsmObjectPropertyValue -Object $PackageB -Name 'DismVersion')) {
        $verB = Get-DsmDriverVersionParsed -VersionString (
            Get-DsmObjectPropertyValue -Object $PackageB -Name 'DismVersion')
    }

    if ($verA -and $verB) {
        if ($verA -gt $verB) { return 1 }
        if ($verA -lt $verB) { return -1 }
    }
    elseif ($verA -and -not $verB) { return 1 }
    elseif ($verB -and -not $verA) { return -1 }

    $dateA = $null
    $dateB = $null
    $driverDateA = Get-DsmObjectPropertyValue -Object $PackageA -Name 'DriverDate'
    $driverDateB = Get-DsmObjectPropertyValue -Object $PackageB -Name 'DriverDate'
    if ($driverDateA) {
        [datetime]::TryParse($driverDateA, [ref]$dateA) | Out-Null
    }
    if ($driverDateB) {
        [datetime]::TryParse($driverDateB, [ref]$dateB) | Out-Null
    }

    if ($dateA -and $dateB) {
        $cmp = [datetime]::Compare($dateA, $dateB)
        if ($cmp -ne 0) { return $cmp }
    }
    elseif ($dateA -and -not $dateB) { return 1 }
    elseif ($dateB -and -not $dateA) { return -1 }

    return [string]::Compare(
        [string](Get-DsmObjectPropertyValue -Object $PackageA -Name 'PublishedName'),
        [string](Get-DsmObjectPropertyValue -Object $PackageB -Name 'PublishedName'),
        [StringComparison]::OrdinalIgnoreCase
    )
}

function Get-DsmLatestPackageInFamily {
    param(
        [Parameter(Mandatory)]
        [psobject[]] $Packages
    )

    $packageArray = @(Write-DsmObjectArray -InputObject $Packages)
    if ($packageArray.Count -eq 0) {
        return $null
    }

    $latest = $packageArray[0]
    for ($i = 1; $i -lt $packageArray.Count; $i++) {
        if ((Compare-DsmDriverPackageRecency -PackageA $packageArray[$i] -PackageB $latest) -gt 0) {
            $latest = $packageArray[$i]
        }
    }

    return $latest
}

function ConvertTo-DsmDriverFilterFromJson {
    param(
        [object] $JsonFilter
    )

    if (-not $JsonFilter) {
        return $null
    }

    $params = @{}
    foreach ($prop in $JsonFilter.PSObject.Properties) {
        $name = $prop.Name
        $val = $prop.Value

        if ($null -eq $val) { continue }

        if ($name -eq 'MinDriverVersion' -or $name -eq 'MaxDriverVersion') {
            $params[$name] = [version]$val
            continue
        }

        if ($name -eq 'Association') {
            $params[$name] = [string]$val
            continue
        }

        if ($val -is [System.Collections.IEnumerable] -and -not ($val -is [string])) {
            $params[$name] = @($val | ForEach-Object { [string]$_ })
        }
        else {
            $params[$name] = @([string]$val)
        }
    }

    if ($params.Count -eq 0) {
        return $null
    }

    return (New-DsmDriverFilter @params)
}

function Get-DsmJsonPropertyValue {
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

function ConvertTo-DsmPreserveRuleFromJson {
    param(
        [object] $JsonRule
    )

    $filter = $null
    $filterJson = Get-DsmJsonPropertyValue -Object $JsonRule -Name 'Filter'
    if ($null -ne $filterJson) {
        $filter = ConvertTo-DsmDriverFilterFromJson -JsonFilter $filterJson
    }

    $published = @()
    $publishedNameValue = Get-DsmJsonPropertyValue -Object $JsonRule -Name 'PublishedName'
    if ($null -ne $publishedNameValue) {
        if ($publishedNameValue -is [System.Collections.IEnumerable] -and -not ($publishedNameValue -is [string])) {
            $published = @($publishedNameValue | ForEach-Object { [string]$_ })
        }
        else {
            $published = @([string]$publishedNameValue)
        }
    }

    $familyGroupBy = 'ProviderOriginalName'
    $familyGroupByValue = Get-DsmJsonPropertyValue -Object $JsonRule -Name 'FamilyGroupBy'
    if ($null -ne $familyGroupByValue) {
        $familyGroupBy = [string]$familyGroupByValue
    }

    $driverVersion = Get-DsmJsonPropertyValue -Object $JsonRule -Name 'DriverVersion'

    return (New-DsmPreserveRule -RuleType (Get-DsmJsonPropertyValue -Object $JsonRule -Name 'RuleType') `
            -Name (Get-DsmJsonPropertyValue -Object $JsonRule -Name 'Name') `
            -Filter $filter -FamilyGroupBy $familyGroupBy `
            -PublishedName $published -DriverVersion $driverVersion)
}

function Get-DsmPreserveRulesFromFile {
    <#
    .SYNOPSIS
        Loads preserve rules from a JSON file (array of rule objects).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Preserve rules file not found: $Path"
    }

    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    $items = $raw | ConvertFrom-Json

    if ($items -isnot [System.Collections.IEnumerable] -or $items -is [string]) {
        $items = @($items)
    }

    $rules = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $items) {
        $rules.Add((ConvertTo-DsmPreserveRuleFromJson -JsonRule $item)) | Out-Null
    }

    return @($rules)
}

function Add-DsmPreserveAnnotation {
    param(
        [psobject] $Package,
        [string] $RuleName,
        [string] $Reason
    )

    if (-not $Package.PSObject.Properties['Preserved']) {
        $Package | Add-Member -NotePropertyName Preserved -NotePropertyValue $false -Force
    }
    if (-not $Package.PSObject.Properties['PreserveReasons']) {
        $Package | Add-Member -NotePropertyName PreserveReasons -NotePropertyValue @() -Force
    }
    if (-not $Package.PSObject.Properties['PreserveRuleNames']) {
        $Package | Add-Member -NotePropertyName PreserveRuleNames -NotePropertyValue @() -Force
    }

    $Package.Preserved = $true
  $reasons = [System.Collections.Generic.List[string]]::new()
    foreach ($r in @($Package.PreserveReasons)) { $reasons.Add($r) | Out-Null }
    if ($reasons -notcontains $Reason) { $reasons.Add($Reason) | Out-Null }
    $Package.PreserveReasons = @($reasons)

    $names = [System.Collections.Generic.List[string]]::new()
    foreach ($n in @($Package.PreserveRuleNames)) { $names.Add($n) | Out-Null }
    if ($RuleName -and $names -notcontains $RuleName) { $names.Add($RuleName) | Out-Null }
    $Package.PreserveRuleNames = @($names)
}

function Initialize-DsmPreserveAnnotations {
    param(
        [psobject[]] $Inventory
    )

    foreach ($pkg in $Inventory) {
        if (-not $pkg.PSObject.Properties['Preserved']) {
            $pkg | Add-Member -NotePropertyName Preserved -NotePropertyValue $false -Force
        }
        if (-not $pkg.PSObject.Properties['PreserveReasons']) {
            $pkg | Add-Member -NotePropertyName PreserveReasons -NotePropertyValue @() -Force
        }
        if (-not $pkg.PSObject.Properties['PreserveRuleNames']) {
            $pkg | Add-Member -NotePropertyName PreserveRuleNames -NotePropertyValue @() -Force
        }
    }
}

function Test-DsmPackageMatchesPreserveRuleScope {
    param(
        [psobject] $Package,
        [psobject] $Rule
    )

    if ($Rule.Filter) {
        return (Test-DsmDriverPackageMatchesFilter -Package $Package -Filter $Rule.Filter)
    }

    return $true
}

function Invoke-DsmPreserveRule {
    param(
        [psobject[]] $Inventory,
        [psobject] $Rule
    )

    $ruleName = if ($Rule.Name) { $Rule.Name } else { $Rule.RuleType }

    switch ($Rule.RuleType) {
        'KeepPublishedName' {
            $allow = [System.Collections.Generic.HashSet[string]]::new(
                [StringComparer]::OrdinalIgnoreCase
            )
            foreach ($n in @($Rule.PublishedName)) {
                if ($n) { [void]$allow.Add($n) }
            }

            foreach ($pkg in $Inventory) {
                if ($allow.Contains($pkg.PublishedName)) {
                    Add-DsmPreserveAnnotation -Package $pkg -RuleName $ruleName `
                        -Reason 'KeepPublishedName'
                }
            }
        }

        'KeepMatching' {
            foreach ($pkg in $Inventory) {
                if (-not $Rule.Filter) { continue }
                if (Test-DsmDriverPackageMatchesFilter -Package $pkg -Filter $Rule.Filter) {
                    Add-DsmPreserveAnnotation -Package $pkg -RuleName $ruleName `
                        -Reason 'KeepMatching'
                }
            }
        }

        'KeepVersion' {
            $targetVersion = $Rule.DriverVersion
            if (-not $targetVersion) { break }

            foreach ($pkg in $Inventory) {
                if ($Rule.Filter -and -not (Test-DsmDriverPackageMatchesFilter -Package $pkg -Filter $Rule.Filter)) {
                    continue
                }

                $verText = $pkg.DriverVersion
                if ($pkg.DismVersion -and -not $verText) { $verText = $pkg.DismVersion }
                if ($verText -like $targetVersion) {
                    Add-DsmPreserveAnnotation -Package $pkg -RuleName $ruleName `
                        -Reason 'KeepVersion'
                }
            }
        }

        'KeepLatest' {
            $familyGroupBy = if ($Rule.FamilyGroupBy) { $Rule.FamilyGroupBy } else { 'ProviderOriginalName' }
            $families = @{}

            foreach ($pkg in $Inventory) {
                $key = Get-DsmDriverFamilyKey -Package $pkg -FamilyGroupBy $familyGroupBy
                if (-not $families.ContainsKey($key)) {
                    $families[$key] = [System.Collections.Generic.List[object]]::new()
                }
                $families[$key].Add($pkg) | Out-Null
            }

            foreach ($key in $families.Keys) {
                $members = @($families[$key])
                $inScope = $false
                foreach ($member in $members) {
                    if (Test-DsmPackageMatchesPreserveRuleScope -Package $member -Rule $Rule) {
                        $inScope = $true
                        break
                    }
                }

                if (-not $inScope) { continue }

                $latest = Get-DsmLatestPackageInFamily -Packages $members
                if ($latest) {
                    Add-DsmPreserveAnnotation -Package $latest -RuleName $ruleName `
                        -Reason 'LatestInFamily'
                }
            }
        }

        default {
            Write-Warning "Unknown preserve RuleType: $($Rule.RuleType)"
        }
    }
}
