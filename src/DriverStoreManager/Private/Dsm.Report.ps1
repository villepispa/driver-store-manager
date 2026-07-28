function Get-DsmAdvisorySeverityRank {
    param(
        [string] $Severity
    )

    switch ($Severity) {
        'Critical' { return 4 }
        'High' { return 3 }
        'Medium' { return 2 }
        'Low' { return 1 }
        'Informational' { return 0 }
        default { return -1 }
    }
}

function Get-DsmPackageAdvisorySeverity {
    <#
    .SYNOPSIS
        Advisory severity hint for operator triage (never triggers auto-remediation).
    .DESCRIPTION
        Critical = blocklisted and connected; High = vulnerable in use;
        Medium = vulnerable unused; Low = signature issue only; Informational = orphan hygiene.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject] $Package,

        [bool] $IncludeSignatureInVulnerable = $true
    )

    $riskSignals = Get-DsmObjectArray -InputObject (Get-DsmObjectPropertyValue -Object $Package -Name 'RiskSignals')
    $deviceAssociation = Get-DsmObjectPropertyValue -Object $Package -Name 'DeviceAssociation'
    $inUse = Get-DsmObjectPropertyValue -Object $Package -Name 'InUse'
    $connected = $deviceAssociation -eq 'Connected' -or (
        -not $deviceAssociation -and $inUse)
    $blocklisted = $riskSignals -contains 'Blocklisted'
    $sigIssue = $riskSignals -contains 'SignatureIssue'
    $vulnerable = Test-DsmPackageIsVulnerable -Package $Package `
        -IncludeSignatureIssues:$IncludeSignatureInVulnerable

    if ($blocklisted -and $connected) {
        return 'Critical'
    }

    if ($vulnerable -and $connected) {
        return 'High'
    }

    if ($blocklisted -or ($vulnerable -and -not $connected)) {
        return 'Medium'
    }

    if ($sigIssue) {
        return 'Low'
    }

    if ($riskSignals -contains 'OrphanCandidate') {
        return 'Informational'
    }

    return 'None'
}

function Test-DsmPackageHasRiskSignal {
    param(
        [psobject] $Package,
        [string] $Signal
    )

    $riskSignalsValue = Get-DsmObjectPropertyValue -Object $Package -Name 'RiskSignals'
    if ($null -eq $riskSignalsValue) {
        return $false
    }

    $riskSignals = Get-DsmObjectArray -InputObject $riskSignalsValue
    return ($riskSignals -contains $Signal)
}

function Test-DsmPackageIsVulnerable {
    param(
        [psobject] $Package,
        [bool] $IncludeSignatureIssues = $true
    )

    $riskSignalsValue = Get-DsmObjectPropertyValue -Object $Package -Name 'RiskSignals'
    if ($null -eq $riskSignalsValue) {
        return $false
    }

    $riskSignals = Get-DsmObjectArray -InputObject $riskSignalsValue

    if ($riskSignals -contains 'Blocklisted') {
        return $true
    }

    if ($IncludeSignatureIssues -and ($riskSignals -contains 'SignatureIssue')) {
        return $true
    }

    return $false
}

function Test-DsmPackageIsOrphanCandidate {
    param(
        [psobject] $Package,
        [switch] $IncludeDisconnectedInstalled
    )

    if ([bool](Get-DsmObjectPropertyValue -Object $Package -Name 'Preserved')) {
        return $false
    }

    $assoc = $Package.DeviceAssociation
    if (-not $assoc) {
        if ($Package.InUse) { return $false }
        if ($Package.DeviceCount -gt 0) {
            return [bool]$IncludeDisconnectedInstalled
        }
        return $true
    }

    if ($assoc -eq 'NeverAssociated') {
        return $true
    }

    if ($IncludeDisconnectedInstalled -and $assoc -eq 'DisconnectedInstalled') {
        return $true
    }

    return $false
}

function Test-DsmPackageIsDeletableCandidate {
    param(
        [psobject] $Package
    )

    if ([bool](Get-DsmObjectPropertyValue -Object $Package -Name 'Preserved')) {
        return $false
    }

    $assoc = $Package.DeviceAssociation
    if (-not $assoc) {
        return (-not $Package.InUse -and $Package.DeviceCount -eq 0)
    }

    return ($assoc -eq 'NeverAssociated')
}

function Get-DsmEstimatedPackageBytes {
    param(
        [psobject] $Package
    )

    $total = 0L
    foreach ($file in @($Package.Files)) {
        if ([string]::IsNullOrWhiteSpace($file)) { continue }
        if (Test-Path -LiteralPath $file) {
            $total += (Get-Item -LiteralPath $file).Length
        }
    }

    return $total
}

function Add-DsmOldVersionFlags {
    param(
        [psobject[]] $Packages,

        [ValidateSet('ProviderOriginalName', 'HwId')]
        [string] $FamilyGroupBy = 'ProviderOriginalName'
    )

    $families = @{}
    foreach ($pkg in $Packages) {
        if ($null -eq $pkg) { continue }
        $key = Get-DsmDriverFamilyKey -Package $pkg -FamilyGroupBy $FamilyGroupBy
        if (-not $families.ContainsKey($key)) {
            $families[$key] = [System.Collections.Generic.List[object]]::new()
        }
        $families[$key].Add($pkg) | Out-Null
    }

    $latestByFamily = @{}
    $connectedFamily = @{}

    foreach ($key in $families.Keys) {
        $members = @($families[$key])
        $latestByFamily[$key] = Get-DsmLatestPackageInFamily -Packages $members
        $connectedFamily[$key] = @($members | Where-Object {
                $_.DeviceAssociation -eq 'Connected' -or (
                    -not $_.DeviceAssociation -and $_.InUse)
            }).Count -gt 0
    }

    foreach ($pkg in $Packages) {
        if ($null -eq $pkg) { continue }
        $key = Get-DsmDriverFamilyKey -Package $pkg -FamilyGroupBy $FamilyGroupBy
        $latest = $latestByFamily[$key]
        $isOld = $false
        if ($latest) {
            $isOld = ($latest.PublishedName -ne $pkg.PublishedName)
        }

        $pkg | Add-Member -NotePropertyName IsOldVersion -NotePropertyValue $isOld -Force
        $pkg | Add-Member -NotePropertyName IsOldVersionOfInUseFamily -NotePropertyValue (
            $isOld -and $connectedFamily[$key]
        ) -Force
        $pkg | Add-Member -NotePropertyName FamilyKey -NotePropertyValue $key -Force
    }
}

function New-DsmDriverStoreListingRow {
    param(
        [psobject] $Package,

        [bool] $IncludeSignatureInVulnerable = $true
    )

    $fileSummary = $null
    $fileAnalysis = Get-DsmObjectPropertyValue -Object $Package -Name 'FileAnalysis'
    if ($null -ne $fileAnalysis) {
        $blockHits = @($fileAnalysis | Where-Object { $_.BlocklistMatch }).Count
        $sigIssues = @($fileAnalysis | Where-Object {
                $_.SignatureStatus -ne 'Valid'
            }).Count
        $sigIndeterminate = @($fileAnalysis | Where-Object {
                $_.SignatureStatus -eq 'UnknownError'
            }).Count
        $fileSummary = [pscustomobject]@{
            FileCount              = @(Get-DsmObjectArray -InputObject $fileAnalysis).Count
            BlocklistMatches       = $blockHits
            SignatureIssues        = $sigIssues
            SignatureIndeterminate = $sigIndeterminate
        }
    }

    $severity = Get-DsmPackageAdvisorySeverity -Package $Package `
        -IncludeSignatureInVulnerable:$IncludeSignatureInVulnerable

    return [pscustomobject]@{
        PublishedName                    = Get-DsmObjectPropertyValue -Object $Package -Name 'PublishedName'
        OriginalName                     = Get-DsmObjectPropertyValue -Object $Package -Name 'OriginalName'
        Provider                         = Get-DsmObjectPropertyValue -Object $Package -Name 'Provider'
        DriverVersion                    = Get-DsmObjectPropertyValue -Object $Package -Name 'DriverVersion'
        DriverClass                      = Get-DsmObjectPropertyValue -Object $Package -Name 'DriverClass'
        DeviceAssociation                = Get-DsmObjectPropertyValue -Object $Package -Name 'DeviceAssociation'
        ConnectedDeviceCount             = Get-DsmObjectPropertyValue -Object $Package -Name 'ConnectedDeviceCount'
        DisconnectedInstalledDeviceCount = Get-DsmObjectPropertyValue -Object $Package -Name 'DisconnectedInstalledDeviceCount'
        Devices                          = @(Get-DsmObjectArray -InputObject (Get-DsmObjectPropertyValue -Object $Package -Name 'Devices'))
        Preserved                        = [bool](Get-DsmObjectPropertyValue -Object $Package -Name 'Preserved')
        PreserveReasons                  = @(Get-DsmObjectArray -InputObject (Get-DsmObjectPropertyValue -Object $Package -Name 'PreserveReasons'))
        PreserveRuleNames                = @(Get-DsmObjectArray -InputObject (Get-DsmObjectPropertyValue -Object $Package -Name 'PreserveRuleNames'))
        RiskSignals                      = @(Get-DsmObjectArray -InputObject (Get-DsmObjectPropertyValue -Object $Package -Name 'RiskSignals'))
        AdvisorySeverity                 = $severity
        AdvisorySeverityRank             = Get-DsmAdvisorySeverityRank -Severity $severity
        FileAnalysisSummary              = $fileSummary
        IsOldVersion                     = [bool](Get-DsmObjectPropertyValue -Object $Package -Name 'IsOldVersion')
        IsOldVersionOfInUseFamily        = [bool](Get-DsmObjectPropertyValue -Object $Package -Name 'IsOldVersionOfInUseFamily')
        FamilyKey                        = Get-DsmObjectPropertyValue -Object $Package -Name 'FamilyKey'
    }
}

function Get-DsmDriverFamilyVersionLadders {
    param(
        [psobject[]] $Packages
    )

    $byFamily = @{}
    foreach ($pkg in $Packages) {
        $key = if ($pkg.FamilyKey) { $pkg.FamilyKey } else { 'unknown' }
        if (-not $byFamily.ContainsKey($key)) {
            $byFamily[$key] = [System.Collections.Generic.List[object]]::new()
        }
        $byFamily[$key].Add($pkg) | Out-Null
    }

    $ladders = [System.Collections.Generic.List[object]]::new()
    foreach ($key in ($byFamily.Keys | Sort-Object)) {
        $members = @($byFamily[$key])
        $latest = Get-DsmLatestPackageInFamily -Packages $members
        $superseded = @($members | Where-Object { $_.PublishedName -ne $latest.PublishedName } |
            Sort-Object DriverVersion)

        $ladders.Add([pscustomobject]@{
                FamilyKey   = $key
                Latest      = (New-DsmDriverStoreListingRow -Package $latest)
                Superseded  = @($superseded | ForEach-Object { New-DsmDriverStoreListingRow -Package $_ })
                MemberCount = $members.Count
            }) | Out-Null
    }

    return @($ladders)
}

function Measure-DsmDriverStoreScope {
    <#
    .SYNOPSIS
        Computes summary counts and listings for a package set.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [psobject[]] $Packages,

        [object] $FilterResult,

        [ValidateSet('ProviderOriginalName', 'HwId')]
        [string] $FamilyGroupBy = 'ProviderOriginalName',

        [bool] $IncludeSignatureInVulnerable = $true,

        [switch] $OrphanIncludesDisconnectedInstalled
    )

    $pkgs = @(
        if ($null -eq $Packages) { @() }
        else { $Packages | Where-Object { $null -ne $_ } }
    )
    if (@($pkgs).Count -gt 0) {
        Initialize-DsmPreserveAnnotations -Inventory $pkgs
    }
    if (@($pkgs).Count -eq 0) {
        $emptySummary = [ordered]@{
            TotalPackages                      = 0
            InUseCount                         = 0
            DisconnectedDeviceDriverCount      = 0
            NeverAssociatedCount               = 0
            UnusedCount                        = 0
            PreservedCount                     = 0
            OldVersionCount                    = 0
            OldVersionsOfInUseFamiliesCount    = 0
            VulnerableCount                    = 0
            VulnerableInUseCount               = 0
            VulnerableUnusedCount              = 0
            BlocklistedInUseCount              = 0
            SignatureIssueCount                = 0
            OrphanCandidateCount               = 0
            DeletableCandidateCount            = 0
            EstimatedReclaimableBytes          = 0
            FilteredCount                      = 0
            FilterMatchRate                    = if ($FilterResult) { $FilterResult.FilterMatchRate } else { 1.0 }
            ExcludedWindowsBuiltInCount        = if ($FilterResult) { $FilterResult.ExcludedWindowsBuiltInCount } else { 0 }
            WindowsBuiltInInScopeCount         = if ($FilterResult) { $FilterResult.WindowsBuiltInInScopeCount } else { 0 }
        }
        $emptyListings = [ordered]@{
            ConnectedDrivers    = @()
            UnusedDrivers       = @()
            PreservedDrivers    = @()
            OldVersionFamilies  = @()
            VulnerableDrivers   = @()
            DeletableCandidates = @()
        }
        return [pscustomobject]@{
            Summary  = [pscustomobject]$emptySummary
            Listings = $emptyListings
        }
    }

    Add-DsmOldVersionFlags -Packages $pkgs -FamilyGroupBy $FamilyGroupBy

    $connected = @($pkgs | Where-Object {
            $_.DeviceAssociation -eq 'Connected' -or (-not $_.DeviceAssociation -and $_.InUse)
        })
    $disconnected = @($pkgs | Where-Object {
            $_.DeviceAssociation -eq 'DisconnectedInstalled' -or (
                -not $_.DeviceAssociation -and -not $_.InUse -and $_.DeviceCount -gt 0)
        })
    $never = @($pkgs | Where-Object {
            $_.DeviceAssociation -eq 'NeverAssociated' -or (
                -not $_.DeviceAssociation -and -not $_.InUse -and ($null -eq $_.DeviceCount -or $_.DeviceCount -eq 0))
        })
    $preserved = @($pkgs | Where-Object {
            [bool](Get-DsmObjectPropertyValue -Object $_ -Name 'Preserved')
        })
    $oldVersions = @($pkgs | Where-Object { $_.IsOldVersion })
    $oldInUseFamilies = @($pkgs | Where-Object { $_.IsOldVersionOfInUseFamily })

    $vulnerable = @($pkgs | Where-Object {
            Test-DsmPackageIsVulnerable -Package $_ -IncludeSignatureIssues:$IncludeSignatureInVulnerable
        })
    $vulnConnected = @($vulnerable | Where-Object {
            $_.DeviceAssociation -eq 'Connected' -or (-not $_.DeviceAssociation -and $_.InUse)
        })
    $vulnUnused = @($vulnerable | Where-Object {
            $_.DeviceAssociation -ne 'Connected' -and -not (
                -not $_.DeviceAssociation -and $_.InUse)
        })
    $blocklistedConnected = @($pkgs | Where-Object {
            (Test-DsmPackageHasRiskSignal -Package $_ -Signal 'Blocklisted') -and (
                $_.DeviceAssociation -eq 'Connected' -or (-not $_.DeviceAssociation -and $_.InUse))
        })
    $signatureOnly = @($pkgs | Where-Object {
            Test-DsmPackageHasRiskSignal -Package $_ -Signal 'SignatureIssue'
        })

    $orphans = @($pkgs | Where-Object {
            Test-DsmPackageIsOrphanCandidate -Package $_ -IncludeDisconnectedInstalled:$OrphanIncludesDisconnectedInstalled
        })
    $deletable = @($pkgs | Where-Object { Test-DsmPackageIsDeletableCandidate -Package $_ })

    $reclaimable = 0L
    foreach ($pkg in $deletable) {
        $reclaimable += Get-DsmEstimatedPackageBytes -Package $pkg
    }

    $unusedCount = $disconnected.Count + $never.Count

    $summary = [ordered]@{
        TotalPackages                      = @( $pkgs ).Count
        InUseCount                         = $connected.Count
        DisconnectedDeviceDriverCount      = $disconnected.Count
        NeverAssociatedCount               = $never.Count
        UnusedCount                        = $unusedCount
        PreservedCount                     = $preserved.Count
        OldVersionCount                    = $oldVersions.Count
        OldVersionsOfInUseFamiliesCount    = $oldInUseFamilies.Count
        VulnerableCount                    = @( $vulnerable ).Count
        VulnerableInUseCount               = $vulnConnected.Count
        VulnerableUnusedCount              = $vulnUnused.Count
        BlocklistedInUseCount              = @( $blocklistedConnected ).Count
        SignatureIssueCount                = $signatureOnly.Count
        OrphanCandidateCount               = $orphans.Count
        DeletableCandidateCount            = $deletable.Count
        EstimatedReclaimableBytes          = $reclaimable
        FilteredCount                      = $pkgs.Count
        FilterMatchRate                    = if ($FilterResult) { $FilterResult.FilterMatchRate } else { 1.0 }
        ExcludedWindowsBuiltInCount        = if ($FilterResult) { $FilterResult.ExcludedWindowsBuiltInCount } else { 0 }
        WindowsBuiltInInScopeCount         = if ($FilterResult) { $FilterResult.WindowsBuiltInInScopeCount } else { 0 }
    }

    $listingParams = @{
        IncludeSignatureInVulnerable = $IncludeSignatureInVulnerable
    }

    $vulnerableListings = @($vulnerable | ForEach-Object {
            New-DsmDriverStoreListingRow -Package $_ @listingParams
        } | Sort-Object AdvisorySeverityRank, PublishedName -Descending)

    $listings = [ordered]@{
        ConnectedDrivers    = @($connected | ForEach-Object {
                New-DsmDriverStoreListingRow -Package $_ @listingParams
            })
        UnusedDrivers       = @($pkgs | Where-Object {
                $_.DeviceAssociation -ne 'Connected' -and -not (
                    -not $_.DeviceAssociation -and $_.InUse)
            } | ForEach-Object { New-DsmDriverStoreListingRow -Package $_ @listingParams })
        PreservedDrivers    = @($preserved | ForEach-Object {
                New-DsmDriverStoreListingRow -Package $_ @listingParams
            })
        OldVersionFamilies  = @(Get-DsmDriverFamilyVersionLadders -Packages $oldVersions)
        VulnerableDrivers   = $vulnerableListings
        DeletableCandidates = @($deletable | ForEach-Object {
                New-DsmDriverStoreListingRow -Package $_ @listingParams
            })
    }

    return [pscustomobject]@{
        Summary  = [pscustomobject]$summary
        Listings = $listings
    }
}

function ConvertTo-DsmDriverStoreReportMarkdown {
    param(
        [psobject] $Report
    )

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add('# Driver Store Manager Report') | Out-Null
    $lines.Add('') | Out-Null
    $lines.Add("Generated: $($Report.GeneratedAt)") | Out-Null
    $lines.Add("Computer: $($Report.ComputerName)") | Out-Null
    $lines.Add('') | Out-Null

    foreach ($scopeName in @('Global', 'Scoped')) {
        $scope = $Report.$scopeName
        $lines.Add("## $scopeName summary") | Out-Null
        $lines.Add('') | Out-Null
        foreach ($prop in $scope.Summary.PSObject.Properties) {
            $lines.Add("- **$($prop.Name)**: $($prop.Value)") | Out-Null
        }
        $lines.Add('') | Out-Null

        $vulnRows = @($scope.Listings.VulnerableDrivers)
        if ($vulnRows.Count -gt 0) {
            $lines.Add("### $scopeName vulnerable drivers (advisory)") | Out-Null
            $lines.Add('') | Out-Null
            foreach ($row in $vulnRows) {
                $signals = ($row.RiskSignals -join ', ')
                $lines.Add("- **$($row.AdvisorySeverity)** - ``$($row.PublishedName)`` ($($row.Provider)) - $signals") | Out-Null
            }
            $lines.Add('') | Out-Null
        }
    }

    if ($Report.VulnerabilityManifest) {
        $lines.Add('## Vulnerability scan') | Out-Null
        $lines.Add('') | Out-Null
        foreach ($prop in $Report.VulnerabilityManifest.PSObject.Properties) {
            $lines.Add("- **$($prop.Name)**: $($prop.Value)") | Out-Null
        }
        $lines.Add('') | Out-Null
    }

    return ($lines -join "`r`n")
}
