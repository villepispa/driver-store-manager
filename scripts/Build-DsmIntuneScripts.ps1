#Requires -Version 5.1
<#
.SYNOPSIS
  Merges Driver Store Manager module sources into standalone Intune detection and remediation scripts.

.DESCRIPTION
  **Safety tier: 2** (writes generated bundles to dist/intune; no network).

  Concatenates Private and Public sources per bundle-order.json, appends entry templates,
  and emits Detect-DsmDriverStoreCompliance.ps1 and Remediate-DsmDriverStore.ps1.
  Also writes the enterprise MVP scripts from scripts/intune/mvp into dist/intune/mvp,
  baking the same switches and settings file for features those scripts implement
  (orphan threshold, supported filters, preserve rules, max deletes, elevation).
  Bakes detect/remediate knobs from parameters (Intune Detection and Remediation
  cannot take runtime parameters). Configuration files may be on-endpoint paths
  or inlined into the generated scripts (blocklist → full Detection only; preserve
  rules → full bundles and the MVP).
  Exit 0 on success.

.PARAMETER OutputDirectory
  Output folder for generated scripts. Default: dist/intune under project root.

.PARAMETER AgentSummary
  Write exactly one line to the success stream so agents can use a single
  pwsh -NoProfile -File invocation (no Shell compound with if ($LASTEXITCODE)):
  DSM-BUILD-OK detectBytes=N remediateBytes=M on exit 0;
  DSM-BUILD-FAIL exit=N on failure.

.PARAMETER DetectBlocklisted
  Baked `$DsmDetectBlocklisted` (default `$true`; advisory — does not change Gate 7).

.PARAMETER DetectSignatureIssues
  Baked `$DsmDetectSignatureIssues` (default `$true`; advisory — does not change Gate 7).

.PARAMETER DetectOrphanCandidates
  Baked `$DsmDetectOrphanCandidates` (default `$true`).

.PARAMETER OrphanThreshold
  Baked `$DsmOrphanThreshold` (default 1). Detection exits 1 when deletable count
  is at least this value.

.PARAMETER SkipMicrosoftBlocklist
  Baked `$DsmSkipMicrosoftBlocklist` (default `$false`).

.PARAMETER ForceBlocklistUpdate
  Baked `$DsmForceBlocklistUpdate` (default `$false`).

.PARAMETER RemediationMaxDeletes
  Baked `$DsmRemediationMaxDeletes` (default 10).

.PARAMETER BackupRetentionDays
  Baked `$DsmBackupRetentionDays` and the enterprise MVP `$MvpBackupRetentionDays`
  (default 30). 0 keeps every backup.

.PARAMETER RestrictProgramDataAccess
  Baked `$DsmRestrictProgramDataAccess` and the enterprise MVP
  `$MvpRestrictProgramDataAccess` (default `$true`). SYSTEM gets full control
  of `%ProgramData%\DriverStoreManager`. Administrators get modify. Signed-in
  users get no access.

.PARAMETER RemediationRequireElevation
  Baked `$DsmRemediationRequireElevation` (default `$true`).

.PARAMETER BlocklistPath
  On-endpoint supplemental blocklist path baked into Detection (path-only mode).
  Mutually exclusive with -InlineBlocklistFile.

.PARAMETER PreserveRulesPath
  On-endpoint preserve-rules JSON path baked into Detection and Remediation
  (path-only mode). Mutually exclusive with -InlinePreserveRulesFile.

.PARAMETER InlineBlocklistFile
  Local hash file whose content is inlined into Detection. At runtime the
  script writes it under ProgramData and sets `$DsmBlocklistPath`.
  A relative path is resolved against the PowerShell current location
  (not the .NET process directory). Mutually exclusive with -BlocklistPath.

.PARAMETER InlinePreserveRulesFile
  Local preserve-rules JSON whose content is inlined into Detection and
  Remediation so cleanup uses the same rules. A relative path is resolved
  against the PowerShell current location (not the .NET process directory).
  Mutually exclusive with -PreserveRulesPath.

.PARAMETER SettingsFile
  Run-profile JSON (same shape as examples/dsm.settings.example.json). Safe
  keys are baked into the generated scripts. A relative path is resolved
  against the PowerShell current location. Bound builder parameters replace
  file values. PreserveRulesPath and BlocklistPath in the file are inlined
  when that file exists at build time.

.PARAMETER Provider
  Baked filter. Same as Get-DsmDriverStoreReport -Provider.

.PARAMETER DeviceName
  Baked filter.

.PARAMETER DriverVersion
  Baked filter.

.PARAMETER MinDriverVersion
  Baked filter. Version string.

.PARAMETER MaxDriverVersion
  Baked filter. Version string.

.PARAMETER DriverClass
  Baked filter. Detection compliance uses the scoped summary, so this limits
  which orphans trigger remediation. Remediation deletes only matching classes.

.PARAMETER ClassGuid
  Baked filter.

.PARAMETER HardwareId
  Baked filter.

.PARAMETER PublishedName
  Baked filter.

.PARAMETER OriginalName
  Baked filter.

.PARAMETER Association
  Baked filter. Any, Connected, DisconnectedInstalled, NeverAssociated,
  InUseOnly, or UnusedOnly. Deletion is still NeverAssociated orphans inside
  that filter.

.PARAMETER FamilyGroupBy
  ProviderOriginalName or HwId. Detection report only.

.PARAMETER IncludePublishedName
  Baked cleanup allow-list of oem#.inf names. Remediation only.

.PARAMETER MicrosoftBlocklistMaxAgeDays
  Baked into Detection. Omit to keep the cmdlet default of 7.

.PARAMETER InventoryMaxAgeMinutes
  Baked into Remediation. Omit to keep the cmdlet default of 15.

.PARAMETER IncludeCleanupPreview
  When true, Detection also writes a WhatIf cleanup preview JSON.

.PARAMETER ExportDiskIdCatalog
  When true, Detection also writes the DiskId catalog JSON and CSV.

.PARAMETER IncludeDism
  When true, inventory is collected with DISM as well as pnputil.

.PARAMETER ShowEffectiveSettings
  When true, the generated scripts write the baked filter keys to the host.

.PARAMETER UseMicrosoftBlocklist
  Baked into Detection when this parameter is passed.

.PARAMETER VulnerableIncludesSignature
  Baked into Detection when this parameter is passed.

.PARAMETER IncludeVulnerabilityScan
  Baked into Detection when this parameter is passed. Default remains on.

.EXAMPLE
  pwsh -NoProfile -File .\scripts\Build-DsmIntuneScripts.ps1

.EXAMPLE
  pwsh -NoProfile -File .\scripts\Build-DsmIntuneScripts.ps1 -AgentSummary

.EXAMPLE
  pwsh -NoProfile -File .\scripts\Build-DsmIntuneScripts.ps1 `
    -PreserveRulesPath 'C:\ProgramData\DriverStoreManager\config\preserve-rules.json' `
    -BlocklistPath 'C:\ProgramData\DriverStoreManager\config\blocklist-hashes.txt'

.EXAMPLE
  pwsh -NoProfile -File .\scripts\Build-DsmIntuneScripts.ps1 `
    -InlinePreserveRulesFile .\examples\preserve-rules.example.json `
    -InlineBlocklistFile .\examples\blocklist-hashes.example.txt

.EXAMPLE
  pwsh -NoProfile -File .\scripts\Build-DsmIntuneScripts.ps1 `
    -SettingsFile .\examples\dsm.settings.example.json

.NOTES
  Rebuild after any Private/ change. Entry templates: scripts/intune/templates/*.Entry.ps1.
  Generated dist/ files are auto-generated — edit src/ and re-run this script.

.LINK
  docs/intune-deployment.md
#>
[CmdletBinding()]
param(
    [string] $OutputDirectory,

    [switch] $AgentSummary,

    [bool] $DetectBlocklisted = $true,

    [bool] $DetectSignatureIssues = $true,

    [bool] $DetectOrphanCandidates = $true,

    [int] $OrphanThreshold = 1,

    [bool] $SkipMicrosoftBlocklist = $false,

    [bool] $ForceBlocklistUpdate = $false,

    [int] $RemediationMaxDeletes = 10,

    [ValidateRange(0, 36500)]
    [int] $BackupRetentionDays = 30,

    [bool] $RestrictProgramDataAccess = $true,

    [bool] $RemediationRequireElevation = $true,

    [string] $BlocklistPath,

    [string] $PreserveRulesPath,

    [string] $InlineBlocklistFile,

    [string] $InlinePreserveRulesFile,

    [string] $SettingsFile,

    [string[]] $Provider,

    [string[]] $DeviceName,

    [string[]] $DriverVersion,

    [string] $MinDriverVersion,

    [string] $MaxDriverVersion,

    [string[]] $DriverClass,

    [string[]] $ClassGuid,

    [string[]] $HardwareId,

    [string[]] $PublishedName,

    [string[]] $OriginalName,

    [string] $Association,

    [string] $FamilyGroupBy,

    [string[]] $IncludePublishedName,

    [int] $MicrosoftBlocklistMaxAgeDays,

    [int] $InventoryMaxAgeMinutes,

    [bool] $IncludeCleanupPreview,

    [bool] $ExportDiskIdCatalog,

    [bool] $IncludeDism,

    [bool] $ShowEffectiveSettings,

    [bool] $UseMicrosoftBlocklist,

    [bool] $VulnerableIncludesSignature,

    [bool] $IncludeVulnerabilityScan
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$manifestPath = Join-Path $PSScriptRoot 'intune\bundle-order.json'
$intuneScriptSizeLimitBytes = 204800

if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $projectRoot 'dist\intune'
}

if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "Bundle manifest not found: $manifestPath"
}

if ($BlocklistPath -and $InlineBlocklistFile) {
    throw 'Cannot set both -BlocklistPath and -InlineBlocklistFile.'
}

if ($PreserveRulesPath -and $InlinePreserveRulesFile) {
    throw 'Cannot set both -PreserveRulesPath and -InlinePreserveRulesFile.'
}

$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
$moduleRoot = Join-Path $projectRoot $manifest.moduleRootRelative

function ConvertTo-DsmPsBoolLiteral {
    param([bool] $Value)

    if ($Value) { return '$true' }
    return '$false'
}

function ConvertTo-DsmPsSingleQuotedLiteral {
    param([AllowNull()][string] $Value)

    if ([string]::IsNullOrEmpty($Value)) {
        return '$null'
    }

    return ("'{0}'" -f ($Value.Replace("'", "''")))
}

function ConvertTo-DsmPsHereStringAssignment {
    param(
        [string] $Name,
        [AllowNull()][object] $Value
    )

    if ($null -eq $Value) {
        return ('${0} = $null' -f $Name)
    }

    $text = [string]$Value
    $normalized = $text -replace "`r`n", "`n" -replace "`r", "`n"
    if ($normalized -match "(?m)^'@") {
        throw ("Cannot inline {0}: content contains a here-string terminator." -f $Name)
    }

    $body = $normalized.TrimEnd("`n")
    return ('${0} = @''{1}{2}{1}''@' -f $Name, "`r`n", $body)
}

function Resolve-DsmPowerShellLiteralPath {
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    # Set-Location updates the PowerShell location only. .NET file APIs
    # resolve a relative path against [Environment]::CurrentDirectory, which
    # stays at the host start directory (often the user profile).
    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    $base = (Get-Location).ProviderPath
    return [System.IO.Path]::GetFullPath((Join-Path $base $Path))
}

function Get-DsmInlineFileText {
    param(
        [string] $LiteralPath,
        [string] $Kind
    )

    $fullPath = Resolve-DsmPowerShellLiteralPath -Path $LiteralPath
    if (-not (Test-Path -LiteralPath $fullPath)) {
        throw ("Inline {0} file not found: {1}" -f $Kind, $fullPath)
    }

    return [System.IO.File]::ReadAllText($fullPath)
}

function ConvertTo-DsmPsValueLiteral {
    param(
        $Value,
        [string] $Kind
    )

    if ($Kind -eq 'array') {
        $parts = @()
        foreach ($item in @($Value)) {
            $parts += ConvertTo-DsmPsSingleQuotedLiteral -Value ([string]$item)
        }
        if ($parts.Count -eq 0) {
            return '$null'
        }
        return ('@({0})' -f ($parts -join ', '))
    }

    if ($Kind -eq 'version') {
        return ('[version]{0}' -f (ConvertTo-DsmPsSingleQuotedLiteral -Value ([string]$Value)))
    }

    if ($Kind -eq 'int') {
        return ([string][int]$Value)
    }

    if ($Kind -eq 'bool') {
        return (ConvertTo-DsmPsBoolLiteral -Value ([bool]$Value))
    }

    if ($null -eq $Value -or [string]::IsNullOrEmpty([string]$Value)) {
        return '$null'
    }

    return (ConvertTo-DsmPsSingleQuotedLiteral -Value ([string]$Value))
}

function ConvertTo-DsmPsOptionalBoolLiteral {
    param($Value)

    if ($null -eq $Value -or ($Value -is [string] -and [string]::IsNullOrEmpty([string]$Value))) {
        return '$null'
    }

    return (ConvertTo-DsmPsBoolLiteral -Value ([bool]$Value))
}

function ConvertTo-DsmPsFilterAssignment {
    param([string[]] $Lines)

    if (@($Lines).Count -eq 0) {
        return '$DsmFilter = @{}'
    }

    return ('$DsmFilter = @{{{0}{1}{0}}}' -f "`r`n", ($Lines -join "`r`n"))
}

function Set-DsmBuildConfigRegion {
    param(
        [string] $Template,
        [string] $ConfigBody
    )

    $pattern = '(?s)# region DSM_BUILD_CONFIG\r?\n.*?# endregion DSM_BUILD_CONFIG'
    if ($Template -notmatch $pattern) {
        throw 'Missing DSM_BUILD_CONFIG region in entry template.'
    }

    $replacement = "# region DSM_BUILD_CONFIG`r`n$($ConfigBody.TrimEnd())`r`n# endregion DSM_BUILD_CONFIG"
    return [regex]::Replace($Template, $pattern, { $replacement }, 1)
}

function Get-DsmBundledSource {
    param(
        [string[]] $RelativePaths
    )

    $parts = [System.Collections.Generic.List[string]]::new()

    foreach ($rel in $RelativePaths) {
        $full = Join-Path $moduleRoot ($rel -replace '/', '\')
        if (-not (Test-Path -LiteralPath $full)) {
            throw "Missing source file: $full"
        }

        $content = Get-Content -LiteralPath $full -Raw -Encoding UTF8
        $parts.Add("#region DSM source: $rel`r`n$content`r`n#endregion DSM source: $rel") | Out-Null
    }

    return ($parts -join "`r`n`r`n")
}

function New-DsmStandaloneScript {
    param(
        [string] $ScriptType,
        [string] $EntryTemplatePath,
        [string] $OutputFileName,
        [string] $BundleBody,
        [string] $ConfigBody
    )

    $entry = Get-Content -LiteralPath $EntryTemplatePath -Raw -Encoding UTF8
    $entry = Set-DsmBuildConfigRegion -Template $entry -ConfigBody $ConfigBody
    $generatedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss K'
    $psVersion = $PSVersionTable.PSVersion.ToString()

    $header = @"
# <auto-generated>
# Driver Store Manager — Intune $ScriptType script
# Generated: $generatedAt
# Builder host PS: $psVersion
# Do not edit by hand; change src/ and run scripts/Build-DsmIntuneScripts.ps1
# </auto-generated>
#Requires -Version 5.1

Set-StrictMode -Version Latest

"@

    $full = $header + $BundleBody + "`r`n`r`n" + $entry
    $outPath = Join-Path $OutputDirectory $OutputFileName

    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }

    if ($PSVersionTable.PSVersion.Major -ge 6) {
        Set-Content -LiteralPath $outPath -Value $full -Encoding utf8NoBOM
    }
    else {
        Set-Content -LiteralPath $outPath -Value $full -Encoding UTF8
    }

    return $outPath
}

$fromFile = $null
if ($SettingsFile) {
    $settingsImpl = Join-Path $projectRoot 'src\DriverStoreManager\Private\Dsm.Settings.ps1'
    . $settingsImpl
    $settingsFull = Resolve-DsmPowerShellLiteralPath -Path $SettingsFile
    $fromFile = Import-DsmSettingsFile -LiteralPath $settingsFull

    if ($fromFile.Contains('IncludeWindowsBuiltIn')) {
        if ($fromFile['IncludeWindowsBuiltIn']) {
            throw @'
IncludeWindowsBuiltIn cannot be enabled for Intune. Inbox driver manifests stay out of the cleanup scope. Omit the key, or set it to false.
'@
        }
        $fromFile.Remove('IncludeWindowsBuiltIn')
    }

    foreach ($blockedRoot in @('OutputPath', 'BackupRoot')) {
        if ($fromFile.Contains($blockedRoot)) {
            throw ($blockedRoot + ' is excluded from Intune builds. Reports and export-before-delete stay under %ProgramData%\DriverStoreManager.')
        }
    }

    if (-not $PSBoundParameters.ContainsKey('PreserveRulesPath') -and
        -not $PSBoundParameters.ContainsKey('InlinePreserveRulesFile') -and
        $fromFile.Contains('PreserveRulesPath')) {
        $resolvedPreserve = [string]$fromFile['PreserveRulesPath']
        if (-not (Test-Path -LiteralPath $resolvedPreserve)) {
            throw "Settings PreserveRulesPath was not found at build time: $resolvedPreserve. Pass -PreserveRulesPath for a path that exists only on the endpoint."
        }
        $InlinePreserveRulesFile = $resolvedPreserve
    }

    if (-not $PSBoundParameters.ContainsKey('BlocklistPath') -and
        -not $PSBoundParameters.ContainsKey('InlineBlocklistFile') -and
        $fromFile.Contains('BlocklistPath')) {
        $resolvedBlocklist = [string]$fromFile['BlocklistPath']
        if (-not (Test-Path -LiteralPath $resolvedBlocklist)) {
            throw "Settings BlocklistPath was not found at build time: $resolvedBlocklist. Pass -BlocklistPath for a path that exists only on the endpoint."
        }
        $InlineBlocklistFile = $resolvedBlocklist
    }

    if (-not $PSBoundParameters.ContainsKey('RemediationMaxDeletes') -and $fromFile.Contains('MaxDeletes')) {
        $RemediationMaxDeletes = [int]$fromFile['MaxDeletes']
    }

    if (-not $PSBoundParameters.ContainsKey('BackupRetentionDays') -and $fromFile.Contains('BackupRetentionDays')) {
        $BackupRetentionDays = [int]$fromFile['BackupRetentionDays']
    }

    if (-not $PSBoundParameters.ContainsKey('RestrictProgramDataAccess') -and $fromFile.Contains('RestrictProgramDataAccess')) {
        $RestrictProgramDataAccess = [bool]$fromFile['RestrictProgramDataAccess']
    }

    if (-not $PSBoundParameters.ContainsKey('SkipMicrosoftBlocklist') -and $fromFile.Contains('SkipMicrosoftBlocklist')) {
        $SkipMicrosoftBlocklist = [bool]$fromFile['SkipMicrosoftBlocklist']
    }

    if (-not $PSBoundParameters.ContainsKey('ForceBlocklistUpdate') -and $fromFile.Contains('UpdateMicrosoftBlocklist')) {
        $ForceBlocklistUpdate = [bool]$fromFile['UpdateMicrosoftBlocklist']
    }
}

$inlineBlocklistText = $null
if ($InlineBlocklistFile) {
    $inlineBlocklistText = Get-DsmInlineFileText -LiteralPath $InlineBlocklistFile -Kind 'blocklist'
}

$inlinePreserveText = $null
if ($InlinePreserveRulesFile) {
    $inlinePreserveText = Get-DsmInlineFileText -LiteralPath $InlinePreserveRulesFile -Kind 'preserve-rules'
    try {
        $null = $inlinePreserveText | ConvertFrom-Json
    }
    catch {
        throw "Inline preserve-rules file is not valid JSON: $InlinePreserveRulesFile"
    }
}

$bakedBlocklistPath = $null
if ($BlocklistPath) { $bakedBlocklistPath = $BlocklistPath }

$bakedPreservePath = $null
if ($PreserveRulesPath) { $bakedPreservePath = $PreserveRulesPath }

$filterKind = @{
    Provider         = 'array'
    DeviceName       = 'array'
    DriverVersion    = 'array'
    MinDriverVersion = 'version'
    MaxDriverVersion = 'version'
    DriverClass      = 'array'
    ClassGuid        = 'array'
    HardwareId       = 'array'
    PublishedName    = 'array'
    OriginalName     = 'array'
    Association      = 'association'
}
$associationAllowed = @(
    'Any', 'Connected', 'DisconnectedInstalled', 'NeverAssociated', 'InUseOnly', 'UnusedOnly'
)
$familyAllowed = @('ProviderOriginalName', 'HwId')
$filterLines = @()
$resolvedFilters = @{}
foreach ($filterName in @($filterKind.Keys)) {
    $filterValue = $null
    $filterSet = $false
    if ($PSBoundParameters.ContainsKey($filterName)) {
        $filterValue = Get-Variable -Name $filterName -ValueOnly
        $filterSet = $true
    }
    elseif ($null -ne $fromFile -and $fromFile.Contains($filterName)) {
        $filterValue = $fromFile[$filterName]
        $filterSet = $true
    }

    if (-not $filterSet -or $null -eq $filterValue) {
        continue
    }

    $kindName = [string]$filterKind[$filterName]
    if ($kindName -eq 'association') {
        $associationText = [string]$filterValue
        if ($associationAllowed -notcontains $associationText) {
            throw "Association value '$associationText' is not valid."
        }
        $resolvedFilters[$filterName] = $associationText
        $filterLines += ('    {0} = {1}' -f $filterName, (ConvertTo-DsmPsValueLiteral -Value $associationText -Kind 'string'))
        continue
    }

    if ($kindName -eq 'array' -and @($filterValue).Count -eq 0) {
        continue
    }

    $resolvedFilters[$filterName] = $filterValue
    $filterLines += ('    {0} = {1}' -f $filterName, (ConvertTo-DsmPsValueLiteral -Value $filterValue -Kind $kindName))
}

function Get-DsmIntuneOptional {
    param(
        [System.Collections.IDictionary] $Bound,
        $Loaded,
        [string] $Name,
        [string] $FileName
    )

    if ($Bound.ContainsKey($Name)) {
        return Get-Variable -Name $Name -Scope 1 -ValueOnly
    }

    if ($null -ne $Loaded -and $Loaded.Contains($FileName)) {
        return $Loaded[$FileName]
    }

    return $null
}

$familyValue = Get-DsmIntuneOptional -Bound $PSBoundParameters -Loaded $fromFile -Name 'FamilyGroupBy' -FileName 'FamilyGroupBy'
if ($null -ne $familyValue -and $familyAllowed -notcontains [string]$familyValue) {
    throw "FamilyGroupBy value '$familyValue' is not valid."
}

$publishedAllow = Get-DsmIntuneOptional -Bound $PSBoundParameters -Loaded $fromFile -Name 'IncludePublishedName' -FileName 'IncludePublishedName'
$inventoryMaxAge = Get-DsmIntuneOptional -Bound $PSBoundParameters -Loaded $fromFile -Name 'InventoryMaxAgeMinutes' -FileName 'InventoryMaxAgeMinutes'
$blocklistMaxAge = Get-DsmIntuneOptional -Bound $PSBoundParameters -Loaded $fromFile -Name 'MicrosoftBlocklistMaxAgeDays' -FileName 'MicrosoftBlocklistMaxAgeDays'
$cleanupPreview = Get-DsmIntuneOptional -Bound $PSBoundParameters -Loaded $fromFile -Name 'IncludeCleanupPreview' -FileName 'IncludeCleanupPreview'
$diskCatalog = Get-DsmIntuneOptional -Bound $PSBoundParameters -Loaded $fromFile -Name 'ExportDiskIdCatalog' -FileName 'ExportDiskIdCatalog'
$includeDismValue = Get-DsmIntuneOptional -Bound $PSBoundParameters -Loaded $fromFile -Name 'IncludeDism' -FileName 'IncludeDism'
$showSettings = Get-DsmIntuneOptional -Bound $PSBoundParameters -Loaded $fromFile -Name 'ShowEffectiveSettings' -FileName 'ShowEffectiveSettings'
$useMsBlocklist = Get-DsmIntuneOptional -Bound $PSBoundParameters -Loaded $fromFile -Name 'UseMicrosoftBlocklist' -FileName 'UseMicrosoftBlocklist'
$vulnSignature = Get-DsmIntuneOptional -Bound $PSBoundParameters -Loaded $fromFile -Name 'VulnerableIncludesSignature' -FileName 'VulnerableIncludesSignature'
$includeVuln = Get-DsmIntuneOptional -Bound $PSBoundParameters -Loaded $fromFile -Name 'IncludeVulnerabilityScan' -FileName 'IncludeVulnerabilityScan'

$publishedLiteral = '$null'
if ($null -ne $publishedAllow) {
    $publishedLiteral = ConvertTo-DsmPsValueLiteral -Value $publishedAllow -Kind 'array'
}

$inventoryAgeLiteral = '$null'
if ($null -ne $inventoryMaxAge) {
    $inventoryAgeLiteral = ConvertTo-DsmPsValueLiteral -Value $inventoryMaxAge -Kind 'int'
}

$blocklistAgeLiteral = '$null'
if ($null -ne $blocklistMaxAge) {
    $blocklistAgeLiteral = ConvertTo-DsmPsValueLiteral -Value $blocklistMaxAge -Kind 'int'
}

$sharedProfile = @(
    (ConvertTo-DsmPsFilterAssignment -Lines $filterLines)
    ('$DsmIncludePublishedName = {0}' -f $publishedLiteral)
    ('$DsmInventoryMaxAgeMinutes = {0}' -f $inventoryAgeLiteral)
    ('$DsmIncludeDism = {0}' -f (ConvertTo-DsmPsOptionalBoolLiteral -Value $includeDismValue))
    ('$DsmShowEffectiveSettings = {0}' -f (ConvertTo-DsmPsOptionalBoolLiteral -Value $showSettings))
    ('$DsmRestrictProgramDataAccess = {0}' -f (ConvertTo-DsmPsBoolLiteral -Value $RestrictProgramDataAccess))
)

$detectConfig = @(
    ('$DsmDetectBlocklisted = {0}' -f (ConvertTo-DsmPsBoolLiteral -Value $DetectBlocklisted))
    ('$DsmDetectSignatureIssues = {0}' -f (ConvertTo-DsmPsBoolLiteral -Value $DetectSignatureIssues))
    ('$DsmDetectOrphanCandidates = {0}' -f (ConvertTo-DsmPsBoolLiteral -Value $DetectOrphanCandidates))
    ('$DsmOrphanThreshold = {0}' -f $OrphanThreshold)
    ('$DsmSkipMicrosoftBlocklist = {0}' -f (ConvertTo-DsmPsBoolLiteral -Value $SkipMicrosoftBlocklist))
    ('$DsmForceBlocklistUpdate = {0}' -f (ConvertTo-DsmPsBoolLiteral -Value $ForceBlocklistUpdate))
    ('$DsmBlocklistPath = {0}' -f (ConvertTo-DsmPsSingleQuotedLiteral -Value $bakedBlocklistPath))
    ('$DsmPreserveRulesPath = {0}' -f (ConvertTo-DsmPsSingleQuotedLiteral -Value $bakedPreservePath))
    (ConvertTo-DsmPsHereStringAssignment -Name 'DsmInlineBlocklistContent' -Value $inlineBlocklistText)
    (ConvertTo-DsmPsHereStringAssignment -Name 'DsmInlinePreserveRulesContent' -Value $inlinePreserveText)
    ('$DsmFamilyGroupBy = {0}' -f (ConvertTo-DsmPsValueLiteral -Value $familyValue -Kind 'string'))
    ('$DsmMicrosoftBlocklistMaxAgeDays = {0}' -f $blocklistAgeLiteral)
    ('$DsmIncludeCleanupPreview = {0}' -f (ConvertTo-DsmPsOptionalBoolLiteral -Value $cleanupPreview))
    ('$DsmExportDiskIdCatalog = {0}' -f (ConvertTo-DsmPsOptionalBoolLiteral -Value $diskCatalog))
    ('$DsmUseMicrosoftBlocklist = {0}' -f (ConvertTo-DsmPsOptionalBoolLiteral -Value $useMsBlocklist))
    ('$DsmVulnerableIncludesSignature = {0}' -f (ConvertTo-DsmPsOptionalBoolLiteral -Value $vulnSignature))
    ('$DsmIncludeVulnerabilityScan = {0}' -f (ConvertTo-DsmPsOptionalBoolLiteral -Value $includeVuln))
) + $sharedProfile
$detectConfig = $detectConfig -join "`r`n"

$remediateConfig = @(
    ('$DsmRemediationMaxDeletes = {0}' -f $RemediationMaxDeletes)
    ('$DsmBackupRetentionDays = {0}' -f $BackupRetentionDays)
    ('$DsmRemediationRequireElevation = {0}' -f (ConvertTo-DsmPsBoolLiteral -Value $RemediationRequireElevation))
    ('$DsmPreserveRulesPath = {0}' -f (ConvertTo-DsmPsSingleQuotedLiteral -Value $bakedPreservePath))
    (ConvertTo-DsmPsHereStringAssignment -Name 'DsmInlinePreserveRulesContent' -Value $inlinePreserveText)
) + $sharedProfile
$remediateConfig = $remediateConfig -join "`r`n"

$bundleBody = Get-DsmBundledSource -RelativePaths @($manifest.sources)

$detectPath = New-DsmStandaloneScript -ScriptType 'Detection' `
    -EntryTemplatePath (Join-Path $PSScriptRoot 'intune\templates\Detect-DsmDriverStoreCompliance.Entry.ps1') `
    -OutputFileName 'Detect-DsmDriverStoreCompliance.ps1' `
    -BundleBody $bundleBody `
    -ConfigBody $detectConfig

$remediatePath = New-DsmStandaloneScript -ScriptType 'Remediation' `
    -EntryTemplatePath (Join-Path $PSScriptRoot 'intune\templates\Remediate-DsmDriverStore.Entry.ps1') `
    -OutputFileName 'Remediate-DsmDriverStore.ps1' `
    -BundleBody $bundleBody `
    -ConfigBody $remediateConfig

function Set-DsmMvpAssignment {
    param(
        [string] $Text,
        [string] $VariableName,
        [string] $Literal
    )

    $pattern = '(?m)^\$' + [regex]::Escape($VariableName) + ' = .*$'
    $match = [regex]::Match($Text, $pattern)
    if (-not $match.Success) {
        throw "MVP config missing `$$VariableName"
    }

    $replacement = '$' + $VariableName + ' = ' + $Literal
    return $Text.Remove($match.Index, $match.Length).Insert($match.Index, $replacement)
}

function Set-DsmMvpPreserveHereString {
    param(
        [string] $Text,
        [string] $JsonText
    )

    $pattern = "(?s)\`$MvpPreserveRulesJson = @'.*?'@"
    $match = [regex]::Match($Text, $pattern)
    if (-not $match.Success) {
        throw 'MVP config missing $MvpPreserveRulesJson here-string.'
    }

    $replacement = ConvertTo-DsmPsHereStringAssignment -Name 'MvpPreserveRulesJson' -Value $JsonText
    return $Text.Remove($match.Index, $match.Length).Insert($match.Index, $replacement)
}

$mvpIgnoredNames = @(
    'BlocklistPath', 'InlineBlocklistFile', 'DetectBlocklisted', 'DetectSignatureIssues',
    'SkipMicrosoftBlocklist', 'ForceBlocklistUpdate', 'MicrosoftBlocklistMaxAgeDays',
    'UseMicrosoftBlocklist', 'VulnerableIncludesSignature', 'IncludeVulnerabilityScan',
    'DeviceName', 'DriverVersion', 'MinDriverVersion', 'MaxDriverVersion', 'ClassGuid',
    'FamilyGroupBy', 'IncludeCleanupPreview', 'ExportDiskIdCatalog', 'IncludeDism',
    'InventoryMaxAgeMinutes', 'ShowEffectiveSettings', 'UpdateMicrosoftBlocklist'
)
$mvpIgnoredSet = @()
foreach ($ignoredName in $mvpIgnoredNames) {
    $ignoredSet = $false
    if ($PSBoundParameters.ContainsKey($ignoredName)) { $ignoredSet = $true }
    if ($null -ne $fromFile -and $fromFile.Contains($ignoredName)) { $ignoredSet = $true }
    if ($ignoredSet) { $mvpIgnoredSet += $ignoredName }
}
if (@($mvpIgnoredSet).Count -gt 0) {
    Write-Warning ("Enterprise MVP ignores unsupported Intune settings: {0}. The full bundles still receive them." -f ($mvpIgnoredSet -join ', '))
}

$mvpFilterVars = @{
    DriverClass   = 'MvpFilterDriverClass'
    Provider      = 'MvpFilterProvider'
    PublishedName = 'MvpFilterPublishedName'
    HardwareId    = 'MvpFilterHardwareId'
    OriginalName  = 'MvpFilterOriginalName'
}

$mvpSourceDir = Join-Path $PSScriptRoot 'intune\mvp'
$mvpOutDir = Join-Path $OutputDirectory 'mvp'
if (-not (Test-Path -LiteralPath $mvpOutDir)) {
    New-Item -ItemType Directory -Path $mvpOutDir -Force | Out-Null
}
$mvpDetectSource = Join-Path $mvpSourceDir 'Detect-DsmDriverStoreCompliance.ps1'
$mvpRemediateSource = Join-Path $mvpSourceDir 'Remediate-DsmDriverStore.ps1'
$mvpLineCounts = @{}
$mvpDetectOut = $null
$mvpRemediateOut = $null
foreach ($mvpSource in @($mvpDetectSource, $mvpRemediateSource)) {
    if (-not (Test-Path -LiteralPath $mvpSource)) {
        throw "MVP source missing: $mvpSource"
    }

    $mvpText = [System.IO.File]::ReadAllText($mvpSource)
    $mvpIsDetect = (Split-Path -Leaf $mvpSource) -like 'Detect-*'
    if ($mvpIsDetect) {
        $mvpText = Set-DsmMvpAssignment -Text $mvpText -VariableName 'MvpOrphanThreshold' -Literal ([string][int]$OrphanThreshold)
        $mvpText = Set-DsmMvpAssignment -Text $mvpText -VariableName 'MvpDetectOrphanCandidates' -Literal (ConvertTo-DsmPsBoolLiteral -Value $DetectOrphanCandidates)
    }
    else {
        $mvpText = Set-DsmMvpAssignment -Text $mvpText -VariableName 'MvpMaxDeletes' -Literal ([string][int]$RemediationMaxDeletes)
        $mvpText = Set-DsmMvpAssignment -Text $mvpText -VariableName 'MvpBackupRetentionDays' -Literal ([string][int]$BackupRetentionDays)
        $mvpText = Set-DsmMvpAssignment -Text $mvpText -VariableName 'MvpRequireElevation' -Literal (ConvertTo-DsmPsBoolLiteral -Value $RemediationRequireElevation)
    }

    $mvpText = Set-DsmMvpAssignment -Text $mvpText -VariableName 'MvpRestrictProgramDataAccess' `
        -Literal (ConvertTo-DsmPsBoolLiteral -Value $RestrictProgramDataAccess)

    foreach ($mvpFilterName in @($mvpFilterVars.Keys)) {
        if (-not $resolvedFilters.ContainsKey($mvpFilterName)) { continue }
        $mvpLiteral = ConvertTo-DsmPsValueLiteral -Value $resolvedFilters[$mvpFilterName] -Kind 'array'
        $mvpText = Set-DsmMvpAssignment -Text $mvpText -VariableName $mvpFilterVars[$mvpFilterName] -Literal $mvpLiteral
    }

    if ($resolvedFilters.ContainsKey('Association')) {
        $mvpText = Set-DsmMvpAssignment -Text $mvpText -VariableName 'MvpFilterAssociation' `
            -Literal (ConvertTo-DsmPsSingleQuotedLiteral -Value ([string]$resolvedFilters['Association']))
    }

    if ($null -ne $publishedAllow -and @($publishedAllow).Count -gt 0) {
        $mvpText = Set-DsmMvpAssignment -Text $mvpText -VariableName 'MvpIncludePublishedName' `
            -Literal (ConvertTo-DsmPsValueLiteral -Value $publishedAllow -Kind 'array')
    }

    if ($bakedPreservePath) {
        $mvpText = Set-DsmMvpAssignment -Text $mvpText -VariableName 'MvpPreserveRulesPath' `
            -Literal (ConvertTo-DsmPsSingleQuotedLiteral -Value $bakedPreservePath)
    }

    if ($null -ne $inlinePreserveText) {
        $mvpText = Set-DsmMvpPreserveHereString -Text $mvpText -JsonText $inlinePreserveText
    }

    $mvpOutPath = Join-Path $mvpOutDir (Split-Path -Leaf $mvpSource)
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($mvpOutPath, $mvpText, $utf8NoBom)
    $mvpLineCounts[(Split-Path -Leaf $mvpSource)] = @([System.IO.File]::ReadAllLines($mvpOutPath)).Count
    if ($mvpIsDetect) { $mvpDetectOut = $mvpOutPath }
    else { $mvpRemediateOut = $mvpOutPath }
}
$mvpDetectLines = $mvpLineCounts['Detect-DsmDriverStoreCompliance.ps1']
$mvpRemediateLines = $mvpLineCounts['Remediate-DsmDriverStore.ps1']

$detectSize = (Get-Item -LiteralPath $detectPath).Length
$remediateSize = (Get-Item -LiteralPath $remediatePath).Length
$mvpDetectSize = (Get-Item -LiteralPath $mvpDetectOut).Length
$mvpRemediateSize = (Get-Item -LiteralPath $mvpRemediateOut).Length

if ($detectSize -gt $intuneScriptSizeLimitBytes) {
    Write-Warning ("Detection script is {0} bytes (Intune remediations typically cap at {1})." -f `
        $detectSize, $intuneScriptSizeLimitBytes)
}

if ($remediateSize -gt $intuneScriptSizeLimitBytes) {
    Write-Warning ("Remediation script is {0} bytes (Intune remediations typically cap at {1})." -f `
        $remediateSize, $intuneScriptSizeLimitBytes)
}

$configLabel = 'none'
if ($SettingsFile) {
    $configLabel = 'settings'
}
elseif ($InlineBlocklistFile -or $InlinePreserveRulesFile) {
    $configLabel = 'inline'
}
elseif ($BlocklistPath -or $PreserveRulesPath) {
    $configLabel = 'path'
}

[pscustomobject]@{
    DetectionScript       = $detectPath
    RemediationScript     = $remediatePath
    DetectionBytes        = $detectSize
    RemediationBytes      = $remediateSize
    MvpDetectionScript    = $mvpDetectOut
    MvpRemediationScript  = $mvpRemediateOut
    MvpDetectionLines     = $mvpDetectLines
    MvpRemediationLines   = $mvpRemediateLines
    MvpDetectionBytes     = $mvpDetectSize
    MvpRemediationBytes   = $mvpRemediateSize
    SourceFileCount       = @($manifest.sources).Count
    ConfigMode            = $configLabel
} | Format-List

Write-Host 'Upload one pair to Intune Proactive Remediation (64-bit, run as SYSTEM).' -ForegroundColor Green
Write-Host 'Full bundles are the module merge. The mvp folder is the enterprise review pair.' -ForegroundColor Green
Write-Host 'See docs/intune-deployment.md for exit codes and pilot guidance.' -ForegroundColor Cyan

if ($AgentSummary) {
    Write-Output ("DSM-BUILD-OK detectBytes={0} remediateBytes={1} sources={2} config={3} mvpDetectLines={4} mvpRemediateLines={5}" -f `
        $detectSize, $remediateSize, @($manifest.sources).Count, $configLabel, $mvpDetectLines, $mvpRemediateLines)
}
