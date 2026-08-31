#Requires -Version 5.1
<#
.SYNOPSIS
  Merges Driver Store Manager module sources into standalone Intune detection and remediation scripts.

.DESCRIPTION
  **Safety tier: 2** (writes generated bundles to dist/intune; no network).

  Concatenates Private and Public sources per bundle-order.json, appends entry templates,
  and emits Detect-DsmDriverStoreCompliance.ps1 and Remediate-DsmDriverStore.ps1.
  Bakes detect/remediate knobs from parameters (Intune Detection and Remediation
  cannot take runtime parameters). Configuration files may be on-endpoint paths
  or inlined into the generated scripts (blocklist → Detection; preserve rules →
  Detection and Remediation).
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
  Mutually exclusive with -BlocklistPath.

.PARAMETER InlinePreserveRulesFile
  Local preserve-rules JSON whose content is inlined into Detection and
  Remediation so cleanup uses the same rules. Mutually exclusive with
  -PreserveRulesPath.

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

    [bool] $RemediationRequireElevation = $true,

    [string] $BlocklistPath,

    [string] $PreserveRulesPath,

    [string] $InlineBlocklistFile,

    [string] $InlinePreserveRulesFile
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

function Get-DsmInlineFileText {
    param(
        [string] $LiteralPath,
        [string] $Kind
    )

    if (-not (Test-Path -LiteralPath $LiteralPath)) {
        throw ("Inline {0} file not found: {1}" -f $Kind, $LiteralPath)
    }

    return [System.IO.File]::ReadAllText($LiteralPath)
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
) -join "`r`n"

$remediateConfig = @(
    ('$DsmRemediationMaxDeletes = {0}' -f $RemediationMaxDeletes)
    ('$DsmRemediationRequireElevation = {0}' -f (ConvertTo-DsmPsBoolLiteral -Value $RemediationRequireElevation))
    ('$DsmPreserveRulesPath = {0}' -f (ConvertTo-DsmPsSingleQuotedLiteral -Value $bakedPreservePath))
    (ConvertTo-DsmPsHereStringAssignment -Name 'DsmInlinePreserveRulesContent' -Value $inlinePreserveText)
) -join "`r`n"

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

$detectSize = (Get-Item -LiteralPath $detectPath).Length
$remediateSize = (Get-Item -LiteralPath $remediatePath).Length

if ($detectSize -gt $intuneScriptSizeLimitBytes) {
    Write-Warning ("Detection script is {0} bytes (Intune remediations typically cap at {1})." -f `
        $detectSize, $intuneScriptSizeLimitBytes)
}

if ($remediateSize -gt $intuneScriptSizeLimitBytes) {
    Write-Warning ("Remediation script is {0} bytes (Intune remediations typically cap at {1})." -f `
        $remediateSize, $intuneScriptSizeLimitBytes)
}

$configLabel = 'none'
if ($InlineBlocklistFile -or $InlinePreserveRulesFile) {
    $configLabel = 'inline'
}
elseif ($BlocklistPath -or $PreserveRulesPath) {
    $configLabel = 'path'
}

[pscustomobject]@{
    DetectionScript   = $detectPath
    RemediationScript = $remediatePath
    DetectionBytes    = $detectSize
    RemediationBytes  = $remediateSize
    SourceFileCount   = @($manifest.sources).Count
    ConfigMode        = $configLabel
} | Format-List

Write-Host 'Upload both scripts to Intune Proactive Remediation (64-bit, run as SYSTEM).' -ForegroundColor Green
Write-Host 'See docs/intune-deployment.md for exit codes and pilot guidance.' -ForegroundColor Cyan

if ($AgentSummary) {
    Write-Output ("DSM-BUILD-OK detectBytes={0} remediateBytes={1} sources={2} config={3}" -f `
        $detectSize, $remediateSize, @($manifest.sources).Count, $configLabel)
}
