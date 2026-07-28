function Test-DsmDriverVulnerabilities {
    <#
    .SYNOPSIS
        Adds vulnerability and hygiene signals to driver inventory objects.
    .DESCRIPTION
        Checks Authenticode signatures on driver image files (.sys/.dll/.cat), blocklist
        SHA256 matches (Microsoft auto-cache plus optional -BlocklistPath), and orphan
        hygiene signals. Does not delete.
    .PARAMETER BlocklistPath
        Optional supplemental hash file merged with the Microsoft auto-updated cache.
    .PARAMETER UseMicrosoftBlocklist
        When true (default), refresh/use Microsoft's blocklist from ProgramData cache.
    .PARAMETER UpdateMicrosoftBlocklist
        Force download of the Microsoft blocklist even when cache is fresh.
    .PARAMETER MicrosoftBlocklistMaxAgeDays
        Refresh Microsoft cache when older than this many days (default 7).
    .PARAMETER SkipMicrosoftBlocklist
        Use only -BlocklistPath (offline / custom feed); disables Microsoft auto-update.
    .PARAMETER BlocklistHashes
        Pre-resolved hash set (internal; avoids duplicate refresh in report pipeline).
    .PARAMETER OrphanIncludesDisconnectedInstalled
        When set, installed-but-disconnected packages receive OrphanCandidate (matches report).
    .EXAMPLE
        Get-DsmDriverStoreInventory | Test-DsmDriverVulnerabilities | Where-Object {
            $_.RiskSignals.Count -gt 0
        }
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [AllowEmptyCollection()]
        [psobject[]] $Inventory,

        [string] $BlocklistPath,

        [bool] $UseMicrosoftBlocklist = $true,

        [switch] $UpdateMicrosoftBlocklist,

        [int] $MicrosoftBlocklistMaxAgeDays = 7,

        [switch] $SkipMicrosoftBlocklist,

        [System.Collections.Generic.HashSet[string]] $BlocklistHashes,

        [switch] $OrphanIncludesDisconnectedInstalled
    )

    begin {
        if ($PSBoundParameters.ContainsKey('BlocklistHashes')) {
            $blocklist = $BlocklistHashes
        }
        else {
            $useMs = $UseMicrosoftBlocklist -and -not $SkipMicrosoftBlocklist
            $resolved = Get-DsmBlocklistHashSet `
                -BlocklistPath $BlocklistPath `
                -UseMicrosoftBlocklist:$useMs `
                -UpdateMicrosoftBlocklist:$UpdateMicrosoftBlocklist `
                -MicrosoftBlocklistMaxAgeDays $MicrosoftBlocklistMaxAgeDays
            $blocklist = $resolved.HashSet
        }
    }

    process {
        if (-not $Inventory) {
            return
        }

        foreach ($pkg in $Inventory) {
            $signals = [System.Collections.Generic.List[string]]::new()
            $fileResults = [System.Collections.Generic.List[object]]::new()

            foreach ($file in @($pkg.Files)) {
                if (-not (Test-DsmIsDriverImagePath -Path $file)) { continue }
                if (-not (Test-Path -LiteralPath $file)) { continue }

                $sig = Get-AuthenticodeSignature -LiteralPath $file -ErrorAction SilentlyContinue
                $hashes = Get-DsmDriverFileHashes -LiteralPath $file
                $signer = $null
                if ($sig.SignerCertificate) {
                    $signer = $sig.SignerCertificate.Subject
                }

                $blockHit = $false
                foreach ($candidateHash in @($hashes.BlocklistMatchHashes)) {
                    if ($blocklist.Contains($candidateHash)) {
                        $blockHit = $true
                        break
                    }
                }

                $fileResults.Add([pscustomobject]@{
                        Path                 = $file
                        SignatureStatus      = $sig.Status
                        Signer               = $signer
                        Sha256               = $hashes.WholeFileSha256
                        AuthenticodeSha256   = $hashes.AuthenticodeSha256
                        BlocklistMatch       = $blockHit
                    })

                if ($sig.Status -eq 'Valid') {
                    # acceptable
                }
                elseif ($sig.Status -eq 'UnknownError') {
                    if ($signals -notcontains 'SignatureIndeterminate') {
                        $signals.Add('SignatureIndeterminate')
                    }
                }
                else {
                    if ($signals -notcontains 'SignatureIssue') {
                        $signals.Add('SignatureIssue')
                    }
                }

                if ($blockHit) {
                    if ($signals -notcontains 'Blocklisted') {
                        $signals.Add('Blocklisted')
                    }
                }
            }

            if (Test-DsmPackageIsOrphanCandidate -Package $pkg `
                    -IncludeDisconnectedInstalled:$OrphanIncludesDisconnectedInstalled) {
                if ($signals -notcontains 'OrphanCandidate') {
                    $signals.Add('OrphanCandidate')
                }
            }

            $pkg | Add-Member -NotePropertyName FileAnalysis -NotePropertyValue ([object[]]@($fileResults)) -Force
            $pkg | Add-Member -NotePropertyName RiskSignals -NotePropertyValue ([object[]]@($signals)) -Force
            $pkg
        }
    }
}
