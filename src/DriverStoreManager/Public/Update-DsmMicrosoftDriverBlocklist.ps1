function Update-DsmMicrosoftDriverBlocklist {
    <#
    .SYNOPSIS
        Downloads and caches Microsoft's vulnerable driver blocklist SHA256 hashes.
    .DESCRIPTION
        Fetches https://aka.ms/VulnerableDriverBlockList and writes hashes to
        %ProgramData%\DriverStoreManager\blocklist\microsoft\vulnerable-driver-hashes.sha256.txt
    .PARAMETER MaxAgeDays
        Skip download when cache is newer than this many days (unless -Force).
    .PARAMETER Force
        Always download, even when cache is fresh.
    .EXAMPLE
        Update-DsmMicrosoftDriverBlocklist -Force
    #>
    [CmdletBinding()]
    param(
        [int] $MaxAgeDays = 7,

        [switch] $Force
    )

    Invoke-DsmMicrosoftBlocklistRefresh @PSBoundParameters
}
