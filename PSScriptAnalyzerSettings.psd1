@{
    # Product lint settings for Driver Store Manager (scripts/ + src/).
    Severity = @('Error', 'Warning')

    # Inventory/audit/build entries are not ShouldProcess cmdlets.
    # Workspace files are UTF-8 without BOM.
    # Write-Host: operator/Intune host output (not pipeline objects).
    # Plural nouns: public cmdlets (Packages, Hashes) are the shipped API.
    ExcludeRules = @(
        'PSUseShouldProcessForStateChangingFunctions',
        'PSUseBOMForUnicodeEncodedFile',
        'PSAvoidUsingWriteHost',
        'PSUseSingularNouns'
    )
}
