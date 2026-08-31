@{
    # Product lint settings for Driver Store Manager (scripts/ + src/).
    Severity = @('Error', 'Warning')

    # Inventory/audit/build entries are not ShouldProcess cmdlets.
    # Workspace files are UTF-8 without BOM.
    ExcludeRules = @(
        'PSUseShouldProcessForStateChangingFunctions',
        'PSUseBOMForUnicodeEncodedFile'
    )
}
