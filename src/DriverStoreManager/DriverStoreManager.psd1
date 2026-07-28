@{
    RootModule        = 'DriverStoreManager.psm1'
    ModuleVersion     = '0.7.10'
    GUID              = 'a3f8c2d1-7b4e-4f91-9c0d-8e5a6b7c8d9e'
    Author            = 'Ville Pispa'
    Description       = 'Inventory, vulnerability scan, and safe cleanup of Windows Driver Store packages.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Get-DsmDriverStoreInventory'
        'New-DsmDriverFilter'
        'Invoke-DsmDriverFilter'
        'New-DsmPreserveRule'
        'Invoke-DsmPreservePolicy'
        'Get-DsmDriverStoreReport'
        'Update-DsmMicrosoftDriverBlocklist'
        'Test-DsmDriverVulnerabilities'
        'Remove-DsmUnusedDriverPackages'
        'Set-DsmContentUtf8'
        'Join-DsmPath'
        'Get-DsmProgramDataRoot'
        'Export-DsmDriverDiskIdCatalog'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
