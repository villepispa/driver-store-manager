function New-TestDsmPackage {
    param(
        [string] $PublishedName = 'oem1.inf',
        [string] $Provider = 'Contoso',
        [string] $OriginalName = 'foo.inf',
        [string] $DriverClass = 'Display',
        [string] $DriverVersion = '10.0.1.0',
        [string] $DeviceAssociation = 'NeverAssociated',
        [string[]] $Devices = @(),
        [string[]] $HardwareIds = @(),
        [string[]] $HardwareIdRoots = @(),
        [string[]] $Files = @(),
        [bool] $InUse = $false
    )

    [pscustomobject]@{
        PublishedName     = $PublishedName
        OriginalName      = $OriginalName
        Provider          = $Provider
        DriverClass       = $DriverClass
        DriverVersion     = $DriverVersion
        DeviceAssociation = $DeviceAssociation
        Devices           = $Devices
        HardwareIds       = $HardwareIds
        HardwareIdRoots   = $HardwareIdRoots
        Files             = $Files
        InUse             = $InUse
        DeviceCount       = $Devices.Count
        CollectedAt       = Get-Date
        InventorySource   = 'ModuleInventory'
    }
}

function Set-DsmTestAsciiFile {
    param(
        [Parameter(Mandatory)]
        [string] $LiteralPath,

        [Parameter(Mandatory)]
        [string] $Value
    )

    [System.IO.File]::WriteAllText($LiteralPath, $Value, [System.Text.Encoding]::ASCII)
}

function Reset-DsmTestRestrictedAcl {
    param(
        [Parameter(Mandatory)]
        [string] $LiteralPath
    )

    # Windows PowerShell 5.1 has DirectoryInfo.SetAccessControl.
    # PowerShell 7 moved that method to FileSystemAclExtensions.
    $useInstance = $null -ne [System.IO.DirectoryInfo].GetMethod('SetAccessControl')
    $pending = New-Object System.Collections.Generic.Queue[string]
    $pending.Enqueue($LiteralPath)
    while ($pending.Count -gt 0) {
        $current = $pending.Dequeue()
        $dirSecurity = New-Object System.Security.AccessControl.DirectorySecurity
        $dirSecurity.SetAccessRuleProtection($false, $false)
        $dirInfo = New-Object System.IO.DirectoryInfo $current
        if ($useInstance) {
            $dirInfo.SetAccessControl($dirSecurity)
        }
        else {
            [System.IO.FileSystemAclExtensions]::SetAccessControl($dirInfo, $dirSecurity)
        }

        foreach ($entry in @(Get-ChildItem -LiteralPath $current -Force -ErrorAction SilentlyContinue)) {
            if ($entry.PSIsContainer) {
                $pending.Enqueue($entry.FullName)
            }
            else {
                $fileSecurity = New-Object System.Security.AccessControl.FileSecurity
                $fileSecurity.SetAccessRuleProtection($false, $false)
                if ($useInstance) {
                    $entry.SetAccessControl($fileSecurity)
                }
                else {
                    [System.IO.FileSystemAclExtensions]::SetAccessControl($entry, $fileSecurity)
                }
            }
        }
    }
}
